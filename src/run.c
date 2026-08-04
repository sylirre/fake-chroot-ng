/* cng_run() — load the guest program with the userland loader, install the
 * path-translation monitor, and transfer control. Command-line parsing lives in
 * main.c; the parameters below arrive already resolved.
 *
 *   rootfs     guest rootfs (host path); "/" means identity (no translation)
 *   libprefix  resolve the ELF interpreter under this dir (test aid; NULL on
 *              real hardware, where the interpreter and libraries resolve
 *              through the rootfs/bind map + the monitor)
 *   workdir    -w/--work-dir: the guest's initial cwd, a guest path (NULL for
 *              the default; see set_workdir)
 *   bind_g/h/ro  nb bind mounts: guest path bind_g[i] is backed by host path
 *              bind_h[i], read-only when bind_ro[i] (the CLI spells this
 *              SRC:DST[:ro], host first)
 *   env_set/ne  the ne -E/--env "VAR=VAL" entries, in command-line order, one
 *              per name; they and the inherited terminal pair are the guest's
 *              whole environment (see build_guest_env)
 *   gargv/gargc  the guest program (gargv[0]) and its arguments
 *
 * The credential/rewrite/loader flags (cng_g_fake_id, cng_g_rewrite,
 * cng_g_loader_file) are set by the option parser before this is called.
 *
 * gargv[0] is a guest path resolved through the rootfs/bind map. The monitor
 * traps the guest's own path syscalls and translates them (see monitor.h).
 * Under qemu-user the seccomp filter is inert, so translation is only exercised
 * on a real AArch64 kernel (and via the `-t dtest` self-test).
 */
#include "cng/broker.h"
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/netlink.h"
#include "cng/path.h"
#include "cng/procfs.h"
#include "cng/ptrace.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

static struct cng_fs g_fs; /* static: the monitor keeps a pointer after we jump */

static const char *load_err(int rc) {
    switch (rc) {
    case CNG_LOAD_EOPEN:
        return "cannot open (missing or unreadable)";
    case CNG_LOAD_EFORMAT:
        return "not an AArch64 ELF64 executable";
    case CNG_LOAD_EIO:
        return "short/failed read";
    case CNG_LOAD_EMAP:
        return "mmap/mprotect failed (execmem denied?)";
    case CNG_LOAD_ETOOBIG:
        return "too many program headers / interp too long";
    default:
        return "unknown error";
    }
}

static char *join2(char *dst, size_t size, const char *a, const char *b) {
    size_t n = cng_strlcpy(dst, a, size);
    if (n < size)
        cng_strlcpy(dst + n, b, size - n);
    return dst;
}

/* Assemble the guest environment into `out` (CNG_MAX_ENV + 3 slots) and
 * NULL-terminate it.
 *
 * The guest starts from a clean slate rather than inheriting ours: a host
 * variable describes the host, not the rootfs — PATH, HOME, LD_*, XDG_*,
 * TMPDIR, SHELL would every one of them send a guest looking at host paths for
 * things the rootfs has its own copies of — and our own CNG_* knobs have no
 * business in a guest's environment either. Only the terminal-appearance pair is
 * inherited, because TERM/COLORTERM describe the tty both sides share; anything
 * else the guest needs is spelled out with -E/--env.
 *
 * An -E entry wins over the inherited value. Emitting both as duplicates would
 * not be enough: getenv() takes the first match and a shell re-exporting envp
 * keeps the last, so the two would disagree about which -E took effect. */
static void build_guest_env(char *const *env_set, int ne, char **host,
                            char **out) {
    static const char *const keep[] = {"TERM=", "COLORTERM="};
    int n = 0;
    for (int i = 0; i < ne; i++)
        out[n++] = env_set[i];
    for (unsigned k = 0; k < sizeof keep / sizeof *keep; k++) {
        size_t kl = strlen(keep[k]);
        int overridden = 0;
        for (int i = 0; i < ne; i++)
            if (!strncmp(env_set[i], keep[k], kl)) {
                overridden = 1;
                break;
            }
        if (overridden)
            continue;
        for (char **e = host; e && *e; e++)
            if (!strncmp(*e, keep[k], kl)) {
                out[n++] = *e;
                break;
            }
    }
    out[n] = 0;
}

/* AArch64 struct stat: the st_mode field, for the -w directory check below. */
#define ST_MODE_OFF 16

/* -w/--work-dir: make the guest path `wd` the initial cwd.
 *
 * `wd` is a guest path resolved through the rootfs and its binds like any other,
 * following symlinks — an absolute one from the guest root, a relative one
 * against the default cwd the caller has just set — so the guest lands exactly
 * where chdir(wd) would have put it, and getcwd() reports the resolved name a
 * real chdir leaves behind rather than the symlink that was typed.
 *
 * A path that does not name a directory is fatal instead of a quiet fallback to
 * "/": the point of the option is to say where the guest starts, and a program
 * started in the wrong directory misbehaves silently — a build in the wrong
 * tree, a relative <program> resolved somewhere else.
 *
 * Returns 0, or -1 with a diagnostic. */
static int set_workdir(struct cng_fs *fs, const char *wd) {
    if (!*wd) {   /* "" would join to the cwd; chdir("") is ENOENT */
        cng_dprintf(2, "chroot-ng: --work-dir: empty path\n");
        return -1;
    }
    char host[CNG_PATH_MAX];
    if (cng_resolve(wd, 1, host, sizeof host) != 0) {
        cng_dprintf(2, "chroot-ng: --work-dir '%s': cannot resolve\n", wd);
        return -1;
    }
    char st[128];   /* struct stat, aarch64 */
    long r = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, (long)host, (long)st, 0, 0,
                     0);
    if (r == -ENOENT) {
        cng_dprintf(2, "chroot-ng: --work-dir '%s': not found\n", wd);
        return -1;
    }
    if (r != 0) {
        cng_dprintf(2, "chroot-ng: --work-dir '%s': cannot stat (errno %d)\n",
                    wd, (int)-r);
        return -1;
    }
    if ((*(unsigned *)(st + ST_MODE_OFF) & CNG_S_IFMT) != CNG_S_IFDIR) {
        cng_dprintf(2, "chroot-ng: --work-dir '%s': not a directory\n", wd);
        return -1;
    }
    /* The guest-side name of what we resolved: absolute and symlink-free by
     * construction. A host path outside the guest view has no such name — only
     * possible for a resolution that left the map, e.g. through /proc/self/fd —
     * so fall back to the lexical form there. */
    char guest[CNG_PATH_MAX];
    if (cng_fs_untranslate(fs, host, guest, sizeof guest) != 0 &&
        cng_fs_abscanon(fs, wd, guest, sizeof guest) != 0) {
        cng_dprintf(2, "chroot-ng: --work-dir '%s': path too long\n", wd);
        return -1;
    }
    cng_fs_set_cwd(fs, guest);
    /* And the real cwd with it, as the default does: a relative path that the
     * monitor never sees — anything untrapped, and everything when no monitor
     * installs at all — resolves against this one. */
    sys_chdir(host);
    return 0;
}

int cng_run(const char *rootfs, const char *libprefix, const char *workdir,
            const char *const *bind_g, const char *const *bind_h,
            const int *bind_ro, int nb, char *const *env_set, int ne,
            int gargc, char **gargv, char **envp, unsigned long *auxv) {
    const char *prog_guest = gargv[0];

    /* Capture host auxv (for emulated execve), the guest exe path (a placeholder
     * for the /proc/self/exe fixups until the program is resolved below, which is
     * what makes it absolute and symlink-resolved) and our own environment (for
     * the CNG_* knobs and
     * for env lookups after argv/envp are out of reach — procreg.c's
     * shared_dir). This is the host environment throughout; the guest's is
     * `genv` below. */
    cng_host_auxv = auxv;
    cng_g_exe_guest = prog_guest;
    cng_g_host_envp = envp;
    /* The break before any guest program has run: what an emulated execve winds
     * the heap back to, since it cannot drop it with the address space. */
    long brk0 = CNG_SYS(__NR_brk, 0, 0, 0, 0, 0, 0);
    if (brk0 > 0)
        cng_g_brk0 = (unsigned long)brk0;

    /* Key the System V shm namespace to this invocation (unless --shared-proc
     * widens it to the rootfs). Seeded here, in the root process while we are
     * still single-threaded, and fork-inherited — so one launch's whole process
     * tree shares one namespace and separate launches stay isolated. */
    cng_broker_seed_session();

    /* CNG_DEBUG=1 in the environment enables verbose syscall-error logging;
     * CNG_L2S_FORCE=1 routes every linkat through the -l emulation (test aid
     * for hosts whose filesystem allows real hardlinks). */
    for (char **e = envp; e && *e; e++) {
        /* An empty value is off, as it is for the two knobs below and for
         * cng_broker_env, which every other CNG_* switch goes through. Without
         * the test, `CNG_DEBUG= chroot-ng ...` — how a shell clears a variable
         * for one command — turned verbose logging ON, onto the guest's own
         * stderr, which is a stream package managers capture and log. */
        if (!strncmp(*e, "CNG_DEBUG=", 10) && (*e)[10] != '\0' &&
            (*e)[10] != '0')
            cng_g_debug = 1;
        if (!strncmp(*e, "CNG_L2S_FORCE=", 14) && (*e)[14] != '\0' &&
            (*e)[14] != '0')
            cng_g_l2s_force = 1;
        /* CNG_PROCSTAT_SYNTH=1 forces the synthesized /proc/stat even where the
         * host file is readable (Android denies it; test hosts do not). */
        if (!strncmp(*e, "CNG_PROCSTAT_SYNTH=", 19) && (*e)[19] != '\0' &&
            (*e)[19] != '0')
            cng_g_procstat_synth = 1;
    }
    /* Stamp the build: this tree is copied to test devices by hand, so a trace
     * has to be able to say whether it came from the build you just made. */
    if (cng_g_debug)
        cng_dprintf(2, "[cng] chroot-ng %s (built %s %s)\n", CNG_VERSION,
                    __DATE__, __TIME__);

    /* The environment the guest will see, built from -E/--env plus TERM /
     * COLORTERM — everything the knob scan above just read stays on our side of
     * the line. It only has to outlive cng_build_stack, which copies the strings
     * onto the guest stack. */
    char *genv[CNG_MAX_ENV + 3];
    build_guest_env(env_set, ne, envp, genv);

    /* Fake identity (--fake-id): establish it from the real invoking ids (which
     * are also the stat-remap source). See cng_cred_setup for the implied-vs-
     * explicit identity default. */
    if (cng_g_fake_id)
        cng_cred_setup((unsigned)sys_getuid(), (unsigned)sys_getgid());

    /* Filesystem view. A prefix that does not fit is refused, not shortened:
     * every guest path is joined to it, so a truncated one would silently root
     * the guest at an ancestor of the tree that was named — or, since the cut
     * lands mid-component, at a path that is not a directory at all. */
    if (cng_fs_init(&g_fs, rootfs) != 0) {
        cng_dprintf(2, "chroot-ng: rootfs '%s': path too long (max %d)\n",
                    rootfs, (int)sizeof g_fs.rootfs - 1);
        return 2;
    }
    for (int j = 0; j < nb; j++)
        if (cng_fs_add_bind(&g_fs, bind_g[j], bind_h[j], bind_ro[j]) != 0) {
            cng_dprintf(2, "chroot-ng: --bind '%s:%s': path too long\n",
                        bind_h[j], bind_g[j]);
            return 2;
        }
    /* The dispatcher (used by both the SIGSYS handler and M8 trampolines) needs
     * the fs view even if the seccomp monitor never installs (e.g. -R only) —
     * and so does cng_resolve, which -w/--work-dir and the program lookup below
     * both go through. */
    cng_g_fs = &g_fs;

    /* Initial guest cwd. With a real rootfs, default to "/" (never leak the host
     * launch dir) and chdir the real process into the rootfs so untranslated
     * relative access stays contained. With an identity rootfs, the host cwd is
     * the guest cwd. */
    if (strcmp(rootfs, "/") != 0) {
        cng_fs_set_cwd(&g_fs, "/");
        char rhost[CNG_PATH_MAX];
        if (cng_fs_translate(&g_fs, "/", rhost, sizeof rhost) == 0)
            sys_chdir(rhost);
    } else {
        char cwd[CNG_PATH_MAX];
        if (sys_getcwd(cwd, sizeof cwd) > 0)
            cng_fs_set_cwd(&g_fs, cwd);
    }
    /* -w/--work-dir overrides that default. It has to land here: <program> is
     * resolved against the cwd just below, so a relative one follows -w, exactly
     * as it would follow the cwd of a shell that ran the same command. */
    if (workdir && set_workdir(&g_fs, workdir) < 0)
        return 1;

    cng_nl_init();
    if (cng_broker_env("CNG_NETLINK_FORCE_BLOCK"))
        cng_nl_force_block = 1;
    if (cng_broker_env("CNG_NETLINK_NO_RELAY")) {
        cng_nl_force_block = 1;
        cng_nl_no_relay = 1;
    }
    if (cng_broker_env("CNG_NETLINK_DENY_GETLINK")) {
        cng_nl_force_block = 1;
        cng_nl_deny_getlink = 1;
    }
    /* Stands alone: the audit refusal has nothing to do with the rtnetlink
     * emulation, so forcing one must not force the other. */
    if (cng_broker_env("CNG_NETLINK_DENY_AUDIT"))
        cng_nl_deny_audit = 1;

    /* Resolve the program itself through the map (following symlinks) to find
     * the host file. */
    char host_prog[CNG_PATH_MAX];
    if (cng_resolve(prog_guest, 1, host_prog, sizeof host_prog) != 0) {
        cng_dprintf(2, "chroot-ng: cannot resolve %s\n", prog_guest);
        return 1;
    }
    /* /proc/self/exe (and the comm derived from it) for the initial program. It
     * was <program> verbatim, while a real kernel reports the absolute,
     * symlink-resolved path of the image it actually loaded — and glibc does not
     * merely tolerate that, it asserts the leading '/' in _dl_get_origin, so a
     * relative <program> ("chroot-ng / build/tests/hello") aborted the guest
     * before main. The host path we just resolved, untranslated back into the
     * guest view, is absolute and symlink-resolved by construction, and it is the
     * same derivation the emulated execve uses for every program after this one
     * (execve.c) — so the first program in a session stops answering differently
     * from its own children. */
    static char exe_guest[CNG_PATH_MAX];
    if (cng_fs_untranslate(&g_fs, host_prog, exe_guest, sizeof exe_guest) == 0 ||
        cng_fs_abscanon(&g_fs, prog_guest, exe_guest, sizeof exe_guest) == 0)
        cng_g_exe_guest = exe_guest;

    /* setuid/setgid-on-exec for the initial program (e.g. running /bin/su
     * directly), mirroring the emulated-execve path. */
    cng_cred_exec(host_prog);

    struct cng_loaded prog;
    int rc = cng_load_elf(host_prog, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        cng_dprintf(2, "chroot-ng: cannot load %s (%s): %s\n", prog_guest,
                    host_prog, load_err(rc));
        return 1;
    }

    unsigned long sp, entry;
    if (prog.has_interp) {
        char ipath[CNG_PATH_MAX];
        const char *ip;
        if (libprefix)
            ip = join2(ipath, sizeof ipath, libprefix, prog.interp);
        else if (cng_resolve(prog.interp, 1, ipath, sizeof ipath) == 0)
            ip = ipath;
        else
            ip = prog.interp;

        struct cng_loaded interp;
        int rc2 = cng_load_elf(ip, 0, &interp);
        if (rc2 != CNG_LOAD_OK) {
            cng_dprintf(2, "chroot-ng: cannot load interpreter %s: %s\n", ip,
                        load_err(rc2));
            return 1;
        }
        sp = cng_build_stack(gargc, gargv, genv, auxv, &prog, &interp,
                             prog_guest);
        entry = interp.entry;
    } else {
        sp = cng_build_stack(gargc, gargv, genv, auxv, &prog, 0, prog_guest);
        entry = prog.entry;
    }
    if (!sp) {
        cng_dprintf(2, "chroot-ng: argument list too long\n");
        return 1;
    }
    /* (svc rewriting + its pool are handled inside the loader, per object.) */

    /* /proc emulation: bring up the PID registry and reserve the synthesized fd
     * range (both must be settled before the seccomp filter is built, which
     * bakes the range in), then publish this process's guest identity from the
     * stack we just built. */
    if (!cng_g_no_proc) {
        cng_procfs_init();
        cng_procfs_publish_stack(sp);
    }

    /* The ptrace link registry: one MAP_SHARED region that every guest process
     * must inherit, so it has to exist before the guest can fork — and before
     * the filter, whose install is the last thing that happens here. */
    cng_pt_init();

    /* Install the monitor last, after all of our own path syscalls are done.
     * Only when translation was actually requested; identity needs none. */
    int want_xlate = (strcmp(rootfs, "/") != 0) || nb > 0 || cng_g_fake_id ||
                     cng_g_rewrite || cng_g_l2s;
    if (want_xlate) {
        int mrc = cng_install_monitor(&g_fs);
        if (mrc < 0)
            cng_dprintf(2,
                        "chroot-ng: warning: could not install seccomp monitor "
                        "(errno %d); %s\n"
                        "           (seccomp is inert under qemu-user; a real "
                        "AArch64 kernel is required for the SIGSYS path)\n",
                        -mrc,
                        cng_g_rewrite
                            ? "svc-rewriting (-R) still handles located sites"
                            : "path translation is INACTIVE");
    }

    cng_enter(sp, entry);
}
