/* cng_run() — load the guest program with the userland loader, install the
 * path-translation monitor, and transfer control. Command-line parsing lives in
 * main.c; the parameters below arrive already resolved.
 *
 *   rootfs     guest rootfs (host path); "/" means identity (no translation)
 *   libprefix  resolve the ELF interpreter under this dir (test aid; NULL on
 *              real hardware, where the interpreter and libraries resolve
 *              through the rootfs/bind map + the monitor)
 *   bind_g/h   nb guest->host bind pairs (guest path G backed by host path H)
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
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"

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

int cng_run(const char *rootfs, const char *libprefix,
            const char *const *bind_g, const char *const *bind_h, int nb,
            int gargc, char **gargv, char **envp, unsigned long *auxv) {
    const char *prog_guest = gargv[0];

    /* Capture host auxv (for emulated execve) and the guest exe path
     * (for /proc/self/exe fixups). */
    cng_host_auxv = auxv;
    cng_g_exe_guest = prog_guest;

    /* CNG_DEBUG=1 in the environment enables verbose syscall-error logging. */
    for (char **e = envp; e && *e; e++)
        if (!strncmp(*e, "CNG_DEBUG=", 10) && (*e)[10] != '0')
            cng_g_debug = 1;

    /* Fake identity (--fake-id): establish it from the real invoking ids (which
     * are also the stat-remap source). See cng_cred_setup for the implied-vs-
     * explicit identity default. */
    if (cng_g_fake_id)
        cng_cred_setup((unsigned)sys_getuid(), (unsigned)sys_getgid());

    /* Filesystem view. */
    cng_fs_init(&g_fs, rootfs);
    for (int j = 0; j < nb; j++)
        cng_fs_add_bind(&g_fs, bind_g[j], bind_h[j]);
    /* Initial guest cwd. With a real rootfs, default to "/" (never leak the host
     * launch dir) and chdir the real process into the rootfs so untranslated
     * relative access stays contained; a -w option can override later. With an
     * identity rootfs, the host cwd is the guest cwd. */
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

    /* The dispatcher (used by both the SIGSYS handler and M8 trampolines) needs
     * the fs view even if the seccomp monitor never installs (e.g. -R only). */
    cng_g_fs = &g_fs;

    /* Resolve the program itself through the map (following symlinks) to find
     * the host file. */
    char host_prog[CNG_PATH_MAX];
    if (cng_resolve(prog_guest, 1, host_prog, sizeof host_prog) != 0) {
        cng_dprintf(2, "chroot-ng: cannot resolve %s\n", prog_guest);
        return 1;
    }
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
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, &interp,
                             prog_guest);
        entry = interp.entry;
    } else {
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, 0, prog_guest);
        entry = prog.entry;
    }
    /* (svc rewriting + its pool are handled inside the loader, per object.) */

    /* Install the monitor last, after all of our own path syscalls are done.
     * Only when translation was actually requested; identity needs none. */
    int want_xlate =
        (strcmp(rootfs, "/") != 0) || nb > 0 || cng_g_fake_id || cng_g_rewrite;
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
