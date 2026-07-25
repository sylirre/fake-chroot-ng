/* In-process execve/execveat emulation.
 *
 * A real kernel execve replaces the address space, wiping our SIGSYS handler
 * (the seccomp filter survives, but with no handler the next trap kills the
 * process). So we never let execve reach the kernel: we load the new program
 * ourselves and rewrite the trapped signal context to enter it, leaving the
 * monitor resident. This is the piece that makes the in-process model hold
 * together across program replacement.
 *
 * We do not tear down the previous program's mappings; the new program gets a
 * fresh stack and a kernel-chosen load base, so they don't collide. Repeated
 * execve leaks the old images (acceptable for now; noted in STATUS).
 */
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

unsigned long *cng_host_auxv = 0;

/* A real execve closes every FD_CLOEXEC descriptor. Our in-process emulation
 * never issues a real execve, so we must do this ourselves — otherwise the
 * exec-notify pipe that fork/exec launchers (git's run-command, posix_spawn)
 * open with O_CLOEXEC never closes, and the parent blocks forever waiting for
 * the EOF that signals "exec succeeded". Iterate /proc/self/fd and close each fd
 * whose FD_CLOEXEC bit is set (skipping the directory fd we are scanning). */
/* A real execve resets signal dispositions (caught -> default, ignored kept)
 * and disables the alternate signal stack. Our in-process emulation must do the
 * same, or the new program inherits the previous one's handlers and altstack —
 * e.g. a C compiler exec'd from Go would inherit Go's SIGSEGV/SIGURG handlers
 * and Go's small per-thread sigaltstack, onto which our SA_ONSTACK SIGSYS
 * handler would then deliver. SIGSYS is left alone (our monitor owns it). */
static void cng_reset_signals(void) {
    /* kernel struct sigaction: handler, flags, restorer, mask (32 bytes). */
    unsigned long cur[4], dfl[4] = {0, 0, 0, 0};
    for (int s = 1; s <= 64; s++) {
        if (s == CNG_SIGSYS)
            continue;
        if (CNG_SYS(__NR_rt_sigaction, s, 0, cur, 8, 0, 0) < 0)
            continue;             /* SIGKILL/SIGSTOP etc.: unqueryable, skip */
        if (cur[0] == 0 || cur[0] == 1)
            continue;             /* already SIG_DFL, or SIG_IGN (keep ignored) */
        CNG_SYS(__NR_rt_sigaction, s, dfl, 0, 8, 0, 0);
    }
    /* stack_t: ss_sp(8), ss_flags(4)@8, ss_size(8)@16 => 24 bytes. SS_DISABLE=2. */
    unsigned long ss[3] = {0, 2, 0};
    CNG_SYS(__NR_sigaltstack, ss, 0, 0, 0, 0, 0);
}

void cng_close_cloexec(void) {
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc/self/fd",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return;
    char buf[4096];
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)dfd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        long o = 0;
        while (o + 19 <= n) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19; /* d_name at record offset +19 */
            o += reclen;
            int fd = 0, ok = (nm[0] >= '0' && nm[0] <= '9');
            for (const char *c = nm; *c; c++) {
                if (*c < '0' || *c > '9') {
                    ok = 0;
                    break;
                }
                fd = fd * 10 + (*c - '0');
            }
            if (!ok || fd == (int)dfd)
                continue;
            long fl = CNG_SYS(__NR_fcntl, fd, 1 /*F_GETFD*/, 0, 0, 0, 0);
            if (fl >= 0 && (fl & 1 /*FD_CLOEXEC*/))
                sys_close(fd);
        }
    }
    sys_close((int)dfd);
}

/* Shared emulation core: resolve the target (shebang-aware), load it, build its
 * stack, and pass the commit point (close FD_CLOEXEC fds, reset signal
 * dispositions, retarget /proc/self/exe). Returns -errno on failure (all of
 * which occur before the commit point), or 0 with *out_sp/*out_entry set for
 * the caller to transfer control into the new program. */
static long execve_core(int dirfd, const char *path, char **argv, char **envp,
                        unsigned long *out_sp, unsigned long *out_entry) {
    if (cng_g_debug)
        cng_dprintf(2, "[cng] execve enter path=%s\n", path ? path : "(null)");

    if (!path)
        return -EFAULT;
    /* l2s machinery is invisible to the guest — not executable either. Both
     * tiers (SIGSYS cng_emulate_execve, -R cng_execve_tramp) come through
     * here, so this covers every exec path. */
    if (cng_g_l2s && cng_l2s_deny(dirfd, path)) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] execve %s -> l2s-hidden\n", path);
        return -ENOENT;
    }

    /* Resolve the target through the rootfs/bind map, following symlinks
     * (absolute or AT_FDCWD); a real dirfd with a relative path is a rare case
     * we pass through. */
    char host[CNG_PATH_MAX];
    if (path[0] == '/' || dirfd == CNG_AT_FDCWD) {
        long rr = cng_resolve(path, 1, host, sizeof host);
        if (rr != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] execve %s -> unresolved errno=%ld\n", path,
                            -rr);
            return -ENOENT;
        }
    } else {
        cng_strlcpy(host, path, sizeof host);
    }
    /* Every failure below this point is silent otherwise, and the guest only
     * sees an errno — trace the resolution so a device-side failure says which
     * stage produced it (and which build is running). */
    if (cng_g_debug)
        cng_dprintf(2, "[cng] execve resolve %s -> %s\n", path, host);

    /* Shebang: the kernel interprets `#!interp [arg]` scripts, but we bypass the
     * kernel, so do it ourselves — exec the interpreter with
     * [interp, arg?, script, orig-args...]. One level (interp is expected to be
     * a real ELF, e.g. /bin/sh -> busybox). */
    /* When the target names one of our own fds ("/proc/self/fd/N", how apk runs
     * package scripts) work from that open file description instead of
     * reopening the magic link. execve(2) checks *execute* permission on the
     * inode; a reopen checks *read* — so a script a real (root) chroot execs
     * happily can come back EACCES here, since our fake root has no DAC bypass.
     * The fd we already hold needs no permission check at all, and covers the
     * anonymous files (memfd, O_TMPFILE, deleted) that have no readable name.
     * Everything below reads it with pread/mmap, so the guest's file offset —
     * shared with its parent through fork — is left alone. */
    int gfd = cng_proc_self_fd(host); /* the guest's fd: never close it */
    if (gfd >= 0 && cng_g_debug) {
        char st[128]; /* AArch64 struct stat: mode@16, uid@24, gid@28 */
        if (CNG_SYS(__NR_fstat, gfd, st, 0, 0, 0, 0) == 0)
            cng_dprintf(2, "[cng] execve fd=%d mode=%o uid=%u gid=%u\n", gfd,
                        *(unsigned *)(st + 16) & 07777, *(unsigned *)(st + 24),
                        *(unsigned *)(st + 28));
    }

    char interp_buf[256], arg_buf[256], *sheb_argv[128];
    char **eff_argv = argv;
    {
        long fd = gfd;
        if (gfd < 0) {
            fd = sys_openat(CNG_AT_FDCWD, host, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
            if (fd < 0) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] execve open %s -> errno=%d\n", host,
                                (int)-fd);
                return fd; /* the real errno (EACCES, ELOOP, ENOENT, ...) */
            }
        }
        char hdr[257];
        long n = sys_pread64((int)fd, hdr, 256, 0);
        if (gfd < 0)
            sys_close((int)fd);
        if (n >= 2 && hdr[0] == '#' && hdr[1] == '!') {
            hdr[n < 256 ? n : 256] = '\0';
            char *p = hdr + 2;
            while (*p == ' ' || *p == '\t')
                p++;
            char *i0 = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
                p++;
            size_t ilen = (size_t)(p - i0);
            while (*p == ' ' || *p == '\t')
                p++;
            char *a0 = p;
            while (*p && *p != '\n' && *p != '\r')
                p++;
            size_t alen = (size_t)(p - a0);
            if (ilen == 0 || ilen >= sizeof interp_buf) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] execve %s -> bad shebang\n", path);
                return -ENOEXEC;
            }
            memcpy(interp_buf, i0, ilen);
            interp_buf[ilen] = '\0';
            int k = 0;
            sheb_argv[k++] = interp_buf;
            if (alen > 0 && alen < sizeof arg_buf) {
                memcpy(arg_buf, a0, alen);
                arg_buf[alen] = '\0';
                sheb_argv[k++] = arg_buf;
            }
            sheb_argv[k++] = (char *)path; /* the script path */
            if (argv)
                for (int j = 1; argv[j] && k < 126; j++)
                    sheb_argv[k++] = argv[j];
            sheb_argv[k] = 0;
            eff_argv = sheb_argv;
            gfd = -1; /* the image to load is now the interpreter, by path */
            if (cng_resolve(interp_buf, 1, host, sizeof host) != 0) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] execve interp %s -> unresolved\n",
                                interp_buf);
                return -ENOENT;
            }
        }
    }

    if (cng_g_debug)
        cng_dprintf(2, "[cng] exec %s host=%s file_backed=%d\n", path, host,
                    cng_g_loader_file);

    struct cng_loaded prog;
    int rc = gfd >= 0 ? cng_load_elf_fd(gfd, 0, &prog) : cng_load_elf(host, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        cng_dprintf(2, "chroot-ng: exec %s (%s): load failed rc=%d\n", path,
                    host, rc);
        return rc == CNG_LOAD_EOPEN ? -ENOENT : -ENOEXEC;
    }
    if (cng_g_debug)
        cng_dprintf(2,
                    "[cng]   prog dyn=%d base=%lx entry=%lx phdr=%lx "
                    "lo=%lx hi=%lx interp=%d\n",
                    prog.is_dyn, prog.base, prog.entry, prog.phdr, prog.load_lo,
                    prog.load_hi, prog.has_interp);

    struct cng_loaded interp;
    int have_interp = 0;
    if (prog.has_interp) {
        char ip[CNG_PATH_MAX];
        if (cng_resolve(prog.interp, 1, ip, sizeof ip) != 0 ||
            cng_load_elf(ip, 0, &interp) != CNG_LOAD_OK) {
            cng_dprintf(2, "chroot-ng: exec %s: interp %s load failed\n", path,
                        prog.interp);
            return -ENOENT;
        }
        have_interp = 1;
        if (cng_g_debug)
            cng_dprintf(2, "[cng]   interp %s base=%lx entry=%lx lo=%lx hi=%lx\n",
                        prog.interp, interp.base, interp.entry, interp.load_lo,
                        interp.load_hi);
    }

    int argc = 0;
    if (eff_argv)
        while (eff_argv[argc])
            argc++;

    unsigned long sp = cng_build_stack(argc, eff_argv, envp, cng_host_auxv,
                                       &prog, have_interp ? &interp : 0,
                                       eff_argv ? eff_argv[0] : path);
    unsigned long entry = have_interp ? interp.entry : prog.entry;
    if (cng_g_debug)
        cng_dprintf(2, "[cng]   argc=%d sp=%lx entry=%lx -> enter\n", argc, sp,
                    entry);

    /* Commit point: the new image loaded successfully, so from here we behave
     * like a real execve. Close FD_CLOEXEC descriptors (see cng_close_cloexec)
     * before entering the new program. */
    cng_close_cloexec();
    cng_reset_signals();

    /* setuid/setgid-on-exec against the fake credential set (--setuid-root /
     * --setgid-root): `host` is the ELF the kernel would honor the set-id bit on
     * (the interpreter for a #! script, matching the kernel's script exception). */
    cng_cred_exec(host);

    /* Track the running program for /proc/self/exe fixups. A real kernel updates
     * /proc/self/exe on every execve (symlinks resolved); tools derive their
     * install root from it — notably `go`, which computes GOROOT from
     * os.Executable(). `host` is the resolved host path of the ELF we actually
     * load (the shebang interpreter for scripts, matching the kernel); store its
     * guest path in a persistent buffer. */
    static char exe_guest[CNG_PATH_MAX];
    const char *exe_host = host;
    char linked[CNG_PATH_MAX];
    /* Exec through a /proc/self/fd/N path (how apk runs package scripts) keeps
     * that path as `host`; the kernel would record the file the fd names, so
     * ask the magic link for it. */
    if (!strncmp(host, "/proc/", 6)) {
        long n = sys_readlinkat(CNG_AT_FDCWD, host, linked, sizeof linked - 1);
        if (n > 0) {
            linked[n] = '\0';
            if (linked[0] == '/')
                exe_host = linked;
        }
    }
    if (cng_fs_untranslate(cng_g_fs, exe_host, exe_guest, sizeof exe_guest) == 0)
        cng_g_exe_guest = exe_guest;

    *out_sp = sp;
    *out_entry = entry;
    return 0;
}

void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp) {
    unsigned long long *r = uc->uc_mcontext.regs;
    unsigned long sp, entry;
    long rc = execve_core(dirfd, path, argv, envp, &sp, &entry);
    if (rc < 0) {
        r[0] = (unsigned long long)rc;
        return;
    }

    /* Rewrite the signal context to the new program's fresh entry state, then
     * return: rt_sigreturn resumes at `entry` with the new stack, handler and
     * filter still installed. */
    for (int i = 0; i < 31; i++)
        r[i] = 0;
    uc->uc_mcontext.sp = sp;
    uc->uc_mcontext.pc = entry;
}

long cng_execve_tramp(int dirfd, const char *path, char **argv, char **envp) {
    unsigned long sp, entry;
    long rc = execve_core(dirfd, path, argv, envp, &sp, &entry);
    if (rc < 0)
        return rc;
    /* Ordinary call context (no signal frame): abandon the old program's stack
     * and enter the new image directly, like the initial `run` does. */
    cng_enter(sp, entry);
}
