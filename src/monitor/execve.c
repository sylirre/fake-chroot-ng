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

void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp) {
    unsigned long long *r = uc->uc_mcontext.regs;

    if (!path) {
        r[0] = (unsigned long long)(long)-EFAULT;
        return;
    }

    /* Resolve the target through the rootfs/bind map, following symlinks
     * (absolute or AT_FDCWD); a real dirfd with a relative path is a rare case
     * we pass through. */
    char host[CNG_PATH_MAX];
    if (path[0] == '/' || dirfd == CNG_AT_FDCWD) {
        if (cng_resolve(path, 1, host, sizeof host) != 0) {
            r[0] = (unsigned long long)(long)-ENOENT;
            return;
        }
    } else {
        cng_strlcpy(host, path, sizeof host);
    }

    /* Shebang: the kernel interprets `#!interp [arg]` scripts, but we bypass the
     * kernel, so do it ourselves — exec the interpreter with
     * [interp, arg?, script, orig-args...]. One level (interp is expected to be
     * a real ELF, e.g. /bin/sh -> busybox). */
    char interp_buf[256], arg_buf[256], *sheb_argv[128];
    char **eff_argv = argv;
    {
        long fd = sys_openat(CNG_AT_FDCWD, host, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
        if (fd < 0) {
            r[0] = (unsigned long long)(long)-ENOENT;
            return;
        }
        char hdr[257];
        long n = sys_pread64((int)fd, hdr, 256, 0);
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
                r[0] = (unsigned long long)(long)-ENOEXEC;
                return;
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
            if (cng_resolve(interp_buf, 1, host, sizeof host) != 0) {
                r[0] = (unsigned long long)(long)-ENOENT;
                return;
            }
        }
    }

    struct cng_loaded prog;
    int rc = cng_load_elf(host, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        cng_dprintf(2, "chroot-ng: exec %s (%s): load failed rc=%d\n", path,
                    host, rc);
        r[0] = (unsigned long long)(long)(rc == CNG_LOAD_EOPEN ? -ENOENT
                                                              : -ENOEXEC);
        return;
    }

    struct cng_loaded interp;
    int have_interp = 0;
    if (prog.has_interp) {
        char ip[CNG_PATH_MAX];
        if (cng_resolve(prog.interp, 1, ip, sizeof ip) != 0 ||
            cng_load_elf(ip, 0, &interp) != CNG_LOAD_OK) {
            cng_dprintf(2, "chroot-ng: exec %s: interp %s load failed\n", path,
                        prog.interp);
            r[0] = (unsigned long long)(long)-ENOENT;
            return;
        }
        have_interp = 1;
    }

    int argc = 0;
    if (eff_argv)
        while (eff_argv[argc])
            argc++;

    unsigned long sp = cng_build_stack(argc, eff_argv, envp, cng_host_auxv,
                                       &prog, have_interp ? &interp : 0,
                                       eff_argv ? eff_argv[0] : path);
    unsigned long entry = have_interp ? interp.entry : prog.entry;

    /* Commit point: the new image loaded successfully, so from here we behave
     * like a real execve. Close FD_CLOEXEC descriptors (see cng_close_cloexec)
     * before entering the new program. */
    cng_close_cloexec();

    /* Rewrite the signal context to the new program's fresh entry state, then
     * return: rt_sigreturn resumes at `entry` with the new stack, handler and
     * filter still installed. */
    for (int i = 0; i < 31; i++)
        r[i] = 0;
    uc->uc_mcontext.sp = sp;
    uc->uc_mcontext.pc = entry;
}
