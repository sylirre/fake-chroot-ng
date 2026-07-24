/* Syscall dispatcher: translate path arguments of a trapped syscall and
 * re-issue the real syscall through the gate (cng_syscall6), whose IP the
 * seccomp filter allows so we don't re-trap. Runs in-process, so path pointers
 * are directly readable — no cross-process memory access like proot needs.
 */
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

struct cng_fs *cng_g_fs = 0;

/* Translate one path argument. Absolute paths and AT_FDCWD-relative paths go
 * through the rootfs/bind map; paths relative to a real dirfd pass through
 * unchanged (the fd already refers to an translated directory). */
static const char *xlate(long dirfd, const char *gp, char *buf, size_t bufsz) {
    if (!gp)
        return gp;
    if (gp[0] == '/' || dirfd == CNG_AT_FDCWD) {
        if (cng_fs_translate(cng_g_fs, gp, buf, bufsz) == 0)
            return buf;
    }
    return gp;
}

long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4,
                  long a5) {
    char b1[CNG_PATH_MAX], b2[CNG_PATH_MAX];

    switch (nr) {
    /* dirfd = a0, path = a1 */
    case __NR_openat:
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_faccessat:
#ifdef __NR_faccessat2
    case __NR_faccessat2:
#endif
    case __NR_readlinkat:
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_unlinkat:
    case __NR_fchownat:
    case __NR_fchmodat:
    case __NR_utimensat:
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
#endif
    {
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1);
        return cng_syscall6(a0, (long)p, a2, a3, a4, a5, nr);
    }

    /* symlinkat(target, newdirfd, linkpath): a0 is stored content, translate
     * only the linkpath (a2, relative to newdirfd a1). */
    case __NR_symlinkat: {
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2);
        return cng_syscall6(a0, a1, (long)lp, a3, a4, a5, nr);
    }

    /* Two paths: old=(dirfd a0, path a1), new=(dirfd a2, path a3). */
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_linkat: {
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1);
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2);
        return cng_syscall6(a0, (long)op, a2, (long)np, a4, a5, nr);
    }

    /* path = a0 */
    case __NR_truncate:
    case __NR_statfs: {
        const char *p = xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1);
        return cng_syscall6((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_chdir: {
        const char *gp = (const char *)a0;
        const char *hp = xlate(CNG_AT_FDCWD, gp, b1, sizeof b1);
        long r = cng_syscall6((long)hp, 0, 0, 0, 0, 0, __NR_chdir);
        if (r == 0) {
            char gc[CNG_PATH_MAX];
            if (cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) == 0)
                cng_fs_set_cwd(cng_g_fs, gc);
        }
        return r;
    }

    case __NR_getcwd: {
        char *buf = (char *)a0;
        unsigned long size = (unsigned long)a1;
        size_t len = strlen(cng_g_fs->cwd) + 1;
        if (len > size)
            return -ERANGE;
        memcpy(buf, cng_g_fs->cwd, len);
        return (long)len; /* raw getcwd returns bytes written incl NUL */
    }

    /* Minimal chroot emulation: re-root at the translated host path. */
    case __NR_chroot: {
        char hp[CNG_PATH_MAX];
        if (cng_fs_translate(cng_g_fs, (const char *)a0, hp, sizeof hp) != 0)
            return -ENAMETOOLONG;
        long r = cng_syscall6(CNG_AT_FDCWD, (long)hp, 0, 0, 0, 0,
                              __NR_faccessat);
        if (r < 0)
            return r;
        cng_fs_init(cng_g_fs, hp);
        return 0;
    }

    default:
        /* Filter only traps the set above; anything else runs unchanged. */
        return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
    }
}
