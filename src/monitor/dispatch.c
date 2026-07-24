/* Syscall dispatcher: translate path arguments of a trapped syscall and
 * re-issue the real syscall through the gate (cng_syscall6), whose IP the
 * seccomp filter allows so we don't re-trap. Runs in-process, so path pointers
 * are directly readable — no cross-process memory access like proot needs.
 *
 * Also applies the M7 fidelity fixups: credential/ownership faking (-0),
 * /proc/self/* readlink fixups, and link2symlink fallback.
 */
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

struct cng_fs *cng_g_fs = 0;

int cng_g_fake_id = 0;
unsigned cng_g_fake_uid = 0;
unsigned cng_g_fake_gid = 0;
const char *cng_g_exe_guest = "/";

/* AArch64 struct stat / statx field offsets for ownership rewriting. */
#define STAT_UID_OFF  24
#define STAT_GID_OFF  28
#define STATX_UID_OFF 20
#define STATX_GID_OFF 24

/* One-shot-per-number diagnostic that a syscall was emulated away (blocked by
 * Android's seccomp filter, or a credential change we can't perform). Shared
 * with the SIGSYS gate-net. Async-signal-safe. */
void cng_note_blocked(int nr) {
    static unsigned char warned[600];
    if (nr < 0 || nr >= (int)sizeof warned || warned[nr])
        return;
    warned[nr] = 1;
    cng_dprintf(2, "chroot-ng: syscall %d not permitted here -> emulated\n", nr);
}

/* Re-issue the guest's (translated) syscall through the gate — but if Android's
 * filter blocks it (measured by cng_probe_blocked), emulate ENOSYS instead, so
 * we never trap on the re-issue. Same signature as cng_syscall6. */
int cng_g_debug = 0;

/* Best-effort path pointer among a0/a1 for logging (path syscalls put the path
 * in a0 or a1). Guards against non-pointer scalars. */
static const char *dbg_path(long a0, long a1) {
    if (a1 > 0x1000 && *(const char *)a1 == '/')
        return (const char *)a1;
    if (a0 > 0x1000 && *(const char *)a0 == '/')
        return (const char *)a0;
    return "";
}

static long reissue(long a0, long a1, long a2, long a3, long a4, long a5,
                    long nr) {
    if (nr >= 0 && nr < CNG_NR_MAX && cng_blocked[nr]) {
        cng_note_blocked((int)nr);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] nr=%ld %s -> BLOCKED ENOSYS\n", nr,
                        dbg_path(a0, a1));
        return -ENOSYS;
    }
    long r = cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
    if (cng_g_debug && r < 0 && r != -ENOENT)
        cng_dprintf(2, "[cng] nr=%ld %s -> errno=%ld\n", nr, dbg_path(a0, a1),
                    -r);
    return r;
}

/* Resolve a guest path to a host path, following symlinks *within the guest*:
 * an absolute symlink target is re-rooted into the rootfs rather than resolved
 * against the host root (which is what breaks Alpine's busybox symlinks). Walks
 * component by component, readlink()-ing each prefix; deref_final controls
 * whether the last component's own symlink is followed. Returns 0/-errno. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz) {
    char cur[CNG_PATH_MAX];
    if (cng_fs_abscanon(cng_g_fs, path, cur, sizeof cur) < 0)
        return -ENAMETOOLONG;

    for (int iter = 0; iter < 40; iter++) {
        size_t len = strlen(cur);
        int found = 0;
        for (size_t e = 1; e <= len; e++) {
            if (e < len && cur[e] != '/')
                continue;
            int is_final = (e == len);
            if (is_final && !deref_final)
                break;

            char prefix[CNG_PATH_MAX], host[CNG_PATH_MAX], link[CNG_PATH_MAX];
            if (e >= sizeof prefix)
                break;
            memcpy(prefix, cur, e);
            prefix[e] = '\0';
            if (cng_fs_translate(cng_g_fs, prefix, host, sizeof host) != 0)
                continue;
            long n = sys_readlinkat(CNG_AT_FDCWD, host, link, sizeof link - 1);
            if (n <= 0)
                continue; /* not a symlink, or missing */
            link[n] = '\0';

            /* Rewrite cur = <link, re-rooted if absolute> + <suffix cur[e..]>. */
            char tmp[CNG_PATH_MAX];
            size_t p;
            if (link[0] == '/') {
                cng_strlcpy(tmp, link, sizeof tmp);
                p = strlen(tmp);
            } else {
                size_t pe = e; /* parent dir of prefix */
                while (pe > 0 && cur[pe - 1] != '/')
                    pe--;
                if (pe > 0)
                    pe--;
                memcpy(tmp, cur, pe);
                p = pe;
                if (p + 1 < sizeof tmp)
                    tmp[p++] = '/';
                cng_strlcpy(tmp + p, link, sizeof tmp - p);
                p = strlen(tmp);
            }
            cng_strlcpy(tmp + p, cur + e, p < sizeof tmp ? sizeof tmp - p : 0);
            if (cng_path_canon(tmp, cur, sizeof cur) < 0)
                return -ENAMETOOLONG;
            found = 1;
            break;
        }
        if (!found)
            return cng_fs_translate(cng_g_fs, cur, out, outsz);
    }
    return -ELOOP;
}

/* Guest directory a real dirfd points at, via /proc/self/fd. Returns 0/-1. */
static int fd_guest_dir(long fd, char *out, size_t sz) {
    char proc[40];
    size_t p = cng_strlcpy(proc, "/proc/self/fd/", sizeof proc);
    char num[16];
    int ni = 0;
    long v = fd;
    if (v <= 0)
        return -1;
    while (v > 0 && ni < 15) {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (ni > 0 && p < sizeof proc - 1)
        proc[p++] = num[--ni];
    proc[p] = '\0';
    char host[CNG_PATH_MAX];
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, host, sizeof host - 1);
    if (n <= 0)
        return -1;
    host[n] = '\0';
    return cng_fs_untranslate(cng_g_fs, host, out, sz);
}

/* Resolve (dirfd, path) to a canonical guest absolute path. Handles absolute
 * paths, AT_FDCWD, and real dirfds (via /proc/self/fd). Returns 0/-1. */
static int resolve_at_guest(long dirfd, const char *path, char *out,
                            size_t sz) {
    if (!path)
        return -1;
    if (path[0] == '/' || dirfd == CNG_AT_FDCWD)
        return cng_fs_abscanon(cng_g_fs, path, out, sz);
    char gdir[CNG_PATH_MAX], tmp[CNG_PATH_MAX];
    if (fd_guest_dir(dirfd, gdir, sizeof gdir) != 0)
        return -1;
    size_t n = cng_strlcpy(tmp, gdir, sizeof tmp);
    if (n && tmp[n - 1] != '/' && n + 1 < sizeof tmp) {
        tmp[n++] = '/';
        tmp[n] = '\0';
    }
    cng_strlcpy(tmp + n, path, sizeof tmp - n);
    return cng_path_canon(tmp, out, sz);
}

static const char *xlate(long dirfd, const char *gp, char *buf, size_t bufsz,
                         int deref_final) {
    if (!gp)
        return gp;
    if (gp[0] == '/' || dirfd == CNG_AT_FDCWD) {
        if (cng_resolve(gp, deref_final, buf, bufsz) == 0)
            return buf;
        if (cng_fs_translate(cng_g_fs, gp, buf, bufsz) == 0)
            return buf;
    }
    return gp;
}

/* /proc/self/{exe,cwd,root} -> guest-visible link target. Returns bytes written
 * (no NUL, like readlink) or -1 if `canon` isn't one of these. */
static long proc_self_fixup(const char *canon, char *buf, unsigned long bufsz) {
    if (strncmp(canon, "/proc/self/", 11) != 0)
        return -1;
    const char *rest = canon + 11;
    const char *val = 0;
    if (!strcmp(rest, "exe"))
        val = cng_g_exe_guest;
    else if (!strcmp(rest, "cwd"))
        val = cng_g_fs->cwd;
    else if (!strcmp(rest, "root"))
        val = "/";
    if (!val)
        return -1;
    size_t len = strlen(val);
    if (len > bufsz)
        len = bufsz;
    memcpy(buf, val, len);
    return (long)len;
}

long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4, long a5,
                  int trapped) {
    char b1[CNG_PATH_MAX], b2[CNG_PATH_MAX];

    switch (nr) {
    /* Simple translate + reissue: dirfd = a0, path = a1. */
    case __NR_openat:
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_faccessat:
#ifdef __NR_faccessat2
    case __NR_faccessat2:
#endif
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_unlinkat:
    case __NR_fchmodat:
    case __NR_utimensat:
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
#endif
    {
        int deref = !(nr == __NR_unlinkat || nr == __NR_mkdirat ||
                      nr == __NR_mknodat);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        return reissue(a0, (long)p, a2, a3, a4, a5, nr);
    }

    /* stat: translate, reissue, then fake ownership if -0. */
    case __NR_newfstatat: {
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_newfstatat);
        if (r == 0 && cng_g_fake_id && a2) {
            *(unsigned *)((char *)a2 + STAT_UID_OFF) = cng_g_fake_uid;
            *(unsigned *)((char *)a2 + STAT_GID_OFF) = cng_g_fake_gid;
        }
        return r;
    }
    case __NR_statx: {
        int deref = !((int)a2 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_statx);
        if (r == 0 && cng_g_fake_id && a4) {
            *(unsigned *)((char *)a4 + STATX_UID_OFF) = cng_g_fake_uid;
            *(unsigned *)((char *)a4 + STATX_GID_OFF) = cng_g_fake_gid;
        }
        return r;
    }

    /* chown: fake success under -0 (a non-root process can't really chown). */
    case __NR_fchownat: {
        if (cng_g_fake_id)
            return 0;
        int deref = !((int)a4 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        return reissue(a0, (long)p, a2, a3, a4, a5, __NR_fchownat);
    }

    /* readlinkat: /proc/self/* fixups, else translate + reissue. */
    case __NR_readlinkat: {
        const char *gp = (const char *)a1;
        if (gp && (gp[0] == '/' || a0 == CNG_AT_FDCWD)) {
            char canon[CNG_PATH_MAX];
            if (cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0) {
                long fx = proc_self_fixup(canon, (char *)a2,
                                          (unsigned long)a3);
                if (fx >= 0)
                    return fx;
            }
        }
        const char *p = xlate(a0, gp, b1, sizeof b1, /*deref_final=*/0);
        return reissue(a0, (long)p, a2, a3, a4, a5, __NR_readlinkat);
    }

    /* symlinkat(target, newdirfd, linkpath): translate only the linkpath. */
    case __NR_symlinkat: {
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2, 0);
        return reissue(a0, a1, (long)lp, a3, a4, a5, __NR_symlinkat);
    }

    /* fchown(fd,...): no path, but under -0 fake success like fchownat — apk
     * fchown()s each extracted file to root and a non-root app gets EPERM. */
    case __NR_fchown:
        if (cng_g_fake_id)
            return 0;
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_fchown);

    /* rename: two translated paths. */
    case __NR_renameat:
    case __NR_renameat2: {
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2, 0);
        return reissue(a0, (long)op, a2, (long)np, a4, a5, nr);
    }

    /* linkat: hardlink; fall back to a symlink where the fs forbids hardlinks
     * (link2symlink). The symlink target is a GUEST path (bare basename when
     * old and new share a directory, else the guest-absolute path) — never a
     * host path — so readlink doesn't leak, and cng_resolve re-roots it. */
    case __NR_linkat: {
        int deref_old = ((int)a4 & CNG_AT_SYMLINK_FOLLOW) ? 1 : 0;
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1, deref_old);
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2, 0);
        long r = reissue(a0, (long)op, a2, (long)np, a4, a5, __NR_linkat);
        if (r == -EPERM || r == -EMLINK || r == -EXDEV || r == -ENOSYS ||
            r == -EACCES || r == -EOPNOTSUPP) {
            /* Resolve both endpoints to guest paths (handling dirfds), and make
             * a symlink at the new host path targeting the old guest path. */
            char oldg[CNG_PATH_MAX], newg[CNG_PATH_MAX], newhost[CNG_PATH_MAX];
            if (resolve_at_guest(a0, (const char *)a1, oldg, sizeof oldg) == 0 &&
                resolve_at_guest(a2, (const char *)a3, newg, sizeof newg) == 0 &&
                cng_fs_translate(cng_g_fs, newg, newhost, sizeof newhost) == 0) {
                /* bare basename when old/new share a dir (b -> a), else the
                 * guest-absolute path — both re-root correctly and don't leak. */
                char *os = strrchr(oldg, '/');
                char *ns = strrchr(newg, '/');
                size_t odl = os ? (size_t)(os - oldg) : 0;
                size_t ndl = ns ? (size_t)(ns - newg) : 0;
                const char *tgt =
                    (odl == ndl && strncmp(oldg, newg, odl) == 0)
                        ? (os ? os + 1 : oldg)
                        : oldg;
                long s = cng_syscall6((long)tgt, CNG_AT_FDCWD, (long)newhost, 0,
                                      0, 0, __NR_symlinkat);
                if (s == -EEXIST) { /* reinstall: replace the existing entry */
                    cng_syscall6(CNG_AT_FDCWD, (long)newhost, 0, 0, 0, 0,
                                 __NR_unlinkat);
                    s = cng_syscall6((long)tgt, CNG_AT_FDCWD, (long)newhost, 0,
                                     0, 0, __NR_symlinkat);
                }
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] l2s %s -> %s sym=%ld\n", oldg, newg,
                                s);
                if (s == 0)
                    return 0;
            }
        }
        return r;
    }

    /* path = a0 */
    case __NR_truncate:
    case __NR_statfs: {
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, 1);
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_chdir: {
        const char *gp = (const char *)a0;
        const char *hp = xlate(CNG_AT_FDCWD, gp, b1, sizeof b1, 1);
        long r = reissue((long)hp, 0, 0, 0, 0, 0, __NR_chdir);
        if (r == 0) {
            char gc[CNG_PATH_MAX];
            if (cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) == 0)
                cng_fs_set_cwd(cng_g_fs, gc);
        }
        return r;
    }

    /* fchdir: the fd already refers to a translated host dir, so perform it,
     * then resync the virtual cwd from the real cwd (reverse-translated). This
     * is what apk relies on when running package scripts. */
    case __NR_fchdir: {
        long r = cng_syscall6(a0, 0, 0, 0, 0, 0, __NR_fchdir);
        if (r == 0) {
            char hc[CNG_PATH_MAX], gc[CNG_PATH_MAX];
            if (sys_getcwd(hc, sizeof hc) > 0 &&
                cng_fs_untranslate(cng_g_fs, hc, gc, sizeof gc) == 0)
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
        return (long)len;
    }

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

    /* Protect our SIGSYS handler: ignore guest attempts to replace it, and
     * strip SIGSYS from any handler's sa_mask so it can't be masked while a
     * guest handler runs. Kernel struct sigaction: handler,flags,restorer,mask
     * (mask at offset 24). */
    case __NR_rt_sigaction:
        if ((int)a0 == CNG_SIGSYS)
            return 0;
        if (a1) {
            unsigned char act[32];
            memcpy(act, (void *)a1, sizeof act);
            *(unsigned long *)(act + 24) &= ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)act, a2, a3, a4, a5,
                                __NR_rt_sigaction);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigaction);

    /* rt_sigprocmask on the trampoline path (the SIGSYS path handles it via
     * uc_sigmask): apply the mask but never block SIGSYS. */
    case __NR_rt_sigprocmask: {
        int how = (int)a0;
        if ((how == 0 /*BLOCK*/ || how == 2 /*SETMASK*/) && a1) {
            unsigned long set = *(unsigned long *)a1 & ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)&set, a2, a3, a4, a5,
                                __NR_rt_sigprocmask);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigprocmask);
    }

    /* --- credential faking (only trapped when -0 is active) --- */
    case __NR_getuid:
    case __NR_geteuid:
        return cng_g_fake_id ? (long)cng_g_fake_uid
                             : cng_syscall6(0, 0, 0, 0, 0, 0, nr);
    case __NR_getgid:
    case __NR_getegid:
        return cng_g_fake_id ? (long)cng_g_fake_gid
                             : cng_syscall6(0, 0, 0, 0, 0, 0, nr);
    case __NR_getresuid:
    case __NR_getresgid: {
        if (!cng_g_fake_id)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        unsigned v = (nr == __NR_getresuid) ? cng_g_fake_uid : cng_g_fake_gid;
        if (a0)
            *(unsigned *)a0 = v;
        if (a1)
            *(unsigned *)a1 = v;
        if (a2)
            *(unsigned *)a2 = v;
        return 0;
    }
    /* Credential setters: under -0, fake success as the emulated identity.
     * Otherwise emulate the result DIRECTLY — never re-issue: these are on
     * Android's seccomp block-list, and a re-issue from inside this (SIGSYS)
     * handler force-kills the process (masked nested seccomp SIGSYS). */
    case __NR_setuid:
    case __NR_setgid:
    case __NR_setresuid:
    case __NR_setresgid:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_setgroups:
        if (cng_g_fake_id)
            return 0;
        cng_note_blocked((int)nr);
        return -ENOSYS;
    case __NR_setfsuid:
    case __NR_setfsgid:
        return 0; /* returns the previous fs id (0); never fails */

    default:
        /* From a seccomp trap, an unhandled syscall was blocked by Android
         * (our filter only traps handled ones) => emulate ENOSYS rather than
         * re-issue and die on the nested trap. From a trampoline it is just an
         * ordinary syscall we don't translate => run it. */
        if (trapped) {
            cng_note_blocked((int)nr);
            return -ENOSYS;
        }
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }
}
