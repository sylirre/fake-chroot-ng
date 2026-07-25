/* Syscall dispatcher: translate path arguments of a trapped syscall and
 * re-issue the real syscall through the gate (cng_syscall6), whose IP the
 * seccomp filter allows so we don't re-trap. Runs in-process, so path pointers
 * are directly readable — no cross-process memory access like proot needs.
 *
 * Also applies the M7 fidelity fixups: credential/ownership faking (--fake-id),
 * /proc/self readlink fixups, and the link2symlink fallback (--link2symlink).
 */
#include "cng/l2s.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

struct cng_fs *cng_g_fs = 0;

/* The fake-identity globals (cng_g_fake_id, cng_g_cred, ...) live in cred.c. */
const char *cng_g_exe_guest = "/";

/* AArch64 struct stat / statx field offsets for ownership rewriting, plus the
 * st_mode offset used by the fake-root access() fallback. */
#define STAT_MODE_OFF  16
#define STAT_UID_OFF   24
#define STAT_GID_OFF   28
#define STATX_UID_OFF  20
#define STATX_GID_OFF  24
#define STATX_MODE_OFF 28   /* stx_mode is a u16 at offset 28 */
#define CNG_X_OK        1   /* access(2) X_OK */

/* Rewrite a struct stat / statx buffer's ownership under a fake identity: files
 * owned by the real invoking user appear owned by the fake id, and a setuid/
 * setgid executable appears root-owned under --setuid-root/--setgid-root (the
 * st_mode drives that; see cng_exec_vis_*). A no-op unless --fake-id is active. */
static void stat_remap(void *st) {
    unsigned mode = *(unsigned *)((char *)st + STAT_MODE_OFF);
    unsigned *u = (unsigned *)((char *)st + STAT_UID_OFF);
    unsigned *g = (unsigned *)((char *)st + STAT_GID_OFF);
    *u = cng_exec_vis_uid(*u, mode);
    *g = cng_exec_vis_gid(*g, mode);
}
static void statx_remap(void *st) {
    unsigned mode = *(unsigned short *)((char *)st + STATX_MODE_OFF);
    unsigned *u = (unsigned *)((char *)st + STATX_UID_OFF);
    unsigned *g = (unsigned *)((char *)st + STATX_GID_OFF);
    *u = cng_exec_vis_uid(*u, mode);
    *g = cng_exec_vis_gid(*g, mode);
}

/* Fake-root turns a privilege-denied ownership/mode change into success — the
 * real process is unprivileged, but the guest believes it is root. Denied
 * (EPERM/EACCES/EINVAL) and Android-blocked (ENOSYS) results are faked; genuine
 * errors (ENOENT, EROFS, ...) still propagate, as do all results when the
 * identity is unprivileged or inactive. */
static long chattr_result(long r) {
    if (r == 0)
        return 0;
    if (cng_fake_root() &&
        (r == -EPERM || r == -EACCES || r == -EINVAL || r == -ENOSYS))
        return 0;
    return r;
}

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

/* --- /proc magic links ---------------------------------------------------
 *
 * Links under /proc/<pid|self|thread-self>/ belong to the HOST namespace: what
 * readlink() reports for them is a host path — and for an fd link it may name
 * no path at all (memfd, O_TMPFILE, a deleted file). Re-rooting such a target
 * into the rootfs, the way an ordinary guest symlink target must be, produces
 * a path that does not exist: that is how apk's script runner, which execve()s
 * "/proc/self/fd/N", came out as ENOENT. */
#define PROC_MAGIC_NONE  0 /* not a magic link */
#define PROC_MAGIC_GUEST 1 /* rewritten to a guest path; keep resolving */
#define PROC_MAGIC_HOST  2 /* already a host path; resolution is done */

/* Length of a leading "/proc/<pid|self|thread-self>/" in a canonical guest
 * path, or 0. `self_only` matches only this process's own view. */
static size_t proc_pid_prefix(const char *p, int self_only) {
    if (strncmp(p, "/proc/", 6) != 0)
        return 0;
    const char *q = p + 6;
    size_t n = 0;
    if (strncmp(q, "self/", 5) == 0)
        n = 5;
    else if (strncmp(q, "thread-self/", 12) == 0)
        n = 12;
    else if (!self_only) {
        while (q[n] >= '0' && q[n] <= '9')
            n++;
        if (n == 0 || q[n] != '/')
            return 0;
        n++;
    }
    return n ? (size_t)(q - p) + n : 0;
}

/* Classify (and for the guest-visible links rewrite in place) a canonical
 * guest path that starts with a /proc magic link. See PROC_MAGIC_*. */
static int proc_magic(char *cur, size_t sz) {
    size_t pl = proc_pid_prefix(cur, 0);
    if (!pl)
        return PROC_MAGIC_NONE;
    const char *rest = cur + pl;

    /* "fd/<n>": the magic path *is* the host path — the kernel takes it
     * straight to the open file description, including the anonymous and
     * deleted files no re-rooted target could ever name. Any trailing
     * components (a directory fd) ride along, as they do for a real dirfd. */
    if (strncmp(rest, "fd/", 3) == 0) {
        const char *d = rest + 3;
        while (*d >= '0' && *d <= '9')
            d++;
        if (d > rest + 3 && (*d == '\0' || *d == '/'))
            return PROC_MAGIC_HOST;
        return PROC_MAGIC_NONE;
    }

    /* exe/cwd/root: substitute the guest-visible target that readlink(2)
     * reports (proc_self_fixup), so exec'ing or opening one lands where the
     * guest expects. The host links point at chroot-ng itself (we never issue
     * a real execve) or at host paths, so following them is never right. Only
     * our own process: another pid's view isn't ours to fake. */
    if (!proc_pid_prefix(cur, 1))
        return PROC_MAGIC_NONE;
    const char *val = 0;
    size_t vl = 0;
    if (strncmp(rest, "exe", 3) == 0) {
        val = cng_g_exe_guest;
        vl = 3;
    } else if (strncmp(rest, "cwd", 3) == 0) {
        val = cng_g_fs->cwd;
        vl = 3;
    } else if (strncmp(rest, "root", 4) == 0) {
        val = "/";
        vl = 4;
    }
    if (!val || (rest[vl] != '\0' && rest[vl] != '/'))
        return PROC_MAGIC_NONE;

    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, val, sizeof tmp);
    if (n >= sizeof tmp)
        return PROC_MAGIC_NONE;
    cng_strlcpy(tmp + n, rest + vl, sizeof tmp - n);
    return cng_path_canon(tmp, cur, sz) == 0 ? PROC_MAGIC_GUEST
                                             : PROC_MAGIC_NONE;
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
        /* Checked every round, not just up front: the guest can reach these
         * through a symlink of its own (Alpine's /dev/fd -> /proc/self/fd). */
        int magic = proc_magic(cur, sizeof cur);
        if (magic == PROC_MAGIC_HOST)
            return cng_strlcpy(out, cur, outsz) < outsz ? 0 : -ENAMETOOLONG;
        if (magic == PROC_MAGIC_GUEST)
            continue;

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

            /* Rewrite cur = <link, re-rooted if absolute> + <suffix cur[e..]>.
             * Exception: an absolute target naming an l2s data file is a HOST
             * path (central store / cross-directory group) — map it into the
             * guest view instead of re-rooting it. */
            char tmp[CNG_PATH_MAX];
            size_t p;
            if (link[0] == '/') {
                if (!(cng_g_l2s &&
                      cng_l2s_untranslate_target(link, tmp, sizeof tmp)))
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

/* "/proc/self/fd/<fd>" into out[40]. fd args are 32-bit: glibc passes ints in
 * w-registers and may leave the x-register's top half dirty, so truncate. */
static void proc_fd_path(long fd, char *out) {
    size_t p = cng_strlcpy(out, "/proc/self/fd/", 40);
    char num[16];
    int ni = 0;
    long v = (int)fd;
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0 && ni < 15);
    while (ni > 0 && p < 39)
        out[p++] = num[--ni];
    out[p] = '\0';
}

/* Resolve (dirfd, path) to a HOST path. Handles absolute paths and AT_FDCWD
 * (through the rootfs, re-rooting guest symlinks — except the /proc magic
 * links, which cng_resolve keeps in the host namespace), and real dirfds
 * (whose /proc/self/fd link is already a host path inside the rootfs, so the
 * relative name needs no translation). `deref` follows the final component's
 * symlink for the absolute/AT_FDCWD case. Returns 0/-1. */
static int resolve_at_host(long dirfd, const char *path, int deref, char *out,
                           size_t sz) {
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || dfd == CNG_AT_FDCWD) {
        if (cng_resolve(path, deref, out, sz) == 0)
            return 0;
        return cng_fs_translate(cng_g_fs, path, out, sz) == 0 ? 0 : -1;
    }
    /* real dirfd: read its host directory path from /proc/self/fd/<dirfd>. */
    if (dfd < 0)
        return -1;
    char proc[40];
    proc_fd_path(dfd, proc);
    char hdir[CNG_PATH_MAX];
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hdir, sizeof hdir - 1);
    if (n <= 0)
        return -1;
    hdir[n] = '\0';
    size_t k = cng_strlcpy(out, hdir, sz);
    if (k && out[k - 1] != '/' && k + 1 < sz) {
        out[k++] = '/';
        out[k] = '\0';
    }
    cng_strlcpy(out + k, path, sz > k ? sz - k : 0);
    return 0;
}

static const char *xlate(long dirfd, const char *gp, char *buf, size_t bufsz,
                         int deref_final) {
    if (!gp)
        return gp;
    if (gp[0] == '/' || (int)dirfd == CNG_AT_FDCWD) {
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

/* 1 if the open fd refers to the rootfs root directory (where the ".l2s"
 * store entry itself must be hidden from listings). */
static int fd_is_rootfs_root(long fd) {
    if (!cng_g_fs)
        return 0;
    char proc[40], hp[CNG_PATH_MAX];
    proc_fd_path(fd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hp, sizeof hp - 1);
    if (n <= 0)
        return 0;
    hp[n] = '\0';
    const char *root = cng_g_fs->rootfs[0] ? cng_g_fs->rootfs : "/";
    return strcmp(hp, root) == 0;
}

long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4, long a5,
                  int trapped) {
    char b1[CNG_PATH_MAX], b2[CNG_PATH_MAX];

    /* -l: paths naming the l2s machinery (backing data/marker names anywhere,
     * the "/.l2s" store dir) do not exist as far as the guest is concerned.
     * Checked on the guest's own path argument, before any resolution, so the
     * resolver's internal symlink-target expansion is unaffected. */
    if (cng_g_l2s) {
        const char *p1 = 0, *p2 = 0;
        long d1 = CNG_AT_FDCWD, d2 = CNG_AT_FDCWD;
        switch (nr) {
        case __NR_openat:
#ifdef __NR_openat2
        case __NR_openat2:
#endif
        case __NR_mkdirat:
        case __NR_mknodat:
#ifdef __NR_name_to_handle_at
        case __NR_name_to_handle_at:
#endif
        case __NR_faccessat:
#ifdef __NR_faccessat2
        case __NR_faccessat2:
#endif
        case __NR_fchmodat:
        case __NR_unlinkat:
        case __NR_utimensat:
        case __NR_newfstatat:
        case __NR_statx:
        case __NR_fchownat:
        case __NR_readlinkat:
            d1 = a0;
            p1 = (const char *)a1;
            break;
        case __NR_symlinkat: /* only the linkpath names something new */
            d1 = a1;
            p1 = (const char *)a2;
            break;
        case __NR_renameat:
        case __NR_renameat2:
        case __NR_linkat:
            d1 = a0;
            p1 = (const char *)a1;
            d2 = a2;
            p2 = (const char *)a3;
            break;
        case __NR_truncate:
        case __NR_statfs:
        case __NR_chdir:
        case __NR_chroot:
            p1 = (const char *)a0;
            break;
        }
        if ((p1 && cng_l2s_deny(d1, p1)) || (p2 && cng_l2s_deny(d2, p2))) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] l2s deny nr=%ld (%s)\n", nr,
                            p1 ? p1 : "");
            return -ENOENT;
        }
    }

    switch (nr) {
    /* Simple translate + reissue: dirfd = a0, path = a1. */
    case __NR_openat:
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_mkdirat:
    case __NR_mknodat:
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
#endif
    {
        int deref = !(nr == __NR_mkdirat || nr == __NR_mknodat);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, nr);
        /* O_NOFOLLOW through a real dirfd lands on the l2s symlink and draws
         * ELOOP where a real hardlink would open. Retry on the backing file —
         * never a symlink itself, so O_NOFOLLOW stays honored for real
         * guest symlinks. */
        if (r == -ELOOP && cng_g_l2s && nr == __NR_openat &&
            ((int)a2 & CNG_O_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                r = reissue(CNG_AT_FDCWD, (long)data, a2, a3, a4, a5,
                            __NR_openat);
        }
        return r;
    }

    /* access: translate + reissue; under fake-root apply root's DAC bypass when
     * the real (unprivileged) check is denied — existence and R/W are granted,
     * X requires at least one execute bit. mode is a2 for both variants. This is
     * what "check-then-write" tools (package managers, `test -w`) rely on. */
    case __NR_faccessat:
#ifdef __NR_faccessat2
    case __NR_faccessat2:
#endif
    {
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 1);
        long fl = a3;
        long dfd = a0;
#ifdef __NR_faccessat2
        /* faccessat2 with AT_SYMLINK_NOFOLLOW on an l2s name must report on
         * the backing file — to the guest, the name IS a regular file. */
        char fdata[CNG_PATH_MAX];
        if (nr == __NR_faccessat2 && cng_g_l2s &&
            ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, fdata, sizeof fdata, 0) == 1) {
                p = fdata;
                dfd = CNG_AT_FDCWD;
                fl = a3 & ~CNG_AT_SYMLINK_NOFOLLOW;
            }
        }
#endif
        long r = reissue(dfd, (long)p, a2, fl, a4, a5, nr);
        if (r < 0 && cng_fake_root()) {
            char sb[128]; /* AArch64 struct stat is 128 bytes */
            if (reissue(dfd, (long)p, (long)sb, 0, 0, 0, __NR_newfstatat) ==
                0) {
                unsigned mode = *(unsigned *)(sb + STAT_MODE_OFF);
                if (((int)a2 & CNG_X_OK) && !(mode & 0111))
                    return -EACCES;
                return 0;
            }
        }
        return r;
    }

    /* chmod: translate + reissue; fake success under fake-root when the host
     * denies the mode change (a chmod on a file you own still applies for real). */
    case __NR_fchmodat: {
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 1);
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }

    /* unlinkat: on removing one of our link2symlink names, drop the group's
     * refcount (and reclaim the backing file on the last reference). */
    case __NR_unlinkat: {
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0;
        if (cng_g_l2s && !((int)a2 & CNG_AT_REMOVEDIR)) {
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1)
                dec = 1;
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_unlinkat);
        if (r == 0 && dec)
            cng_l2s_decref(data, cnt);
        return r;
    }

    /* utimensat(dirfd, path, times, flags): if the target is one of our
     * link2symlink entries, redirect to its backing file (the guest thinks it's
     * a regular file, so a set-then-lstat-verify — as apk does to preserve mtime
     * — must land on the backing, not the link). Setting an explicit time needs
     * ownership; under fake-root fake success on EPERM. */
    case __NR_utimensat: {
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1) {
                long r = cng_syscall6(CNG_AT_FDCWD, (long)data, a2, 0, 0, 0,
                                      __NR_utimensat);
                if (cng_fake_root() && (r == -EPERM || r == -EACCES))
                    return 0;
                return r;
            }
        }
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_utimensat);
        if (cng_fake_root() && (r == -EPERM || r == -EACCES))
            return 0;
        return r;
    }

    /* stat: translate, reissue, then remap ownership under a fake id. A
     * link2symlink entry is presented as its backing file (a regular file) with
     * st_nlink = the live group count, regardless of the NOFOLLOW flag — so the
     * guest never sees the emulation as a symlink. */
    case __NR_newfstatat: {
        if (cng_g_l2s && a2) {
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_stat(hnf, (void *)a2) == 1) {
                if (cng_g_fake_id)
                    stat_remap((void *)a2);
                return 0;
            }
        }
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_newfstatat);
        if (r == 0 && cng_g_l2s && a2 && ((int)a3 & CNG_AT_EMPTY_PATH)) {
            const char *gp = (const char *)a1; /* fstat-by-fd form */
            if (!gp || !gp[0])
                cng_l2s_fix_fd(a0, (void *)a2);
        }
        if (r == 0 && cng_g_fake_id && a2)
            stat_remap((void *)a2);
        return r;
    }
    case __NR_statx: {
        if (cng_g_l2s && a4) {
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_statx(hnf, (void *)a4, (unsigned)a3, (unsigned)a2) ==
                    1) {
                if (cng_g_fake_id)
                    statx_remap((void *)a4);
                return 0;
            }
        }
        int deref = !((int)a2 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_statx);
        if (r == 0 && cng_g_l2s && a4 && ((int)a2 & CNG_AT_EMPTY_PATH)) {
            const char *gp = (const char *)a1; /* fstat-by-fd form */
            if (!gp || !gp[0])
                cng_l2s_fix_fd_statx(a0, (void *)a4);
        }
        if (r == 0 && cng_g_fake_id && a4)
            statx_remap((void *)a4);
        return r;
    }

    /* chown: try the real change (a chown to your own id succeeds for real),
     * then fake success under fake-root when the host denies it. An l2s name
     * redirects to its backing file even under AT_SYMLINK_NOFOLLOW — the
     * guest thinks the name IS the file, so lchown must land on the data. */
    case __NR_fchownat: {
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return chattr_result(reissue(CNG_AT_FDCWD, (long)data, a2, a3,
                                             0, a5, __NR_fchownat));
        }
        int deref = !((int)a4 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, __NR_fchownat));
    }

    /* readlinkat: /proc/self magic-link fixups, else translate + reissue. */
    case __NR_readlinkat: {
        const char *gp = (const char *)a1;
        if (gp && (gp[0] == '/' || (int)a0 == CNG_AT_FDCWD)) {
            char canon[CNG_PATH_MAX];
            if (cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0) {
                long fx = proc_self_fixup(canon, (char *)a2,
                                          (unsigned long)a3);
                if (fx >= 0)
                    return fx;
            }
        }
        const char *p = xlate(a0, gp, b1, sizeof b1, /*deref_final=*/0);
        /* A link2symlink entry presents as a regular file: readlink must fail
         * with EINVAL rather than leak the backing path — including through a
         * real dirfd, which xlate passes through untranslated. */
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (resolve_at_host(a0, gp, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return -EINVAL;
        }
        return reissue(a0, (long)p, a2, a3, a4, a5, __NR_readlinkat);
    }

    /* symlinkat(target, newdirfd, linkpath): translate only the linkpath. */
    case __NR_symlinkat: {
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2, 0);
        return reissue(a0, a1, (long)lp, a3, a4, a5, __NR_symlinkat);
    }

    /* fchown(fd,...): no path — try the real change, fake success under fake-root
     * (apk fchown()s each extracted file to root and a non-root app gets EPERM).
     * Routed through reissue so an Android-blocked fchown emulates ENOSYS rather
     * than trapping from the handler (fchown is in the block-list probe set). */
    case __NR_fchown:
        return chattr_result(reissue(a0, a1, a2, a3, a4, a5, __NR_fchown));

    /* fstat(fd): no path, but the fd may name an l2s backing file whose
     * st_nlink must reflect the live group count (tar/rsync/ls stat open
     * fds). Trapped only under -l; the fake-id remap rides along. */
    case __NR_fstat: {
        long r = reissue(a0, a1, a2, a3, a4, a5, __NR_fstat);
        if (r == 0 && a1) {
            if (cng_g_l2s)
                cng_l2s_fix_fd(a0, (void *)a1);
            if (cng_g_fake_id)
                stat_remap((void *)a1);
        }
        return r;
    }

    /* getdents64: hide the l2s machinery from directory listings — backing
     * data/marker names anywhere, and the ".l2s" store dir in the rootfs
     * root. Filtered in place in the guest buffer; when a whole batch is
     * ours, re-read so a filtered 0 isn't mistaken for end-of-directory. */
    case __NR_getdents64: {
        long n = reissue(a0, a1, a2, a3, a4, a5, __NR_getdents64);
        if (!cng_g_l2s || n <= 0 || !a1)
            return n;
        int at_root = fd_is_rootfs_root(a0);
        char *buf = (char *)a1;
        for (;;) {
            /* linux_dirent64: d_reclen u16 @16, d_name @19. d_off cookies are
             * directory-stream positions, so compaction is seek-safe. */
            long w = 0, o = 0;
            while (o + 19 <= n) {
                unsigned short reclen;
                memcpy(&reclen, buf + o + 16, 2);
                if (reclen == 0 || o + reclen > n)
                    break;
                const char *nm = buf + o + 19;
                int hide =
                    cng_l2s_hidden(nm) || (at_root && !strcmp(nm, ".l2s"));
                if (!hide) {
                    if (w != o)
                        memmove(buf + w, buf + o, reclen);
                    w += reclen;
                }
                o += reclen;
            }
            if (w > 0)
                return w;
            n = reissue(a0, a1, a2, a3, a4, a5, __NR_getdents64);
            if (n <= 0)
                return n;
        }
    }

    /* clone with CLONE_VFORK (only these are trapped; see seccomp.c): a
     * vfork-style spawn shares the parent's address space and suspends the
     * parent until the child execs. Our execve is emulated in-process, so a
     * shared-VM child would load the new program over the parent's memory and
     * never issue the real execve that resumes the parent. Strip CLONE_VM and
     * CLONE_VFORK so it becomes an ordinary COW fork: the child gets a private
     * copy, the emulated execve happens there, and the parent continues (the
     * child's execve closes the O_CLOEXEC notify pipe, signalling success). */
    /* The SIGSYS path handles clone in cng_sigsys_body (it needs the ucontext to
     * fix the child's stack). This branch is only reached via an M8 trampoline
     * (-R); best-effort strip of the shared-VM flags. */
    case __NR_clone: {
        long flags = a0 & ~(long)(CNG_CLONE_VM | CNG_CLONE_VFORK);
        return cng_syscall6(flags, a1, a2, a3, a4, a5, __NR_clone);
    }

    /* execve/execveat: only reached via an M8 trampoline (-R); the SIGSYS path
     * intercepts them in cng_sigsys_body (it must rewrite the signal context).
     * Emulate in-process — re-issuing the raw syscall would exec the
     * untranslated guest path on the host (ENOENT), or worse, succeed and wipe
     * the monitor. On success cng_execve_tramp enters the new program and never
     * returns; on failure return -errno like a real execve. */
    case __NR_execve:
        return cng_execve_tramp(CNG_AT_FDCWD, (const char *)a0, (char **)a1,
                                (char **)a2);
#ifdef __NR_execveat
    case __NR_execveat:
        return cng_execve_tramp((int)a0, (const char *)a1, (char **)a2,
                                (char **)a3);
#endif

    /* rename: two translated paths. If the destination is one of our
     * link2symlink names, it is replaced by the rename, so drop its group's
     * refcount (apk installs by renaming a temp file over the final name) —
     * except under RENAME_EXCHANGE, where both names live on. A legacy-format
     * source (bare-basename target) moving to another directory is repointed
     * at its (unmoved) data file afterwards. */
    case __NR_renameat:
    case __NR_renameat2: {
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2, 0);
        int exch = (nr == __NR_renameat2 && ((int)a4 & CNG_RENAME_EXCHANGE));
        char data[CNG_PATH_MAX], absdata[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0, fix = 0;
        if (cng_g_l2s && !exch && strcmp(op, np) != 0 &&
            resolve_at_host(a2, (const char *)a3, 0, dsth, sizeof dsth) == 0) {
            if (cng_l2s_resolve(dsth, data, sizeof data, &cnt) == 1)
                dec = 1;
            char hnf[CNG_PATH_MAX];
            if (resolve_at_host(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0)
                fix = cng_l2s_rename_prep(hnf, absdata, sizeof absdata);
        }
        long r = reissue(a0, (long)op, a2, (long)np, a4, a5, nr);
        if (r == 0 && dec)
            cng_l2s_decref(data, cnt);
        if (r == 0 && fix)
            cng_l2s_rename_fixup(dsth, absdata);
        return r;
    }

    /* linkat: hardlink; where the fs forbids hardlinks (Android/SELinux returns
     * EACCES/EXDEV, some EPERM) and -l/--link2symlink was given, fall back to the
     * link2symlink backing-file scheme (see l2s.c): the contents move to a hidden
     * ".l2s.<ino>" and every name becomes a same-directory relative symlink to
     * it, so the group presents as regular files (via the stat fixups) with a
     * shared inode. Without -l the host's refusal reaches the guest unchanged. */
    case __NR_linkat: {
        const char *sp = (const char *)a1;
        int follow = ((int)a4 & CNG_AT_SYMLINK_FOLLOW) ? 1 : 0;
        int empty = ((int)a4 & CNG_AT_EMPTY_PATH) && (!sp || !sp[0]);
        char srch[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        /* AT_SYMLINK_FOLLOW is applied at guest level (the host must never
         * follow a guest symlink's target itself); the host call then runs
         * with no flags. Link-by-fd (AT_EMPTY_PATH, the O_TMPFILE publish
         * idiom) goes through /proc/self/fd, which the host must follow. */
        if (empty) {
            proc_fd_path(a0, srch);
        } else if (resolve_at_host(a0, sp, follow, srch, sizeof srch) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: src unresolved (%s)\n",
                            sp ? sp : "(null)");
            return -ENOENT;
        }
        if (resolve_at_host(a2, (const char *)a3, 0, dsth, sizeof dsth) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: dst unresolved (%s)\n",
                            a3 ? (const char *)a3 : "(null)");
            return -ENOENT;
        }
        long r;
        if (cng_g_l2s && cng_g_l2s_force)
            r = -EPERM; /* CNG_L2S_FORCE: exercise the fallback directly */
        else
            r = reissue(CNG_AT_FDCWD, (long)srch, CNG_AT_FDCWD, (long)dsth,
                        empty ? CNG_AT_SYMLINK_FOLLOW : 0, 0, __NR_linkat);
        if (cng_g_debug && r != 0)
            cng_dprintf(2, "[cng] linkat %s -> %s real=%ld\n", srch, dsth, r);
        /* Some Android builds deny app-data hardlinks with ENOENT rather
         * than EACCES/EPERM. ENOENT is only believable when the source is
         * really absent — if it exists, treat the refusal like any other
         * denial. (A genuinely missing dst parent still surfaces as ENOENT
         * from the fallback's own symlink step.) */
        if (cng_g_l2s && r == -ENOENT) {
            char stt[144];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, srch, stt,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0)
                r = -EPERM;
        }
        if (cng_g_l2s &&
            (r == -EPERM || r == -EMLINK || r == -EXDEV || r == -ENOSYS ||
             r == -EACCES || r == -EOPNOTSUPP)) {
            if (empty) {
                /* If the fd names a live file, link its real path — an fd
                 * onto a group's data file then bumps that group. Anonymous
                 * or deleted files keep the /proc path: the fallback's
                 * materialize copies the contents. */
                char tgt[CNG_PATH_MAX], stt[144];
                long tn = sys_readlinkat(CNG_AT_FDCWD, srch, tgt,
                                         sizeof tgt - 1);
                if (tn > 0) {
                    tgt[tn] = '\0';
                    if (tgt[0] == '/' &&
                        CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, tgt, stt,
                                CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0)
                        cng_strlcpy(srch, tgt, sizeof srch);
                }
            }
            int s = cng_l2s_link(srch, dsth);
            if (cng_g_debug)
                cng_dprintf(2, "[cng] l2s %s -> %s rc=%d\n", srch, dsth, s);
            return s;
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

    /* chroot: move the guest root, keeping the rest of the view. The binds and
     * the cwd are rebased onto the new root (cng_fs_chroot), not discarded — a
     * real chroot unmounts nothing, and apk runs every package script under
     * chroot("."), which would otherwise strip that child of /proc, /dev and
     * every other bind. */
    case __NR_chroot: {
        const char *gp = (const char *)a0;
        if (!gp)
            return -EFAULT;
        char gc[CNG_PATH_MAX], hp[CNG_PATH_MAX];
        if (cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) != 0)
            return -ENAMETOOLONG;
        if (cng_resolve(gc, 1, hp, sizeof hp) != 0 &&
            cng_fs_translate(cng_g_fs, gc, hp, sizeof hp) != 0)
            return -ENAMETOOLONG;
        /* Name the new root by where the symlinks led, so the guest and host
         * sides of the new view describe the same directory. */
        char resolved[CNG_PATH_MAX];
        if (cng_fs_untranslate(cng_g_fs, hp, resolved, sizeof resolved) == 0)
            cng_strlcpy(gc, resolved, sizeof gc);
        char sb[128]; /* AArch64 struct stat is 128 bytes */
        long r = cng_syscall6(CNG_AT_FDCWD, (long)hp, (long)sb, 0, 0, 0,
                              __NR_newfstatat);
        if (r < 0)
            return r;
        if ((*(unsigned *)(sb + STAT_MODE_OFF) & 0170000) != 0040000)
            return -ENOTDIR;
        cng_fs_chroot(cng_g_fs, gc, hp);
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

    /* --- credential syscalls (trapped only when --fake-id is active) ---
     * All get/set uid/gid family, groups, and capability calls are emulated
     * against the synthetic credential set in cred.c, which enforces real POSIX
     * privilege rules. These never re-issue under --fake-id: the setters sit on
     * Android's seccomp block-list, and a re-issue from inside this (SIGSYS)
     * handler force-kills the process (masked nested seccomp SIGSYS). */
    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid:
    case __NR_getresuid:
    case __NR_getresgid:
    case __NR_getgroups:
    case __NR_setuid:
    case __NR_setgid:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_setresuid:
    case __NR_setresgid:
    case __NR_setfsuid:
    case __NR_setfsgid:
    case __NR_setgroups:
    case __NR_capget:
    case __NR_capset:
        return cng_cred_handle(nr, a0, a1, a2, a3, a4, a5);

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
