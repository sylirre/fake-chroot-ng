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
#include "cng/procfs.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/netlink.h"
#include "cng/unixsock.h"
#include "cng/rt.h"
#include "cng/shm.h"
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

/* A mutating syscall whose target lands under a `:ro` bind must answer -EROFS,
 * the way it would on a real read-only mount. Keyed on the already-resolved
 * HOST path, so a guest symlink that leads into the bind is covered however the
 * path got there. Checked before the reissue, and before chattr_result — a
 * read-only mount is a genuine error that fake-root does not paper over. */
static int ro_denied(const char *host) {
    return host && cng_g_fs && cng_fs_host_ro(cng_g_fs, host);
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
char **cng_g_host_envp = 0;

/* Is `p` safe to print as a path string? A magnitude test is not enough: the
 * args of a *failing* syscall include plain scalars (a uid, an offset, a
 * length) that are large enough to look like pointers, and dereferencing one
 * reads a wild address — a SIGSEGV inside the handler, with SIGSEGV masked,
 * kills the guest outright. CNG_DEBUG must never change behaviour, so ask the
 * kernel instead: faccessat() copies the path in from user space before doing
 * anything else, and EFAULT/ENAMETOOLONG mean "not a readable C string". */
static int dbg_str(long p) {
    if (p <= 0x1000 || cng_blocked[__NR_faccessat])
        return 0;
    long r = CNG_SYS(__NR_faccessat, CNG_AT_FDCWD, p, 0 /*F_OK*/, 0, 0, 0);
    return r != -EFAULT && r != -ENAMETOOLONG;
}

/* Best-effort path pointer among a0/a1 for logging (path syscalls put the path
 * in a0 or a1). */
static const char *dbg_path(long a0, long a1) {
    if (dbg_str(a1) && *(const char *)a1 == '/')
        return (const char *)a1;
    if (dbg_str(a0) && *(const char *)a0 == '/')
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

static long proc_self_fixup(const char *canon, char *buf, unsigned long bufsz);

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
     * a real execve) or at host paths, so following them is never right. This
     * covers another guest process too — its target comes from the registry —
     * while a host process never reaches here (the path layer hides it). */
    size_t vl = 0;
    if (strncmp(rest, "exe", 3) == 0 || strncmp(rest, "cwd", 3) == 0)
        vl = 3;
    else if (strncmp(rest, "root", 4) == 0)
        vl = 4;
    if (!vl || (rest[vl] != '\0' && rest[vl] != '/'))
        return PROC_MAGIC_NONE;

    /* The link component alone, for the fixup; the rest rides along after. */
    char link[CNG_PATH_MAX], tmp[CNG_PATH_MAX];
    if (pl + vl >= sizeof link)
        return PROC_MAGIC_NONE;
    memcpy(link, cur, pl + vl);
    link[pl + vl] = '\0';
    long n = proc_self_fixup(link, tmp, sizeof tmp - 1);
    if (n < 0)
        return PROC_MAGIC_NONE;
    tmp[n] = '\0';
    cng_strlcpy(tmp + n, rest + vl, sizeof tmp - (size_t)n);
    return cng_path_canon(tmp, cur, sz) == 0 ? PROC_MAGIC_GUEST
                                             : PROC_MAGIC_NONE;
}

/* If `host` names one of *this* process's own open fds — "/proc/self/fd/<n>",
 * the thread-self spelling, or our own pid — return that fd, else -1. We run
 * in-process, so the guest's fds are ours: the caller can use the open file
 * description directly instead of reopening the magic link. Trailing
 * components (a directory fd) are not this, and neither is another process. */
int cng_proc_self_fd(const char *host) {
    size_t pl = proc_pid_prefix(host, 0);
    if (!pl || strncmp(host + pl, "fd/", 3) != 0)
        return -1;
    if (!proc_pid_prefix(host, 1)) { /* numeric form: must be our own pid */
        long pid = 0;
        const char *q = host + 6;
        for (; *q >= '0' && *q <= '9'; q++)
            pid = pid * 10 + (*q - '0');
        if (pid != sys_getpid())
            return -1;
    }
    const char *d = host + pl + 3;
    if (*d < '0' || *d > '9')
        return -1;
    int fd = 0;
    for (; *d >= '0' && *d <= '9'; d++)
        fd = fd * 10 + (*d - '0');
    return *d == '\0' ? fd : -1;
}

/* Rewrite the /dev aliases of the /proc fd links in place — /dev/fd[/...] to
 * /proc/self/fd[/...], /dev/std{in,out,err} to /proc/self/fd/{0,1,2} — so the
 * resolver's existing magic-link handling covers them. Returns 1 if `cur` was
 * rewritten (the caller re-runs the round), 0 otherwise. */
static int dev_magic(char *cur, size_t sz) {
    if (cng_g_no_dev || strncmp(cur, "/dev/", 5) != 0)
        return 0;
    const char *leaf = cur + 5;
    const char *rest = 0;
    const char *base = 0;
    if (!strncmp(leaf, "fd", 2) && (leaf[2] == '\0' || leaf[2] == '/')) {
        base = "/proc/self/fd";
        rest = leaf + 2;
    } else if (!strcmp(leaf, "stdin")) {
        base = "/proc/self/fd/0";
        rest = "";
    } else if (!strcmp(leaf, "stdout")) {
        base = "/proc/self/fd/1";
        rest = "";
    } else if (!strcmp(leaf, "stderr")) {
        base = "/proc/self/fd/2";
        rest = "";
    } else {
        return 0;
    }
    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, base, sizeof tmp);
    cng_strlcpy(tmp + n, rest, sizeof tmp > n ? sizeof tmp - n : 0);
    cng_strlcpy(cur, tmp, sz);
    return 1;
}

static int dirfd_host(int dfd, char *hdir, size_t sz);

/* The canonical GUEST directory an open fd names, for the getdents64 overlay
 * splicing below. Returns 0/-1. */
static int dirfd_guest_dir(long dirfd, char *out, size_t sz) {
    char hdir[CNG_PATH_MAX];
    if (dirfd_host((int)dirfd, hdir, sizeof hdir) != 0)
        return -1;
    return cng_fs_untranslate(cng_g_fs, hdir, out, sz);
}

/* Append one synthesized linux_dirent64. Layout is a fixed kernel ABI:
 * d_ino @0, d_off @8, d_reclen @16 (u16), d_type @18, d_name @19, records
 * 8-byte aligned. `d_off` is an opaque stream cookie, so a high constant keeps
 * these clear of the kernel's own. Returns the bytes written, or 0 if the record
 * would not fit — a short batch is legal and the guest simply reads again. */
static long put_dent(char *buf, long at, long cap, const char *name,
                     unsigned long long ino, unsigned char dtype,
                     long long cookie) {
    size_t nl = strlen(name);
    long reclen = (long)((19 + nl + 1 + 7) & ~(size_t)7);
    if (at < 0 || cap < 0 || at + reclen > cap)
        return 0;
    char *rec = buf + at;
    memset(rec, 0, (size_t)reclen);
    memcpy(rec, &ino, 8);
    memcpy(rec + 8, &cookie, 8);
    unsigned short rl = (unsigned short)reclen;
    memcpy(rec + 16, &rl, 2);
    rec[18] = (char)dtype;
    memcpy(rec + 19, name, nl + 1);
    return reclen;
}

/* Is `name` already present in the batch, or a real dirent of the directory? */
static int dent_present(long dirfd, const char *name, const char *buf,
                        long used) {
    for (long o = 0; o + 19 <= used;) {
        unsigned short rl;
        memcpy(&rl, buf + o + 16, 2);
        if (rl == 0)
            break;
        if (!strcmp(buf + o + 19, name))
            return 1;
        o += rl;
    }
    char st[144];
    return CNG_SYS(__NR_newfstatat, dirfd, (long)name, (long)st,
                   CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0;
}

/* Splice the entries that exist only as path-resolution overlays and therefore
 * have no physical dirent for getdents64 to return:
 *
 *  - **bind mount points**: a -b destination is pure resolution (cng_fs_translate
 *    matches the prefix), so `ls /` never showed a `-b SRC:/host`. Anything that
 *    enumerates before opening — shell globbing, find, a package manager's tree
 *    walk — could not see it.
 *  - the **device nodes**: the /dev whitelist grants access by name only, so a
 *    rootfs /dev (usually empty) listed as empty even though /dev/null opens.
 *
 * Both are skipped when the name is already there, so a rootfs that ships a real
 * `null`, or a bind over an existing directory, is not duplicated. d_ino/d_type
 * come from an lstat of the real host target, so `ls -l` and `find -type` agree
 * with what an open of the same name gets. Returns the bytes appended. */
static long inject_dents(long dirfd, const char *gdir, char *buf, long used,
                         long cap) {
    long added = 0;
    /* Bind mount points whose parent is exactly this directory. */
    for (int i = 0; i < cng_g_fs->nbinds; i++) {
        const char *g = cng_g_fs->binds[i].guest;
        const char *slash = 0;
        for (const char *p = g; *p; p++)
            if (*p == '/')
                slash = p;
        if (!slash || !slash[1])
            continue;
        char parent[CNG_PATH_MAX];
        size_t plen = (size_t)(slash - g);
        if (plen == 0)
            cng_strlcpy(parent, "/", sizeof parent);
        else {
            if (plen >= sizeof parent)
                continue;
            memcpy(parent, g, plen);
            parent[plen] = '\0';
        }
        if (strcmp(parent, gdir) != 0)
            continue;
        const char *base = slash + 1;
        if (dent_present(dirfd, base, buf, used + added))
            continue;
        unsigned long long ino = 0xffffffffULL - (unsigned)i;
        unsigned char type = 4; /* DT_DIR */
        char st[144];
        if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD,
                    (long)cng_g_fs->binds[i].host, (long)st, 0, 0, 0) == 0) {
            ino = *(unsigned long long *)(st + 8);
            type = (unsigned char)((*(unsigned *)(st + STAT_MODE_OFF) >> 12) &
                                   0xf);
        }
        long k = put_dent(buf, used + added, cap, base, ino, type,
                          0x7fffffff00000000LL + i);
        if (!k)
            return added;
        added += k;
    }
    /* /dev whitelist, when this is the guest's own /dev (a -b for /dev makes
     * that directory's real contents authoritative, and cng_fs_translate would
     * have matched the bind first, so gdir would not be "/dev" here). */
    if (!cng_g_no_dev && strcmp(gdir, "/dev") == 0) {
        for (int i = 0; i < cng_dev_nnodes; i++) {
            const char *name = cng_dev_nodes[i].name;
            char st[144];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD,
                        (long)cng_dev_nodes[i].host, (long)st,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) != 0)
                continue; /* not present on this host */
            if (dent_present(dirfd, name, buf, used + added))
                continue;
            unsigned long long ino = *(unsigned long long *)(st + 8);
            unsigned char type =
                (unsigned char)((*(unsigned *)(st + STAT_MODE_OFF) >> 12) & 0xf);
            long k = put_dent(buf, used + added, cap, name, ino, type,
                              0x7ffffffe00000000LL + i);
            if (!k)
                return added;
            added += k;
        }
    }
    return added;
}

/* Append one component to the resolved prefix ("/a" + "b" -> "/a/b"). 0/-1. */
static int canon_push(char *c, size_t sz, const char *comp, size_t clen) {
    size_t n = strlen(c);
    if (n == 1 && c[0] == '/')
        n = 0; /* the root is spelled "/", not "" — do not double the slash */
    if (n + 1 + clen + 1 > sz)
        return -1;
    c[n] = '/';
    memcpy(c + n + 1, comp, clen);
    c[n + 1 + clen] = '\0';
    return 0;
}

/* Drop the last component ("/a/b" -> "/a", "/a" -> "/"). "/" stays "/", which
 * is what clamps a `..` run at the guest root. */
static void canon_pop(char *c) {
    char *s = strrchr(c, '/');
    if (!s || s == c) {
        c[0] = '/';
        c[1] = '\0';
        return;
    }
    *s = '\0';
}

/* rest = tgt + remainder, where `remainder` points into `rest` itself. */
static int splice_rest(char *rest, size_t sz, const char *tgt,
                       const char *remainder) {
    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, tgt, sizeof tmp);
    if (n >= sizeof tmp || cng_strlcpy(tmp + n, remainder, sizeof tmp - n) >=
                               sizeof tmp - n)
        return -1;
    return cng_strlcpy(rest, tmp, sz) < sz ? 0 : -1;
}

/* Resolve a guest path to a host path, following symlinks *within the guest*:
 * an absolute symlink target is re-rooted into the rootfs rather than resolved
 * against the host root (which is what breaks Alpine's busybox symlinks).
 *
 * The walk is *physical*, like the kernel's: components are consumed one at a
 * time against a resolved prefix, and `..` pops that prefix — so it backs out of
 * where a symlink actually led. Canonicalizing `..` up front instead (which is
 * what this used to do) is logical resolution, the shell's convention, not the
 * kernel's: with /bin a symlink to /usr/bin, "/bin/../lib" is "/usr/lib" to
 * every syscall and was "/lib" to us. `..` at the guest root stays at the guest
 * root, which is what keeps the rootfs closed.
 *
 * deref_final controls whether the last component's own symlink is followed;
 * "last" is judged against the path as it stands, so a symlink expanded earlier
 * moves it, exactly as O_NOFOLLOW behaves. Returns 0/-errno. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz) {
    char canon[CNG_PATH_MAX], rest[CNG_PATH_MAX];
    if (!path || !path[0])
        return -ENOENT;
    const char *base = path[0] == '/'          ? "/"
                       : cng_g_fs->cwd[0] != 0 ? cng_g_fs->cwd
                                               : "/";
    if (cng_strlcpy(canon, base, sizeof canon) >= sizeof canon ||
        cng_strlcpy(rest, path, sizeof rest) >= sizeof rest)
        return -ENAMETOOLONG;

    int nlinks = 0;
    char *p = rest;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        char *end = p;
        while (*end && *end != '/')
            end++;
        const char *comp = p;
        size_t clen = (size_t)(end - p);
        int last = 1; /* nothing but slashes left after this component */
        for (const char *q = end; *q; q++)
            if (*q != '/') {
                last = 0;
                break;
            }
        p = end;

        if (clen == 1 && comp[0] == '.')
            continue;
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') {
            canon_pop(canon);
            continue;
        }
        if (canon_push(canon, sizeof canon, comp, clen) < 0)
            return -ENAMETOOLONG;

        /* /dev/fd/N and /dev/std{in,out,err} are the same magic links as their
         * /proc spelling, so rewrite them to it and let the checks below treat
         * them as such — readlink-ing an fd link like an ordinary symlink would
         * try to re-root whatever it names, which for a pipe or a memfd is not a
         * path at all ("pipe:[12345]"). */
        dev_magic(canon, sizeof canon);
        int magic = proc_magic(canon, sizeof canon);
        if (magic == PROC_MAGIC_HOST) {
            /* The magic path IS the host path. Any components left ride along,
             * as they do for a real dirfd. */
            size_t n = cng_strlcpy(out, canon, outsz);
            if (n >= outsz || cng_strlcpy(out + n, p, outsz - n) >= outsz - n)
                return -ENAMETOOLONG;
            return 0;
        }
        if (magic == PROC_MAGIC_GUEST) {
            /* exe/cwd/root: the guest-visible target replaces the link, which
             * is a symlink expansion in everything but name. */
            if (++nlinks > 40)
                return -ELOOP;
            if (splice_rest(rest, sizeof rest, canon, p) < 0)
                return -ENAMETOOLONG;
            p = rest;
            cng_strlcpy(canon, "/", sizeof canon);
            continue;
        }

        if (last && !deref_final)
            continue;
        char host[CNG_PATH_MAX], link[CNG_PATH_MAX];
        if (cng_fs_translate(cng_g_fs, canon, host, sizeof host) != 0)
            continue;
        long n = sys_readlinkat(CNG_AT_FDCWD, host, link, sizeof link - 1);
        if (n <= 0)
            continue; /* not a symlink, or missing */
        link[n] = '\0';
        if (++nlinks > 40)
            return -ELOOP;
        canon_pop(canon); /* the link itself is replaced by its target */
        if (link[0] == '/') {
            /* An absolute target is re-rooted — except one naming an l2s data
             * file, which is a HOST path (central store / cross-directory
             * group) and must be mapped into the guest view instead. */
            char tmp[CNG_PATH_MAX];
            if (cng_g_l2s && cng_l2s_untranslate_target(link, tmp, sizeof tmp))
                cng_strlcpy(link, tmp, sizeof link);
            cng_strlcpy(canon, "/", sizeof canon);
        }
        if (splice_rest(rest, sizeof rest, link, p) < 0)
            return -ENAMETOOLONG;
        p = rest;
    }
    return cng_fs_translate(cng_g_fs, canon, out, outsz);
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

/* Read the host directory a real dirfd names, from /proc/self/fd/<dirfd>.
 * Returns 0/-1. */
static int dirfd_host(int dfd, char *hdir, size_t sz) {
    if (dfd < 0)
        return -1;
    char proc[40];
    proc_fd_path(dfd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hdir, sz - 1);
    if (n <= 0)
        return -1;
    hdir[n] = '\0';
    return 0;
}

/* Put a dirfd-relative name through the same containment an absolute path gets:
 * map the dirfd's host directory back to its GUEST path, join the name onto it,
 * and resolve the whole thing through the rootfs/bind map. Concatenating the
 * host directory instead — which is what this used to do — leaves the kernel to
 * resolve the name itself, and the kernel has no rootfs: a ".." component
 * climbs straight past it and an absolute symlink target is taken from the HOST
 * root.
 *
 * `out` comes back an absolute host path. Callers reissue with the original
 * dirfd, which the kernel ignores for an absolute path, so no caller changes.
 * Returns -1 when the dirfd names a directory outside the guest view (a /proc
 * dirfd, say) — there is no guest path to express it as, and the /proc zone
 * wants the host namespace anyway, so the caller passes the name through. */
static int xlate_at(int dfd, const char *path, char *out, size_t sz, int deref) {
    char hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX], gp[CNG_PATH_MAX];
    if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
        return -1;
    if (cng_fs_untranslate(cng_g_fs, hdir, gdir, sizeof gdir) != 0)
        return -1;
    size_t k = cng_strlcpy(gp, gdir, sizeof gp);
    if (k && gp[k - 1] != '/' && k + 1 < sizeof gp) {
        gp[k++] = '/';
        gp[k] = '\0';
    }
    cng_strlcpy(gp + k, path, sizeof gp > k ? sizeof gp - k : 0);
    return cng_resolve(gp, deref, out, sz) == 0 ? 0 : -1;
}

/* Does a dirfd-relative name need the guest-side walk above, or can the kernel
 * be trusted with it? The dirfd itself already points inside the guest view, so
 * only two things can redirect out of it: a ".." component, and a symlink. This
 * is the hot path (every relative openat), so the cheap cases stay cheap.
 *
 *  - any '/' => some intermediate component is followed as a symlink => walk;
 *  - a ".." component => walk;
 *  - otherwise a single component, and only its own symlink can escape: one
 *    readlinkat settles it. EINVAL (not a symlink) and ENOENT (nothing there)
 *    are safe for the kernel to finish; a real link needs the walk. */
static int at_needs_xlate(int dfd, const char *path, int deref) {
    for (const char *p = path; *p; p++)
        if (*p == '/')
            return 1;
    if (path[0] == '.' && path[1] == '.' && !path[2])
        return 1;
    if (!deref)
        return 0;
    char lb[8];
    return sys_readlinkat(dfd, path, lb, sizeof lb) >= 0;
}

/* Resolve (dirfd, path) to a HOST path. Handles absolute paths and AT_FDCWD
 * (through the rootfs, re-rooting guest symlinks — except the /proc magic
 * links, which cng_resolve keeps in the host namespace), and real dirfds (via
 * xlate_at, so a relative name is contained the same way an absolute one is).
 * `deref` follows the final component's symlink. Returns 0/-1. */
int cng_resolve_at(long dirfd, const char *path, int deref, char *out,
                   size_t sz) {
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || dfd == CNG_AT_FDCWD) {
        if (cng_resolve(path, deref, out, sz) == 0)
            return 0;
        return cng_fs_translate(cng_g_fs, path, out, sz) == 0 ? 0 : -1;
    }
    if (dfd < 0)
        return -1;
    if (xlate_at(dfd, path, out, sz, deref) == 0)
        return 0;
    /* Outside the guest view (a /proc dirfd): the host directory joined with
     * the name is the only answer available, and the right one there. */
    char hdir[CNG_PATH_MAX];
    if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
        return -1;
    size_t k = cng_strlcpy(out, hdir, sz);
    if (k && out[k - 1] != '/' && k + 1 < sz) {
        out[k++] = '/';
        out[k] = '\0';
    }
    cng_strlcpy(out + k, path, sz > k ? sz - k : 0);
    return 0;
}

/* An open the host refused on a path naming one of *our own* fds. We hold that
 * descriptor, so the guest can still be served — two distinct refusals, two
 * answers (apk 3 runs into both when it execs a package script and the shebang
 * interpreter reopens it):
 *
 *  - the inode already grants us the access asked for, so the refusal did not
 *    come from DAC. On Android that is SELinux declining an app an `open` on
 *    the tmpfs inode behind a memfd — where apk 3 keeps its scripts (mode 0777,
 *    owned by us). A fresh description of the same file is exactly what the
 *    open would have produced: duplicate ours and rewind it. The duplicate
 *    shares the original's file offset, hence the rewind — a real open always
 *    starts at 0.
 *  - the inode denies it and the guest is fake-root: real root would have
 *    bypassed DAC, so lend the inode the owner bit *through the fd* (no path
 *    race), reopen properly, and put the mode straight back.
 *
 * Returns the new fd, or `err` unchanged when this is not that case. */
long cng_fd_reopen(const char *host, long flags, long mode, long err) {
    int fd = cng_proc_self_fd(host);
    if (fd < 0)
        return err;
    /* Nothing here reproduces creation/truncation/append semantics. */
    if ((int)flags & (CNG_O_CREAT | CNG_O_EXCL | CNG_O_TRUNC | CNG_O_APPEND |
                      CNG_O_DIRECTORY))
        return err;
    char st[128];
    if (CNG_SYS(__NR_fstat, fd, st, 0, 0, 0, 0) != 0)
        return err;
    unsigned m = *(unsigned *)(st + STAT_MODE_OFF);
    if ((m & 0170000) != 0100000)
        return err; /* plain files only */

    int acc = (int)flags & 3; /* O_ACCMODE: RDONLY/WRONLY/RDWR */
    unsigned need = (acc == CNG_O_WRONLY)  ? 0200u
                    : (acc == CNG_O_RDWR)  ? 0600u
                                           : 0400u;
    int ours = (*(unsigned *)(st + STAT_UID_OFF) == (unsigned)sys_getuid());

    if (ours && (m & need) == need) {
        /* Not a DAC refusal: hand over a duplicate of the description. */
        long cur = CNG_SYS(__NR_fcntl, fd, 3 /*F_GETFL*/, 0, 0, 0, 0);
        if (cur < 0)
            return err;
        if ((cur & 3) != CNG_O_RDWR && (cur & 3) != acc)
            return err; /* our fd cannot serve that access mode */
        long nfd = CNG_SYS(__NR_fcntl, fd,
                           ((int)flags & CNG_O_CLOEXEC) ? 1030 /*F_DUPFD_CLOEXEC*/
                                                        : 0 /*F_DUPFD*/,
                           0, 0, 0, 0);
        if (nfd < 0)
            return err;
        sys_lseek((int)nfd, 0, CNG_SEEK_SET);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] fd reopen %s -> dup %ld (mode %o)\n", host,
                        nfd, m & 07777);
        return nfd;
    }

    if (!cng_fake_root() || !ours)
        return err;
    if (CNG_SYS(__NR_fchmod, fd, (m & 07777) | need, 0, 0, 0, 0) != 0)
        return err;
    long r = cng_syscall6(CNG_AT_FDCWD, (long)host, flags, mode, 0, 0,
                          __NR_openat);
    CNG_SYS(__NR_fchmod, fd, m & 07777, 0, 0, 0, 0);
    if (cng_g_debug)
        cng_dprintf(2, "[cng] fake-root reopen %s (mode %o) -> %ld\n", host,
                    m & 07777, r);
    return r;
}

static const char *xlate(long dirfd, const char *gp, char *buf, size_t bufsz,
                         int deref_final) {
    if (!gp)
        return gp;
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (gp[0] == '/' || dfd == CNG_AT_FDCWD) {
        if (cng_resolve(gp, deref_final, buf, bufsz) == 0)
            return buf;
        if (cng_fs_translate(cng_g_fs, gp, buf, bufsz) == 0)
            return buf;
        return gp;
    }
    /* Relative to a real dirfd. Handing this to the kernel unchanged — which is
     * what we used to do — lets a ".." run climb out of the rootfs and an
     * absolute symlink target resolve from the HOST root, since the kernel does
     * not know about the rootfs. Contain it like any other path, but only when
     * something in it could actually redirect (see at_needs_xlate). */
    if (dfd >= 0 && at_needs_xlate(dfd, gp, deref_final) &&
        xlate_at(dfd, gp, buf, bufsz, deref_final) == 0)
        return buf;
    return gp;
}

/* /proc/<pid>/{exe,cwd,root} -> guest-visible link target. Our own process
 * answers from the live view; another guest process from the registry entry it
 * published (a host process never gets here — the path layer hides it). Returns
 * bytes written (no NUL, like readlink) or -1 if `canon` isn't one of these. */
static long proc_self_fixup(const char *canon, char *buf, unsigned long bufsz) {
    size_t pl = proc_pid_prefix(canon, 0);
    if (!pl)
        return -1;
    const char *rest = canon + pl;
    if (strcmp(rest, "exe") && strcmp(rest, "cwd") && strcmp(rest, "root"))
        return -1;

    const char *val = 0;
    char own[CNG_PROCREG_PATH + 1];
    if (proc_pid_prefix(canon, 1)) { /* self / thread-self */
        val = rest[0] == 'e' ? cng_g_exe_guest
              : rest[0] == 'c' ? cng_g_fs->cwd
                               : "/";
    } else {
        long pid = 0;
        for (const char *q = canon + 6; *q >= '0' && *q <= '9'; q++)
            pid = pid * 10 + (*q - '0');
        if (pid == sys_getpid()) {
            val = rest[0] == 'e' ? cng_g_exe_guest
                  : rest[0] == 'c' ? cng_g_fs->cwd
                                   : "/";
        } else if (rest[0] == 'r') {
            val = "/"; /* every guest process shares this session's root */
        } else {
            struct cng_procsnap snap;
            if (!cng_procreg_get((int)pid, &snap))
                return -1;
            unsigned n = rest[0] == 'e' ? snap.exe_len : snap.cwd_len;
            const char *src = rest[0] == 'e' ? snap.exe : snap.cwd;
            if (!n) {
                if (rest[0] == 'e')
                    return -1; /* no recorded exe: nothing safe to report */
                val = "/"; /* an empty cwd snapshot reads as the guest root —
                            * falling through would leak the host path */
            } else {
                if (n > CNG_PROCREG_PATH)
                    n = CNG_PROCREG_PATH;
                memcpy(own, src, n);
                own[n] = '\0';
                val = own;
            }
        }
    }
    if (!val)
        return -1;
    size_t len = strlen(val);
    if (len > bufsz)
        len = bufsz;
    memcpy(buf, val, len);
    return (long)len;
}

/* Cheap pre-filter for the /proc hooks on a dirfd-relative path: resolving one
 * costs a readlink of the dirfd, which must not be paid by every openat a guest
 * makes. Only a final component that could name a synthesized file is worth
 * resolving — procps opens "<pid>/stat" and "status" against a /proc dirfd, so
 * the test is on the basename, not the whole path. */
static int leaf_may_synth(const char *p) {
    static const char *const leafs[] = {
        "cmdline", "environ",   "auxv",   "maps",  "mounts", "mountinfo",
        "status",  "mountstats", "loadavg", "uptime", "stat",
    };
    const char *b = strrchr(p, '/');
    b = b ? b + 1 : p;
    for (unsigned i = 0; i < sizeof leafs / sizeof leafs[0]; i++)
        if (!strcmp(b, leafs[i]))
            return 1;
    return 0;
}

/* Same idea for readlinkat: could this name be an fd or map_files link, whose
 * target is a host path that has to be mapped back into the guest view? An
 * absolute name must be under /proc; a cwd-relative one is cheap to
 * canonicalize either way; a dirfd-relative one only matters for the entries
 * of a /proc/<pid>/fd directory (digit names, `ls -l /proc/self/fd`) or of
 * /proc/<pid>/map_files ("<start>-<end>" in lowercase hex), so the basename
 * must consist of hex digits and '-'. */
static int rl_may_fdlink(long dirfd, const char *p) {
    if (!p)
        return 0;
    if (p[0] == '/')
        return !strncmp(p, "/proc", 5);
    if ((int)dirfd == CNG_AT_FDCWD)
        return 1;
    const char *b = strrchr(p, '/');
    b = b ? b + 1 : p;
    if (!*b)
        return 0;
    for (; *b; b++)
        if (!((*b >= '0' && *b <= '9') || (*b >= 'a' && *b <= 'f') ||
              *b == '-'))
            return 0;
    return 1;
}

/* The canonical GUEST path an (dirfd, path) pair names, for the /proc hooks.
 * A real dirfd is resolved through its host path and mapped back; a host /proc
 * path is already the guest spelling (that zone passes through). Returns 0/-1. */
static int at_canon(long dirfd, const char *path, char *out, size_t sz) {
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || (int)dirfd == CNG_AT_FDCWD)
        return cng_fs_abscanon(cng_g_fs, path, out, sz);
    char host[CNG_PATH_MAX];
    if (cng_resolve_at(dirfd, path, 0, host, sizeof host) != 0)
        return -1;
    if (!strncmp(host, "/proc/", 6) || !strcmp(host, "/proc"))
        return cng_path_canon(host, out, sz);
    return cng_fs_untranslate(cng_g_fs, host, out, sz);
}

/* 1 if the open fd refers to the host's real /proc — the directory whose
 * numeric entries the hidden-process view has to filter out of a listing.
 * Keyed on the fd's host path, so an explicit `-b /proc:/proc` (or the host
 * /proc bound at some other guest path) is covered exactly like the built-in
 * passthrough. */
static int fd_is_host_proc(long fd) {
    char proc[40], hp[CNG_PATH_MAX];
    proc_fd_path(fd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hp, sizeof hp - 1);
    if (n <= 0)
        return 0;
    hp[n] = '\0';
    return strcmp(hp, "/proc") == 0;
}

/* Does this getdents64 batch contain an all-digit name? Only then can the
 * hidden-process filter have anything to do, so this keeps the readlink in
 * fd_is_host_proc off every ordinary directory listing. */
static int dents_have_pid(const char *buf, long n) {
    for (long o = 0; o + 19 <= n;) {
        unsigned short reclen;
        memcpy(&reclen, buf + o + 16, 2);
        if (reclen == 0 || o + reclen > n)
            break;
        const char *nm = buf + o + 19;
        if (*nm >= '0' && *nm <= '9')
            return 1;
        o += reclen;
    }
    return 0;
}

/* A /proc entry the guest may see: anything not all-digits (self, sys, net,
 * version, ...), plus the guest processes' own pids. */
static int proc_name_visible(const char *nm) {
    if (*nm < '0' || *nm > '9')
        return 1;
    long pid = 0;
    for (const char *p = nm; *p; p++) {
        if (*p < '0' || *p > '9')
            return 1; /* "1abc" is an ordinary name, not a pid */
        pid = pid * 10 + (*p - '0');
        if (pid > 0x7fffffff)
            return 1;
    }
    return cng_procreg_has((int)pid);
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

/* The guest's own path arguments of a trapped syscall — up to two (dirfd, path)
 * pairs, as the guest wrote them, before any resolution. `p1`/`p2` stay 0 for a
 * syscall that carries no path there (and utimensat's legitimate NULL path,
 * which means "operate on the dirfd"). */
struct path_args {
    const char *p1, *p2;
    long d1, d2;
};

static void path_args_of(long nr, long a0, long a1, long a2, long a3,
                         struct path_args *pa) {
    pa->p1 = pa->p2 = 0;
    pa->d1 = pa->d2 = CNG_AT_FDCWD;
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
#ifdef __NR_fchmodat2
    case __NR_fchmodat2:
#endif
    case __NR_unlinkat:
    case __NR_utimensat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_fchownat:
    case __NR_readlinkat:
        pa->d1 = a0;
        pa->p1 = (const char *)a1;
        break;
    case __NR_symlinkat: /* only the linkpath names something new */
        pa->d1 = a1;
        pa->p1 = (const char *)a2;
        break;
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_linkat:
        pa->d1 = a0;
        pa->p1 = (const char *)a1;
        pa->d2 = a2;
        pa->p2 = (const char *)a3;
        break;
    case __NR_truncate:
    case __NR_statfs:
    case __NR_chdir:
    case __NR_chroot:
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr:
        pa->p1 = (const char *)a0;
        break;
    }
}

/* May the *first* path argument of `nr` legitimately be the empty string? Only
 * where the call names the dirfd itself instead: AT_EMPTY_PATH where the guest
 * set it, and readlinkat, which has read the link a dirfd names since Linux
 * 2.6.39 without asking for a flag. A second path argument (linkat/renameat's
 * destination) never may — AT_EMPTY_PATH governs the source alone. */
static int empty_path_ok(long nr, long a0, long a2, long a3, long a4) {
    switch (nr) {
    case __NR_newfstatat:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_statx:
        return ((int)a2 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_fchownat:
    case __NR_linkat:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
#ifdef __NR_faccessat2
    case __NR_faccessat2:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
#endif
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
#endif
    case __NR_readlinkat:
        return (int)a0 != CNG_AT_FDCWD; /* with no dirfd there is no link */
    default:
        return 0;
    }
}

/* Deliver a translated sockaddr to the guest exactly as move_addr_to_user()
 * would: copy at most what the caller's buffer holds, then report the
 * UNtruncated length ("fromlen shall refer to the value before truncation",
 * 1003.1g). `src`/`slen` is the guest-view address in our own buffer; `aa`/`alp`
 * are the guest's buffer and its in/out length. Returns 0 or -errno.
 *
 * The reason the readback side bounces through our buffer at all: the kernel
 * writes only min(caller's length, real length) bytes but stores the *real*
 * length back, so a guest with a short buffer left us a truncated host path and
 * a length describing bytes that were never written. Translating that in place
 * read past the guest's buffer — a fault the SIGSYS handler cannot survive,
 * since it runs with SIGSEGV masked — and could write the shortened guest path
 * past its end. With the whole address in hand there is nothing to reconstruct:
 * the guest sees precisely what a kernel with no rootfs under it would have
 * written, short buffer and all. */
static long addr_out(const void *src, long slen, long aa, long alp) {
    if (!aa || !alp)
        return 0;
    /* The writability probe validates a range by zeroing it (uaccess.c), so the
     * caller's length has to be read out before anything is probed for writing. */
    if (!cng_user_readable((void *)alp, sizeof(int)))
        return -EFAULT;
    int n = *(int *)alp;
    if (n > (int)slen)
        n = (int)slen;
    if (n < 0)
        return -EINVAL;
    if (n) {
        if (!cng_user_writable((void *)aa, (unsigned long)n))
            return -EFAULT;
        memcpy((void *)aa, src, (size_t)n);
    }
    if (!cng_user_writable((void *)alp, sizeof(int)))
        return -EFAULT;
    *(int *)alp = (int)slen;
    return 0;
}

/* Run the readback translation over an address the kernel just wrote into our
 * bounce buffer, and hand the result to the guest. `al` is what the kernel
 * reported; it cannot exceed the buffer (the kernel bounds every address by
 * sockaddr_storage), but it is clamped rather than trusted. */
static long sun_deliver(char *ab, unsigned al, long aa, long alp) {
    long got = (long)al;
    if (got > CNG_SOCKADDR_MAX)
        got = CNG_SOCKADDR_MAX;
    cng_sun_out(ab, &got);
    return addr_out(ab, got, aa, alp);
}

long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4, long a5,
                  int trapped) {
    char b1[CNG_PATH_MAX], b2[CNG_PATH_MAX];

    struct path_args pa;
    path_args_of(nr, a0, a1, a2, a3, &pa);

    /* An empty pathname is ENOENT to the kernel — the one answer every
     * path-bearing syscall agrees on — except where AT_EMPTY_PATH (or
     * readlinkat) makes the dirfd the subject. Without this the resolver made
     * "" mean the cwd and answered for a directory the guest never named, so
     * `[ -x "" ]` came back true: that is how every dpkg maintainer script
     * generated by dh_installmenu (`[ -x "$(command -v update-menus)" ]`) went
     * on to run a program that is not installed, and exited 127. */
    if ((pa.p1 && !pa.p1[0] && !empty_path_ok(nr, a0, a2, a3, a4)) ||
        (pa.p2 && !pa.p2[0]))
        return -ENOENT;

    /* -l: paths naming the l2s machinery (backing data/marker names anywhere,
     * the "/.l2s" store dir) do not exist as far as the guest is concerned.
     * Checked on the guest's own path argument, before any resolution, so the
     * resolver's internal symlink-target expansion is unaffected. */
    if (cng_g_l2s) {
        if ((pa.p1 && cng_l2s_deny(pa.d1, pa.p1)) ||
            (pa.p2 && cng_l2s_deny(pa.d2, pa.p2))) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] l2s deny nr=%ld (%s)\n", nr,
                            pa.p1 ? pa.p1 : "");
            return -ENOENT;
        }
    }

    /* The designed-ENOSYS set. The filter answers these with RET_ERRNO, so a
     * seccomp-tier guest never gets here; a rewritten svc site (-R) has no
     * filter and calls straight in, so the refusal has to live here too. */
    if (cng_denied_syscall(nr)) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] nr=%ld denied (designed ENOSYS)\n", nr);
        return -ENOSYS;
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
        /* openat2 carries its flags in the open_how it points at. */
#ifdef __NR_openat2
        int is_open = (nr == __NR_openat || nr == __NR_openat2);
#else
        int is_open = (nr == __NR_openat);
#endif
        long oflags = 0;
        if (is_open) {
            oflags = a2;
#ifdef __NR_openat2
            /* openat2's flags live in the open_how it points at, so reading
             * them is a guest dereference like any other. */
            if (nr == __NR_openat2) {
                if (a2 && !cng_user_readable((void *)a2, sizeof(unsigned long)))
                    return -EFAULT;
                oflags = a2 ? (long)*(unsigned long *)a2 : 0;
            }
#endif
        }
        /* O_NOFOLLOW must reach the kernel as a symlink, or it has nothing to
         * refuse: resolving the final component here would hand over the
         * target and the open would succeed where it must ELOOP. (An l2s link
         * name is the deliberate exception, restored by the ELOOP retry below —
         * the guest believes that name IS the file.) */
        int deref = !(nr == __NR_mkdirat || nr == __NR_mknodat) &&
                    !(is_open && (oflags & CNG_O_NOFOLLOW));
        /* A read-only open of a /proc file that would describe chroot-ng
         * instead of the guest is served from an in-memory copy of the guest
         * view (see procfs.c). */
        if (is_open) {
            const char *gp = (const char *)a1;
            char canon[CNG_PATH_MAX];
            long pr;
            /* Absolute and cwd-relative names canonicalize without a syscall;
             * a real dirfd costs a readlink, so it is resolved only when the
             * name could be a synthesized file at all. */
            int have = 0;
            if (gp && (gp[0] == '/' || (int)a0 == CNG_AT_FDCWD))
                have = cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0;
            else if (gp && leaf_may_synth(gp))
                have = at_canon(a0, gp, canon, sizeof canon) == 0;
            if (have && !strncmp(canon, "/proc", 5) &&
                cng_procfs_open(canon, oflags, &pr))
                return pr;
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        /* :ro bind — mkdirat/mknodat always create; an open only offends with
         * write intent (non-RDONLY, or O_CREAT/O_TRUNC). name_to_handle_at also
         * lands here and never writes, so its a2 (a handle pointer) is never
         * read as flags. */
        if (ro_denied(p)) {
            if (nr == __NR_mkdirat || nr == __NR_mknodat)
                return -EROFS;
            if (is_open && ((oflags & 3) != CNG_O_RDONLY ||
                            (oflags & (CNG_O_CREAT | CNG_O_TRUNC))))
                return -EROFS;
        }
        long r = reissue(a0, (long)p, a2, a3, a4, a5, nr);
        /* O_NOFOLLOW through a real dirfd lands on the l2s symlink and draws
         * ELOOP where a real hardlink would open. Retry on the backing file —
         * never a symlink itself, so O_NOFOLLOW stays honored for real
         * guest symlinks. */
        if (r == -ELOOP && cng_g_l2s && nr == __NR_openat &&
            ((int)a2 & CNG_O_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                r = reissue(CNG_AT_FDCWD, (long)data, a2, a3, a4, a5,
                            __NR_openat);
        }
        if ((r == -EACCES || r == -EPERM) && nr == __NR_openat)
            r = cng_fd_reopen(p, a2, a3, r);
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
        /* faccessat2 has a real flags word, so unlike its predecessor it can ask
         * about the symlink itself. Resolving the final component here would
         * hand the kernel the target and answer for the wrong file. */
        int deref = 1;
#ifdef __NR_faccessat2
        if (nr == __NR_faccessat2 && ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW))
            deref = 0;
#endif
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        long fl = a3;
        long dfd = a0;
#ifdef __NR_faccessat2
        /* faccessat2 with AT_SYMLINK_NOFOLLOW on an l2s name must report on
         * the backing file — to the guest, the name IS a regular file. */
        char fdata[CNG_PATH_MAX];
        if (nr == __NR_faccessat2 && cng_g_l2s &&
            ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
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
        if (ro_denied(p))
            return -EROFS;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }

    /* fchmodat2(dirfd, path, mode, flags): same as fchmodat but with a real
     * flags word, so unlike its predecessor it can chmod a symlink itself. */
#ifdef __NR_fchmodat2
    case __NR_fchmodat2: {
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (ro_denied(p))
            return -EROFS;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }
#endif

    /* unlinkat: on removing one of our link2symlink names, drop the group's
     * refcount (and reclaim the backing file on the last reference). */
    case __NR_unlinkat: {
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0;
        if (cng_g_l2s && !((int)a2 & CNG_AT_REMOVEDIR)) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1)
                dec = 1;
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        if (ro_denied(p))
            return -EROFS;
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
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
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
        if (ro_denied(p))
            return -EROFS;
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
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
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
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
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
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return chattr_result(reissue(CNG_AT_FDCWD, (long)data, a2, a3,
                                             0, a5, __NR_fchownat));
        }
        int deref = !((int)a4 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (ro_denied(p))
            return -EROFS;
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
            if (cng_resolve_at(a0, gp, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return -EINVAL;
        }
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_readlinkat);
        /* An fd link reports a HOST path (the kernel names the open file
         * description), and a map_files link the host path of the mapped file.
         * Map them back into the guest view so the guest never sees where its
         * rootfs really lives — `ls -l /proc/self/fd`, Alpine's /dev/fd, and
         * lsof's map_files walk all land here. Targets outside the view
         * (memfd:, pipe:[..], a host-only file) are left exactly as the kernel
         * wrote them. */
        if (r > 0 && r < (long)a3 && *(char *)a2 == '/' &&
            rl_may_fdlink(a0, gp)) {
            char canon[CNG_PATH_MAX];
            if (at_canon(a0, gp, canon, sizeof canon) == 0) {
                size_t pl = proc_pid_prefix(canon, 0);
                if (pl && (!strncmp(canon + pl, "fd/", 3) ||
                           !strncmp(canon + pl, "map_files/", 10))) {
                    char tgt[CNG_PATH_MAX], guest[CNG_PATH_MAX];
                    if ((size_t)r < sizeof tgt) {
                        memcpy(tgt, (const char *)a2, (size_t)r);
                        tgt[r] = '\0';
                        if (cng_fs_untranslate(cng_g_fs, tgt, guest,
                                               sizeof guest) == 0) {
                            size_t gl = strlen(guest);
                            if (gl > (size_t)a3)
                                gl = (size_t)a3;
                            memcpy((char *)a2, guest, gl);
                            r = (long)gl;
                        }
                    }
                }
            }
        }
        return r;
    }

    /* symlinkat(target, newdirfd, linkpath): translate only the linkpath. */
    case __NR_symlinkat: {
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2, 0);
        if (ro_denied(lp))
            return -EROFS;
        return reissue(a0, a1, (long)lp, a3, a4, a5, __NR_symlinkat);
    }

    /* fchown(fd,...): no path — try the real change, fake success under fake-root
     * (apk fchown()s each extracted file to root and a non-root app gets EPERM).
     * Routed through reissue so an Android-blocked fchown emulates ENOSYS rather
     * than trapping from the handler (fchown is in the block-list probe set). */
    /* fchmod(fd): the same fail-soft. A guest that opens a file and chmods the
     * descriptor (tar, cp -p, install) has no path for the fchmodat branch to
     * catch, so without this the fake root saw EPERM where the path form
     * succeeded. */
    case __NR_fchown:
    case __NR_fchmod:
        return chattr_result(reissue(a0, a1, a2, a3, a4, a5, nr));

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
     * ours, re-read so a filtered 0 isn't mistaken for end-of-directory.
     * Then splice in the entries that exist only as resolution overlays (bind
     * mount points, /dev nodes) and so have no physical dirent to return. */
    case __NR_getdents64: {
        /* Injection belongs at the start of the stream and only there, so the
         * decision is taken before the read: lseek(SEEK_CUR) == 0 means nothing
         * has been read from this fd yet. Deciding it up front also means an
         * empty directory (n == 0 below) still gets its overlay entries. */
        char injdir[CNG_PATH_MAX];
        int inject = a1 && sys_lseek((int)a0, 0, CNG_SEEK_CUR) == 0 &&
                     dirfd_guest_dir(a0, injdir, sizeof injdir) == 0;

        long n = reissue(a0, a1, a2, a3, a4, a5, __NR_getdents64);
        if (n < 0 || !a1)
            return n;
        if (n == 0)
            return inject ? inject_dents(a0, injdir, (char *)a1, 0, (long)a2)
                          : 0;
        /* Hidden-process view, listing side: the path layer makes a host
         * process's /proc entry unreachable, but `ls /proc` and `ps` read the
         * directory, so the numeric entries have to go as well. Deciding that
         * costs a readlink of the fd, so it is asked only when this batch
         * actually holds a numeric name — outside /proc almost nothing does. */
        int at_proc = !cng_g_no_proc && dents_have_pid((const char *)a1, n) &&
                      fd_is_host_proc(a0);
        if (!cng_g_l2s && !at_proc)
            return inject ? n + inject_dents(a0, injdir, (char *)a1, n,
                                             (long)a2)
                          : n;
        int at_root = cng_g_l2s && fd_is_rootfs_root(a0);
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
                int hide = (cng_g_l2s && (cng_l2s_hidden(nm) ||
                                          (at_root && !strcmp(nm, ".l2s")))) ||
                           (at_proc && !proc_name_visible(nm));
                if (!hide) {
                    if (w != o)
                        memmove(buf + w, buf + o, reclen);
                    w += reclen;
                }
                o += reclen;
            }
            if (w > 0)
                return inject ? w + inject_dents(a0, injdir, buf, w, (long)a2)
                              : w;
            n = reissue(a0, a1, a2, a3, a4, a5, __NR_getdents64);
            /* A real end-of-directory (0) still owes the overlay entries. */
            if (n <= 0)
                return (n == 0 && inject)
                           ? inject_dents(a0, injdir, buf, 0, (long)a2)
                           : n;
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
    /* clone: trapped for process creation only (a thread keeps CLONE_VM and
     * runs natively). CLONE_VM|CLONE_VFORK are stripped — our execve is
     * emulated in-process, so a child sharing our address space would corrupt
     * it — and the parent then publishes the child into the PID registry, which
     * is what makes the new process visible as a guest one. The child cannot do
     * this itself: nothing guarantees it makes another traced syscall before
     * something reads its /proc entry. */
    case __NR_clone: {
        /* Decided from the flags the guest asked for, before the conversion
         * below erases CLONE_VFORK. */
        int ev = cng_pt_clone_event((unsigned long)a0);
        /* Sampled before the clone: in the child the per-task lookup is keyed
         * by a tid that has no entry yet, so it would answer NULL. The frame
         * itself is on the trampoline's stack, which the child inherits at the
         * same address. */
        struct cng_uregs *ur = cng_pt_cur_regs();
        long flags = a0 & ~(long)(CNG_CLONE_VM | CNG_CLONE_VFORK);
        long r = cng_syscall6(flags, a1, a2, a3, a4, a5, __NR_clone);
        if (r > 0) {
            cng_procreg_fork((int)r);
            if (ur) {
                cng_pt_report_event(ur, ev, (u64)r);
                /* Our fork does not suspend the parent the way a real vfork
                 * would, so "vfork done" is reported as soon as the child is. */
                if (a0 & CNG_CLONE_VFORK)
                    cng_pt_report_event(ur, CNG_PTRACE_EVENT_VFORK_DONE, (u64)r);
            }
        } else if (r == 0) {
            cng_shm_fork_child(); /* the child inherited our shm attaches */
            if (ur)
                cng_pt_fork_child(ur, ev);
        }
        return r;
    }

    /* System V shared memory. Android's seccomp filter denies all four
     * outright, so they are served from the broker instead of the host kernel
     * — see shm.c. Trapped unconditionally (seccomp.c), so the guest gets one
     * shm namespace whatever the host's own SysV IPC would have allowed. */
#ifdef __NR_shmget
    case __NR_shmget:
#endif
#ifdef __NR_shmat
    case __NR_shmat:
#endif
#ifdef __NR_shmdt
    case __NR_shmdt:
#endif
#ifdef __NR_shmctl
    case __NR_shmctl:
#endif
    {
        long r = cng_shm_handle(nr, a0, a1, a2);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] sysv-shm nr=%ld -> %ld\n", nr, r);
        return r;
    }


    /* The read family is trapped only for fds in the reserved synthesized
     * range (the seccomp filter compares fd against cng_g_synth_fd_base),
     * where a read starting at offset 0 regenerates a time-varying file —
     * procps opens /proc/loadavg once and lseek(0)+rereads it every cycle.
     * Any other fd that lands in the range just gets re-issued. The p-variants
     * carry their offset in a3 (LP64: the full offset in pos_l; -1 means the
     * current position, which pre_read resolves with an lseek). */
    case __NR_read:
    case __NR_readv:
        /* A netlink stand-in is a socketpair end, so the read itself works —
         * but a request the guest submitted with untrapped write(2) must be
         * served first or this read blocks on an empty queue (busybox ip under
         * the -R tier; the seccomp tier never traps read on ordinary fds). */
        cng_nl_poke((int)a0);
        cng_procfs_pre_read((int)a0, -1);
        return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
    case __NR_pread64:
    case __NR_preadv:
#ifdef __NR_preadv2
    case __NR_preadv2:
#endif
        cng_procfs_pre_read((int)a0, a3);
        return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);

    /* execve/execveat: only reached via an M8 trampoline (-R); the SIGSYS path
     * intercepts them in cng_sigsys_body (it must rewrite the signal context).
     * Emulate in-process — re-issuing the raw syscall would exec the
     * untranslated guest path on the host (ENOENT), or worse, succeed and wipe
     * the monitor. On success cng_execve_tramp enters the new program and never
     * returns; on failure return -errno like a real execve. */
    case __NR_execve:
        return cng_execve_tramp(CNG_AT_FDCWD, (const char *)a0, (char **)a1,
                                (char **)a2, 0);
#ifdef __NR_execveat
    case __NR_execveat:
        return cng_execve_tramp((int)a0, (const char *)a1, (char **)a2,
                                (char **)a3, (int)a4);
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
        /* A rename unlinks the old name and creates the new one, so either end
         * under a :ro bind is EROFS. */
        if (ro_denied(op) || ro_denied(np))
            return -EROFS;
        int exch = (nr == __NR_renameat2 && ((int)a4 & CNG_RENAME_EXCHANGE));
        char data[CNG_PATH_MAX], absdata[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0, fix = 0;
        if (cng_g_l2s && !exch && strcmp(op, np) != 0 &&
            cng_resolve_at(a2, (const char *)a3, 0, dsth, sizeof dsth) == 0) {
            if (cng_l2s_resolve(dsth, data, sizeof data, &cnt) == 1)
                dec = 1;
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0)
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
        } else if (cng_resolve_at(a0, sp, follow, srch, sizeof srch) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: src unresolved (%s)\n",
                            sp ? sp : "(null)");
            return -ENOENT;
        }
        if (cng_resolve_at(a2, (const char *)a3, 0, dsth, sizeof dsth) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: dst unresolved (%s)\n",
                            a3 ? (const char *)a3 : "(null)");
            return -ENOENT;
        }
        /* Only the new name is created, so only the destination end matters —
         * linking *from* a read-only mount is allowed, as on Linux. Checked
         * after both ends resolve so a bad source still reports ENOENT. */
        if (ro_denied(dsth))
            return -EROFS;
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
    /* socket(): where the host denies app domains rtnetlink — Android does —
     * hand back an emulated NETLINK_ROUTE socket instead of the kernel's
     * refusal, so getifaddrs/iproute2/bubblewrap keep working. Every other
     * socket runs native. */
    case __NR_socket: {
        long fd = cng_nl_socket(a0, a1, a2);
        if (fd >= 0)
            return fd;
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        /* The same policy denies NETLINK_AUDIT, which is not emulated but does
         * need the refusal libaudit's callers survive: a permission error there
         * aborts every shadow-utils tool (`useradd`, `su`), while "no audit in
         * this kernel" is a case they all handle. */
        return cng_nl_audit_refusal(a0, a2, r);
    }

    /* AF_UNIX addresses. A pathname socket's sun_path is a filesystem path and
     * gets the same containment as any other: translated on the way out, mapped
     * back to guest spelling on the way in. bind() keeps the final component
     * literal (it is the name being created); connect/sendto follow it. The
     * translated address lives in our own buffer, so the guest's is untouched. */
    case __NR_bind:
    case __NR_connect:
    case __NR_sendto: {
        /* An emulated netlink socket: bind is a silent success (the guest is
         * binding a netlink address we do not really have), and a send is the
         * request whose reply the matching recv will drain. */
        if (cng_nl_is_fake((int)a0)) {
            if (nr == __NR_bind || nr == __NR_connect)
                return 0;
            long out = 0;
            if (cng_nl_send((int)a0, (const void *)a1, a2, &out))
                return out;
            return 0;
        }
        int is_send = (nr == __NR_sendto);
        long aa = is_send ? a4 : a1;   /* sockaddr */
        long al = is_send ? a5 : a2;   /* addrlen */
        struct cng_sun_xlate x;
        long r;
        if (cng_sun_in(&x, (const void *)aa, al, nr != __NR_bind)) {
            if (is_send)
                r = reissue(a0, a1, a2, a3, (long)x.buf, x.len, nr);
            else
                r = reissue(a0, (long)x.buf, x.len, a3, a4, a5, nr);
        } else {
            r = reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        cng_sun_done(&x); /* after the syscall: the kernel walked the dirfd */
        return r;
    }

    /* sendmsg: the address hangs off msg_name in the msghdr, so the header is
     * copied to swap that pointer — the guest's own struct is never written. */
    case __NR_sendmsg: {
        /* The msghdr is read here, ahead of any kernel call that would have
         * validated it, so a bad one must answer -EFAULT rather than fault. */
        if (a1 && !cng_user_readable((void *)a1, sizeof(struct cng_msghdr)))
            return -EFAULT;
        if (cng_nl_is_fake((int)a0)) {
            /* The payload is the first iovec; netlink requests are single-iov
             * in every library that builds them. */
            long out = 0;
            const char *m = (const char *)a1;
            if (m) {
                struct cng_iovec *iov = *(struct cng_iovec **)(m + 16);
                unsigned long nio = *(unsigned long *)(m + 24);
                if (iov && nio > 0 &&
                    !cng_user_readable(iov, sizeof *iov))
                    return -EFAULT;
                if (iov && nio > 0)
                    cng_nl_send((int)a0, iov[0].base, (long)iov[0].len, &out);
            }
            return out;
        }
        struct cng_sun_xlate x;
        char mh[56];
        long r;
        x.dirfd = -1; /* a NULL msghdr never reaches cng_sun_in, and cng_sun_done
                       * must not then close whatever the stack held */
        if (a1 && cng_sun_in(&x, *(void **)(char *)a1,
                             (long)*(unsigned *)((char *)a1 + 8), 1)) {
            memcpy(mh, (const void *)a1, sizeof mh);
            *(void **)mh = x.buf;
            *(unsigned *)(mh + 8) = (unsigned)x.len;
            r = reissue(a0, (long)mh, a2, a3, a4, a5, nr);
        } else {
            r = reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        cng_sun_done(&x);
        return r;
    }

    /* sendmmsg: sendmsg's array form, and one msg_name per message is the whole
     * of what it adds. The call exists to spend one syscall on a batch — UDP is
     * what it is for — so a batch carrying no AF_UNIX address is re-issued
     * whole and costs a scan. Only when a message really does carry one is the
     * array taken apart into per-message sendmsg calls, which is what the
     * kernel's own loop does anyway: send until one fails, write each msg_len
     * back as it goes, report the count if any went out and the error only if
     * none did. The guest's array is never rewritten — each translated header is
     * a copy, exactly as in sendmsg above.
     *
     * (An emulated netlink socket needs nothing here: a native sendmmsg puts the
     * request datagrams into the stand-in socketpair, which is the same route an
     * untrapped write(2) takes, and the matching receive serves them.) */
    case __NR_sendmmsg: {
        struct cng_mmsghdr *v = (struct cng_mmsghdr *)a1;
        unsigned long vlen = (unsigned)a2;
        if (vlen > CNG_UIO_MAXIOV) /* as the kernel clamps it */
            vlen = CNG_UIO_MAXIOV;
        if (!v || !vlen)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        /* A socket that is not AF_UNIX cannot carry a sun_path at all, and a UDP
         * batch is what this call exists for — so ask the socket once instead of
         * reading up to 1024 addresses out of guest memory to find that out.
         * (Each of those reads has to be probed first, since a fault in the
         * handler is unblockable, and a probe is itself a syscall: the whole
         * point of sendmmsg is not to spend one per message.) */
        int dom = 0;
        unsigned dlen = sizeof dom;
        if (CNG_SYS(__NR_getsockopt, a0, CNG_SOL_SOCKET, CNG_SO_DOMAIN, &dom,
                    &dlen, 0) == 0 &&
            dom != CNG_AF_UNIX)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        /* One probe for the whole array where it is all readable, which is the
         * usual case; per element otherwise, since the kernel stops at the first
         * unreadable one rather than refusing the batch. */
        int whole = cng_user_readable(v, vlen * sizeof *v);
        int any = 0;
        for (unsigned long i = 0; i < vlen; i++) {
            if (!whole && !cng_user_readable(&v[i], sizeof v[i]))
                break; /* the kernel never gets past here either */
            if (cng_sun_needed(v[i].hdr.name, (long)v[i].hdr.namelen)) {
                any = 1;
                break;
            }
        }
        if (!any)
            return reissue(a0, a1, a2, a3, a4, a5, nr);

        unsigned long sent = 0;
        long r = 0;
        for (unsigned long i = 0; i < vlen; i++) {
            if (!whole && !cng_user_readable(&v[i], sizeof v[i])) {
                r = -EFAULT;
                break;
            }
            struct cng_msghdr mh = v[i].hdr;
            struct cng_sun_xlate x;
            if (cng_sun_in(&x, mh.name, (long)mh.namelen, 1)) {
                mh.name = x.buf;
                mh.namelen = (unsigned)x.len;
            }
            r = reissue(a0, (long)&mh, a3, 0, 0, 0, __NR_sendmsg);
            cng_sun_done(&x);
            if (r < 0)
                break;
            /* The kernel does not count a message whose length writeback
             * faults, even though it has already gone out. Neither do we. */
            if (!cng_user_writable(&v[i].len, sizeof v[i].len)) {
                r = -EFAULT;
                break;
            }
            v[i].len = (unsigned)r;
            sent++;
        }
        return sent ? (long)sent : r;
    }

    /* The readback side. The kernel writes a HOST sun_path here; handing that to
     * the guest leaks where the rootfs lives and breaks any program comparing it
     * against what it bound. The address is fetched into a buffer of ours and
     * delivered by addr_out, which reproduces the kernel's own truncation rule
     * over the *translated* address — see the note there for why the guest's own
     * buffer cannot be translated in place. */
    case __NR_getsockname:
    case __NR_getpeername:
    case __NR_accept:
    case __NR_accept4:
    case __NR_recvfrom: {
        int is_recv = (nr == __NR_recvfrom);
        long aa = is_recv ? a4 : a1;
        long alp = is_recv ? a5 : a2;
        if (cng_nl_is_fake((int)a0)) {
            if (is_recv) {
                long out = 0;
                cng_nl_recv((int)a0, (void *)a1, a2, a3, &out);
                if (aa && alp)
                    cng_nl_srcaddr((int)a0, (void *)aa, (unsigned *)alp);
                return out;
            }
            /* getsockname/getpeername must report a sockaddr_nl: the real
             * AF_UNIX answer is 2 bytes and iproute2 refuses it. */
            if (cng_nl_getname((int)a0, (void *)aa, (unsigned *)alp))
                return 0;
        }
        if (!aa || !alp) /* no address wanted: nothing to translate */
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        char ab[CNG_SOCKADDR_MAX];
        unsigned al = sizeof ab;
        long r = is_recv ? reissue(a0, a1, a2, a3, (long)ab, (long)&al, nr)
                         : reissue(a0, (long)ab, (long)&al, a3, a4, a5, nr);
        if (r < 0)
            return r;
        long e = sun_deliver(ab, al, aa, alp);
        if (e) {
            /* accept has already created the descriptor. The kernel drops it
             * when the address writeback fails rather than returning an fd the
             * caller never learned the peer of, so this must too. */
            if (nr == __NR_accept || nr == __NR_accept4)
                sys_close((int)r);
            return e;
        }
        return r;
    }

    case __NR_recvmsg: {
        if (cng_nl_is_fake((int)a0)) {
            long out = 0;
            char *m = (char *)a1;
            if (m && !cng_user_readable(m, sizeof(struct cng_msghdr)))
                return -EFAULT;
            if (m) {
                struct cng_iovec *iov = *(struct cng_iovec **)(m + 16);
                unsigned long nio = *(unsigned long *)(m + 24);
                if (iov && nio > 0 && !cng_user_readable(iov, sizeof *iov))
                    return -EFAULT;
                if (iov && nio > 0)
                    cng_nl_recv((int)a0, iov[0].base, (long)iov[0].len, a2,
                                &out);
                void *name = *(void **)m;
                unsigned *nlp = (unsigned *)(m + 8);
                if (name && nlp)
                    cng_nl_srcaddr((int)a0, name, nlp);
            }
            return out;
        }
        /* msg_name is an output buffer of the guest's, so it gets the same
         * bounce the single-address calls get. The header is copied to point at
         * ours; the three fields the kernel writes back into the header it was
         * given (msg_namelen, msg_controllen, msg_flags) then have to be carried
         * over to the guest's own, or a caller loses MSG_TRUNC/MSG_CTRUNC and
         * the length of the control data it is about to walk. */
        struct cng_msghdr *g = (struct cng_msghdr *)a1;
        if (!a1 || !cng_user_readable(g, sizeof *g))
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        struct cng_msghdr snap = *g; /* the guest's header, before any probe */
        if (!snap.name || !snap.namelen)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        char ab[CNG_SOCKADDR_MAX];
        struct cng_msghdr mh = snap;
        mh.name = ab;
        mh.namelen = sizeof ab;
        long r = reissue(a0, (long)&mh, a2, a3, a4, a5, nr);
        if (r < 0)
            return r;
        /* Restored whole rather than field by field: the writability probe
         * zeroes what it validates, so a partial update would leave the rest of
         * the guest's header zeroed. */
        if (!cng_user_writable(g, sizeof *g))
            return -EFAULT;
        *g = snap;
        g->controllen = mh.controllen;
        g->flags = mh.flags;
        long e = sun_deliver(ab, mh.namelen, (long)snap.name, (long)&g->namelen);
        return e ? e : r;
    }

    /* recvmmsg: the readback side of the array forms. A source address cannot be
     * mapped back in the guest's own buffer (see addr_out), so an AF_UNIX batch
     * is taken apart into per-message recvmsg calls, each with the bounce the
     * single form uses — which is what the kernel's own loop does anyway. Only
     * AF_UNIX pays for that: no other family can carry a sun_path, so the socket
     * is asked once and everything else is re-issued whole and left untouched. */
    case __NR_recvmmsg: {
        struct cng_mmsghdr *v = (struct cng_mmsghdr *)a1;
        unsigned long vlen = (unsigned)a2;
        if (vlen > CNG_UIO_MAXIOV)
            vlen = CNG_UIO_MAXIOV;

        /* An emulated netlink socket has to be taken apart per message instead:
         * its replies are built on demand, and a client discards any whose
         * source address is not the kernel's — which means msg_name must be
         * filled by cng_nl_srcaddr from the guest's own buffer length, not
         * overwritten by the socketpair's AF_UNIX answer first. The timeout is
         * not honored (a reply is already waiting or is never coming); the
         * MSG_WAITFORONE rule is, since without it a batch larger than the
         * pending replies would block on a socket nothing else will feed. */
        if (cng_nl_is_fake((int)a0) && v && vlen) {
            unsigned long got = 0;
            long r = 0;
            for (; got < vlen; got++) {
                struct cng_mmsghdr *m = &v[got];
                if (!cng_user_readable(m, sizeof *m)) {
                    r = -EFAULT;
                    break;
                }
                struct cng_iovec *iov = m->hdr.iov;
                if (!iov || !m->hdr.iovlen ||
                    !cng_user_readable(iov, sizeof *iov)) {
                    r = -EFAULT;
                    break;
                }
                long fl = a3 & ~(long)CNG_MSG_WAITFORONE;
                if (got && (a3 & CNG_MSG_WAITFORONE))
                    fl |= CNG_MSG_DONTWAIT;
                long out = 0;
                cng_nl_recv((int)a0, iov[0].base, (long)iov[0].len, fl, &out);
                if (out < 0) {
                    r = out;
                    break;
                }
                if (!cng_user_writable(&m->len, sizeof m->len)) {
                    r = -EFAULT;
                    break;
                }
                m->len = (unsigned)out;
                if (m->hdr.name)
                    cng_nl_srcaddr((int)a0, m->hdr.name, &m->hdr.namelen);
            }
            return got ? (long)got : r;
        }

        /* One question to the socket instead of a scan of the array: a family
         * other than AF_UNIX has no sun_path to map back, and a UDP batch is
         * what this call exists for. (The same shortcut sendmmsg takes.) */
        int dom = 0;
        unsigned dlen = sizeof dom;
        if (!v || !vlen ||
            (CNG_SYS(__NR_getsockopt, a0, CNG_SOL_SOCKET, CNG_SO_DOMAIN, &dom,
                     &dlen, 0) == 0 &&
             dom != CNG_AF_UNIX))
            return reissue(a0, a1, a2, a3, a4, a5, nr);

        /* Per message from here. The kernel blocks for the whole batch unless
         * MSG_WAITFORONE, and bounds that with the timeout argument; a loop of
         * recvmsg calls has no timeout to give, so a batch that carries one
         * behaves as if it had asked for MSG_WAITFORONE — returning early, never
         * blocking past where the kernel would have stopped. */
        int first_only = (a3 & CNG_MSG_WAITFORONE) != 0 || a4 != 0;
        unsigned long got = 0;
        long r = 0;
        for (; got < vlen; got++) {
            struct cng_mmsghdr *m = &v[got];
            if (!cng_user_readable(m, sizeof *m)) {
                r = -EFAULT;
                break;
            }
            char ab[CNG_SOCKADDR_MAX];
            struct cng_msghdr snap = m->hdr; /* before any probe zeroes it */
            struct cng_msghdr mh = snap;
            if (snap.name) {
                mh.name = ab;
                mh.namelen = sizeof ab;
            }
            long fl = a3 & ~(long)CNG_MSG_WAITFORONE;
            if (got && first_only)
                fl |= CNG_MSG_DONTWAIT;
            long n = reissue(a0, (long)&mh, fl, 0, 0, 0, __NR_recvmsg);
            if (n < 0) {
                r = n;
                break;
            }
            if (!cng_user_writable(m, sizeof *m)) {
                r = -EFAULT;
                break;
            }
            m->hdr = snap; /* the probe zeroed it: restore, then update */
            m->hdr.controllen = mh.controllen;
            m->hdr.flags = mh.flags;
            m->len = (unsigned)n;
            if (snap.name) {
                long e = sun_deliver(ab, mh.namelen, (long)snap.name,
                                     (long)&m->hdr.namelen);
                if (e) {
                    r = e; /* the message is consumed either way, as it is
                            * for the single form */
                    break;
                }
            }
        }
        /* Whatever arrived is reported; the error only if nothing did. */
        return got ? (long)got : r;
    }

    /* getsockopt(SOL_SOCKET, SO_PEERCRED): the kernel reports the real invoking
     * uid/gid for the peer, but a guest daemon compares it against its own
     * getuid(), which under --fake-id is the fake identity. Remap the pair
     * through the same rule stat uses. The pid is deliberately left alone: guest
     * pid == host pid here, so it is already correct. Trapped only under
     * --fake-id. */
    case __NR_getsockopt: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0 && cng_g_fake_id && a1 == CNG_SOL_SOCKET &&
            a2 == CNG_SO_PEERCRED && a3 && a4 &&
            *(unsigned *)a4 >= 12) { /* struct ucred: pid,uid,gid */
            unsigned *uc = (unsigned *)a3;
            uc[1] = cng_remap_uid(uc[1]);
            uc[2] = cng_remap_gid(uc[2]);
        }
        return r;
    }

    /* Extended attributes: the path is a0 and there is no dirfd, so this is a
     * plain translate + reissue. The "l" forms do not follow a final symlink;
     * the setters and removers mutate, so a :ro bind refuses them. */
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr: {
        int deref = !(nr == __NR_lsetxattr || nr == __NR_lgetxattr ||
                      nr == __NR_llistxattr || nr == __NR_lremovexattr);
        int writes = (nr == __NR_setxattr || nr == __NR_lsetxattr ||
                      nr == __NR_removexattr || nr == __NR_lremovexattr);
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, deref);
        if (writes && ro_denied(p))
            return -EROFS;
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_truncate:
    case __NR_statfs: {
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, 1);
        if (nr == __NR_truncate && ro_denied(p)) /* statfs only reads */
            return -EROFS;
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_chdir: {
        const char *gp = (const char *)a0;
        const char *hp = xlate(CNG_AT_FDCWD, gp, b1, sizeof b1, 1);
        long r = reissue((long)hp, 0, 0, 0, 0, 0, __NR_chdir);
        if (r == 0) {
            char gc[CNG_PATH_MAX];
            /* Record where the chdir LANDED, not what was typed: the kernel's
             * cwd is the directory itself, so getcwd reports the symlink-free
             * name and a later ".." backs out of the real parent. Falls back to
             * the lexical form only for a directory outside the guest view. */
            if (cng_fs_untranslate(cng_g_fs, hp, gc, sizeof gc) == 0 ||
                cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) == 0) {
                cng_fs_set_cwd(cng_g_fs, gc);
                cng_procreg_set_cwd(cng_g_fs->cwd); /* /proc/<pid>/cwd */
            }
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
                cng_fs_untranslate(cng_g_fs, hc, gc, sizeof gc) == 0) {
                cng_fs_set_cwd(cng_g_fs, gc);
                cng_procreg_set_cwd(cng_g_fs->cwd);
            }
        }
        return r;
    }

    case __NR_getcwd: {
        char *buf = (char *)a0;
        unsigned long size = (unsigned long)a1;
        size_t len = strlen(cng_g_fs->cwd) + 1;
        /* ERANGE is decided before the buffer is touched, as the kernel does —
         * which also keeps the write probe's zeroing invisible: it only ever
         * runs immediately before the copy that overwrites it. */
        if (len > size)
            return -ERANGE;
        if (!cng_user_writable(buf, len))
            return -EFAULT;
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
        /* chroot(2) needs CAP_SYS_CHROOT, which for us means the guest's
         * effective uid is 0 under --fake-id. Ungated, an unprivileged guest
         * could move its own root where a real kernel would have refused —
         * a privilege check the guest's own code may be relying on (a daemon
         * that drops privileges and then expects chroot to fail). The /proc
         * passthrough surviving into the new root is a deliberate divergence:
         * a real chroot leaves /proc unmounted, but a guest that cannot see
         * /proc cannot run apk's package scripts, which chroot(".") first. */
        if (!cng_fake_root())
            return -EPERM;
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
    case __NR_rt_sigaction: {
        if ((int)a0 == CNG_SIGSYS)
            return 0;
        /* While the task is traced, ptsig.c owns the real disposition of every
         * signal (a tracee must stop before its own handler runs), and it owns
         * the kick signal's slot always. It answers from its mirror of what the
         * guest asked for; otherwise it just records and lets this through. */
        long ptr;
        if (cng_pt_sigaction((int)a0, (u64)a1, (u64)a2, (u64)a3, &ptr))
            return ptr;
        if (a1) {
            unsigned char act[32];
            if (!cng_user_readable((void *)a1, sizeof act))
                return -EFAULT;
            memcpy(act, (void *)a1, sizeof act);
            *(unsigned long *)(act + 24) &= ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)act, a2, a3, a4, a5,
                                __NR_rt_sigaction);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigaction);
    }

    /* ---- ptrace(2) and the syscalls its emulation has to account for ----
     *
     * ptrace is trapped for every guest (it is the only way to see a
     * PTRACE_TRACEME, and no ordinary program calls it); the rest are trapped
     * only on tasks that have entered a ptrace role, by the filter stacked in
     * cng_pt_arm_tracer/tracee. See src/monitor/ptrace.c. */
    case __NR_ptrace:
        return cng_pt_syscall(a0, a1, (u64)a2, (u64)a3);

    case __NR_wait4:
        return cng_pt_wait4(a0, (u64)a1, a2, (u64)a3, cng_pt_cur_uc());

    case __NR_waitid:
        return cng_pt_waitid(a0, a1, (u64)a2, a3, (u64)a4, cng_pt_cur_uc());

    /* A stop signal aimed at a tracee becomes a cooperative group-stop: a real
     * SIGSTOP would freeze it inside its ptrace service loop, and every later
     * tracer request would deadlock (strace sends exactly that on ^C). SIGCONT
     * ends a PTRACE_LISTEN group-stop the same way. Everything else, and every
     * target that is not a tracee, is sent for real. */
    case __NR_kill:
        if (cng_pt_signal_route(a0, (int)a1))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    case __NR_tkill:
        if (cng_pt_signal_route(a0, (int)a1))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    case __NR_tgkill:
        if (cng_pt_signal_route(a1, (int)a2))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);

    /* strace reads tracee memory with these before falling back to PEEKDATA.
     * When the peer is one of our stopped tracees they are served from the
     * ptrace mailbox, because the host has no reason to believe the caller is
     * attached to it and may refuse (Yama ptrace_scope, SELinux). Any other
     * peer runs natively. */
    case __NR_process_vm_readv:
    case __NR_process_vm_writev: {
        long out;
        if (cng_pt_vm_rw(nr, a0, (u64)a1, (u64)a2, (u64)a3, (u64)a4, &out))
            return out;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* exit/exit_group are trapped only on a tracee (the trap-everything
     * filter). The death has to reach the tracer: PTRACE_EVENT_EXIT first if it
     * asked for one, then either a synthetic exit in the registry or a plain
     * link drop when the tracer is our parent and reaps us for real. */
    case __NR_exit:
    case __NR_exit_group: {
        int wstatus = ((int)a0 & 0xff) << 8;
        struct cng_uregs *ur = cng_pt_cur_regs(); /* either tier's frame */
        if (ur)
            cng_pt_exit_stop(ur, wstatus);
        cng_pt_exit_report(wstatus);
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* rt_sigprocmask on the trampoline path (the SIGSYS path handles it via
     * uc_sigmask): apply the mask but never block SIGSYS. */
    case __NR_rt_sigprocmask: {
        int how = (int)a0;
        if ((how == 0 /*BLOCK*/ || how == 2 /*SETMASK*/) && a1) {
            if (!cng_user_readable((void *)a1, sizeof(unsigned long)))
                return -EFAULT;
            unsigned long set = *(unsigned long *)a1 & ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)&set, a2, a3, a4, a5,
                                __NR_rt_sigprocmask);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigprocmask);
    }

    /* ioctl, trapped only for the SIOCxIF request band (seccomp.c tests the
     * request in BPF, so every other ioctl runs native). The interface getters
     * are answered from the same enumeration the netlink dumps are built on —
     * a guest told by `ip addr` that it has only loopback must not be shown the
     * host's whole interface list by `ifconfig`. The setters and anything else
     * in the band fall through to the host, which refuses them to an
     * unprivileged process exactly as it should. */
    case __NR_ioctl: {
        long r = 0;
        if (cng_nl_ioctl((int)a0, (unsigned long)a1, (void *)a2, &r))
            return r;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* uname: a fixed kernel identity (CNG_KREL/CNG_KVER), which /proc/version
     * repeats word for word. The host's release describes the device rather
     * than the rootfs — on Android it carries `-android14-11-...`/`-perf`
     * vendor suffixes that identify the phone — and a modern glibc rootfs
     * refuses to start on a release below its build-time minimum whatever else
     * is true. nodename and domainname are the host's: they name the machine
     * the guest really is on, which is what a guest expects to see and what
     * `hostname` reports either way. The buffer is six 65-byte fields
     * (__NEW_UTS_LEN + 1); the kernel filled and validated it just now. */
    case __NR_uname: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r != 0 || !a0)
            return r;
        char *u = (char *)a0;
        cng_strlcpy(u + 0 * 65, "Linux", 65);
        cng_strlcpy(u + 2 * 65, CNG_KREL, 65);
        cng_strlcpy(u + 3 * 65, CNG_KVER, 65);
        cng_strlcpy(u + 4 * 65, "aarch64", 65);
        return 0;
    }

    /* POSIX timers do not survive an execve, and ours is emulated — the address
     * space stays, so a timer would go on firing into a program that never
     * armed it, through a handler that no longer exists. Nothing enumerates a
     * process's timers, so the ids are recorded as they are handed out. */
    case __NR_timer_create: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0 && a2)
            cng_timer_note(*(int *)a2); /* the kernel just validated a2 */
        return r;
    }
    case __NR_timer_delete: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0)
            cng_timer_forget((int)a0);
        return r;
    }

    /* prctl: the four ops that describe OUR confinement rather than the guest's.
     * Only these are trapped (seccomp.c tests args[0] in BPF); every other op is
     * real process state and runs natively.
     *
     * The no_new_privs bit is ours — cng_install_seccomp sets it because a
     * filter cannot be installed without it — so the guest is told what it
     * itself asked for, not what we did. It survives fork (ordinary memory) and
     * our emulated execve, which is where a real one would keep it too. */
    case __NR_prctl: {
        static int guest_nnp = 0;
        switch ((int)a0) {
        case CNG_PR_GET_SECCOMP:
            /* Mode 2 is the filter WE installed. A sandbox that asks this to
             * find out whether it still has work to do would conclude it is
             * already confined and skip installing anything. */
            return 0;
        case CNG_PR_SET_SECCOMP:
            /* A second filter would also govern the syscalls the handler
             * re-issues through the gate, which the guest's filter has no way to
             * know about — one that kills on an unlisted syscall would take the
             * monitor down with it. EACCES is what a kernel answers when the
             * caller may not install a filter, and the callers that matter
             * (libseccomp, systemd, browser sandboxes) all have a path for it. */
            if (cng_g_debug)
                cng_dprintf(2, "[cng] prctl(PR_SET_SECCOMP) refused\n");
            return -EACCES;
        case CNG_PR_SET_NO_NEW_PRIVS:
            if (a1 != 1 || a2 || a3 || a4)
                return -EINVAL; /* the kernel's own argument check */
            guest_nnp = 1;
            return 0; /* already set for real, at install */
        case CNG_PR_GET_NO_NEW_PRIVS:
            return guest_nnp;
        }
        return reissue(a0, a1, a2, a3, a4, a5, nr);
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
        /* A tracee carries the trap-everything filter, so an unhandled syscall
         * here is an ordinary one that simply has to run — the Android-blocked
         * reading below does not apply, and the designed-ENOSYS set (which that
         * filter converts from the base filter's RET_ERRNO into a trap) has to
         * be refused by hand. */
        if (trapped && cng_pt_traceall()) {
            if (cng_denied_syscall(nr))
                return -ENOSYS;
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        }
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

/* The -R trampoline's entry point: one rewritten `svc` site, with a full
 * register frame the trampoline built on its own stack (see tramp.S).
 *
 * It is the SIGSYS handler's counterpart on a tier that has no signal frame,
 * and it exists so the two tiers behave the same for a ptrace tracee: the same
 * entry/exit stops around the syscall, the same register file for the tracer to
 * read and write, and the same single-step report. `trapped` is 0 here — an
 * unhandled syscall on this path is an ordinary one to re-issue, not one
 * Android blocked. */
void cng_tramp_dispatch(struct cng_uregs *r) {
    long nr = (long)r->x[8];
    cng_pt_set_frame(r, 0);
    if (!cng_pt_active()) {
        r->x[0] = (u64)cng_dispatch(nr, (long)r->x[0], (long)r->x[1],
                                    (long)r->x[2], (long)r->x[3], (long)r->x[4],
                                    (long)r->x[5], 0);
        return;
    }
    if (!cng_pt_syscall_entry(r, &nr)) {
        cng_pt_syscall_exit(r); /* cancelled: x0 is the tracer's own answer */
        return;
    }
    r->x[0] = (u64)cng_dispatch(nr, (long)r->x[0], (long)r->x[1], (long)r->x[2],
                                (long)r->x[3], (long)r->x[4], (long)r->x[5], 0);
    cng_pt_syscall_exit(r);
    cng_pt_step_report(r);
}
