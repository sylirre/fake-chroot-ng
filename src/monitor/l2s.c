/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* link2symlink backing-file scheme (see include/cng/l2s.h). Freestanding: raw
 * syscalls + the cng runtime string helpers only, so it is safe to run inside
 * the SIGSYS handler. Every path here is an already-resolved host path. */
#include "cng/l2s.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>
#include <asm-generic/errno.h>

int cng_g_l2s = 0;
int cng_g_l2s_force = 0;

#define L2S_PREFIX     ".l2s."
#define L2S_PREFIX_LEN 5

/* Failure-path diagnostics (CNG_DEBUG=1). */
#define L2S_LOG(...)                                                          \
    do {                                                                      \
        if (cng_g_debug)                                                      \
            cng_dprintf(2, __VA_ARGS__);                                      \
    } while (0)

/* aarch64 struct stat field offsets (see dispatch.c). */
#define ST_INO_OFF   8
#define ST_MODE_OFF  16
#define ST_NLINK_OFF 20
#define ST_SIZE      128
/* struct statx field offsets. */
#define STX_MASK_OFF  0
#define STX_NLINK_OFF 16
#define STX_MODE_OFF  28
#define STX_SIZE      256

#define S_IFMT_  0170000
#define S_IFLNK_ 0120000
#define S_IFREG_ 0100000
#define S_IFDIR_ 0040000

/* ---- raw-syscall wrappers (host paths) ---------------------------------- */

static long l2s_lstat(const char *p, void *st) {
    return CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, p, st, CNG_AT_SYMLINK_NOFOLLOW,
                   0, 0);
}
static long l2s_statf(const char *p, void *st) { /* follow */
    return CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, p, st, 0, 0, 0);
}
static long l2s_readlink(const char *p, char *b, size_t n) {
    return sys_readlinkat(CNG_AT_FDCWD, p, b, n);
}
static long l2s_symlink(const char *target, const char *linkpath) {
    return CNG_SYS(__NR_symlinkat, target, CNG_AT_FDCWD, linkpath, 0, 0, 0);
}
static long l2s_rename(const char *o, const char *n) {
    return CNG_SYS(__NR_renameat, CNG_AT_FDCWD, o, CNG_AT_FDCWD, n, 0, 0);
}
static long l2s_unlink(const char *p) {
    return CNG_SYS(__NR_unlinkat, CNG_AT_FDCWD, p, 0, 0, 0, 0);
}
static void l2s_touch(const char *p) {
    long fd = sys_openat(CNG_AT_FDCWD, p,
                         CNG_O_WRONLY | CNG_O_CREAT | CNG_O_CLOEXEC, 0600);
    if (fd >= 0)
        sys_close((int)fd);
}

static unsigned st_mode(const void *st) {
    return *(const unsigned *)((const char *)st + ST_MODE_OFF);
}
static int is_lnk(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFLNK_; }
static int is_reg(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFREG_; }
static int is_dir(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFDIR_; }

/* ---- name parsing / formatting ------------------------------------------ */

/* Parse a run of decimal digits: 1 (+ value, +end) if >=1 digit, else 0. */
static int parse_u64(const char *p, unsigned long long *out, const char **end) {
    unsigned long long v = 0;
    const char *s = p;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (unsigned)(*p - '0');
        p++;
    }
    if (p == s)
        return 0;
    if (out)
        *out = v;
    if (end)
        *end = p;
    return 1;
}

/* ".l2s.<ino>" exactly (data backing file). */
static int parse_data(const char *name, unsigned long long *ino) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    if (!parse_u64(name + L2S_PREFIX_LEN, ino, &end))
        return 0;
    return *end == '\0';
}

/* ".l2s.<ino>.<count>" (marker). */
static int parse_marker(const char *name, unsigned long long *ino,
                        unsigned long *count) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    unsigned long long v;
    if (!parse_u64(name + L2S_PREFIX_LEN, &v, &end) || *end != '.')
        return 0;
    unsigned long long c;
    if (!parse_u64(end + 1, &c, &end) || *end != '\0')
        return 0;
    if (ino)
        *ino = v;
    if (count)
        *count = (unsigned long)c;
    return 1;
}

int cng_l2s_hidden(const char *name) {
    return parse_data(name, 0) || parse_marker(name, 0, 0);
}

static const char *l2s_basename(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Directory portion of `path` into `dir` ("/" for a root child). */
static void l2s_dirname(const char *path, char *dir, size_t sz) {
    const char *s = strrchr(path, '/');
    if (!s || s == path) {
        cng_strlcpy(dir, "/", sz);
        return;
    }
    size_t dl = (size_t)(s - path);
    if (dl >= sz)
        dl = sz - 1;
    memcpy(dir, path, dl);
    dir[dl] = '\0';
}

/* Append an unsigned decimal, zero-padded to at least `width`, at *pp — storing
 * only what fits before `end`, but advancing *pp by the whole width either way.
 * That advance is what makes the caller's `p > end` test see an overflow: with
 * *pp stopped at `end` instead, a name whose digits did not fit came back
 * shortened and *valid*, so ".l2s.<ino>" silently became another group's
 * backing file rather than -ENAMETOOLONG. */
static void put_u64(char **pp, char *end, unsigned long long v, int width) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n < width)
        tmp[n++] = '0';
    char *p = *pp;
    while (n > 0) {
        if (p < end)
            *p = tmp[n - 1];
        n--;
        p++;
    }
    *pp = p;
}

/* "<dir>/.l2s.<ino>" (count < 0) or "<dir>/.l2s.<ino>.<count>" into out.
 * Returns 0 or -ENAMETOOLONG. */
static int build_name(char *out, size_t sz, const char *dir,
                      unsigned long long ino, long count) {
    char *p = out, *end = out + sz - 1;
    size_t dl = strlen(dir);
    int need_sep = !(dl && dir[dl - 1] == '/');
    p += cng_strlcpy(p, dir, (size_t)(end - p) + 1);
    if (p > end)
        return -ENAMETOOLONG;
    if (need_sep && p < end)
        *p++ = '/';
    p += cng_strlcpy(p, L2S_PREFIX, (size_t)(end - p) + 1);
    if (p >= end)
        return -ENAMETOOLONG;
    put_u64(&p, end, ino, 1);
    if (count >= 0) {
        if (p < end)
            *p++ = '.';
        put_u64(&p, end, (unsigned long long)count, 4);
    }
    if (p > end)
        return -ENAMETOOLONG;
    *p = '\0';
    return 0;
}

/* ---- directory scan for the marker -------------------------------------- */

/* linux_dirent64: d_ino(8) d_off(8) d_reclen(2 @16) d_type(1 @18) name(@19). */
static int find_marker(const char *dir, unsigned long long ino,
                       unsigned long *count) {
    long fd = sys_openat(CNG_AT_FDCWD, dir,
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int found = -1;
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        long o = 0;
        while (o + 19 <= n) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            unsigned long long dino;
            unsigned long dc;
            if (parse_marker(nm, &dino, &dc) && dino == ino) {
                *count = dc;
                found = 0;
                break;
            }
            o += reclen;
        }
        if (found == 0)
            break;
    }
    sys_close((int)fd);
    return found;
}

/* ---- marker locking ----------------------------------------------------- */

/* Serialize the marker's read-modify-write (find + rename/unlink) across
 * processes sharing the rootfs: an exclusive flock on the data file. Best
 * effort — callers proceed unlocked when the open or lock fails (the lock
 * narrows the race window, it is not a correctness guarantee the scheme
 * otherwise relies on). Returns the locked fd, or -1. */
static long l2s_lock(const char *data) {
    long fd = sys_openat(CNG_AT_FDCWD, data, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (CNG_SYS(__NR_flock, (int)fd, 2 /* LOCK_EX */, 0, 0, 0, 0) < 0) {
        sys_close((int)fd);
        return -1;
    }
    return fd;
}

static void l2s_unlock(long fd) {
    if (fd >= 0)
        sys_close((int)fd); /* closing drops the flock */
}

/* ---- central store ------------------------------------------------------ */

/* Host path of the per-rootfs object store "<rootfs>/.l2s", created on demand
 * (0700). New link groups keep their data + marker here, and every name is a
 * symlink carrying the data file's absolute host path — so links span
 * directories and survive renames of any name or parent directory. The guest
 * never sees the store (getdents hides it, the path guard denies it).
 * Returns 0 or -errno. */
static int l2s_store_dir(char *out, size_t sz) {
    const char *root = cng_g_fs ? cng_g_fs->rootfs : "";
    size_t n = cng_strlcpy(out, root, sz);
    if (n + 6 >= sz)
        return -ENAMETOOLONG;
    cng_strlcpy(out + n, "/.l2s", sz - n);
    long r = CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, out, 0700, 0, 0, 0);
    if (r < 0 && r != -EEXIST)
        return (int)r;
    char st[ST_SIZE];
    if (l2s_lstat(out, st) < 0 || !is_dir(st))
        return -ENOTDIR; /* a plain file squats on the name: store unusable */
    return 0;
}

int cng_l2s_deny(long dirfd, const char *gp) {
    if (!gp || !gp[0])
        return 0;
    /* Backing data/marker names do not exist for the guest, wherever they
     * are named from. */
    if (cng_l2s_hidden(l2s_basename(gp)))
        return 1;
    /* The store dir itself: deny "/.l2s" and everything under it. Only for
     * absolute/cwd-relative paths — a ".l2s" entry elsewhere in the tree
     * stays usable, and a dirfd-relative walk can only reach the store
     * through ".." (accepted, documented). */
    if ((gp[0] == '/' || (int)dirfd == CNG_AT_FDCWD) && cng_g_fs) {
        char canon[CNG_PATH_MAX];
        if (cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0 &&
            !strncmp(canon, "/.l2s", 5) &&
            (canon[5] == '\0' || canon[5] == '/'))
            return 1;
    }
    return 0;
}

int cng_l2s_untranslate_target(const char *tgt, char *out, size_t sz) {
    if (tgt[0] != '/' || !parse_data(l2s_basename(tgt), 0))
        return 0;
    if (cng_g_fs && cng_fs_untranslate(cng_g_fs, tgt, out, sz) == 0)
        return 1;
    /* Stale prefix (the rootfs tree was moved): the store sits at a fixed
     * guest location, so the basename alone reconstructs it. */
    size_t n = cng_strlcpy(out, "/.l2s/", sz);
    if (n >= sz)
        return 0;
    cng_strlcpy(out + n, l2s_basename(tgt), sz - n);
    return 1;
}

/* ---- core --------------------------------------------------------------- */

/* If `host` is one of our l2s symlinks, fill data+count. 1/0/-errno. */
int cng_l2s_resolve(const char *host, char *data, size_t dsz,
                    unsigned long *count) {
    char st[ST_SIZE];
    long r = l2s_lstat(host, st);
    if (r < 0)
        return (int)r;
    if (!is_lnk(st))
        return 0;

    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(host, tgt, sizeof tgt - 1);
    if (n < 0)
        return (int)n;
    tgt[n] = '\0';

    unsigned long long ino;
    if (!parse_data(l2s_basename(tgt), &ino))
        return 0; /* an ordinary symlink */

    char dir[CNG_PATH_MAX];
    if (tgt[0] == '/') {
        /* Absolute host target: the central store, or a legacy group joined
         * from another directory. */
        l2s_dirname(tgt, dir, sizeof dir);
        if (build_name(data, dsz, dir, ino, -1) < 0)
            return -ENAMETOOLONG;
        if (l2s_lstat(data, st) < 0) {
            /* Stale target (the rootfs tree was moved): self-heal via the
             * current rootfs' store, and repoint the link (best effort). */
            char store[CNG_PATH_MAX];
            if (l2s_store_dir(store, sizeof store) != 0 ||
                build_name(data, dsz, store, ino, -1) < 0 ||
                l2s_lstat(data, st) < 0)
                return 0; /* dangling: just an ordinary symlink */
            l2s_unlink(host);
            l2s_symlink(data, host);
            cng_strlcpy(dir, store, sizeof dir);
        }
    } else {
        l2s_dirname(host, dir, sizeof dir); /* relative: beside the link */
        if (build_name(data, dsz, dir, ino, -1) < 0)
            return -ENAMETOOLONG;
    }
    unsigned long c = 0;
    if (count) {
        if (find_marker(dir, ino, &c) != 0)
            c = 0;
        *count = c;
    }
    return 1;
}

/* Map `host` to its backing file: our symlink (NOFOLLOW) or the data file
 * itself (a FOLLOW resolution already landed on it). 1/0/-errno. */
static int l2s_target(const char *host, char *data, size_t dsz,
                      unsigned long *count) {
    int isl = cng_l2s_resolve(host, data, dsz, count);
    if (isl != 0)
        return isl;
    unsigned long long ino;
    if (parse_data(l2s_basename(host), &ino)) {
        char dir[CNG_PATH_MAX];
        l2s_dirname(host, dir, sizeof dir);
        if (build_name(data, dsz, dir, ino, -1) < 0)
            return -ENAMETOOLONG;
        if (count) {
            unsigned long c = 0;
            if (find_marker(dir, ino, &c) != 0)
                c = 0;
            *count = c;
        }
        return 1;
    }
    return 0;
}

/* Copy the contents of `src` (opened, follows /proc/self/fd/N) into a new
 * regular file `dst`. Used when src has no named regular inode to symlink to
 * (e.g. /proc/self/fd/N naming an O_TMPFILE), or the link spans directories. */
static int l2s_materialize(const char *src, const char *dst) {
    long in = sys_openat(CNG_AT_FDCWD, src, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (in < 0)
        return (int)in;
    /* A real hardlink shares the source's mode; the copy must too (apk
     * publishes its database files this way — 0644, not 0755). */
    char st[ST_SIZE];
    unsigned mode = 0644;
    if (CNG_SYS(__NR_fstat, (int)in, st, 0, 0, 0, 0) == 0) {
        if (!is_reg(st)) {
            sys_close((int)in);
            return -EPERM; /* link(2) on a directory etc. */
        }
        mode = st_mode(st) & 07777;
    }
    long out = sys_openat(CNG_AT_FDCWD, dst,
                          CNG_O_WRONLY | CNG_O_CREAT | CNG_O_EXCL |
                              CNG_O_CLOEXEC,
                          (int)mode);
    if (out < 0) {
        sys_close((int)in);
        return (int)out;
    }
    char buf[8192];
    long rc = 0, n;
    while ((n = sys_read((int)in, buf, sizeof buf)) > 0) {
        long off = 0;
        while (off < n) {
            long w = sys_write((int)out, buf + off, (size_t)(n - off));
            if (w < 0) {
                rc = w;
                break;
            }
            off += w;
        }
        if (rc)
            break;
    }
    if (n < 0 && rc == 0)
        rc = n;
    if (rc == 0) /* the open mode went through umask; the link's does not */
        CNG_SYS(__NR_fchmod, (int)out, mode, 0, 0, 0, 0);
    sys_close((int)in);
    sys_close((int)out);
    if (rc != 0)
        l2s_unlink(dst);
    return (int)rc;
}

int cng_l2s_link(const char *src, const char *dst) {
    char st[ST_SIZE];
    if (l2s_lstat(dst, st) == 0)
        return -EEXIST; /* link(2): dst must not exist */

    char data[CNG_PATH_MAX], sdir[CNG_PATH_MAX], ddir[CNG_PATH_MAX];
    unsigned long count = 0;
    unsigned long long ino;

    l2s_dirname(dst, ddir, sizeof ddir);

    int isl = cng_l2s_resolve(src, data, sizeof data, &count);
    if (isl < 0) {
        L2S_LOG("[cng] l2s: src probe %s -> %d\n", src, isl);
        return isl;
    }
    /* AT_SYMLINK_FOLLOW may have resolved src straight onto the data file. */
    if (isl == 0 && l2s_lstat(src, st) == 0 && is_reg(st) &&
        parse_data(l2s_basename(src), &ino)) {
        cng_strlcpy(data, src, sizeof data);
        l2s_dirname(src, sdir, sizeof sdir);
        if (find_marker(sdir, ino, &count) != 0)
            count = 0;
        isl = 1;
    }

    if (isl == 1) {
        /* Existing group (either format): bump the marker beside the data,
         * then point dst at it — same-directory relative target when dst sits
         * beside the data (the legacy look), absolute host path otherwise
         * (how names in other directories join a group). */
        parse_data(l2s_basename(data), &ino);
        l2s_dirname(data, sdir, sizeof sdir);
        long lk = l2s_lock(data);
        if (lk >= 0 && find_marker(sdir, ino, &count) != 0)
            count = 0; /* re-read under the lock */
        char newm[CNG_PATH_MAX], oldm[CNG_PATH_MAX];
        unsigned long nc = (count ? count : 1) + 1;
        if (build_name(newm, sizeof newm, sdir, ino, (long)nc) < 0) {
            l2s_unlock(lk);
            return -ENAMETOOLONG;
        }
        int bumped = 0;
        if (count && build_name(oldm, sizeof oldm, sdir, ino, (long)count) == 0)
            bumped = (l2s_rename(oldm, newm) == 0);
        if (!bumped)
            l2s_touch(newm); /* marker lost: recreate at the new count */
        long sr = strcmp(sdir, ddir) == 0
                      ? l2s_symlink(l2s_basename(data), dst)
                      : l2s_symlink(data, dst);
        if (sr < 0) { /* roll the bump back */
            L2S_LOG("[cng] l2s: group dst symlink %s -> %d\n", dst, (int)sr);
            if (bumped)
                l2s_rename(newm, oldm);
            else
                l2s_unlink(newm);
            l2s_unlock(lk);
            return (int)sr;
        }
        l2s_unlock(lk);
        return 0;
    }

    /* First link for a real file. */
    if (l2s_lstat(src, st) < 0) {
        L2S_LOG("[cng] l2s: src %s missing\n", src);
        return -ENOENT;
    }
    if (!is_reg(st)) /* e.g. /proc/self/fd/N O_TMPFILE: copy contents */
        return l2s_materialize(src, dst);
    ino = *(unsigned long long *)((char *)st + ST_INO_OFF);

    /* Prefer the central store: the group's names then carry the data file's
     * absolute host path, so they work across directories and keep working
     * when a name or its directory is renamed. The rename also pins <ino>
     * against reuse for the group's lifetime. */
    char store[CNG_PATH_MAX];
    long mv = -1;
    int sdr = l2s_store_dir(store, sizeof store);
    if (sdr == 0) {
        if (build_name(data, sizeof data, store, ino, -1) < 0)
            return -ENAMETOOLONG;
        mv = l2s_rename(src, data);
    }
    if (mv != 0)
        L2S_LOG("[cng] l2s: store unavailable (dir=%d mv=%d), per-dir "
                "fallback\n",
                sdr, (int)mv);
    if (mv == 0) {
        long sr = l2s_symlink(data, src);
        if (sr < 0) {
            L2S_LOG("[cng] l2s: src symlink %s -> %d\n", src, (int)sr);
            l2s_rename(data, src); /* rollback */
            return (int)sr;
        }
        char newm[CNG_PATH_MAX];
        int have_m = (build_name(newm, sizeof newm, store, ino, 2) == 0);
        if (have_m)
            l2s_touch(newm);
        sr = l2s_symlink(data, dst);
        if (sr < 0) { /* full rollback */
            L2S_LOG("[cng] l2s: dst symlink %s -> %d\n", dst, (int)sr);
            if (have_m)
                l2s_unlink(newm);
            l2s_unlink(src);
            l2s_rename(data, src);
            return (int)sr;
        }
        return 0;
    }

    /* Store unusable, or the rename refused (-EXDEV: src on a bind mount from
     * another filesystem): per-directory scheme, as before. Cross-directory
     * then still degrades to an independent copy. */
    l2s_dirname(src, sdir, sizeof sdir);
    if (strcmp(sdir, ddir) != 0)
        return l2s_materialize(src, dst);
    if (build_name(data, sizeof data, sdir, ino, -1) < 0)
        return -ENAMETOOLONG;
    if ((mv = l2s_rename(src, data)) < 0) {
        L2S_LOG("[cng] l2s: per-dir rename %s -> %d\n", src, (int)mv);
        return (int)mv;
    }
    long sr = l2s_symlink(l2s_basename(data), src);
    if (sr < 0) {
        L2S_LOG("[cng] l2s: per-dir src symlink %s -> %d\n", src, (int)sr);
        l2s_rename(data, src); /* rollback */
        return (int)sr;
    }
    char newm[CNG_PATH_MAX];
    int have_m = (build_name(newm, sizeof newm, sdir, ino, 2) == 0);
    if (have_m)
        l2s_touch(newm);
    sr = l2s_symlink(l2s_basename(data), dst);
    if (sr < 0) { /* full rollback */
        if (have_m)
            l2s_unlink(newm);
        l2s_unlink(src);
        l2s_rename(data, src);
        return (int)sr;
    }
    return 0;
}

int cng_l2s_rename_prep(const char *srch, char *absdata, size_t sz) {
    char st[ST_SIZE];
    if (l2s_lstat(srch, st) != 0 || !is_lnk(st))
        return 0;
    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(srch, tgt, sizeof tgt - 1);
    if (n < 0)
        return 0;
    tgt[n] = '\0';
    if (tgt[0] == '/' || !parse_data(l2s_basename(tgt), 0))
        return 0; /* absolute targets survive any move; others aren't ours */
    char dir[CNG_PATH_MAX];
    l2s_dirname(srch, dir, sizeof dir);
    size_t k = cng_strlcpy(absdata, dir, sz);
    if (k && absdata[k - 1] != '/' && k + 1 < sz) {
        absdata[k++] = '/';
        absdata[k] = '\0';
    }
    cng_strlcpy(absdata + k, tgt, sz > k ? sz - k : 0);
    return 1;
}

void cng_l2s_rename_fixup(const char *dsth, const char *absdata) {
    char ddir[CNG_PATH_MAX], sdir[CNG_PATH_MAX];
    l2s_dirname(dsth, ddir, sizeof ddir);
    l2s_dirname(absdata, sdir, sizeof sdir);
    if (strcmp(ddir, sdir) == 0)
        return; /* still beside the data: the relative target stays valid */
    l2s_unlink(dsth);
    l2s_symlink(absdata, dsth);
}

void cng_l2s_decref(const char *data, unsigned long count) {
    unsigned long long ino;
    if (!parse_data(l2s_basename(data), &ino))
        return;
    char dir[CNG_PATH_MAX], m[CNG_PATH_MAX], newm[CNG_PATH_MAX];
    l2s_dirname(data, dir, sizeof dir);
    long lk = l2s_lock(data);
    if (lk >= 0) {
        unsigned long c;
        if (find_marker(dir, ino, &c) == 0)
            count = c; /* fresher than the caller's pre-unlink read */
    }
    if (count <= 1) { /* last reference */
        l2s_unlink(data);
        if (build_name(m, sizeof m, dir, ino, (long)(count ? count : 1)) == 0)
            l2s_unlink(m);
        l2s_unlock(lk);
        return;
    }
    if (build_name(m, sizeof m, dir, ino, (long)count) == 0 &&
        build_name(newm, sizeof newm, dir, ino, (long)(count - 1)) == 0)
        l2s_rename(m, newm);
    l2s_unlock(lk);
}

int cng_l2s_stat(const char *host, void *statbuf) {
    char data[CNG_PATH_MAX];
    unsigned long count = 0;
    int r = l2s_target(host, data, sizeof data, &count);
    if (r != 1)
        return r;
    long s = l2s_statf(data, statbuf);
    if (s < 0)
        return (int)s;
    *(unsigned *)((char *)statbuf + ST_NLINK_OFF) = count ? count : 1;
    return 1;
}

int cng_l2s_statx(const char *host, void *statxbuf, unsigned mask,
                  unsigned flags) {
    char data[CNG_PATH_MAX];
    unsigned long count = 0;
    int r = l2s_target(host, data, sizeof data, &count);
    if (r != 1)
        return r;
    /* The data path is never a symlink: force a follow so the guest's
     * NOFOLLOW cannot expose the emulation. Sync flags pass through. */
    flags &= ~(unsigned)(CNG_AT_SYMLINK_NOFOLLOW | CNG_AT_EMPTY_PATH);
    long s = CNG_SYS(__NR_statx, CNG_AT_FDCWD, data, flags, mask, statxbuf, 0);
    if (s < 0)
        return (int)s;
    *(unsigned *)((char *)statxbuf + STX_NLINK_OFF) = count ? count : 1;
    *(unsigned *)((char *)statxbuf + STX_MASK_OFF) |= CNG_STATX_NLINK;
    return 1;
}

/* If /proc/self/fd/<fd> names a data file, yield the group's live count.
 * Returns 1 (*count filled, floored to 1) or 0. */
static int l2s_fd_count(long fd, unsigned long *count) {
    char link[64], *p = link;
    char *end = link + sizeof link - 1;
    p += cng_strlcpy(p, "/proc/self/fd/", (size_t)(end - p) + 1);
    /* int arg: the x-register's top half may be dirty (glibc). */
    put_u64(&p, end, (unsigned long long)(unsigned)(int)fd, 1);
    *p = '\0';
    char path[CNG_PATH_MAX];
    long n = l2s_readlink(link, path, sizeof path - 1);
    if (n < 0)
        return 0;
    path[n] = '\0';
    unsigned long long ino;
    if (!parse_data(l2s_basename(path), &ino))
        return 0;
    char dir[CNG_PATH_MAX];
    unsigned long c = 0;
    l2s_dirname(path, dir, sizeof dir);
    if (find_marker(dir, ino, &c) != 0)
        return 0;
    *count = c ? c : 1;
    return 1;
}

void cng_l2s_fix_fd(long fd, void *statbuf) {
    unsigned long c;
    if (l2s_fd_count(fd, &c))
        *(unsigned *)((char *)statbuf + ST_NLINK_OFF) = (unsigned)c;
}

void cng_l2s_fix_fd_statx(long fd, void *statxbuf) {
    unsigned long c;
    if (l2s_fd_count(fd, &c)) {
        *(unsigned *)((char *)statxbuf + STX_NLINK_OFF) = (unsigned)c;
        *(unsigned *)((char *)statxbuf + STX_MASK_OFF) |= CNG_STATX_NLINK;
    }
}
