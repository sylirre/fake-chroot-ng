/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* link2symlink backing-file scheme (see include/cng/l2s.h). Freestanding: raw
 * syscalls + the cng runtime string helpers only, so it is safe to run inside
 * the SIGSYS handler. Every path here is an already-resolved host path. */
#include "cng/l2s.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/pin.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

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
#define ST_ATIM_OFF  72
#define ST_MTIM_OFF  88
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

/* ---- syscall wrappers (host paths) -------------------------------------- */

/* Every path here is a host path derived from a guest name, so each is
 * handed to the kernel pinned (cng/pin.h): against the directory the walk
 * reached, never as a string for the kernel to resolve again. */
static long l2s_lstat(const char *p, void *st) {
    return cng_pin_fstatat(p, st, CNG_AT_SYMLINK_NOFOLLOW);
}
static long l2s_statf(const char *p, void *st) { /* follow */
    return cng_pin_fstatat(p, st, 0);
}
static long l2s_readlink(const char *p, char *b, size_t n) {
    return cng_pin_readlink(p, b, n);
}
static long l2s_symlink(const char *target, const char *linkpath) {
    return cng_pin_symlink(target, linkpath);
}
static long l2s_rename(const char *o, const char *n) {
    return cng_pin_rename(o, n, 0);
}
/* Never issued where the ambient filter refuses it: in the SIGSYS handler
 * that refusal is a nested SIGSYS, and the process dies of it. */
static long l2s_exchange(const char *a, const char *b) {
    if (cng_blocked[__NR_renameat2])
        return -ENOSYS;
    return cng_pin_rename(a, b, CNG_RENAME_EXCHANGE);
}
static long l2s_unlink(const char *p) { return cng_pin_unlink(p, 0); }
static void l2s_touch(const char *p) {
    long fd = cng_pin_open(p, CNG_O_WRONLY | CNG_O_CREAT | CNG_O_CLOEXEC, 0600);
    if (fd >= 0)
        sys_close((int)fd);
}

static unsigned st_mode(const void *st) {
    return *(const unsigned *)((const char *)st + ST_MODE_OFF);
}
static int is_lnk(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFLNK_; }
static int is_reg(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFREG_; }
static int is_dir(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFDIR_; }
/* What a group's data file can be: anything a link(2) can name — a regular
 * file, a FIFO, a socket, a device node — which is everything but a directory
 * (EPERM) and a symlink (linked as itself, l2s_copy_symlink). */
static int is_data(const void *st) { return !is_dir(st) && !is_lnk(st); }

/* ---- name parsing / formatting ------------------------------------------ */

/* Parse a run of decimal digits, setting *end past it: 0 for no digits, 1 for
 * a run whose value is in *out, 2 for one whose value does not fit in 64 bits
 * (*out untouched). The value used to be accumulated modulo 2^64, so a name
 * spelling ino + 2^64 parsed as ino. */
static int parse_u64(const char *p, unsigned long long *out, const char **end) {
    unsigned long long v = 0;
    const char *s = p;
    int wide = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned d = (unsigned)(*p - '0');
        if (v > (~0ULL - d) / 10)
            wide = 1;
        else
            v = v * 10 + d;
        p++;
    }
    if (p == s)
        return 0;
    if (end)
        *end = p;
    if (wide)
        return 2;
    if (out)
        *out = v;
    return 1;
}

/* A number field of the names below. The grammar — what cng_l2s_hidden hides
 * and refuses — is any digit run, however long, and a caller asking only that
 * passes no `out`; one that wants the number gets it only if there is one. */
static int parse_field(const char *p, unsigned long long *out,
                       const char **end) {
    int r = parse_u64(p, out, end);
    return r == 1 || (r == 2 && !out);
}

/* ".l2s.<ino>" exactly (data backing file). */
static int parse_data(const char *name, unsigned long long *ino) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    if (!parse_field(name + L2S_PREFIX_LEN, ino, &end))
        return 0;
    return *end == '\0';
}

/* ".l2s.<ino>.<count>" (marker). */
static int parse_marker(const char *name, unsigned long long *ino,
                        unsigned long *count) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    unsigned long long v, c;
    int want = ino || count;
    if (!parse_field(name + L2S_PREFIX_LEN, want ? &v : 0, &end) ||
        *end != '.')
        return 0;
    if (!parse_field(end + 1, want ? &c : 0, &end) || *end != '\0')
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

/* ".l2s.<ino>" exactly as build_name writes it: the digits of the number and
 * nothing else — no leading zero, no run a parse would wrap. parse_data takes
 * any digit run, which is the right grammar for the names that are hidden and
 * refused, but not for the ones followed: ".l2s.07" is not ".l2s.7", and a
 * link spelling one must not be taken for a link to the other. */
static int parse_data_exact(const char *name, unsigned long long *ino) {
    unsigned long long v;
    if (!parse_data(name, &v))
        return 0;
    char tmp[24], *p = tmp;
    put_u64(&p, tmp + sizeof tmp - 1, v, 1);
    *p = '\0';
    if (strcmp(tmp, name + L2S_PREFIX_LEN) != 0)
        return 0;
    if (ino)
        *ino = v;
    return 1;
}

/* ".l2s.<ino>.<count>" exactly as build_name writes it: the inode with no
 * leading zero, the count zero-padded to four digits and no wider — the one
 * marker name a group has. find_marker used to take any name of the grammar
 * whose number came out equal, and the numbers came out equal for spellings
 * no marker of ours ever had: ".l2s.<ino + 2^64>.<n>" (the parse wrapped),
 * ".l2s.<ino>.5" or ".l2s.0<ino>.0005". A tree carrying one — a rootfs from
 * elsewhere; the guest cannot make such a name — had its count read from the
 * stray, which the next update then failed to rename (it renames the
 * canonical name), or which outvoted the real marker, whichever the directory
 * listed first. */
static int parse_marker_exact(const char *name, unsigned long long *ino,
                              unsigned long *count) {
    unsigned long long v;
    unsigned long c;
    if (!parse_marker(name, &v, &c))
        return 0;
    char tmp[48], *p = tmp, *end = tmp + sizeof tmp - 1;
    put_u64(&p, end, v, 1);
    if (p < end)
        *p++ = '.';
    put_u64(&p, end, (unsigned long long)c, 4);
    if (p > end)
        return 0;
    *p = '\0';
    if (strcmp(tmp, name + L2S_PREFIX_LEN) != 0)
        return 0;
    if (ino)
        *ino = v;
    if (count)
        *count = c;
    return 1;
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
    long fd = cng_pin_open(dir, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                           0);
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
            if (parse_marker_exact(nm, &dino, &dc) && dino == ino) {
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

static int l2s_store_dir(char *out, size_t sz);

/* Serialize the marker's read-modify-write (find + rename/unlink) across
 * processes sharing the rootfs, and across threads of one: an exclusive flock,
 * held for the update. Fills *h, which l2s_unlock gives back whatever the
 * answer, and returns the locked fd, or -1.
 *
 * The lock used to be taken on the data file, opened for reading, and a data
 * file that could not be opened that way — mode 0200, mode 0000, both of which
 * a package can ship — left the update running unlocked, so two links or
 * unlinks of the group at once could leave st_nlink wrong or a backing file
 * behind. The lock is now a file of our own in the store, ".l2s/.lock" under
 * the rootfs, created 0600 in a directory we made 0700: openable by us
 * whatever mode the group's own files carry, and one lock per rootfs is the
 * right scope, since that is what the store is. The data file (either way it
 * can be opened) and then its directory stand in only where the store cannot
 * be had at all — a rootfs on which nothing can be created, where no link is
 * going to be made either. Proceeding unlocked is the last resort and is
 * logged, since it is the one outcome the scheme's counts cannot survive.
 *
 * A first link asks by its source, the file that is to become the data file,
 * and that can be a FIFO or a device: only a regular file is opened to stand
 * in, since opening one of those blocks or acts.
 *
 * Every signal is blocked from before the lock is asked for until it is given
 * back, as the view's and the credentials' writers hold theirs (path.c,
 * cred.c). On the -R tier the dispatcher runs on the guest's own mask, and a
 * signal is delivered on the way out of any syscall an update makes: a
 * handler that linked or unlinked a name itself opened the lock file again
 * and waited for the lock its own thread held, forever — an flock belongs to
 * the open file, and the second open is another one. A signal that arrives
 * meanwhile is taken once the update is done. And the lock is given back
 * with LOCK_UN before the close: a fork by another thread meanwhile hands the
 * child a duplicate of the locked open file, and the close of ours alone left
 * the lock held until the child exec'd or exited. */
struct l2s_held {
    long fd;            /* the locked descriptor, or -1: no lock to be had */
    unsigned long mask; /* the signal mask to restore */
};

static long l2s_lock(const char *data, struct l2s_held *h) {
    char lk[CNG_PATH_MAX], st[ST_SIZE];
    long fd = -1;
    unsigned long all = ~0UL;
    CNG_SYS(__NR_rt_sigprocmask, 2 /*SIG_SETMASK*/, &all, &h->mask, 8, 0, 0);
    h->fd = -1;
    if (l2s_store_dir(lk, sizeof lk) == 0) {
        size_t n = strlen(lk);
        if (n + 7 < sizeof lk) {
            memcpy(lk + n, "/.lock", 7);
            fd = cng_pin_open(lk, CNG_O_RDWR | CNG_O_CREAT | CNG_O_CLOEXEC,
                              0600);
        }
    }
    if (fd < 0 && l2s_lstat(data, st) == 0 && is_reg(st)) {
        fd = cng_pin_open(data, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
        if (fd < 0)
            fd = cng_pin_open(data, CNG_O_WRONLY | CNG_O_CLOEXEC, 0);
    }
    if (fd < 0) {
        l2s_dirname(data, lk, sizeof lk);
        fd = cng_pin_open(lk, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                          0);
    }
    if (fd < 0) {
        L2S_LOG("[cng] l2s: no lock to be had for %s (%ld): unlocked update\n",
                data, fd);
        return -1;
    }
    long r;
    do {
        r = CNG_SYS(__NR_flock, (int)fd, 2 /* LOCK_EX */, 0, 0, 0, 0);
    } while (r == -EINTR);
    if (r < 0) {
        L2S_LOG("[cng] l2s: flock for %s refused (%ld): unlocked update\n",
                data, r);
        sys_close((int)fd);
        return -1;
    }
    return h->fd = fd;
}

static void l2s_unlock(const struct l2s_held *h) {
    if (h->fd >= 0) {
        CNG_SYS(__NR_flock, (int)h->fd, 8 /* LOCK_UN */, 0, 0, 0, 0);
        sys_close((int)h->fd);
    }
    CNG_SYS(__NR_rt_sigprocmask, 2 /*SIG_SETMASK*/, &h->mask, 0, 8, 0, 0);
}

/* ---- central store ------------------------------------------------------ */

/* Host path of the per-rootfs object store "<rootfs>/.l2s", created on demand
 * (0700). New link groups keep their data + marker here, and every name is a
 * symlink carrying the data file's absolute host path — so links span
 * directories and survive renames of any name or parent directory. The guest
 * never sees the store (getdents hides it, the path guard denies it).
 * Returns 0 or -errno. */
static int l2s_store_dir(char *out, size_t sz) {
    size_t n = cng_g_fs ? cng_fs_rootfs(out, sz) : cng_strlcpy(out, "", sz);
    if (n + 6 >= sz)
        return -ENAMETOOLONG;
    cng_strlcpy(out + n, "/.l2s", sz - n);
    long r = cng_pin_mkdir(out, 0700);
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

/* ---- which links are ours ------------------------------------------------
 *
 * A link is recognized by its target, and a target is text: the kernel keeps
 * whatever symlinkat was given, and the guest calls symlinkat too. Taken on
 * its word — any target whose last component parsed as ".l2s.<digits>" —
 * that text named the file every no-follow call was then redirected to: a
 * guest's `ln -s /elsewhere/on/the/host/.l2s.1 x` made lstat of x describe a
 * host file outside the rootfs, chown and utimensat change it, an O_NOFOLLOW
 * open read and write it, and unlink delete it — another rootfs's store is
 * exactly such a place. So a target is only ours where it names a data file
 * the emulation could have written, which is one of:
 *
 *  - a bare ".l2s.<ino>": the legacy same-directory link, its data beside it;
 *  - an absolute path, in canonical form, to a data file in a place of the
 *    guest's own (l2s_owned): this rootfs's store, a legacy group joined from
 *    another directory, a group in a bind;
 *  - an absolute path into some other "<dir>/.l2s" store, which is what a
 *    link carries after its rootfs tree was moved or copied: it self-heals
 *    onto this rootfs's store under the same name, and the file it named is
 *    never looked at.
 *
 * and the data file has to be there: a regular file, a FIFO, a socket or a
 * device node (is_data) — whatever was linked, never a directory or a
 * symlink. Everything else is an ordinary symlink, whatever its last
 * component says. The guest can no longer write such a target at all (the
 * symlinkat refusal in dispatch.c); this is what keeps a tree that already
 * holds one — from before that refusal, from the host, from another tool —
 * from being read the old way. */

/* The view chroot-ng was started with: run.c's, never written after it is
 * published. A guest chroot narrows the view, and a group linked before it
 * keeps its data where the wider view put it. 0 in the unit harness. */
static const struct cng_fs *g_home;

void cng_l2s_home(const struct cng_fs *fs) { g_home = fs; }

/* A place of the guest's own: somewhere the view names (the rootfs, a bind,
 * the /dev/shm stand-in — cng_host_dir_guest), or somewhere the view it was
 * started with named. `p` is canonical, so a prefix is a containment. */
static int l2s_owned(const char *p) {
    if (!cng_g_fs)
        return 1; /* no view at all: the host root is the rootfs */
    char g[CNG_PATH_MAX];
    if (cng_host_dir_guest(p, g, sizeof g) == 0)
        return 1;
    return g_home && cng_fs_untranslate(g_home, p, g, sizeof g) == 0;
}

/* Absolute, and no empty, "." or ".." component, no trailing slash: the form
 * of every target this file writes (the store path and the walk's host paths
 * both are), and the only one whose prefix says where it leads. */
static int l2s_canonical(const char *p) {
    if (p[0] != '/')
        return 0;
    for (const char *c = p + 1;;) {
        const char *e = c;
        while (*e && *e != '/')
            e++;
        size_t n = (size_t)(e - c);
        if (n == 0 || (n == 1 && c[0] == '.') ||
            (n == 2 && c[0] == '.' && c[1] == '.'))
            return 0;
        if (!*e)
            return 1;
        c = e + 1;
    }
}

/* "<dir>/.l2s/.l2s.<ino>": a data file in some rootfs's store. */
static int l2s_store_shaped(const char *p) {
    const char *b = l2s_basename(p);
    return b - p >= 6 && !strncmp(b - 6, "/.l2s/", 6);
}

/* For a target in some "<dir>/.l2s" store — what a link carries after its
 * rootfs tree was moved or copied — the same name in this rootfs's store,
 * into `out`. 1 (filled, and not the target itself), 0, or -ENAMETOOLONG.
 * Whether anything is there is the caller's question. */
static int l2s_store_heal(const char *tgt, char *out, size_t sz) {
    if (!l2s_store_shaped(tgt))
        return 0;
    char store[CNG_PATH_MAX];
    if (l2s_store_dir(store, sizeof store) != 0)
        return 0;
    const char *b = l2s_basename(tgt);
    size_t sl = strlen(store);
    if (sl + 1 + strlen(b) >= sz)
        return -ENAMETOOLONG;
    memcpy(out, store, sl);
    out[sl] = '/';
    cng_strlcpy(out + sl + 1, b, sz - sl - 1);
    return strcmp(out, tgt) != 0;
}

/* The data file the link at `host` names by `tgt`, into `data`: 1 (ours), 0
 * (an ordinary symlink), or -ENAMETOOLONG. *heal is set when the target is a
 * stale store path and `data` is where this rootfs's store has it: the link
 * should be repointed. */
static int l2s_locate(const char *host, const char *tgt, char *data,
                      size_t dsz, int *heal) {
    char st[ST_SIZE];
    const char *b = l2s_basename(tgt);
    *heal = 0;
    if (!parse_data_exact(b, 0))
        return 0;
    if (tgt[0] != '/') {
        if (b != tgt)
            return 0; /* a relative target of ours is the bare name */
        char dir[CNG_PATH_MAX];
        l2s_dirname(host, dir, sizeof dir);
        size_t dl = strlen(dir);
        int sep = !(dl && dir[dl - 1] == '/');
        if (dl + (size_t)sep + strlen(b) >= dsz)
            return -ENAMETOOLONG;
        memcpy(data, dir, dl);
        if (sep)
            data[dl++] = '/';
        cng_strlcpy(data + dl, b, dsz - dl);
        return l2s_lstat(data, st) == 0 && is_data(st);
    }
    if (!l2s_canonical(tgt))
        return 0;
    if (l2s_owned(tgt)) {
        if (cng_strlcpy(data, tgt, dsz) >= dsz)
            return -ENAMETOOLONG;
        if (l2s_lstat(data, st) == 0 && is_data(st))
            return 1;
    }
    int k = l2s_store_heal(tgt, data, dsz);
    if (k != 1)
        return k;
    if (l2s_lstat(data, st) != 0 || !is_data(st))
        return 0; /* dangling: just an ordinary symlink */
    *heal = 1;
    return 1;
}

/* ---- proot's groups -------------------------------------------------------
 *
 * A rootfs installed through proot (proot-distro's) carries the hardlinks
 * proot's own link2symlink made, in a scheme of its own:
 *
 *   member       every name of the group: a symlink whose text is the HOST
 *                path of the indirection, absolute;
 *   indirection  "<prefix><name><NNNN>" — a symlink in proot's l2s directory
 *                (proot-distro's is "<rootfs>/.l2s", the same as our store;
 *                beside the first-linked name with no PROOT_L2S_DIR), whose
 *                text is the host path of the data file beside it;
 *   data         "<indirection>.<CCCC>" — the linked file itself, CCCC its
 *                live link count. A name added or removed renames the data
 *                file to the new count and repoints the indirection, which is
 *                why the members name the indirection: its name never moves.
 *
 * <prefix> is ".l2s." (".proot.l2s." in UserLAnd's build), <name> the first
 * name's basename, <NNNN> the first four-digit suffix free in that directory.
 * The guest-level walk used to re-root a member's text like any absolute
 * target, so every name dangled into "<rootfs><rootfs>/.l2s".
 *
 * Read here, and kept, with proot's own bookkeeping so the tree goes on
 * working under proot: a group is presented as the one file a hardlink is
 * (through cng_l2s_resolve, so every caller of ours sees it), a new link of a
 * member is a member with the same text after the count went up, a removed one
 * takes it down, and the last removes the data and the indirection. New groups
 * are still made in the emulation's own scheme.
 *
 * The text of every link here is the guest's — any image can hold any text in
 * one — so nothing of it is followed. A member's text is placed by the same
 * rule as our own targets (a canonical absolute path in a place of the guest's
 * own, or a stale store path healed onto this rootfs's store), and of the
 * indirection's text only the BASENAME is used: it must be the indirection's
 * own name plus ".<CCCC>", and the data file is taken beside the indirection —
 * which is the directory the text has to spell (or, for a tree that was moved,
 * a stale store path while the indirection is in a store). The data file has
 * to be there and be a file (is_data).
 *
 * A count change is two renames — the data, then the indirection over a
 * fresh symlink made under "<indirection>.cng" — so the indirection itself is
 * never missing, but between the two it names a file that is gone. Every
 * change of ours takes the lock (l2s_lock), re-reads the chain under it, and
 * repairs one a killed process left cut (the one data file of that name in
 * the directory, found by a scan); a reader that finds the data missing
 * looks again a few times. proot takes no lock, so it and chroot-ng changing
 * one group at the same moment can still interleave: a count can end one
 * off. */

#define PR_MAX_COUNT 9999
#define PR_TMP_SUFFIX ".cng"

static size_t pr_prefix_len(const char *name) {
    if (!strncmp(name, ".l2s.", 5))
        return 5;
    if (!strncmp(name, ".proot.l2s.", 11))
        return 11;
    return 0;
}

static int pr_four(const char *s) {
    for (int i = 0; i < 4; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return 1;
}

/* An indirection's basename: "<prefix><name><NNNN>", <name> not empty. The
 * bound keeps the data name and the temporary inside NAME_MAX. */
static int pr_is_ind(const char *name) {
    size_t pl = pr_prefix_len(name), n = strlen(name);
    return pl && n >= pl + 1 + 4 && n <= 240 && pr_four(name + n - 4);
}

/* A data basename "<ind>.<CCCC>" for the indirection basename `ind` (of
 * length il): *count from it, a zero read as one. */
static int pr_data_of(const char *dn, const char *ind, size_t il,
                      unsigned long *count) {
    if (strncmp(dn, ind, il) || dn[il] != '.' || !pr_four(dn + il + 1) ||
        dn[il + 5])
        return 0;
    unsigned long c = 0;
    for (int i = 1; i <= 4; i++)
        c = c * 10 + (unsigned long)(dn[il + i] - '0');
    if (count)
        *count = c ? c : 1;
    return 1;
}

/* Any data basename: its indirection's is all but the last five bytes. */
static int pr_is_data(const char *dn) {
    size_t n = strlen(dn);
    char ind[256];
    if (n < 6 || n - 5 >= sizeof ind)
        return 0;
    memcpy(ind, dn, n - 5);
    ind[n - 5] = '\0';
    return pr_is_ind(ind) && pr_data_of(dn, ind, n - 5, 0);
}

struct pr_group {
    char ind[CNG_PATH_MAX];  /* the indirection's host path */
    char data[CNG_PATH_MAX]; /* the data file's host path, as last read */
    size_t dl;               /* length of their directory, its '/' included */
    unsigned long count;     /* the count in the data file's name */
};

/* g->data = the indirection's directory + `dn`. */
static int pr_set_data(struct pr_group *g, const char *dn) {
    size_t n = strlen(dn);
    if (g->dl + n >= sizeof g->data)
        return -ENAMETOOLONG;
    memcpy(g->data, g->ind, g->dl);
    memcpy(g->data + g->dl, dn, n + 1);
    return 0;
}

/* Read the chain from the indirection at g->ind: 1 (g->data and g->count
 * filled; the data file is there), 0 (not a group), or -ENOENT (the
 * indirection names a data file that is not there: another process between
 * its two renames, or a chain a killed one left cut). */
static int pr_chain(struct pr_group *g) {
    char st[ST_SIZE], t2[CNG_PATH_MAX];
    const char *ib = l2s_basename(g->ind);
    g->dl = (size_t)(ib - g->ind);
    if (l2s_lstat(g->ind, st) != 0 || !is_lnk(st))
        return 0;
    long n = l2s_readlink(g->ind, t2, sizeof t2 - 1);
    if (n <= 0)
        return 0;
    t2[n] = '\0';
    const char *db = l2s_basename(t2);
    if (!pr_data_of(db, ib, strlen(ib), &g->count) ||
        pr_set_data(g, db) != 0)
        return 0;
    /* Beside the indirection, as proot writes it — or, for a tree that was
     * moved, any store's spelling while the indirection is in a store. */
    if (strcmp(t2, g->data) != 0 &&
        !(l2s_canonical(t2) && l2s_store_shaped(t2) &&
          l2s_store_shaped(g->ind)))
        return 0;
    long r = l2s_lstat(g->data, st);
    if (r == -ENOENT)
        return -ENOENT;
    return r == 0 && is_data(st);
}

/* The group's one data file in its directory, by a scan for
 * "<indirection>.<CCCC>": a count change only ever renames it, so there is
 * one. For a chain left cut. 0 (g->data and g->count filled), -ENOENT (none:
 * the group is gone) or -EIO (more than one: not guessed at). */
static int pr_find_data(struct pr_group *g) {
    char dir[CNG_PATH_MAX], st[ST_SIZE], dn[256];
    const char *ib = l2s_basename(g->ind);
    size_t il = strlen(ib);
    l2s_dirname(g->ind, dir, sizeof dir);
    long fd = cng_pin_open(dir, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                           0);
    if (fd < 0)
        return (int)fd;
    char buf[4096];
    int found = 0;
    unsigned long c = 0;
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        for (long o = 0; o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            unsigned long nc;
            o += reclen;
            if (!pr_data_of(nm, ib, il, &nc) ||
                CNG_SYS(__NR_newfstatat, (int)fd, nm, st,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) != 0 ||
                !is_data(st))
                continue;
            if (found++)
                break;
            cng_strlcpy(dn, nm, sizeof dn);
            c = nc;
        }
        if (found > 1)
            break;
    }
    sys_close((int)fd);
    if (found != 1)
        return found ? -EIO : -ENOENT;
    g->count = c;
    return pr_set_data(g, dn);
}

/* Point the indirection at g->data: a symlink made under the temporary name
 * and renamed over it, so the indirection is never missing. Its text is the
 * data file's host path as it is spelled now, which also heals a moved
 * tree's. 0 or -errno. */
static long pr_repoint(struct pr_group *g) {
    char tmp[CNG_PATH_MAX];
    size_t il = strlen(g->ind);
    if (il + sizeof PR_TMP_SUFFIX > sizeof tmp)
        return -ENAMETOOLONG;
    memcpy(tmp, g->ind, il);
    memcpy(tmp + il, PR_TMP_SUFFIX, sizeof PR_TMP_SUFFIX);
    l2s_unlink(tmp); /* one a killed update left */
    long r = l2s_symlink(g->data, tmp);
    if (r == 0 && (r = l2s_rename(tmp, g->ind)) < 0)
        l2s_unlink(tmp);
    return r;
}

/* Under the lock: the chain as it is now, made whole where it is cut. 1, 0
 * (not a group, or gone) or -errno. */
static int pr_settle(struct pr_group *g) {
    int r = pr_chain(g);
    if (r != -ENOENT)
        return r;
    if (pr_find_data(g) != 0)
        return 0;
    L2S_LOG("[cng] l2s: proot group %s was cut, repointed\n", g->ind);
    return pr_repoint(g) == 0 ? 1 : 0;
}

/* Move the count by `delta` (+1/-1), proot's own steps: the data file renamed
 * to its new count, the indirection repointed. Under the lock, after
 * pr_settle. The last name dropped removes the data and the indirection. 0 or
 * -errno; on failure nothing has moved. */
static long pr_adjust(struct pr_group *g, int delta) {
    if (delta < 0 && g->count <= 1) {
        l2s_unlink(g->data);
        l2s_unlink(g->ind);
        return 0;
    }
    if (delta > 0 && g->count >= PR_MAX_COUNT)
        return -EMLINK;
    unsigned long nc = g->count + (unsigned long)(long)delta;
    char old[CNG_PATH_MAX], dn[256], *p = dn;
    const char *ib = l2s_basename(g->ind);
    size_t il = strlen(ib);
    if (il + 6 > sizeof dn)
        return -ENAMETOOLONG;
    memcpy(p, ib, il);
    p += il;
    *p++ = '.';
    put_u64(&p, dn + sizeof dn - 1, nc, 4);
    *p = '\0';
    cng_strlcpy(old, g->data, sizeof old);
    if (pr_set_data(g, dn) != 0)
        return -ENAMETOOLONG;
    long r = l2s_rename(old, g->data);
    if (r == 0 && (r = pr_repoint(g)) < 0)
        l2s_rename(g->data, old); /* the count back */
    if (r < 0) {
        cng_strlcpy(g->data, old, sizeof g->data);
        return r;
    }
    g->count = nc;
    return 0;
}

/* pr_chain, looked at again a few times while the data file is missing:
 * another process of ours is between the two renames of a count change. */
static int pr_chain_look(struct pr_group *g) {
    int r = pr_chain(g);
    for (int i = 0; i < 3 && r == -ENOENT; i++) {
        if (!cng_blocked[__NR_sched_yield])
            CNG_SYS(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
        r = pr_chain(g);
    }
    return r;
}

/* If the symlink `host` (its text `tgt`) is a member of a proot group, fill
 * *g: 1, else 0. The indirection is where the text says, in a place of the
 * guest's own, or — the text a stale store path — in this rootfs's store,
 * and then the member is repointed at it, as a stale link of ours is.
 *
 * A chain cut for good (its data file not where the indirection says, after
 * the looks) is still a member, with g->data the missing file: a stat of it
 * fails, so to the guest it is the dangling symlink proot shows too, while an
 * unlink or a link of it is the change of the group that mends the chain
 * under the lock (pr_settle) and moves the count. Taken for an ordinary
 * symlink, the unlink left the count high for good and a link made a member
 * the count never had. */
static int pr_member(const char *host, const char *tgt, struct pr_group *g) {
    if (tgt[0] != '/' || !pr_is_ind(l2s_basename(tgt)) || !l2s_canonical(tgt))
        return 0;
    int r = 0, heal = 0;
    if (l2s_owned(tgt) &&
        cng_strlcpy(g->ind, tgt, sizeof g->ind) < sizeof g->ind)
        r = pr_chain_look(g);
    if (r == 0) {
        if (l2s_store_heal(tgt, g->ind, sizeof g->ind) != 1)
            return 0;
        heal = 1;
        r = pr_chain_look(g);
    }
    if (r != 1 && r != -ENOENT)
        return 0;
    if (heal) {
        l2s_unlink(host);
        l2s_symlink(g->ind, host);
    }
    return 1;
}

/* Is the file at `host` a proot data file — its indirection beside it, naming
 * it? `host` canonical, in a place of the guest's own. 1 (*g filled) or 0. */
static int pr_data_here(const char *host, struct pr_group *g) {
    const char *b = l2s_basename(host);
    size_t n = strlen(host);
    if (!pr_is_data(b) || n - 5 >= sizeof g->ind || !l2s_canonical(host) ||
        !l2s_owned(host))
        return 0;
    memcpy(g->ind, host, n - 5);
    g->ind[n - 5] = '\0';
    return pr_chain(g) == 1 && !strcmp(g->data, host);
}

/* The indirection of the data file `data`: all but its ".<CCCC>". */
static int pr_from_data(const char *data, struct pr_group *g) {
    size_t n = strlen(data);
    if (n < 6 || n - 5 >= sizeof g->ind)
        return -ENAMETOOLONG;
    memcpy(g->ind, data, n - 5);
    g->ind[n - 5] = '\0';
    return 0;
}

/* A new name `dst` of the proot group whose data file is `data` (as a
 * resolve read it): the count raised first, then a member carrying the
 * indirection's host path, as proot makes one; where the member cannot be
 * made, the count is put back. 0 or -errno. */
static int pr_link(const char *data, const char *dst) {
    struct pr_group g;
    if (pr_from_data(data, &g) != 0)
        return -ENAMETOOLONG;
    struct l2s_held lk;
    l2s_lock(data, &lk);
    int k = pr_settle(&g);
    long r = k == 1 ? pr_adjust(&g, 1) : k < 0 ? k : -ENOENT;
    if (r == 0 && (r = l2s_symlink(g.ind, dst)) < 0)
        pr_adjust(&g, -1);
    l2s_unlock(&lk);
    return (int)r;
}

/* A name of the proot group whose data file is `data` is gone: the count
 * lowered, and with the last name the data file and the indirection. */
static void pr_drop(const char *data) {
    struct pr_group g;
    if (pr_from_data(data, &g) != 0)
        return;
    struct l2s_held lk;
    l2s_lock(data, &lk);
    if (pr_settle(&g) == 1)
        pr_adjust(&g, -1);
    l2s_unlock(&lk);
}

int cng_l2s_untranslate_target(const char *tgt, char *out, size_t sz) {
    const char *b = l2s_basename(tgt);
    /* Ours names a data file; proot's members name an indirection, and an
     * indirection names a data file of its own grammar. */
    if (tgt[0] != '/' || !l2s_canonical(tgt) ||
        !(parse_data_exact(b, 0) || pr_is_ind(b) || pr_is_data(b)))
        return 0;
    if (cng_g_fs && cng_host_dir_guest(tgt, out, sz) == 0)
        return 1;
    /* A stale store path (the rootfs tree was moved or copied): the store
     * sits at a fixed guest location, so the basename alone reconstructs it,
     * as l2s_locate's self-heal does. Anything else is re-rooted like the
     * absolute target of any other symlink. */
    if (!l2s_store_shaped(tgt))
        return 0;
    size_t n = cng_strlcpy(out, "/.l2s/", sz);
    if (n >= sz)
        return 0;
    cng_strlcpy(out + n, b, sz - n);
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

    int heal;
    int k = l2s_locate(host, tgt, data, dsz, &heal);
    if (k == 0) { /* not ours: one of proot's? */
        struct pr_group g;
        if (pr_member(host, tgt, &g) != 1)
            return 0;
        if (cng_strlcpy(data, g.data, dsz) >= dsz)
            return -ENAMETOOLONG;
        if (count)
            *count = g.count;
        return 1;
    }
    if (k != 1)
        return k;
    if (heal) { /* repoint the stale link at its data (best effort) */
        l2s_unlink(host);
        l2s_symlink(data, host);
    }
    if (count) {
        unsigned long long ino;
        unsigned long c = 0;
        char dir[CNG_PATH_MAX];
        parse_data(l2s_basename(data), &ino);
        l2s_dirname(data, dir, sizeof dir);
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
    if (parse_data_exact(l2s_basename(host), &ino) && l2s_canonical(host) &&
        l2s_owned(host)) {
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
    struct pr_group g;
    if (pr_data_here(host, &g)) {
        if (cng_strlcpy(data, host, dsz) >= dsz)
            return -ENAMETOOLONG;
        if (count)
            *count = g.count;
        return 1;
    }
    return 0;
}

/* Copy the contents of `src` (opened, follows /proc/self/fd/N) into a new
 * regular file `dst`. Used when src has no named regular inode to symlink to
 * (e.g. /proc/self/fd/N naming an O_TMPFILE), or the link spans directories.
 * Only a regular file has contents to copy, and only one is opened: opening a
 * FIFO blocked the linker until a writer came (`ln fifo fifo2` hung), and
 * opening a device acts on it. The type is asked first, and the open is
 * non-blocking and takes no terminal, for a file swapped in between. */
static int l2s_materialize(const char *src, const char *dst) {
    char st[ST_SIZE];
    long sr = l2s_statf(src, st);
    if (sr < 0)
        return (int)sr;
    if (!is_reg(st))
        return -EPERM; /* link(2) on a directory; a node it cannot group */
    long in = cng_pin_open(src,
                           CNG_O_RDONLY | CNG_O_NONBLOCK | CNG_O_NOCTTY |
                               CNG_O_CLOEXEC,
                           0);
    if (in < 0)
        return (int)in;
    /* A real hardlink shares the source's mode; the copy must too (apk
     * publishes its database files this way — 0644, not 0755). */
    unsigned mode = 0644;
    if (CNG_SYS(__NR_fstat, (int)in, st, 0, 0, 0, 0) == 0) {
        if (!is_reg(st)) {
            sys_close((int)in);
            return -EPERM; /* link(2) on a directory etc. */
        }
        mode = st_mode(st) & 07777;
    }
    long out = cng_pin_open(dst,
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

/* The host's /proc: the one place a symlink is not the guest's but a
 * descriptor's magic link (the AT_EMPTY_PATH source is spelled as one), the
 * same zone pin.c hands over unpinned. */
static int l2s_under_proc(const char *p) {
    return strncmp(p, "/proc", 5) == 0 && (p[5] == '\0' || p[5] == '/');
}

/* link(2) of a symlink links the symlink itself: the kernel gives the new name
 * the same inode, so it reads the same text. A symlink cannot be a group's
 * data file — a group's names are followed onto it, and a relative text would
 * then be read against the store — so the new name is a second symlink with
 * that text, carrying the original's times as one inode would (its count
 * stays 1, the one divergence). The source is read, never opened or followed:
 * l2s_materialize used to open it, which the pin refused with ELOOP. A text
 * in the ".l2s." grammar is not copied, as the guest's own symlinkat of one
 * is refused (dispatch.c): beside a data file of that name the copy would be
 * taken for a name of its group that was never counted. 0 or -errno. */
static int l2s_copy_symlink(const char *src, const char *dst, const void *st) {
    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(src, tgt, sizeof tgt - 1);
    if (n < 0)
        return (int)n;
    tgt[n] = '\0';
    if (cng_l2s_hidden(l2s_basename(tgt)))
        return -EPERM;
    long r = l2s_symlink(tgt, dst);
    if (r < 0)
        return (int)r;
    if (!cng_blocked[__NR_utimensat]) {
        struct cng_pin p;
        long ts[4];
        memcpy(ts, (const char *)st + ST_ATIM_OFF, sizeof ts / 2);
        memcpy(ts + 2, (const char *)st + ST_MTIM_OFF, sizeof ts / 2);
        if (cng_pin_at(CNG_AT_FDCWD, dst, &p) == 0)
            CNG_SYS(__NR_utimensat, p.dfd, (long)p.name, (long)ts,
                    CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
        cng_unpin(&p);
    }
    return 0;
}

/* What `src` is to a link: 1 a member of a group (`data` and `*count`
 * filled), 0 a file of its own, or -errno. */
static int l2s_link_source(const char *src, int own, char *data, size_t dsz,
                           unsigned long *count) {
    int isl = cng_l2s_resolve(src, data, dsz, count);
    if (isl < 0) {
        L2S_LOG("[cng] l2s: src probe %s -> %d\n", src, isl);
        return isl;
    }
    /* AT_SYMLINK_FOLLOW may have resolved src straight onto the data file. */
    char st[ST_SIZE], sdir[CNG_PATH_MAX];
    unsigned long long ino;
    struct pr_group g;
    if (isl == 0 && own && l2s_lstat(src, st) == 0 && is_data(st) &&
        parse_data_exact(l2s_basename(src), &ino)) {
        cng_strlcpy(data, src, dsz);
        l2s_dirname(src, sdir, sizeof sdir);
        if (find_marker(sdir, ino, count) != 0)
            *count = 0;
        isl = 1;
    } else if (isl == 0 && own && pr_data_here(src, &g)) {
        cng_strlcpy(data, src, dsz);
        *count = g.count;
        isl = 1;
    }
    return isl;
}

/* Move the file `src` to `data` and leave in its name a symlink whose text is
 * `tgt`. Done as a rename and then the symlink, the name was missing in
 * between, and the kernel never shows a name being linked as gone: busybox
 * `ln` stats its source first, and a second `ln a c` failed with ENOENT while
 * the first made the group. So the symlink is made under `data` first and the
 * two names exchanged in one renameat2: the name is the file, then the link
 * to it. Where the exchange cannot be had — no renameat2, a filesystem
 * without RENAME_EXCHANGE, a stale symlink of ours under `data` — the two
 * steps stand; any other file under `data` is EEXIST. 0 or -errno; on
 * failure nothing has moved. */
static long l2s_swap_in(const char *src, const char *data, const char *tgt) {
    long r = l2s_symlink(tgt, data);
    if (r == 0) {
        if ((r = l2s_exchange(src, data)) == 0)
            return 0;
        l2s_unlink(data);
    }
    L2S_LOG("[cng] l2s: no exchange for %s (%ld): rename, then symlink\n", src,
            r);
    /* The rename replaces whatever is under `data`, so it is made over
     * nothing, or over the symlink a swap killed after its first step left
     * (its text is `tgt`) — never over a file of someone else's. The store
     * is proot-distro's l2s directory too, and an indirection of proot's for
     * a file named by digits (".l2s.<digits>") spells a data name of ours;
     * so does a data file whose tree was copied in under another inode. */
    char st[ST_SIZE], old[CNG_PATH_MAX];
    if (l2s_lstat(data, st) == 0) {
        long n = is_lnk(st) ? l2s_readlink(data, old, sizeof old - 1) : -1;
        if (n < 0 || (old[n] = '\0', strcmp(old, tgt) != 0))
            return -EEXIST;
    }
    r = l2s_rename(src, data);
    if (r < 0)
        return r;
    r = l2s_symlink(tgt, src);
    if (r < 0)
        l2s_rename(data, src); /* rollback */
    return r;
}

/* Undo l2s_swap_in: the file back under `src`, by the exchange where it can
 * be had, and the symlink gone. */
static void l2s_swap_out(const char *src, const char *data) {
    if (l2s_exchange(src, data) == 0) {
        l2s_unlink(data);
        return;
    }
    l2s_unlink(src);
    l2s_rename(data, src);
}

/* The first link of a file of its own: src becomes the group's data file and
 * a symlink takes its name. Run under the lock. Returns 0, -errno, or 1 where
 * src cannot join a group and dst is to be a copy of it instead — made by the
 * caller once the lock is dropped, since nothing of a group's is touched. */
static int l2s_first_link(const char *src, const char *dst, const char *ddir,
                          int own) {
    char st[ST_SIZE], data[CNG_PATH_MAX], sdir[CNG_PATH_MAX];
    unsigned long long ino;

    if (l2s_lstat(src, st) < 0) {
        L2S_LOG("[cng] l2s: src %s missing\n", src);
        return -ENOENT;
    }
    /* A descriptor's magic link is followed by the copy below, as the
     * AT_EMPTY_PATH publish means it to be; any other symlink is linked as
     * itself. */
    if (is_lnk(st) && !l2s_under_proc(src))
        return l2s_copy_symlink(src, dst, st);
    /* A FIFO, a socket or a device node becomes a group as a regular file
     * does: the node itself moves into the store, so every name opens the one
     * pipe, connects to the one socket. A copy cannot stand in for those. */
    if (!is_data(st) || !own) /* e.g. /proc/self/fd/N O_TMPFILE: copy contents */
        return 1;
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
        mv = l2s_swap_in(src, data, data);
    }
    if (mv != 0)
        L2S_LOG("[cng] l2s: store unavailable (dir=%d mv=%d), per-dir "
                "fallback\n",
                sdr, (int)mv);
    if (mv == 0) {
        char newm[CNG_PATH_MAX];
        int have_m = (build_name(newm, sizeof newm, store, ino, 2) == 0);
        if (have_m)
            l2s_touch(newm);
        long sr = l2s_symlink(data, dst);
        if (sr < 0) { /* full rollback */
            L2S_LOG("[cng] l2s: dst symlink %s -> %d\n", dst, (int)sr);
            if (have_m)
                l2s_unlink(newm);
            l2s_swap_out(src, data);
            return (int)sr;
        }
        return 0;
    }

    /* Store unusable, or the move refused (-EXDEV: src on a bind mount from
     * another filesystem): per-directory scheme, as before. Cross-directory
     * then still degrades to an independent copy. */
    l2s_dirname(src, sdir, sizeof sdir);
    if (strcmp(sdir, ddir) != 0)
        return 1;
    if (build_name(data, sizeof data, sdir, ino, -1) < 0)
        return -ENAMETOOLONG;
    if ((mv = l2s_swap_in(src, data, l2s_basename(data))) < 0) {
        L2S_LOG("[cng] l2s: per-dir move %s -> %d\n", src, (int)mv);
        return (int)mv;
    }
    char newm[CNG_PATH_MAX];
    int have_m = (build_name(newm, sizeof newm, sdir, ino, 2) == 0);
    if (have_m)
        l2s_touch(newm);
    long sr = l2s_symlink(l2s_basename(data), dst);
    if (sr < 0) { /* full rollback */
        if (have_m)
            l2s_unlink(newm);
        l2s_swap_out(src, data);
        return (int)sr;
    }
    return 0;
}

int cng_l2s_link(const char *src, const char *dst) {
    char st[ST_SIZE];
    if (l2s_lstat(dst, st) == 0)
        return -EEXIST; /* link(2): dst must not exist */

    char data[CNG_PATH_MAX], sdir[CNG_PATH_MAX], ddir[CNG_PATH_MAX];
    unsigned long count = 0;
    unsigned long long ino;

    l2s_dirname(dst, ddir, sizeof ddir);

    /* A source outside every place of the guest's own — the file behind a
     * descriptor it was handed, linked by AT_EMPTY_PATH — is never renamed
     * into the store or given a marker beside it: that would move a file,
     * and write a directory, that no name of the guest's reaches. Its
     * contents are copied instead, as for a file with no name at all. */
    int own = l2s_canonical(src) && l2s_owned(src);
    int isl = l2s_link_source(src, own, data, sizeof data, &count);

    /* A first link turns src into a group: renames it into the store and puts
     * a symlink in its place. Two first links of one file at once both found
     * it a file of their own, unlocked, and the later then renamed the
     * earlier's symlink over the data — the file became a link to itself, its
     * contents gone — or found that symlink where it had seen the file, or no
     * src at all between the rename and the symlink, and failed (`ln a b &
     * ln a c`). So what src is, unless it is a member already, is asked again
     * under the lock every group update takes, held until the group exists,
     * and a src another link has made a member meanwhile joins that group.
     * The lock is asked for by src, the inode that becomes the data file:
     * where the store cannot be had, that is what the group's own updates
     * lock (l2s_lock). */
    if (isl <= 0) {
        struct l2s_held lk;
        l2s_lock(src, &lk);
        isl = l2s_link_source(src, own, data, sizeof data, &count);
        if (isl == 0) {
            int r = l2s_first_link(src, dst, ddir, own);
            l2s_unlock(&lk);
            return r == 1 ? l2s_materialize(src, dst) : r;
        }
        l2s_unlock(&lk);
    }
    if (isl < 0)
        return isl;

    if (pr_is_data(l2s_basename(data)))
        return pr_link(data, dst);

    /* Existing group (either format): bump the marker beside the data,
     * then point dst at it — same-directory relative target when dst sits
     * beside the data (the legacy look), absolute host path otherwise
     * (how names in other directories join a group). */
    parse_data(l2s_basename(data), &ino);
    l2s_dirname(data, sdir, sizeof sdir);
    struct l2s_held lk;
    l2s_lock(data, &lk);
    if (lk.fd >= 0 && find_marker(sdir, ino, &count) != 0)
        count = 0; /* re-read under the lock */
    char newm[CNG_PATH_MAX], oldm[CNG_PATH_MAX];
    unsigned long nc = (count ? count : 1) + 1;
    if (build_name(newm, sizeof newm, sdir, ino, (long)nc) < 0) {
        l2s_unlock(&lk);
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
        l2s_unlock(&lk);
        return (int)sr;
    }
    l2s_unlock(&lk);
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
    if (tgt[0] == '/')
        return 0; /* absolute targets survive any move */
    int heal;
    return l2s_locate(srch, tgt, absdata, sz, &heal) == 1;
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
    if (pr_is_data(l2s_basename(data))) {
        pr_drop(data);
        return;
    }
    if (!parse_data(l2s_basename(data), &ino))
        return;
    char dir[CNG_PATH_MAX], m[CNG_PATH_MAX], newm[CNG_PATH_MAX];
    l2s_dirname(data, dir, sizeof dir);
    struct l2s_held lk;
    l2s_lock(data, &lk);
    if (lk.fd >= 0) {
        unsigned long c;
        if (find_marker(dir, ino, &c) == 0)
            count = c; /* fresher than the caller's pre-unlink read */
    }
    if (count <= 1) { /* last reference */
        l2s_unlink(data);
        if (build_name(m, sizeof m, dir, ino, (long)(count ? count : 1)) == 0)
            l2s_unlink(m);
        l2s_unlock(&lk);
        return;
    }
    if (build_name(m, sizeof m, dir, ino, (long)count) == 0 &&
        build_name(newm, sizeof newm, dir, ino, (long)(count - 1)) == 0)
        l2s_rename(m, newm);
    l2s_unlock(&lk);
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
    long s = cng_pin_statx(data, (int)flags, mask, statxbuf);
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
    /* Where the kernel says the file is, which is only a data file of ours
     * — or of proot's — in a place of the guest's own (see l2s_locate). */
    struct pr_group g;
    if (pr_data_here(path, &g)) {
        *count = g.count;
        return 1;
    }
    unsigned long long ino;
    if (!parse_data_exact(l2s_basename(path), &ino) || !l2s_canonical(path) ||
        !l2s_owned(path))
        return 0;
    char dir[CNG_PATH_MAX];
    unsigned long c = 0;
    l2s_dirname(path, dir, sizeof dir);
    if (find_marker(dir, ino, &c) != 0)
        return 0;
    *count = c ? c : 1;
    return 1;
}

/* The host path of the directory behind an open fd, for the one place a
 * listing has to fall back to the path-based machinery. */
static int l2s_fd_dir(long fd, char *out, size_t sz) {
    char link[64], *p = link;
    char *end = link + sizeof link - 1;
    p += cng_strlcpy(p, "/proc/self/fd/", (size_t)(end - p) + 1);
    put_u64(&p, end, (unsigned long long)(unsigned)(int)fd, 1);
    *p = '\0';
    long n = l2s_readlink(link, out, sz - 1);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return 0;
}

int cng_l2s_dirent(long dirfd, const char *name, unsigned long long *ino,
                   unsigned *type) {
    /* One readlink tells an ordinary symlink from ours: the target of ours
     * is a data file's name, absolute (the store, or a legacy group joined
     * from another directory) or bare (a legacy same-directory link); a
     * member of proot's names an indirection, by an absolute path. A name
     * that is not a symlink at all answers EINVAL here, which is what makes
     * this cheap enough to ask about a DT_UNKNOWN record too. */
    char tgt[CNG_PATH_MAX];
    long n = sys_readlinkat((int)dirfd, name, tgt, sizeof tgt - 1);
    if (n <= 0)
        return 0;
    tgt[n] = '\0';
    const char *b = l2s_basename(tgt);
    if (tgt[0] == '/' ? !(parse_data_exact(b, 0) || pr_is_ind(b))
                      : (b != tgt || !parse_data_exact(b, 0)))
        return 0;
    /* What stat(2) of the name answers is the data file — a follow lands on
     * it — so the record carries that inode and type. The target is asked
     * about directly rather than followed by the kernel: a data file is never
     * a symlink, and the link is the guest's to have pointed anywhere — which
     * is why an absolute one is asked about only where l2s_locate would take
     * it as it stands, in a place of the guest's own. */
    char st[ST_SIZE];
    long sr = -1;
    if (tgt[0] != '/')
        sr = CNG_SYS(__NR_newfstatat, (int)dirfd, tgt, st,
                     CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    else if (l2s_canonical(tgt) && l2s_owned(tgt))
        sr = cng_pin_fstatat(tgt, st, CNG_AT_SYMLINK_NOFOLLOW);
    if (sr < 0 || !is_data(st)) {
        if (tgt[0] != '/')
            return 0; /* a bare name with no data beside it: not ours */
        /* Not a data file where it says: an absolute target whose rootfs tree
         * was moved or copied, which cng_l2s_stat self-heals onto the current
         * store, a member of proot's (the target is its indirection), or no
         * link of ours at all — and a listing must say what the stat after it
         * will. */
        char host[CNG_PATH_MAX];
        size_t dl;
        if (l2s_fd_dir(dirfd, host, sizeof host) < 0 ||
            (dl = strlen(host)) + 1 + strlen(name) >= sizeof host)
            return 0;
        if (dl && host[dl - 1] != '/')
            host[dl++] = '/';
        cng_strlcpy(host + dl, name, sizeof host - dl);
        if (cng_l2s_stat(host, st) != 1)
            return 0; /* still dangling: what the kernel said stands */
    }
    *ino = *(unsigned long long *)(st + ST_INO_OFF);
    *type = (st_mode(st) & S_IFMT_) >> 12; /* DT_* is S_IFMT >> 12 */
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
