/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* A host path, pinned for one syscall: see include/cng/pin.h. Freestanding,
 * raw syscalls only — this runs inside the SIGSYS handler. */
#include "cng/pin.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm-generic/errno.h>

#define ST_MODE_OFF 16
#define S_IFLNK_    0120000u

#define PIN_DIR_FLAGS (CNG_O_PATH | CNG_O_DIRECTORY | CNG_O_CLOEXEC)

static unsigned fd_mode(int fd) {
    char st[128]; /* AArch64 struct stat */
    if (sys_fstat(fd, st) != 0)
        return 0;
    return *(unsigned *)(st + ST_MODE_OFF);
}

static void fd_link(int fd, char *out, size_t sz) {
    cng_snprintf(out, sz, "/proc/self/fd/%d", fd);
}

/* The host's /proc: a zone the guest cannot put a symlink in, and whose magic
 * links are the point of naming it. */
static int under_proc(const char *h) {
    return strncmp(h, "/proc", 5) == 0 && (h[5] == '\0' || h[5] == '/');
}

/* A /dev whitelist node named as itself: a host object the guest cannot
 * replace, and one the host is free to have made a symlink (/dev/ptmx). */
static int dev_node_itself(const char *h) {
    if (cng_g_no_dev)
        return 0;
    for (int i = 0; i < cng_dev_nnodes; i++)
        if (strcmp(h, cng_dev_nodes[i].host) == 0)
            return 1;
    return 0;
}

static int host_under(const char *host, const char *pfx, size_t len) {
    return strncmp(host, pfx, len) == 0 &&
           (host[len] == '/' || host[len] == '\0');
}

/* The longest host prefix `h` lies under — the rootfs, a bind's source, a
 * /dev directory node — copied to `out`; its length, 0 for none (or for an
 * identity rootfs, whose prefix is the host root itself). Those are the
 * directories the host controls and the guest cannot rename or replace, so
 * a walk that has to verify a directory by descriptor starts from one. */
static size_t prefix_of(const char *h, char *out, size_t sz) {
    size_t best = 0;
    out[0] = '\0';
    if (cng_g_fs) {
        const struct cng_fs *v;
        do {
            unsigned seq = cng_fs_read_begin(&v);
            best = 0;
            size_t rl = v->rlen;
            if (rl && host_under(h, v->rootfs, rl)) {
                best = cng_strlcpy(out, v->rootfs, sz);
            }
            for (int i = 0; i < v->nbinds; i++) {
                const char *bh = v->binds[i].host;
                size_t hl = v->binds[i].hlen;
                if (hl > best && host_under(h, bh, hl))
                    best = cng_strlcpy(out, bh, sz);
            }
            if (!cng_fs_read_retry(seq))
                break;
        } while (1);
    }
    if (!cng_g_no_dev)
        for (int i = 0; i < cng_dev_nnodes; i++) {
            const char *dh = cng_dev_nodes[i].host;
            size_t hl = strlen(dh);
            if (hl > best && host_under(h, dh, hl) && !under_proc(dh))
                best = cng_strlcpy(out, dh, sz);
        }
    if (best >= sz) {
        out[0] = '\0';
        return 0;
    }
    return best;
}

/* The directory `dir` reached descriptor by descriptor from its prefix, each
 * component opened O_NOFOLLOW: the authority on whether the directory is the
 * one the walk named, needing no name to agree with. The prefix itself is
 * the host's, opened the ordinary way. Returns the O_PATH descriptor, or the
 * error the resolution meets — and ELOOP for a symlink where the walk saw a
 * directory, which is the race this exists to refuse. */
static long walk_dir(const char *dir) {
    char pfx[CNG_PATH_MAX];
    size_t pl = prefix_of(dir, pfx, sizeof pfx);
    long cur = sys_openat(CNG_AT_FDCWD, pl ? pfx : "/", PIN_DIR_FLAGS, 0);
    if (cur < 0)
        return cur;
    const char *rest = dir + pl;
    while (*rest) {
        while (*rest == '/')
            rest++;
        if (!*rest)
            break;
        const char *end = rest;
        while (*end && *end != '/')
            end++;
        char comp[256]; /* NAME_MAX + 1: a longer component is the kernel's
                         * ENAMETOOLONG before anything is looked up */
        size_t cl = (size_t)(end - rest);
        if (cl >= sizeof comp) {
            sys_close((int)cur);
            return -ENAMETOOLONG;
        }
        memcpy(comp, rest, cl);
        comp[cl] = '\0';
        long nx = sys_openat((int)cur, comp, PIN_DIR_FLAGS | CNG_O_NOFOLLOW, 0);
        if (nx == -ENOTDIR) {
            /* A file, which the kernel refuses the same way — or a symlink,
             * which O_DIRECTORY|O_NOFOLLOW refuses with the same word. */
            char st[128];
            if (CNG_SYS(__NR_newfstatat, (int)cur, (long)comp, (long)st,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0 &&
                (*(unsigned *)(st + ST_MODE_OFF) & CNG_S_IFMT) == S_IFLNK_)
                nx = -ELOOP;
        }
        sys_close((int)cur);
        if (nx < 0)
            return nx;
        cur = nx;
        rest = end;
    }
    return cur;
}

long cng_pin_at(int dirfd, const char *path, struct cng_pin *p) {
    p->dfd = dirfd;
    p->own = 0;
    p->pinned = 0;
    p->want_dir = 0;
    p->leaf = -1;
    p->name = path;
    p->link[0] = '\0';
    if (!path || !path[0])
        return 0;
    size_t n = strlen(path);
    if (path[0] != '/') {
        /* Against the caller's own descriptor (or the cwd, which is one to
         * the kernel): already a place, and only the last component's own
         * link could redirect. The NOFOLLOW is what settles that. */
        p->pinned = 1;
        p->want_dir = path[n - 1] == '/';
        return 0;
    }
    if (n == 1 || under_proc(path) || dev_node_itself(path))
        return 0;

    /* Split: the last component (one trailing slash kept, as the request for
     * a directory it is) and the directory before it. */
    size_t e = n;
    while (e > 1 && path[e - 1] == '/')
        e--;
    if (e < n)
        p->want_dir = 1;
    if (e == 1)
        return 0; /* "//": the root, spelled at length */
    size_t cut = e;
    while (path[cut - 1] != '/')
        cut--;
    size_t cl = e - cut;
    if (cl + 2 > sizeof p->buf)
        return -ENAMETOOLONG;
    memcpy(p->buf, path + cut, cl);
    if (p->want_dir)
        p->buf[cl++] = '/';
    p->buf[cl] = '\0';
    char dir[CNG_PATH_MAX];
    size_t dl = cut > 1 ? cut - 1 : 1;
    memcpy(dir, path, dl);
    dir[dl] = '\0';

    /* The directory, and the kernel's own name for what was opened. A
     * spelling that agrees is the directory at that path, reached without a
     * link (the prefixes are stored as the kernel spells them, and below them
     * the walk's form is symlink-free); one that does not is asked of the
     * descriptor walk, which decides by inodes and not by names. */
    long fd = sys_openat(CNG_AT_FDCWD, dir, PIN_DIR_FLAGS, 0);
    if (fd < 0)
        return fd; /* ENOENT, ENOTDIR, EACCES, ELOOP: the directory's own */
    char lk[32], real[CNG_PATH_MAX];
    fd_link((int)fd, lk, sizeof lk);
    long rn = sys_readlinkat(CNG_AT_FDCWD, lk, real, sizeof real - 1);
    if (rn > 0 && (size_t)rn < sizeof real) {
        real[rn] = '\0';
        if (strcmp(real, dir) == 0)
            goto pinned;
    }
    sys_close((int)fd);
    fd = walk_dir(dir);
    if (fd < 0)
        return fd;
pinned:
    p->dfd = (int)fd;
    p->own = 1;
    p->pinned = 1;
    p->name = p->buf;
    return 0;
}

long cng_pin_leaf(struct cng_pin *p, int need_dir) {
    if (!p->pinned || p->leaf >= 0)
        return -EINVAL;
    char nm[CNG_PATH_MAX];
    size_t n = cng_strlcpy(nm, p->name, sizeof nm);
    if (n >= sizeof nm)
        return -ENAMETOOLONG;
    while (n > 1 && nm[n - 1] == '/')
        nm[--n] = '\0';
    long fd = sys_openat(p->dfd, nm, CNG_O_PATH | CNG_O_NOFOLLOW | CNG_O_CLOEXEC,
                         0);
    if (fd < 0)
        return fd;
    unsigned m = fd_mode((int)fd) & CNG_S_IFMT;
    if (m == S_IFLNK_) {
        sys_close((int)fd);
        return -ELOOP;
    }
    if ((need_dir || p->want_dir) && m != CNG_S_IFDIR) {
        sys_close((int)fd);
        return -ENOTDIR;
    }
    p->leaf = (int)fd;
    fd_link((int)fd, p->link, sizeof p->link);
    return 0;
}

int cng_pin_spell(const struct cng_pin *p, char *out, size_t sz) {
    if (!p->pinned)
        return cng_strlcpy(out, p->name, sz) < sz ? 0 : -1;
    if (p->dfd < 0) /* the cwd: the name is already relative to it */
        return cng_strlcpy(out, p->name, sz) < sz ? 0 : -1;
    return cng_snprintf(out, sz, "/proc/self/fd/%d/%s", p->dfd, p->name) < sz
               ? 0
               : -1;
}

void cng_unpin(struct cng_pin *p) {
    if (p->leaf >= 0) {
        sys_close(p->leaf);
        p->leaf = -1;
    }
    if (p->own && p->dfd >= 0) {
        sys_close(p->dfd);
        p->own = 0;
    }
    p->dfd = -1;
}

/* ---- the whole-path conveniences ---------------------------------------- */

long cng_pin_open(const char *host, long flags, long mode) {
    struct cng_pin p;
    long r = cng_pin_at(CNG_AT_FDCWD, host, &p);
    if (r == 0) {
        if (!p.pinned)
            r = sys_openat(CNG_AT_FDCWD, p.name, flags, mode);
        else if (p.want_dir && !(flags & CNG_O_CREAT)) {
            /* A trailing slash makes the kernel follow whatever O_NOFOLLOW
             * says, so the directory is pinned and opened by its link. (With
             * O_CREAT the kernel answers EISDIR before it looks, which the
             * pinned pair gets from it unchanged.) */
            r = cng_pin_leaf(&p, 1);
            if (r == 0)
                r = sys_openat(CNG_AT_FDCWD, p.link, flags & ~CNG_O_NOFOLLOW,
                               mode);
        } else
            r = sys_openat(p.dfd, p.name, flags | CNG_O_NOFOLLOW, mode);
    }
    cng_unpin(&p);
    return r;
}

/* The stat family: NOFOLLOW on the pinned pair, or the leaf's own link
 * (followed, to an inode that is not a link) where a trailing slash asked for
 * the directory. */
static long stat_form(const char *host, struct cng_pin *p, int *atflags,
                      long *dfd, const char **name) {
    long r = cng_pin_at(CNG_AT_FDCWD, host, p);
    if (r)
        return r;
    *dfd = p->dfd;
    *name = p->name;
    if (!p->pinned)
        return 0;
    if (p->want_dir) {
        r = cng_pin_leaf(p, 1);
        if (r)
            return r;
        *dfd = CNG_AT_FDCWD;
        *name = p->link;
        *atflags &= ~CNG_AT_SYMLINK_NOFOLLOW;
        return 0;
    }
    *atflags |= CNG_AT_SYMLINK_NOFOLLOW;
    return 0;
}

long cng_pin_fstatat(const char *host, void *st, int atflags) {
    struct cng_pin p;
    long dfd;
    const char *name;
    long r = stat_form(host, &p, &atflags, &dfd, &name);
    if (r == 0)
        r = CNG_SYS(__NR_newfstatat, dfd, (long)name, (long)st, atflags, 0, 0);
    cng_unpin(&p);
    return r;
}

long cng_pin_statx(const char *host, int atflags, unsigned mask, void *sx) {
    struct cng_pin p;
    long dfd;
    const char *name;
    long r = stat_form(host, &p, &atflags, &dfd, &name);
    if (r == 0)
        r = CNG_SYS(__NR_statx, dfd, (long)name, atflags, mask, (long)sx, 0);
    cng_unpin(&p);
    return r;
}

long cng_pin_readlink(const char *host, char *buf, size_t n) {
    struct cng_pin p;
    long r = cng_pin_at(CNG_AT_FDCWD, host, &p);
    if (r == 0)
        r = sys_readlinkat(p.dfd, p.name, buf, n);
    cng_unpin(&p);
    return r;
}

long cng_pin_symlink(const char *target, const char *host) {
    struct cng_pin p;
    long r = cng_pin_at(CNG_AT_FDCWD, host, &p);
    if (r == 0)
        r = CNG_SYS(__NR_symlinkat, (long)target, p.dfd, (long)p.name, 0, 0, 0);
    cng_unpin(&p);
    return r;
}

long cng_pin_rename(const char *from, const char *to) {
    struct cng_pin a, b;
    long r = cng_pin_at(CNG_AT_FDCWD, from, &a);
    if (r == 0) {
        r = cng_pin_at(CNG_AT_FDCWD, to, &b);
        if (r == 0)
            r = CNG_SYS(__NR_renameat, a.dfd, (long)a.name, b.dfd, (long)b.name,
                        0, 0);
        cng_unpin(&b);
    }
    cng_unpin(&a);
    return r;
}

long cng_pin_unlink(const char *host, int flags) {
    struct cng_pin p;
    long r = cng_pin_at(CNG_AT_FDCWD, host, &p);
    if (r == 0)
        r = CNG_SYS(__NR_unlinkat, p.dfd, (long)p.name, flags, 0, 0, 0);
    cng_unpin(&p);
    return r;
}

long cng_pin_mkdir(const char *host, int mode) {
    struct cng_pin p;
    long r = cng_pin_at(CNG_AT_FDCWD, host, &p);
    if (r == 0)
        r = CNG_SYS(__NR_mkdirat, p.dfd, (long)p.name, mode, 0, 0, 0);
    cng_unpin(&p);
    return r;
}
