#include "cng/path.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

int cng_g_no_proc = 0;

/* /proc passes through to the host rather than resolving inside the rootfs: a
 * plain directory tree has no /proc, and we cannot mount one without
 * privileges. A -b bind for the same guest path outranks this (below). */
static int proc_zone(const char *canon) {
    return !cng_g_no_proc && strncmp(canon, "/proc", 5) == 0 &&
           (canon[5] == '\0' || canon[5] == '/');
}

int cng_g_no_dev = 0;

/* The /dev zone. A rootfs directory tree ships no device nodes and mknod(2)
 * needs privileges we do not have, so a fixed whitelist of harmless host
 * devices passes through and everything else under /dev resolves into the
 * rootfs — usually ENOENT. The alternative users reach for, `-b /dev:/dev`, is
 * far coarser: it hands the guest the host's whole /dev, block devices and all.
 *
 * Order matters against the binds: cng_fs_translate matches binds first, so an
 * explicit -b for /dev or a subpath still overrides this.
 *
 * `fd` and the std* aliases point into /proc/self/fd. Guest fd == host fd here,
 * so that link is already the right answer, and it reaches the anonymous files
 * (pipes, memfd, O_TMPFILE) that no re-rooted name could describe at all. The
 * resolver rewrites those to their /proc spelling a step earlier (dev_magic in
 * dispatch.c) so the walk treats them as the magic links they are rather than
 * readlink'ing them as ordinary symlinks; this table is what a direct
 * cng_fs_translate call falls back on, and the two agree. */
const struct cng_dev_node cng_dev_nodes[] = {
    {"null", "/dev/null"},         {"zero", "/dev/zero"},
    {"full", "/dev/full"},         {"random", "/dev/random"},
    {"urandom", "/dev/urandom"},   {"tty", "/dev/tty"},
    {"ptmx", "/dev/ptmx"},         {"console", "/dev/tty"},
    {"pts", "/dev/pts"},           {"shm", "/dev/shm"},
    {"fd", "/proc/self/fd"},       {"stdin", "/proc/self/fd/0"},
    {"stdout", "/proc/self/fd/1"}, {"stderr", "/proc/self/fd/2"},
};
const int cng_dev_nnodes =
    (int)(sizeof cng_dev_nodes / sizeof cng_dev_nodes[0]);

/* Fill `out` for a guest path inside the /dev zone. Returns 1 when it did, 0 to
 * fall through to ordinary rootfs prefixing, -1 when the name did not fit. */
static int dev_zone(const char *canon, char *out, size_t outsz) {
    if (cng_g_no_dev)
        return 0;
    if (strncmp(canon, "/dev", 4) != 0 || (canon[4] && canon[4] != '/'))
        return 0;
    if (!canon[4])
        return 0; /* "/dev" itself is the rootfs directory we list into */
    const char *leaf = canon + 5;
    for (int i = 0; i < cng_dev_nnodes; i++) {
        size_t nl = strlen(cng_dev_nodes[i].name);
        if (strncmp(leaf, cng_dev_nodes[i].name, nl) != 0)
            continue;
        char c = leaf[nl];
        if (c == '\0') {
            cng_strlcpy(out, cng_dev_nodes[i].host, outsz);
            return 1;
        }
        /* A subpath is only meaningful for the directory-valued entries
         * (pts/<n>, shm/<name>, fd/<n>); a device node has no children. */
        if (c == '/') {
            const char *h = cng_dev_nodes[i].host;
            if (strcmp(h, "/dev/pts") == 0 || strcmp(h, "/dev/shm") == 0 ||
                strcmp(h, "/proc/self/fd") == 0) {
                size_t n = cng_strlcpy(out, h, outsz);
                if (n >= outsz ||
                    cng_strlcpy(out + n, leaf + nl, outsz - n) >= outsz - n)
                    return -1; /* truncated: the caller must not use `out` */
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

/* The hidden-process view: a numeric entry of the host's real /proc that is not
 * a guest process must appear not to exist, so the guest sees only its own
 * session. The test is on the RESOLVED HOST path, not on the guest one, so it
 * holds however the path got there — the passthrough above, or an explicit
 * `-b /proc:/proc`, which otherwise would have handed the guest the host's
 * whole process list. Every path syscall funnels through cng_fs_translate, so
 * this one check covers open/stat/readlink/execve and the *at forms alike.
 *
 * Non-numeric names (self, sys, net, version, ...) are global or virtualized
 * elsewhere, and always pass through. */
static int host_proc_hidden(const char *host) {
    if (cng_g_no_proc || strncmp(host, "/proc/", 6) != 0)
        return 0;
    const char *p = host + 6;
    if (*p < '0' || *p > '9')
        return 0;
    long pid = 0;
    for (; *p && *p != '/'; p++) {
        if (*p < '0' || *p > '9')
            return 0; /* not a pid ("1abc"): an ordinary host name */
        pid = pid * 10 + (*p - '0');
        if (pid > 0x7fffffff)
            return 0;
    }
    return !cng_procreg_has((int)pid);
}

/* Redirect a hidden process's path to /proc/0, which never exists: pid 0 is the
 * idle task and the kernel gives it no /proc entry. That yields the ENOENT a
 * guest reads as "no such process", whatever the rootfs is — prefixing the
 * rootfs instead would not hide anything under an identity ("/") root. */
static void hide_proc_pid(char *out, size_t outsz) {
    const char *rest = out + 6;
    while (*rest && *rest != '/')
        rest++;
    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, "/proc/0", sizeof tmp);
    cng_strlcpy(tmp + n, rest, sizeof tmp - n);
    cng_strlcpy(out, tmp, outsz);
}

/* Strip a trailing '/'; treat "/" as "" (root of host). Returns 0, or -1 when
 * `src` did not fit — a truncation is not something to tolerate here: this is a
 * prefix every guest path is joined to, so a short one silently roots the guest
 * at some ancestor of the tree that was asked for, or
 * — since the cut lands wherever 512 bytes happen to end — at a path that is
 * not a directory at all. The caller refuses instead. */
static int normalize_root(char *dst, size_t dstsz, const char *src) {
    size_t n = cng_strlcpy(dst, src, dstsz);
    if (n >= dstsz) {
        /* cng_strlcpy reports the length of the SOURCE, so n is past the end of
         * dst: the trim below would read there, and write there for a byte that
         * happened to be '/'. */
        dst[0] = '\0';
        return -1;
    }
    while (n > 1 && dst[n - 1] == '/')
        dst[--n] = '\0';
    if (n == 1 && dst[0] == '/')
        dst[0] = '\0'; /* "/" => "" */
    return 0;
}

/* Store a host prefix (the rootfs, a bind source) the way the kernel spells it:
 * symlink-free. These prefixes are not only prepended to guest paths, they are
 * matched against host paths the kernel *produced* — getcwd() after the guest
 * fchdir()s, a /proc/self/fd readback — and the kernel always reports those
 * fully resolved. An unresolved prefix therefore matches nothing coming back,
 * and every reverse lookup falls out of the guest view.
 *
 * Android is where this bites: the app hands us the rootfs under
 * /data/user/0/<pkg>, a symlink to /data/data/<pkg>. apk runs a package script
 * by fchdir()ing to its root fd and exec'ing a *relative* path; getcwd() then
 * answered /data/data/..., which cng_fs_untranslate could not reverse, so the
 * virtual cwd stayed where it was and the script resolved under it — ENOENT.
 *
 * Resolved by opening the directory and reading back the kernel's own name for
 * it. Anything that does not resolve (a nonexistent path — diagnosed by the
 * caller — or the synthetic roots the self-tests use, which have no host inode)
 * is kept verbatim, exactly as before. */
static int canon_host_root(char *dst, size_t dstsz, const char *src) {
    long fd = sys_openat(CNG_AT_FDCWD, src,
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd >= 0) {
        char link[40], real[CNG_PATH_MAX];
        cng_snprintf(link, sizeof link, "/proc/self/fd/%d", (int)fd);
        long n = sys_readlinkat(CNG_AT_FDCWD, link, real, sizeof real - 1);
        sys_close((int)fd);
        /* A deleted or otherwise unnamed directory reads back as something
         * that is not an absolute path ("... (deleted)", "pipe:[N]"); only a
         * plain absolute name is a prefix we can match against. */
        if (n > 0 && (size_t)n < sizeof real && real[0] == '/') {
            real[n] = '\0';
            if (!strchr(real, ' '))
                return normalize_root(dst, dstsz, real);
        }
    }
    return normalize_root(dst, dstsz, src);
}

int cng_fs_init(struct cng_fs *fs, const char *rootfs) {
    memset(fs, 0, sizeof *fs);
    int r = canon_host_root(fs->rootfs, sizeof fs->rootfs, rootfs ? rootfs : "/");
    fs->cwd[0] = '/';
    fs->cwd[1] = '\0';
    return r;
}

int cng_fs_add_bind(struct cng_fs *fs, const char *guest, const char *host,
                    int ro) {
    if (fs->nbinds >= CNG_MAX_BINDS)
        return -1;
    struct cng_bind *b = &fs->binds[fs->nbinds];
    char canon[CNG_PATH_MAX];
    if (guest[0] == '/') {
        if (cng_path_canon(guest, canon, sizeof canon) < 0)
            return -1;
    } else {
        return -1; /* bind guest paths must be absolute */
    }
    /* Same reasoning as the rootfs: a bind prefix that does not fit would be
     * cut to some shorter guest path, and then the host directory is exposed
     * at a name nobody asked for. */
    if (cng_strlcpy(b->guest, canon, sizeof b->guest) >= sizeof b->guest)
        return -1;
    if (canon_host_root(b->host, sizeof b->host, host) != 0)
        return -1;
    b->glen = (unsigned)strlen(b->guest);
    b->ro = ro ? 1u : 0u;
    fs->nbinds++;
    return 0;
}

int cng_fs_host_ro(const struct cng_fs *fs, const char *host) {
    int best = -1;
    size_t blen = 0;
    for (int i = 0; i < fs->nbinds; i++) {
        const char *bh = fs->binds[i].host;
        size_t hl = strlen(bh);
        if (hl && strncmp(host, bh, hl) == 0 &&
            (host[hl] == '/' || host[hl] == '\0') && hl > blen) {
            best = i;
            blen = hl;
        }
    }
    return best >= 0 && fs->binds[best].ro;
}

/* Rebase a canonical guest path onto a new root: under root "/a", "/a/b"
 * becomes "/b" and "/a" itself becomes "/". Returns 0 when `p` falls outside
 * the new root (a real chroot makes it unreachable). `rlen` is 0 for "/". */
static int rebase(char *dst, size_t dstsz, const char *p, const char *root,
                  size_t rlen) {
    if (rlen == 0) {
        cng_strlcpy(dst, p, dstsz);
        return 1;
    }
    if (strncmp(p, root, rlen) != 0 || (p[rlen] && p[rlen] != '/'))
        return 0;
    cng_strlcpy(dst, p[rlen] ? p + rlen : "/", dstsz);
    return 1;
}

void cng_fs_chroot(struct cng_fs *fs, const char *guest_root,
                   const char *host_root) {
    char root[CNG_PATH_MAX];
    if (cng_path_canon(guest_root, root, sizeof root) < 0)
        return;
    size_t rlen = strlen(root);
    if (rlen == 1) /* "/": everything stays where it is */
        rlen = 0;

    /* Binds are mounts: chroot doesn't unmount them, it only moves the root
     * they are named from. Those under the new root keep working (rebased);
     * the rest fall out of the guest's view. A bind *at* the new root needs no
     * entry — its host side becomes the rootfs below. */
    int w = 0;
    for (int i = 0; i < fs->nbinds; i++) {
        char g[sizeof fs->binds[0].guest];
        if (!rebase(g, sizeof g, fs->binds[i].guest, root, rlen) ||
            strcmp(g, "/") == 0)
            continue;
        if (w != i)
            fs->binds[w] = fs->binds[i];
        cng_strlcpy(fs->binds[w].guest, g, sizeof fs->binds[w].guest);
        fs->binds[w].glen = (unsigned)strlen(fs->binds[w].guest);
        w++;
    }
    fs->nbinds = w;

    char cwd[CNG_PATH_MAX];
    if (rebase(cwd, sizeof cwd, fs->cwd, root, rlen))
        cng_strlcpy(fs->cwd, cwd, sizeof fs->cwd);
    else
        cng_strlcpy(fs->cwd, "/", sizeof fs->cwd);

    normalize_root(fs->rootfs, sizeof fs->rootfs, host_root);
}

void cng_fs_set_cwd(struct cng_fs *fs, const char *guest_cwd) {
    char canon[CNG_PATH_MAX];
    if (guest_cwd[0] == '/' &&
        cng_path_canon(guest_cwd, canon, sizeof canon) == 0)
        cng_strlcpy(fs->cwd, canon, sizeof fs->cwd);
}

int cng_path_canon(const char *abs, char *out, size_t outsz) {
    size_t olen = 0;
    const char *p = abs;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != '/')
            p++;
        size_t clen = (size_t)(p - start);
        if (clen == 1 && start[0] == '.')
            continue;
        if (clen == 2 && start[0] == '.' && start[1] == '.') {
            while (olen > 0 && out[olen - 1] != '/')
                olen--; /* drop last component */
            if (olen > 0)
                olen--; /* drop its leading '/' */
            continue;
        }
        if (olen + 1 + clen >= outsz)
            return -1;
        out[olen++] = '/';
        memcpy(out + olen, start, clen);
        olen += clen;
    }
    if (olen == 0)
        out[olen++] = '/';
    out[olen] = '\0';
    return 0;
}

int cng_fs_abscanon(const struct cng_fs *fs, const char *path, char *out,
                    size_t outsz) {
    char tmp[CNG_PATH_MAX];
    if (path[0] == '/') {
        cng_strlcpy(tmp, path, sizeof tmp);
    } else {
        size_t n = cng_strlcpy(tmp, fs->cwd, sizeof tmp);
        if (n && tmp[n - 1] != '/' && n + 1 < sizeof tmp) {
            tmp[n++] = '/';
            tmp[n] = '\0';
        }
        cng_strlcpy(tmp + n, path, sizeof tmp - n);
    }
    return cng_path_canon(tmp, out, outsz);
}

int cng_fs_translate(const struct cng_fs *fs, const char *path, char *out,
                     size_t outsz) {
    char canon[CNG_PATH_MAX];
    if (cng_fs_abscanon(fs, path, canon, sizeof canon) < 0)
        return -1;

    /* Longest-prefix bind match. */
    int best = -1;
    unsigned blen = 0;
    for (int i = 0; i < fs->nbinds; i++) {
        const struct cng_bind *b = &fs->binds[i];
        if (strncmp(canon, b->guest, b->glen) == 0 &&
            (canon[b->glen] == '/' || canon[b->glen] == '\0')) {
            if (b->glen > blen) {
                best = i;
                blen = b->glen;
            }
        }
    }

    /* A prefix that does not fit is a failure, never a shorter path. cng_strlcpy
     * reports what the source needed, so truncation is visible — and it has to
     * be acted on: silently cut, "<rootfs>/very/long/name" becomes a different
     * name that exists, so an unlink deletes the wrong entry and an O_CREAT
     * makes the wrong file. The caller answers -ENAMETOOLONG, which is what a
     * kernel whose PATH_MAX the name exceeded would have said. */
    int dz = 0;
    if (best >= 0) {
        const char *suffix = canon + blen; /* "" or "/rest" */
        size_t n = cng_strlcpy(out, fs->binds[best].host, outsz);
        if (n >= outsz || cng_strlcpy(out + n, suffix, outsz - n) >= outsz - n)
            return -1;
    } else if (proc_zone(canon)) {
        /* A bind wins over the passthrough (checked first, above): an explicit
         * -b DIR:/proc is the user overriding the host view. */
        if (cng_strlcpy(out, canon, outsz) >= outsz)
            return -1;
    } else if ((dz = dev_zone(canon, out, outsz)) != 0) {
        if (dz < 0)
            return -1; /* filled by the zone, unless it did not fit */
    } else {
        size_t n = cng_strlcpy(out, fs->rootfs, outsz); /* "" or "/root" */
        if (n >= outsz || cng_strlcpy(out + n, canon, outsz - n) >= outsz - n)
            return -1;
    }
    /* Applied to the result, so a bind onto the host /proc is covered too. */
    if (host_proc_hidden(out))
        hide_proc_pid(out, outsz);
    return 0;
}

/* Does `host` start with the host prefix `pfx` (of length `len`) at a component
 * boundary? A zero-length prefix is the identity rootfs, which covers the whole
 * filesystem and so matches everything. */
static int host_under(const char *host, const char *pfx, size_t len) {
    return len == 0 || (strncmp(host, pfx, len) == 0 &&
                        (host[len] == '/' || host[len] == '\0'));
}

int cng_fs_untranslate(const struct cng_fs *fs, const char *host, char *out,
                       size_t outsz) {
    /* Longest host-prefix match, with the rootfs standing in the same contest as
     * the binds rather than being consulted only after they all miss.
     *
     * Forward, the rule is "longest *guest* prefix wins", and the rootfs is the
     * shortest prefix there is ("/"), so every matching bind outranks it for
     * free. The mirror of that rule is this one — and it is not the same thing
     * as "binds first, rootfs otherwise", because a rootfs that lives *inside*
     * a bound directory is reachable both ways, and then the bind is the
     * shorter, less specific of the two.
     *
     * That is not a contrived arrangement: on Termux the suite's own rootfs
     * comes from mktemp under $TMPDIR, which is inside $PREFIX — and $PREFIX is
     * bound in so a dynamically linked guest can find its linker. Answering
     * with the bind spelling then reported the guest's own /bin/prog, its cwd,
     * and every AF_UNIX name it bound as the host path they sit at on the
     * device, and left the /dev zone and the bind mount points unrecognizable
     * when a dirfd was resolved back through here. */
    int best = -2; /* -2 nothing matched, -1 the rootfs, >= 0 that bind */
    size_t blen = 0;
    size_t rl = strlen(fs->rootfs); /* "" for an identity rootfs */
    if (host_under(host, fs->rootfs, rl)) {
        best = -1;
        blen = rl;
    }
    for (int i = 0; i < fs->nbinds; i++) {
        const char *bh = fs->binds[i].host;
        size_t hl = strlen(bh);
        if (hl > blen && host_under(host, bh, hl)) {
            best = i;
            blen = hl;
        }
    }
    if (best == -2)
        return -1; /* outside the guest view */

    /* Truncation is a failure here too, and a bind can make the guest spelling
     * the LONGER of the two — `-b /x:/a/very/long/mount/point` grows every path
     * under it — so this direction is not safe by construction either. Callers
     * read a non-zero return as "outside the guest view" and leave the host
     * name alone, which is the right answer for a name that cannot be said. */
    const char *suffix = host + blen;
    size_t n = cng_strlcpy(out, best >= 0 ? fs->binds[best].guest : "", outsz);
    if (n >= outsz || cng_strlcpy(out + n, suffix, outsz - n) >= outsz - n)
        return -1;
    if (out[0] == '\0')
        cng_strlcpy(out, "/", outsz);
    return 0;
}
