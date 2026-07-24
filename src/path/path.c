#include "cng/path.h"
#include "cng/rt.h"

/* Strip a trailing '/'; treat "/" as "" (root of host). */
static void normalize_root(char *dst, size_t dstsz, const char *src) {
    size_t n = cng_strlcpy(dst, src, dstsz);
    while (n > 1 && dst[n - 1] == '/')
        dst[--n] = '\0';
    if (n == 1 && dst[0] == '/')
        dst[0] = '\0'; /* "/" => "" */
}

void cng_fs_init(struct cng_fs *fs, const char *rootfs) {
    memset(fs, 0, sizeof *fs);
    normalize_root(fs->rootfs, sizeof fs->rootfs, rootfs ? rootfs : "/");
    fs->cwd[0] = '/';
    fs->cwd[1] = '\0';
}

int cng_fs_add_bind(struct cng_fs *fs, const char *guest, const char *host) {
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
    cng_strlcpy(b->guest, canon, sizeof b->guest);
    normalize_root(b->host, sizeof b->host, host);
    b->glen = (unsigned)strlen(b->guest);
    fs->nbinds++;
    return 0;
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

    if (best >= 0) {
        const char *suffix = canon + blen; /* "" or "/rest" */
        size_t n = cng_strlcpy(out, fs->binds[best].host, outsz);
        cng_strlcpy(out + n, suffix, outsz > n ? outsz - n : 0);
    } else {
        size_t n = cng_strlcpy(out, fs->rootfs, outsz); /* "" or "/root" */
        cng_strlcpy(out + n, canon, outsz > n ? outsz - n : 0);
    }
    return 0;
}

int cng_fs_untranslate(const struct cng_fs *fs, const char *host, char *out,
                       size_t outsz) {
    /* Longest host-prefix bind match, reversed. */
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
    if (best >= 0) {
        const char *suffix = host + blen;
        size_t n = cng_strlcpy(out, fs->binds[best].guest, outsz);
        cng_strlcpy(out + n, suffix, outsz > n ? outsz - n : 0);
        if (out[0] == '\0')
            cng_strlcpy(out, "/", outsz);
        return 0;
    }

    size_t rl = strlen(fs->rootfs);
    if (rl == 0) { /* identity rootfs */
        cng_strlcpy(out, host, outsz);
        return 0;
    }
    if (strncmp(host, fs->rootfs, rl) == 0 &&
        (host[rl] == '/' || host[rl] == '\0')) {
        const char *suffix = host + rl;
        cng_strlcpy(out, suffix[0] ? suffix : "/", outsz);
        return 0;
    }
    return -1; /* outside the guest view */
}
