/* Path virtualization core: map guest paths onto host paths using a rootfs plus
 * bind mounts, exactly like proot but mechanism-independent (the SIGSYS monitor
 * calls this; so does the `_xlate` debug command). Lexical `..` canonicalization
 * keeps guest paths from escaping the rootfs.
 */
#ifndef CNG_PATH_H
#define CNG_PATH_H

#include <stddef.h>

#define CNG_PATH_MAX  4096
#define CNG_MAX_BINDS 64

struct cng_bind {
    char guest[256];  /* canonical guest prefix */
    char host[512];   /* host path, no trailing slash */
    unsigned glen;    /* strlen(guest) */
};

struct cng_fs {
    char rootfs[512]; /* host root, normalized: no trailing slash; "" == "/" */
    struct cng_bind binds[CNG_MAX_BINDS];
    int nbinds;
    char cwd[CNG_PATH_MAX]; /* canonical guest cwd, default "/" */
};

void cng_fs_init(struct cng_fs *fs, const char *rootfs);
int cng_fs_add_bind(struct cng_fs *fs, const char *guest, const char *host);
void cng_fs_set_cwd(struct cng_fs *fs, const char *guest_cwd);

/* Emulate chroot(2): make the guest directory `guest_root` (canonical, with
 * `host_root` its already-translated host path) the new guest root. Bind
 * mounts and the cwd are rebased onto it rather than dropped — a real chroot
 * unmounts nothing (apk runs every package script under chroot(".")). */
void cng_fs_chroot(struct cng_fs *fs, const char *guest_root,
                   const char *host_root);

/* Lexically canonicalize an absolute guest path (collapse //, ., ..). `..` at
 * the root stays at the root. Returns 0 on success, -1 on overflow. */
int cng_path_canon(const char *abs, char *out, size_t outsz);

/* Resolve a guest path (absolute or relative to fs->cwd) to a canonical guest
 * absolute path (no host rootfs applied). Returns 0/-1. */
int cng_fs_abscanon(const struct cng_fs *fs, const char *path, char *out,
                    size_t outsz);

/* Translate a guest path (absolute, or relative to fs->cwd) to a host path.
 * Returns 0 on success, -1 on overflow. */
int cng_fs_translate(const struct cng_fs *fs, const char *path, char *out,
                     size_t outsz);

/* Reverse translation: map a host path back to the guest path it represents
 * (strip rootfs / reverse binds). Returns 0 on success, -1 if the host path is
 * outside the guest view. Used to keep the virtual cwd in sync after fchdir. */
int cng_fs_untranslate(const struct cng_fs *fs, const char *host, char *out,
                       size_t outsz);

#endif /* CNG_PATH_H */
