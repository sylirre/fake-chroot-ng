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
    unsigned ro;      /* ":ro" mount: mutating syscalls under it get -EROFS */
};

struct cng_fs {
    char rootfs[512]; /* host root, normalized: no trailing slash; "" == "/" */
    struct cng_bind binds[CNG_MAX_BINDS];
    int nbinds;
    char cwd[CNG_PATH_MAX]; /* canonical guest cwd, default "/" */
};

/* --no-proc: disable the /proc passthrough and the synthesized /proc files, so
 * the guest sees only whatever /proc its rootfs (or an explicit -b) provides. */
extern int cng_g_no_proc;

/* --no-dev: disable the /dev device-node passthrough, so /dev is served from the
 * rootfs (or an explicit -b) only. */
extern int cng_g_no_dev;

/* The /dev passthrough whitelist, shared by the path zone and the getdents64
 * synthesis so the two can never disagree about what /dev contains. `host` is
 * what the name resolves to (usually itself; the std* aliases and fd point into
 * /proc/self/fd), and is what gets lstat'ed for a real d_type when the entry is
 * spliced into a listing. */
struct cng_dev_node {
    const char *name; /* basename under /dev */
    const char *host; /* host path it resolves to */
};
extern const struct cng_dev_node cng_dev_nodes[];
extern const int cng_dev_nnodes;

/* 0, or -1 when the rootfs path does not fit fs->rootfs: it is refused rather
 * than truncated, since a short prefix roots the guest somewhere else. */
int cng_fs_init(struct cng_fs *fs, const char *rootfs);
int cng_fs_add_bind(struct cng_fs *fs, const char *guest, const char *host,
                    int ro);
void cng_fs_set_cwd(struct cng_fs *fs, const char *guest_cwd);

/* 1 if `host` (an already-resolved host path) lies under a read-only bind, so a
 * mutating syscall on it must answer -EROFS. Keyed on the host side — as the
 * oracle's host_ro is — so a guest symlink that lands inside a :ro bind is
 * covered too, however the path got there. */
int cng_fs_host_ro(const struct cng_fs *fs, const char *host);

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
