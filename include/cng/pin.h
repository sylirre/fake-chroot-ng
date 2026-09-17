/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* A host path, pinned for one syscall.
 *
 * The walk (cng_resolve) turns a guest name into a host path by reading the
 * tree component by component, and the syscall was then re-issued on that
 * string — which the kernel resolves again, from scratch, following whatever
 * it finds. Between the two, the tree is the guest's to change: a directory
 * on the way replaced by an absolute symlink is followed from the HOST root by
 * the second resolution, and the call lands outside the rootfs. Every
 * path-bearing syscall had that window, and it is the classic time-of-check
 * to time-of-use of a string-based translator (proot has it too).
 *
 * So no host path is handed to the kernel as a string any more. It is split
 * into the directory it is in and the last component; the directory is opened
 * O_PATH and held for the call, verified to be the directory the walk named;
 * and the syscall is made against that descriptor with the last component as
 * a plain name and the NOFOLLOW flag of its family set. A descriptor is an
 * inode, not a name: nothing the guest renames or replaces afterwards moves
 * it. The last component is safe because the walk followed everything that
 * was to be followed — an absolute host path from it never names a symlink
 * the kernel should still follow — so NOFOLLOW changes nothing for a tree at
 * rest and refuses exactly a link that appeared in the race. Where a family
 * has no NOFOLLOW (access, chmod on older kernels, truncate, statfs, chdir,
 * the non-at xattr calls, inotify, an AF_UNIX connect) or where the kernel
 * follows regardless (a trailing slash), the last component is pinned too
 * (cng_pin_leaf), checked not to be a symlink, and the call is made through
 * its own fd link — which resolves to that inode and nothing further.
 *
 * Verifying the directory: the kernel's own name for what was opened
 * (readlink of the fd link) is compared with the path asked for — the rootfs
 * and bind prefixes are stored the way the kernel spells them (canon_host_root
 * in path.c), and everything below them is the walk's canonical, symlink-free
 * form, so the two agree unless a link was followed on the way. When they do
 * not agree the directory is walked from its prefix descriptor by descriptor,
 * each component opened O_NOFOLLOW, which is the authority: a name can differ
 * in spelling and still be the right directory (a case-insensitive
 * filesystem answers the stored case, and a bind of /sdcard is one), and a
 * link met on that walk is the race, refused with ELOOP as RESOLVE_NO_SYMLINKS
 * refuses it.
 *
 * Not pinned, and handed over whole: a relative name against the caller's
 * own dirfd (already a descriptor: the last-component NOFOLLOW is all it
 * needs), an empty name (AT_EMPTY_PATH), anything under the host's /proc (a
 * zone the guest cannot put a symlink in, and whose magic links are meant to
 * be followed), a /dev whitelist node itself (a host object, possibly a
 * symlink of the host's own), and "/". */
#ifndef CNG_PIN_H
#define CNG_PIN_H

#include <stddef.h>

#include "cng/path.h"

struct cng_pin {
    int dfd;      /* the directory the name is against */
    int own;      /* dfd was opened here; cng_unpin closes it */
    int pinned;   /* `name` is one component against dfd: NOFOLLOW applies */
    int want_dir; /* the name asked for a directory (a trailing slash) */
    int leaf;     /* an O_PATH descriptor on the leaf (cng_pin_leaf), or -1 */
    const char *name;
    char link[32]; /* "/proc/self/fd/<leaf>" once the leaf is pinned */
    char buf[CNG_PATH_MAX];
};

/* Prepare (dirfd, path) for a syscall. 0, or the error the kernel would have
 * given for the directory (ENOENT, ENOTDIR, EACCES, ELOOP; EACCES too where
 * nothing can be verified, on a host with no /proc). Always pair with
 * cng_unpin, whatever the answer. */
long cng_pin_at(int dirfd, const char *path, struct cng_pin *p);

/* Pin the last component too: p->leaf and p->link. `need_dir` asks for a
 * directory (ENOTDIR otherwise). A symlink there is ELOOP — the walk saw none,
 * so one is the race. 0 or -errno. */
long cng_pin_leaf(struct cng_pin *p, int need_dir);

/* "/proc/self/fd/<dfd>/<name>" — the pinned pair as one string, for the
 * path-only syscalls that never follow their last component. 0/-1. */
int cng_pin_spell(const struct cng_pin *p, char *out, size_t sz);

void cng_unpin(struct cng_pin *p);

/* The dirfd-free conveniences: one syscall on a host path, race-free. Each
 * answers what the syscall answers. The atflags of the stat forms and the
 * flags of the open are the caller's; the NOFOLLOW is added here. */
long cng_pin_open(const char *host, long flags, long mode);
long cng_pin_fstatat(const char *host, void *st, int atflags);
long cng_pin_statx(const char *host, int atflags, unsigned mask, void *sx);
long cng_pin_readlink(const char *host, char *buf, size_t n);
long cng_pin_symlink(const char *target, const char *host);
long cng_pin_rename(const char *from, const char *to);
long cng_pin_unlink(const char *host, int flags);
long cng_pin_mkdir(const char *host, int mode);

#endif /* CNG_PIN_H */
