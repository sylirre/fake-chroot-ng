/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* link2symlink: emulate hardlinks with tracked symlinks + a backing file, for
 * hosts that refuse link(2) (Android/SELinux returns EACCES/EXDEV, some EPERM).
 *
 * A guest hardlink group lives in the per-rootfs object store "<rootfs>/.l2s":
 *   data   ".l2s.<ino>"          holds the real contents; every "hardlink" name
 *                                is a symlink carrying the data file's absolute
 *                                *host* path, so links span directories and
 *                                survive renames of names or parent dirs. <ino>
 *                                is the host inode of the original file (kept
 *                                by the rename into the store), giving each
 *                                group a stable unique name and pinning the
 *                                inode number against reuse.
 *   marker ".l2s.<ino>.<count>"  an empty file whose name encodes the live link
 *                                count; renamed on every count change, deleted
 *                                with the data on the last unlink.
 * When the store is unusable or the source sits on another filesystem (bind
 * mount: rename returns EXDEV), the group falls back to the pre-store layout —
 * data + marker in the first-linked name's own directory, names as same-
 * directory *relative* symlinks. That legacy format (also what arm64chroot
 * writes) is still recognized everywhere; absolute targets whose rootfs prefix
 * went stale (the tree was moved) self-heal onto the current store.
 *
 * stat/statx on any of the names is redirected to the data file, with st_nlink
 * overridden to the marker count, so the group presents as ordinary regular
 * files sharing one inode (matching st_ino, shared contents) — which is what
 * lets programs that set+verify metadata (e.g. apk preserving mtime) succeed.
 *
 * All paths here are already rootfs-resolved *host* paths. Freestanding: raw
 * syscalls only, safe to call from the SIGSYS handler. Triggered as the linkat
 * fallback, and only when opted into with -l/--link2symlink.
 */
#ifndef CNG_L2S_H
#define CNG_L2S_H

#include <stddef.h>

/* -l/--link2symlink: opt in to the emulation. Off by default — a host that
 * refuses link(2) then reports that refusal to the guest verbatim, rather than
 * silently substituting symlinks + hidden backing files for its hardlinks. */
extern int cng_g_l2s;

/* CNG_L2S_FORCE=1 in the environment: route every linkat through the emulation
 * without trying the real hardlink first. Test aid for hosts whose filesystem
 * happily allows link(2) (mirrors arm64chroot's A64_L2S_FORCE). */
extern int cng_g_l2s_force;

/* Emulate link(src, dst) (host paths) via the backing-file symlink scheme.
 * Returns 0 or -errno. */
int cng_l2s_link(const char *src, const char *dst);

/* If `host` is one of our l2s symlinks, fill `data` with its backing-file path
 * and *count with the marker count (0 if the marker is lost). Returns 1 (ours),
 * 0 (a real file/symlink), or -errno. `count` may be NULL. */
int cng_l2s_resolve(const char *host, char *data, size_t dsz,
                    unsigned long *count);

/* One name of a group was removed: `data`/`count` come from cng_l2s_resolve run
 * *before* the removal. Decrement the marker; delete data+marker on the last. */
void cng_l2s_decref(const char *data, unsigned long count);

/* Rename support for legacy-format links (bare same-directory symlink
 * targets, which dangle when the name moves away from its data): before the
 * rename, `prep` captures the data file's absolute host path (1 = ours,
 * caller must fix up after a successful move); after it, `fixup` repoints the
 * moved name unless it still sits beside the data. */
int cng_l2s_rename_prep(const char *srch, char *absdata, size_t sz);
void cng_l2s_rename_fixup(const char *dsth, const char *absdata);

/* If `host` resolves to a backing file (via our symlink, or is the data file
 * itself), stat/statx it into `buf` (a real regular file) with st_nlink set to
 * the live count. statx honors the guest's mask and (follow-forced) flags and
 * advertises STATX_NLINK. Returns 1 (filled), 0 (not ours), or -errno. */
int cng_l2s_stat(const char *host, void *statbuf);
int cng_l2s_statx(const char *host, void *statxbuf, unsigned mask,
                  unsigned flags);

/* fd variants: if the fd names a backing file, correct st_nlink (and for
 * statx, advertise STATX_NLINK) in the buffer. */
void cng_l2s_fix_fd(long fd, void *statbuf);
void cng_l2s_fix_fd_statx(long fd, void *statxbuf);

/* True for any hidden l2s file (data or marker) basename — used to hide them
 * from the guest's directory listings. */
int cng_l2s_hidden(const char *name);

/* If `tgt` (a symlink target) is an absolute host path naming an l2s data
 * file, fill `out` with its guest-view path — for the guest-level resolver,
 * which must not re-root such targets as guest paths. Self-heals store paths
 * whose rootfs prefix went stale. Returns 1 (filled) or 0 (not ours). */
int cng_l2s_untranslate_target(const char *tgt, char *out, size_t sz);

/* 1 if the guest-supplied (dirfd, path) names l2s machinery — a data/marker
 * basename anywhere, or the "/.l2s" store dir — which must appear not to
 * exist (callers return -ENOENT before any resolution). */
int cng_l2s_deny(long dirfd, const char *gp);

#endif /* CNG_L2S_H */
