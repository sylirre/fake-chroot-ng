/* link2symlink: emulate hardlinks with tracked symlinks + a backing file, for
 * hosts that refuse link(2) (Android/SELinux returns EACCES/EXDEV, some EPERM).
 *
 * A guest hardlink group is represented, in the directory of the first-linked
 * name, by:
 *   data   ".l2s.<ino>"          holds the real contents; every "hardlink" name
 *                                is a same-directory *relative* symlink to it
 *                                (so it never dangles and never leaks a host
 *                                path). <ino> is the host inode of the original
 *                                file, giving each group a stable unique name.
 *   marker ".l2s.<ino>.<count>"  an empty file whose name encodes the live link
 *                                count; renamed on every count change, deleted
 *                                with the data on the last unlink.
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

/* Set the first time a backing group is created, so the stat/utimensat fixups
 * can skip their extra path resolution entirely until link2symlink has fired. */
extern int cng_l2s_active;

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

/* If `host` resolves to a backing file (via our symlink, or is the data file
 * itself), stat/statx it into `buf` (a real regular file) with st_nlink set to
 * the live count. Returns 1 (filled), 0 (not ours), or -errno. */
int cng_l2s_stat(const char *host, void *statbuf);
int cng_l2s_statx(const char *host, void *statxbuf);

/* fd variant: if the fd names a backing file, correct st_nlink in `statbuf`. */
void cng_l2s_fix_fd(long fd, void *statbuf);

/* True for any hidden l2s file (data or marker) basename — used to hide them
 * from the guest's directory listings. */
int cng_l2s_hidden(const char *name);

#endif /* CNG_L2S_H */
