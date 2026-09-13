/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Synthesized /proc files.
 *
 * Host /proc passes through (see cng_fs_translate), but a few files there
 * describe chroot-ng rather than the guest, because we never issue a real
 * execve: cmdline is our invocation, environ our exec-time environment, auxv
 * our exec-time auxv block, and maps names host paths for the guest's own
 * libraries. mounts/mountinfo/mountstats describe the host (on Android, the
 * app-sandbox) mount namespace, which confuses df- and apt-style tools.
 * loadavg, uptime and stat are readable here but denied to apps by Android's
 * SELinux policy, where an unpatched guest tool would simply fail. And under
 * --fake-id the Uid:/Gid:/Groups: lines of status carry the real invoking id,
 * which ps/top read to name the user.
 *
 * An open of one of those names is diverted to an anonymous in-memory file
 * holding the guest view, handed over as a read-only description with the
 * guest's status flags on it (what the real file gives) and judged by the same
 * open-flag rules the kernel applies to the real file: write intent is
 * EACCES, O_DIRECT EINVAL, O_NOATIME the owner's, and O_PATH, O_DIRECTORY,
 * O_TMPFILE and O_CREAT|O_EXCL are left to the real open, whose answer needs
 * no content. The fd's own account of itself is the real file's too: fstat
 * (and the by-fd forms of newfstatat and statx), fstatfs, the /proc/self/fd
 * link's text and a stat through that link all name and describe the /proc
 * file, not the memfd behind it — found again from the memfd's name, which
 * follows the inode through dup, fork, exec and a reopen. What still shows the
 * memfd through: mmap of the fd succeeds read-only where the real file
 * answers ENODEV, and fsync returns 0 where it is EINVAL; trapping mmap and
 * fsync wholesale for those is not worth what they would cost. Everything
 * else under /proc stays host passthrough, including stat() of these paths
 * (readers open and read them).
 *
 * Ported from arm64chroot's sys_procfs.c. What differs is what does NOT need
 * synthesizing here: the guest is a real host process, so its status, stat,
 * statm and the /proc/<pid>/maps *addresses* are already true, and /proc/version
 * is correct because chroot-ng does not fake uname.
 */
#ifndef CNG_PROCFS_H
#define CNG_PROCFS_H

#include "cng/rt.h"

/* Number of high fds reserved for synthesized files that refresh on rewind. */
#define CNG_SYNTH_FD_SLOTS 16

/* Lowest fd number reserved for refreshable synthesized files, or 0 when the
 * process's fd limit is too small to reserve a range (then those files keep
 * their open-time snapshot). Set by cng_procfs_init, baked into the seccomp
 * filter as the threshold above which read/pread64/lseek trap, so it must be
 * final before cng_install_seccomp runs. */
extern int cng_g_synth_fd_base;

/* CNG_PROCSTAT_SYNTH=1: serve the synthesized /proc/stat even where the host
 * file is readable. Android denies it to apps (which is what the synthesis is
 * for); test hosts do not, so this is how the fallback gets exercised. */
extern int cng_g_procstat_synth;

/* Bring up the registry and choose the reserved fd range. Called once from
 * cng_run, before the seccomp filter is built. */
void cng_procfs_init(void);

/* Publish this process's guest identity, read straight off the initial stack
 * the loader built for it (argc/argv/envp/auxv, exactly the block a kernel
 * execve would have laid down) plus the current exe and cwd. Called after every
 * stack build — the initial run and each emulated execve — because those are
 * the points a real kernel rewrites cmdline, environ and auxv. Also sets the
 * process name (comm), which the kernel would take from the exec'd file. */
void cng_procfs_publish_stack(unsigned long guest_sp);

/* If `canon` (a canonical guest path) names a synthesized file, open the guest
 * view: returns 1 with *ret set to a host fd or -errno; returns 0 to let the
 * caller fall through to the host. `gflags` are the guest's open flags. */
int cng_procfs_open(const char *canon, long gflags, long *ret);

/* Regenerate a time-varying file (loadavg, uptime, stat) when a read starts at
 * offset 0: procps opens these once and lseek(0)+rereads every refresh cycle,
 * so an open-time snapshot would freeze top and vmstat. `off` is the read's
 * explicit offset, or -1 to use the description's current one. A no-op for any
 * fd that is not a tracked synthesized file. */
void cng_procfs_pre_read(int fd, long off);

/* The fstat family on a synthesized fd. The kernel has just filled `stat` /
 * `statx` — for the memfd behind fd `fd`, or for whatever the name at (dirfd,
 * path) resolved to, which for a stat through /proc/<pid>/fd/N is that memfd
 * too. When that is one of ours, the buffer is refilled from the real /proc
 * file and 1 returned; 0 leaves it as the kernel wrote it. A file whose
 * process is gone gets the attributes every /proc regular file has. `flags`
 * and `mask` are the guest's statx arguments. fstatfs is answered outright
 * with procfs's statfs: 1 with `buf` filled, 0 when the fd is not one of
 * ours, -errno. cng_procfs_link_name turns the memfd's link text ("/memfd:
 * cng-proc:/proc/N/cmdline (deleted)") into the file's name, for readlink of
 * the fd links. */
int cng_procfs_fix_fd(int fd, void *stat);
int cng_procfs_fix_path(long dirfd, const char *path, void *stat);
int cng_procfs_fix_fd_statx(int fd, unsigned flags, unsigned mask, void *statx);
int cng_procfs_fix_path_statx(long dirfd, const char *path, unsigned flags,
                              unsigned mask, void *statx);
int cng_procfs_fstatfs(int fd, void *buf);
int cng_procfs_fix_path_statfs(long dirfd, const char *path, void *buf);
int cng_procfs_link_name(const char *tgt, char *out, size_t sz);

#endif /* CNG_PROCFS_H */
