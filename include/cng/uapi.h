/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Self-contained UAPI constants for AArch64 Linux.
 *
 * We deliberately avoid pulling in libc or hunting through kernel headers for
 * these; the values are part of the stable syscall ABI and identical across
 * every AArch64 kernel we target (>= 3.5).  Keeping them local makes the
 * freestanding build hermetic.
 */
#ifndef CNG_UAPI_H
#define CNG_UAPI_H

/* openat() dirfd / *at() flags */
#define CNG_AT_FDCWD            (-100)
#define CNG_AT_SYMLINK_NOFOLLOW 0x100
#define CNG_AT_REMOVEDIR        0x200
#define CNG_AT_SYMLINK_FOLLOW   0x400
#define CNG_AT_NO_AUTOMOUNT     0x800
#define CNG_AT_EMPTY_PATH       0x1000

/* open() flags */
#define CNG_O_RDONLY    0
#define CNG_O_WRONLY    1
#define CNG_O_RDWR      2
#define CNG_O_ACCMODE   3
#define CNG_O_CREAT     0100
#define CNG_O_EXCL      0200
#define CNG_O_NOCTTY    0400
#define CNG_O_TRUNC     01000
#define CNG_O_APPEND    02000
#define CNG_O_NONBLOCK  04000
#define CNG_O_DSYNC     010000
#define CNG_O_DIRECTORY 040000
#define CNG_O_NOFOLLOW  0100000
#define CNG_O_DIRECT    0200000  /* arm64's own value, not asm-generic's */
#define CNG_O_LARGEFILE 0400000  /* likewise */
#define CNG_O_NOATIME   01000000
#define CNG_O_CLOEXEC   02000000
#define CNG___O_SYNC    04000000
#define CNG___O_TMPFILE 020000000
#define CNG_O_TMPFILE   (CNG___O_TMPFILE | CNG_O_DIRECTORY)

/* linux_dirent64 d_type: S_IFMT >> 12 of the entry's mode. */
#define CNG_DT_UNKNOWN 0
#define CNG_DT_DIR     4
#define CNG_DT_REG     8
#define CNG_DT_LNK     10
#define CNG_O_PATH      010000000

/* renameat2 flags */
#define CNG_RENAME_NOREPLACE 1
#define CNG_RENAME_EXCHANGE  2

/* inotify_add_watch: the one mask bit that changes path resolution. */
#define CNG_IN_DONT_FOLLOW 0x02000000

/* mmap prot */
#define CNG_PROT_NONE   0x0
#define CNG_PROT_READ   0x1
#define CNG_PROT_WRITE  0x2
#define CNG_PROT_EXEC   0x4

/* mmap flags */
#define CNG_MAP_SHARED          0x01
#define CNG_MAP_PRIVATE         0x02
#define CNG_MAP_FIXED           0x10
#define CNG_MAP_ANONYMOUS       0x20
#define CNG_MAP_GROWSDOWN       0x0100
#define CNG_MAP_FIXED_NOREPLACE 0x100000
#define CNG_MAP_FAILED          ((void *)-1L)

/* openat2(2): struct open_how and its resolve constraints. The struct is the
 * kernel's ABI — three u64s, and `size` is checked against it — so it is
 * spelled out here rather than read a field at a time. */
struct cng_open_how {
    unsigned long flags;
    unsigned long mode;
    unsigned long resolve;
};
#define CNG_RESOLVE_NO_XDEV       0x01
#define CNG_RESOLVE_NO_MAGICLINKS 0x02
#define CNG_RESOLVE_NO_SYMLINKS   0x04
#define CNG_RESOLVE_BENEATH       0x08
#define CNG_RESOLVE_IN_ROOT       0x10
#define CNG_RESOLVE_CACHED        0x20

/* clone(2) flags (subset). */
#define CNG_CLONE_VM     0x00000100
#define CNG_CLONE_VFORK  0x00004000

/* fcntl ops (the subset the monitor issues) */
#define CNG_F_DUPFD          0
#define CNG_F_GETFD          1
#define CNG_F_SETFD          2
#define CNG_F_GETFL          3
#define CNG_F_DUPFD_CLOEXEC  1030

/* memfd_create flags */
#define CNG_MFD_CLOEXEC 1

/* clock_gettime clocks. BOOTTIME counts suspend, which is what /proc/uptime
 * reports (CLOCK_MONOTONIC does not). */
#define CNG_CLOCK_REALTIME  0
#define CNG_CLOCK_MONOTONIC 1
#define CNG_CLOCK_BOOTTIME  7

/* getrlimit/prlimit64 resources */
#define CNG_RLIMIT_STACK  3
#define CNG_RLIMIT_NOFILE 7
#define CNG_RLIM_INFINITY (~0UL)

/* sysinfo() load averages are fixed-point, scaled by 1 << SI_LOAD_SHIFT. */
#define CNG_SI_LOAD_SHIFT 16

/* lseek whence */
#define CNG_SEEK_SET 0
#define CNG_SEEK_CUR 1
#define CNG_SEEK_END 2

/* statfs f_flags */
#define CNG_ST_RDONLY 0x0001
#define CNG_ST_NOSUID 0x0002
#define CNG_ST_NODEV  0x0004
#define CNG_ST_NOEXEC 0x0008

/* prctl */
#define CNG_PR_SET_NAME         15
#define CNG_PR_SET_NO_NEW_PRIVS 38
#define CNG_PR_GET_NO_NEW_PRIVS 39
#define CNG_PR_SET_SECCOMP      22
#define CNG_PR_GET_SECCOMP      21
#define CNG_PR_SET_TAGGED_ADDR_CTRL 55
#define CNG_PR_GET_TAGGED_ADDR_CTRL 56
/* Memory-Deny-Write-Execute (Linux 6.3+): with REFUSE_EXEC_GAIN set, an
 * mprotect that adds PROT_EXEC to a mapping is EACCES — the same refusal
 * Android's execmem revocation produces, and the only way a development host
 * can reach the loader's fall back from the anonymous strategy. */
#define CNG_PR_SET_MDWE             65
#define CNG_PR_MDWE_REFUSE_EXEC_GAIN 1

/* seccomp */
#define CNG_SECCOMP_MODE_FILTER      2
#define CNG_SECCOMP_SET_MODE_FILTER  1
#define CNG_SECCOMP_RET_KILL_THREAD  0x00000000U
#define CNG_SECCOMP_RET_TRAP         0x00030000U
#define CNG_SECCOMP_RET_ERRNO        0x00050000U
#define CNG_SECCOMP_RET_TRACE        0x7ff00000U
#define CNG_SECCOMP_RET_ALLOW        0x7fff0000U
#define CNG_SECCOMP_RET_DATA         0x0000ffffU

/* AArch64 seccomp arch token (AUDIT_ARCH_AARCH64) */
#define CNG_AUDIT_ARCH_AARCH64  0xc00000b7U

/* statx mask bits we care about */
#define CNG_STATX_TYPE  0x00000001U
#define CNG_STATX_MODE  0x00000002U
#define CNG_STATX_NLINK 0x00000004U
#define CNG_STATX_BASIC_STATS 0x000007ffU

/* ioctl requests that take write access on the mount the descriptor's file is
 * on (mnt_want_write_file) without the descriptor itself being open for
 * writing — what a :ro bind has to refuse by descriptor (dispatch.c, fd_ro).
 * The encodings are the kernel's, identical on every arch that uses the
 * asm-generic ioctl layout (arm64 and the x86_64 dev host both); FIDEDUPERANGE
 * is apart because its targets are the dest_fd fields of its argument. */
#define CNG_FS_IOC_SETFLAGS              0x40086602u /* _IOW('f', 2, long) */
#define CNG_FS_IOC_FSSETXATTR            0x401c5820u /* _IOW('X', 32, fsxattr) */
#define CNG_FS_IOC_SETVERSION            0x40087602u /* _IOW('v', 2, long) */
#define CNG_FS_IOC_SET_ENCRYPTION_POLICY 0x800c6613u /* _IOR('f', 19, policy) */
#define CNG_FS_IOC_ENABLE_VERITY         0x40806685u /* _IOW('f', 133, arg) */
#define CNG_EXT4_IOC_MIGRATE             0x00006609u /* _IO('f', 9) */
#define CNG_EXT4_IOC_ALLOC_DA_BLKS       0x0000660cu /* _IO('f', 12) */
#define CNG_BTRFS_IOC_SNAP_CREATE        0x50009401u
#define CNG_BTRFS_IOC_SNAP_CREATE_V2     0x50009417u
#define CNG_BTRFS_IOC_SUBVOL_CREATE      0x5000940eu
#define CNG_BTRFS_IOC_SUBVOL_CREATE_V2   0x50009418u
#define CNG_BTRFS_IOC_SNAP_DESTROY       0x5000940fu
#define CNG_BTRFS_IOC_SNAP_DESTROY_V2    0x5000943fu
#define CNG_BTRFS_IOC_DEFRAG             0x50009402u
#define CNG_BTRFS_IOC_DEFRAG_RANGE       0x40309410u
#define CNG_BTRFS_IOC_SUBVOL_SETFLAGS    0x4008941au
#define CNG_BTRFS_IOC_SET_RECEIVED_SUBVOL 0xc0c89425u
#define CNG_F2FS_IOC_SET_PIN_FILE        0x4004f50du
#define CNG_FIDEDUPERANGE                0xc0189436u /* _IOWR(0x94, 54, range) */
/* struct file_dedupe_range: src_offset u64, src_length u64, dest_count u16,
 * two reserved words; then dest_count of struct file_dedupe_range_info:
 * dest_fd s64, dest_offset u64, bytes_deduped u64, status s32, reserved u32. */
#define CNG_DEDUPE_HDR        24
#define CNG_DEDUPE_COUNT_OFF  16
#define CNG_DEDUPE_INFO       32
#define CNG_DEDUPE_STATUS_OFF 24

/* AF_UNIX sockets + ppoll — the --shared-proc registry broker (procreg.c). */
#define CNG_AF_UNIX      1
#define CNG_SOCK_STREAM  1
#define CNG_SOCK_CLOEXEC CNG_O_CLOEXEC
#define CNG_SOL_SOCKET   1
#define CNG_SO_RCVTIMEO  20 /* SO_RCVTIMEO_OLD: takes the 64-bit timeval */
#define CNG_SO_SNDTIMEO  21 /* SO_SNDTIMEO_OLD, likewise */
#define CNG_SO_PEERCRED  17
#define CNG_SO_SNDBUF    7
#define CNG_SO_DOMAIN    39 /* the socket's own address family, in one call */
#define CNG_SCM_RIGHTS   1
#define CNG_MSG_NOSIGNAL 0x4000
#define CNG_MSG_DONTWAIT 0x40
#define CNG_MSG_OOB      0x1  /* msg_flags: out-of-band data, which ends a batch */
#define CNG_MSG_CTRUNC   0x8  /* msg_flags: control data was cut */
#define CNG_MSG_WAITFORONE 0x10000 /* recvmmsg: return once one message is in */
#define CNG_POLLIN       1

/* The kernel clamps sendmmsg/recvmmsg's vlen to this (UIO_MAXIOV) before it
 * loops, so the array forms bound their own walk the same way. */
#define CNG_UIO_MAXIOV   1024

struct cng_sockaddr_un {
    unsigned short family;
    char path[108]; /* path[0] == NUL => abstract namespace */
};
/* sizeof(struct sockaddr_storage): the kernel's own upper bound on an address
 * of any family (it BUG_ONs above it in move_addr_to_user), so a buffer this
 * size always receives a whole address whatever the caller asked for. */
#define CNG_SOCKADDR_MAX 128
struct cng_timeval {
    long tv_sec;
    long tv_usec;
};
struct cng_pollfd {
    int fd;
    short events, revents;
};
struct cng_iovec {
    void *base;
    unsigned long len;
};
/* LP64 syscall ABI layout; natural alignment supplies the kernel's padding. */
struct cng_msghdr {
    void *name;
    unsigned namelen;
    struct cng_iovec *iov;
    unsigned long iovlen;
    void *control;
    unsigned long controllen;
    unsigned flags;
};
/* sendmmsg/recvmmsg's array element: a message plus the byte count the kernel
 * writes back for it. 64 bytes here, as in the kernel's own struct — natural
 * alignment supplies the four bytes of tail padding after msg_len. */
struct cng_mmsghdr {
    struct cng_msghdr hdr;
    unsigned len;
};
struct cng_cmsghdr { /* 8-aligned header, payload follows in place */
    unsigned long len; /* header + payload bytes (CMSG_LEN) */
    int level, type;
};

#endif /* CNG_UAPI_H */
