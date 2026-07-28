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
#define CNG_O_CREAT     0100
#define CNG_O_EXCL      0200
#define CNG_O_TRUNC     01000
#define CNG_O_APPEND    02000
#define CNG_O_NONBLOCK  04000
#define CNG_O_DIRECTORY 040000
#define CNG_O_NOFOLLOW  0100000
#define CNG_O_CLOEXEC   02000000
#define CNG_O_TMPFILE   (020000000 | CNG_O_DIRECTORY)

/* renameat2 flags */
#define CNG_RENAME_NOREPLACE 1
#define CNG_RENAME_EXCHANGE  2

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

/* AF_UNIX sockets + ppoll — the --shared-proc registry broker (procreg.c). */
#define CNG_AF_UNIX      1
#define CNG_SOCK_STREAM  1
#define CNG_SOCK_CLOEXEC CNG_O_CLOEXEC
#define CNG_SOL_SOCKET   1
#define CNG_SO_RCVTIMEO  20 /* SO_RCVTIMEO_OLD: takes the 64-bit timeval */
#define CNG_SO_SNDTIMEO  21 /* SO_SNDTIMEO_OLD, likewise */
#define CNG_SO_PEERCRED  17
#define CNG_SO_DOMAIN    39 /* the socket's own address family, in one call */
#define CNG_SCM_RIGHTS   1
#define CNG_MSG_NOSIGNAL 0x4000
#define CNG_MSG_DONTWAIT 0x40
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
