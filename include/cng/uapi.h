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
#define CNG_O_DIRECTORY 0200000
#define CNG_O_CLOEXEC   02000000

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
#define CNG_PR_SET_NO_NEW_PRIVS 38
#define CNG_PR_GET_NO_NEW_PRIVS 39
#define CNG_PR_SET_SECCOMP      22
#define CNG_PR_GET_SECCOMP      21

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
#define CNG_STATX_BASIC_STATS 0x000007ffU

#endif /* CNG_UAPI_H */
