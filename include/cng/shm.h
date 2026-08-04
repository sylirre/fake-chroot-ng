/* System V shared memory (shmget/shmat/shmdt/shmctl), emulated in-process.
 *
 * Android denies all four syscalls (they are not on the app seccomp allow-list
 * and SELinux forbids the class), so a guest that uses them — anything built
 * against a stock libc's shm functions, PostgreSQL, X clients, dpkg's own
 * plumbing — dies on the first call. chroot-ng serves them instead, without
 * ever issuing a host SysV IPC syscall and without needing /dev/shm: the
 * per-namespace broker daemon (broker.h) is the authoritative registry and owns
 * each segment's backing fd, and shmat maps that fd MAP_SHARED into this
 * process, which is also the guest's address space.
 *
 * Ported from arm64chroot's src/sys_ipc.c. The emulator there had to map into a
 * synthetic guest address space; here the mapping is an ordinary host mmap, so
 * the attach-address rules (SHM_RND/SHM_REMAP/an occupied range) are expressed
 * as mmap flags instead.
 */
#ifndef CNG_SHM_H
#define CNG_SHM_H

#include "cng/rt.h"

/* shmget() shmflg: the low 9 bits are the permission mode; these are the
 * control flags above them (asm-generic == every arch). */
#define CNG_IPC_CREAT   01000 /* create if the key does not exist */
#define CNG_IPC_EXCL    02000 /* with IPC_CREAT: fail if the key exists */
#define CNG_IPC_PRIVATE 0     /* private key: always a fresh segment */

/* shmctl() cmd. IPC_* are the generic ops, SHM_* the shm-specific ones.
 * Callers pass them OR'd with IPC_64 (0x100) on arm64; shm.c strips it. */
#define CNG_IPC_RMID     0
#define CNG_IPC_SET      1
#define CNG_IPC_STAT     2
#define CNG_IPC_INFO     3
#define CNG_SHM_LOCK     11
#define CNG_SHM_UNLOCK   12
#define CNG_SHM_STAT     13
#define CNG_SHM_INFO     14
#define CNG_SHM_STAT_ANY 15

/* A mode bit rather than a permission: set by IPC_RMID on a segment that still
 * has attachers, and the only way a caller can tell one marked for destruction
 * from an ordinary one (`ipcs -m` prints it as the "dest" status). */
#define CNG_SHM_DEST 01000

/* shmat() shmflg. */
#define CNG_SHM_RDONLY 010000  /* attach read-only */
#define CNG_SHM_RND    020000  /* round the attach address down to SHMLBA */
#define CNG_SHM_REMAP  040000  /* take over an existing mapping at the address */
#define CNG_SHM_EXEC   0100000 /* execute permission on the segment */

/* asm-generic struct ipc64_perm (48 bytes). The guest is native AArch64, so
 * this is simply the host layout. */
struct cng_ipc64_perm {
    s32 key;
    u32 uid, gid, cuid, cgid;
    u32 mode;
    u16 seq;
    u16 __pad2;
    u32 __pad3; /* aligns __unused1 to offset 32 */
    u64 __unused1, __unused2;
};

/* asm-generic struct shmid64_ds for arm64 (LP64: shm_[adc]time are 8 bytes). */
struct cng_shmid64_ds {
    struct cng_ipc64_perm shm_perm; /* @0  operation permission struct */
    u64 shm_segsz;                  /* @48 size of the segment in bytes */
    s64 shm_atime;                  /* @56 last attach time */
    s64 shm_dtime;                  /* @64 last detach time */
    s64 shm_ctime;                  /* @72 last change time */
    s32 shm_cpid;                   /* @80 pid of the creator */
    s32 shm_lpid;                   /* @84 pid of the last shmat/shmdt */
    u64 shm_nattch;                 /* @88 current attaches */
    u64 __unused4, __unused5;       /* @96 */
};                                  /* 112 bytes */

/* struct shm_info (SHM_INFO output), asm-generic LP64 (48 bytes). */
struct cng_shm_info {
    s32 used_ids;
    s32 __pad; /* aligns shm_tot to offset 8 */
    u64 shm_tot;
    u64 shm_rss;
    u64 shm_swp;
    u64 swap_attempts, swap_successes; /* deprecated (0) */
};

/* struct shminfo64 (IPC_INFO output), asm-generic LP64 (72 bytes). */
struct cng_shminfo64 {
    u64 shmmax, shmmin, shmmni, shmseg, shmall;
    u64 __unused1, __unused2, __unused3, __unused4;
};

/* Emulate one of the four syscalls. `nr` selects; only the first three
 * arguments are meaningful to any of them. Returns the guest result (an
 * address for shmat, else 0 / an id / -errno). */
long cng_shm_handle(long nr, long a0, long a1, long a2);

/* Re-count every attachment a fork child inherited (the host fork copied both
 * the mappings and the attach list, so the broker must count them again). Run
 * by the child, right after its clone returns 0. */
void cng_shm_fork_child(void);

/* Detach every attachment: unmap it and drop it from the broker's count. A real
 * execve tears down the address space, so the emulated one must do this at its
 * commit point. There is no exit hook — see the reclaim note in broker.c. */
void cng_shm_detach_all(void);

#endif /* CNG_SHM_H */
