/* SysV IPC on a libc that may not declare it, plus semctl's union.
 *
 * bionic guards semget/msgget/shmget and everything around them behind
 * __INTRODUCED_IN(26), and Termux's clang targets a lower API by default, so
 * on-device none of the SysV guests compile at all — every call is an implicit
 * declaration, which is an error under C99 and later. The syscalls themselves
 * are unconditional on arm64: there is no ipc() multiplexer to route through
 * and no API level gates a syscall number, so where the wrapper is missing the
 * call goes straight to syscall(). Same answer sem_block.c has always used for
 * semtimedop, and handleat.c for name_to_handle_at.
 *
 * Renamed through macros rather than at the call sites, because at the levels
 * where this fires libc declares none of these names, so nothing collides —
 * and the guests stay written in the ordinary way, which is what makes them
 * readable as a statement of what the kernel does.
 *
 * The cmd is passed to the ctl syscalls verbatim, NOT or'd with IPC_64. A
 * 64-bit arch does not select CONFIG_ARCH_WANT_IPC_PARSE_VERSION, so the kernel
 * never parses a version bit out of cmd and only ever speaks the new layout;
 * setting it makes the switch fall through to EINVAL instead (measured on the
 * host, both ways round).
 *
 * Define CNG_SYSVIPC_FORCE_SYSCALL to take this path on any libc. That is how
 * the shim is tested: build the guests with it on a platform whose wrappers do
 * exist and the differential against the real kernel still has to pass, which
 * it cannot if a wrapper here gets an argument or a return value wrong.
 */
#ifndef CNG_TESTS_SYSVIPC_H
#define CNG_TESTS_SYSVIPC_H

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

/* semctl's fourth argument, under our own name. glibc and musl leave the union
 * to the caller — the classic idiom — while bionic declares a `union semun` of
 * its own, which a local definition then collides with. semctl is variadic, so
 * a differently named union of the same shape is passed alike by all three. */
union cng_semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

#if defined(CNG_SYSVIPC_FORCE_SYSCALL) \
    || (defined(__BIONIC__) && __ANDROID_API__ < 26)

#include <stdarg.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static inline int cng_semget(key_t key, int nsems, int semflg) {
    return (int)syscall(SYS_semget, key, nsems, semflg);
}

static inline int cng_semop(int semid, struct sembuf *sops, size_t nsops) {
    return (int)syscall(SYS_semop, semid, sops, nsops);
}

/* Variadic like the real one, and the argument is read only for the commands
 * that carry one — reading a va_arg that was never passed is undefined, and
 * GETVAL/GETNCNT/IPC_RMID are all called here with three arguments. */
static inline int cng_semctl(int semid, int semnum, int cmd, ...) {
    union cng_semun arg = {0};
    switch (cmd) {
    case SETVAL:
    case GETALL:
    case SETALL:
    case IPC_STAT:
    case IPC_SET:
    /* The three a libc may hide behind _GNU_SOURCE. No guest asks for them;
     * they are here so the switch is the kernel's list, not this suite's. */
#ifdef IPC_INFO
    case IPC_INFO:
#endif
#ifdef SEM_INFO
    case SEM_INFO:
#endif
#ifdef SEM_STAT
    case SEM_STAT:
#endif
    {
        va_list ap;
        va_start(ap, cmd);
        arg = va_arg(ap, union cng_semun);
        va_end(ap);
        break;
    }
    default:
        break;
    }
    return (int)syscall(SYS_semctl, semid, semnum, cmd, arg.buf);
}

static inline int cng_msgget(key_t key, int msgflg) {
    return (int)syscall(SYS_msgget, key, msgflg);
}

static inline int cng_msgsnd(int msqid, const void *msgp, size_t msgsz,
                             int msgflg) {
    return (int)syscall(SYS_msgsnd, msqid, msgp, msgsz, msgflg);
}

static inline ssize_t cng_msgrcv(int msqid, void *msgp, size_t msgsz,
                                 long msgtyp, int msgflg) {
    return (ssize_t)syscall(SYS_msgrcv, msqid, msgp, msgsz, msgtyp, msgflg);
}

static inline int cng_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
    return (int)syscall(SYS_msgctl, msqid, cmd, buf);
}

static inline int cng_shmget(key_t key, size_t size, int shmflg) {
    return (int)syscall(SYS_shmget, key, size, shmflg);
}

/* The kernel hands back the address itself, so syscall()'s own -1-and-errno is
 * already the (void *)-1 the caller compares against. */
static inline void *cng_shmat(int shmid, const void *shmaddr, int shmflg) {
    return (void *)syscall(SYS_shmat, shmid, shmaddr, shmflg);
}

static inline int cng_shmdt(const void *shmaddr) {
    return (int)syscall(SYS_shmdt, shmaddr);
}

static inline int cng_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    return (int)syscall(SYS_shmctl, shmid, cmd, buf);
}

#define semget cng_semget
#define semop  cng_semop
#define semctl cng_semctl
#define msgget cng_msgget
#define msgsnd cng_msgsnd
#define msgrcv cng_msgrcv
#define msgctl cng_msgctl
#define shmget cng_shmget
#define shmat  cng_shmat
#define shmdt  cng_shmdt
#define shmctl cng_shmctl

#endif /* shim */

#endif /* CNG_TESTS_SYSVIPC_H */
