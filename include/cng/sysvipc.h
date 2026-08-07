/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* System V semaphores and message queues, emulated in-process.
 *
 * The companion to shm.h. M12 gave the guest its own shared-memory namespace but
 * left semget/semop/semctl/semtimedop and msgget/msgsnd/msgrcv/msgctl running
 * natively, so on a desktop host the guest operated in the HOST's sem/msg
 * namespace — it could attach to host semaphores, and host `ipcs -s`/`-q` listed
 * the guest's objects. They were refused ENOSYS as a stop-gap (the oracle's
 * answer); this is the emulation that replaces the refusal, and it is also what
 * makes them work at all on Android, where the whole SysV family is off the app
 * seccomp allow-list.
 *
 * Unlike shm — whose payload lives in a memfd the broker hands out and the guest
 * maps — sem and msg state is plain broker memory. Every operation is an RPC, so
 * the daemon is the one arbiter: a multi-op semop is trivially atomic, and a
 * guest that dies mid-operation cannot leave the registry inconsistent. An
 * operation that must sleep parks its connection in the daemon and is answered
 * when it can proceed, when its semtimedop deadline expires, when the object is
 * removed (EIDRM), or when the caller cancels it because a signal became
 * deliverable (EINTR — SysV IPC waits are never restarted).
 *
 * Ported from arm64chroot's src/sys_ipc.c and the sem/msg half of its
 * proctab.c. The differences are all consequences of running the guest in our
 * own process: guest memory is simply memory (validated, never copied through a
 * bounce), there is no allocator to lean on, and the client half runs inside the
 * SIGSYS handler, where every signal but SIGSYS is masked — so a blocking wait
 * cannot be interrupted by delivery and has to watch the pending set instead.
 */
#ifndef CNG_SYSVIPC_H
#define CNG_SYSVIPC_H

#include "cng/rt.h"
#include "cng/shm.h" /* struct cng_ipc64_perm and the generic IPC_* commands */

/* ---- semaphores --------------------------------------------------------- */

/* semctl() cmd. The generic IPC_RMID/SET/STAT/INFO live in shm.h. */
#define CNG_GETPID       11 /* sempid: pid of the last modifier */
#define CNG_GETVAL       12
#define CNG_GETALL       13
#define CNG_GETNCNT      14 /* waiters for the value to increase */
#define CNG_GETZCNT      15 /* waiters for the value to reach zero */
#define CNG_SETVAL       16
#define CNG_SETALL       17
#define CNG_SEM_STAT     18 /* by kernel-array index (what ipcs walks) */
#define CNG_SEM_INFO     19
#define CNG_SEM_STAT_ANY 20

/* semop() sem_flg (IPC_NOWAIT is 04000, shared with the rest of SysV IPC). */
#define CNG_IPC_NOWAIT 04000
#define CNG_SEM_UNDO   0x1000 /* undo the op when the process dies */

/* Reported through IPC_INFO/SEM_INFO. SEMVMX/SEMAEM are the kernel's hard ABI
 * bounds; the rest are this implementation's caps, chosen to match the kernel's
 * defaults so a guest that reads them plans the same way. */
#define CNG_SEMVMX 32767 /* max value of one semaphore */
#define CNG_SEMAEM 32767 /* max |semadj| */
#define CNG_SEMMSL 32000 /* max semaphores in one set */
#define CNG_SEMMNI 1024  /* max sets in a namespace (the broker's table) */
#define CNG_SEMOPM 500   /* max operations in one semop */

/* struct sembuf: three 2-byte fields, naturally packed (asm-generic). */
struct cng_sembuf {
    u16 sem_num;
    s16 sem_op;
    s16 sem_flg;
};

/* asm-generic struct semid64_ds for arm64 (LP64). */
struct cng_semid64_ds {
    struct cng_ipc64_perm sem_perm; /* @0  operation permission struct */
    s64 sem_otime;                  /* @48 last semop time */
    s64 sem_ctime;                  /* @56 last change time */
    u64 sem_nsems;                  /* @64 semaphores in the set */
    u64 __unused3, __unused4;       /* @72 */
};                                  /* 88 bytes */

/* struct seminfo (IPC_INFO / SEM_INFO output): ten native ints. SEM_INFO
 * repurposes semusz as the number of existing sets and semaem as the number of
 * semaphores over all of them. */
struct cng_seminfo {
    s32 semmap, semmni, semmns, semmnu, semmsl, semopm;
    s32 semume, semusz, semvmx, semaem;
};

/* ---- message queues ----------------------------------------------------- */

/* msgctl() cmd. */
#define CNG_MSG_STAT     11 /* by kernel-array index (what ipcs walks) */
#define CNG_MSG_INFO     12
#define CNG_MSG_STAT_ANY 13

/* msgsnd()/msgrcv() msgflg. */
#define CNG_MSG_NOERROR 010000 /* truncate an oversized message silently */
#define CNG_MSG_EXCEPT  020000 /* msgtyp > 0: take any type but that one */
#define CNG_MSG_COPY    040000 /* checkpoint/restore peek: not emulated */

#define CNG_MSGMAX 8192  /* max bytes in one message */
#define CNG_MSGMNB 16384 /* default msg_qbytes */
#define CNG_MSGMNI 1024  /* max queues in a namespace (the broker's table) */

/* asm-generic struct msqid64_ds for arm64 (LP64). */
struct cng_msqid64_ds {
    struct cng_ipc64_perm msg_perm; /* @0   operation permission struct */
    s64 msg_stime;                  /* @48  last msgsnd time */
    s64 msg_rtime;                  /* @56  last msgrcv time */
    s64 msg_ctime;                  /* @64  last change time */
    u64 msg_cbytes;                 /* @72  bytes currently queued */
    u64 msg_qnum;                   /* @80  messages currently queued */
    u64 msg_qbytes;                 /* @88  max bytes allowed on the queue */
    s32 msg_lspid;                  /* @96  pid of the last msgsnd */
    s32 msg_lrpid;                  /* @100 pid of the last msgrcv */
    u64 __unused4, __unused5;       /* @104 */
};                                  /* 120 bytes */

/* struct msginfo (IPC_INFO / MSG_INFO output): seven ints and a short, with the
 * tail padding the kernel zeroes spelled out. MSG_INFO repurposes msgpool as
 * the number of queues, msgmap as messages over all of them, msgtql as bytes. */
struct cng_msginfo {
    s32 msgpool, msgmap, msgmax, msgmnb, msgmni, msgssz, msgtql;
    u16 msgseg;
    u16 __pad;
};

/* ---- entry points ------------------------------------------------------- */

/* Emulate one of the eight syscalls; `nr` selects. Returns the guest result (a
 * set/queue id, a semaphore value, a byte count, 0, or -errno). */
long cng_sysvipc_handle(long nr, long a0, long a1, long a2, long a3, long a4);

/* Is a signal pending that the guest would take delivery of? A blocking wait has
 * to end in EINTR exactly when a real one would, and our handler runs with every
 * signal but SIGSYS masked — so a signal arriving mid-wait queues instead of
 * interrupting anything, and the pending set has to be polled against the mask
 * the signal frame will restore. Implemented in sigsys.c, which owns the frame.
 */
int cng_sig_deliverable(void);

#endif /* CNG_SYSVIPC_H */
