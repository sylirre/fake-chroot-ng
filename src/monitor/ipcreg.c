/* Daemon-side System V semaphores and message queues (see include/cng/ipcreg.h).
 *
 * Ported from the sem/msg half of arm64chroot's proctab.c. Runs only inside the
 * broker daemon, single-threaded from the poll loop in broker.c, so nothing here
 * needs locking. Freestanding like the rest of the monitor: raw syscalls through
 * the gate, no libc — which is the one structural difference from the original,
 * whose daemon could malloc. Semaphore vectors and queued messages are
 * variable-sized and come and go, so they come from the small arena below
 * instead.
 *
 * The shape of the emulation follows the kernel's:
 *   - a semop is attempted as a whole against the live values and rolled back if
 *     any operation in it cannot proceed (ipc/sem.c's perform_atomic_semop);
 *   - a blocking operation parks its connection and is retried, in arrival
 *     order, after every state change (ipc_rescan) — which also reproduces the
 *     kernel's pipelined msgsnd -> parked-receiver handoff, as an enqueue and a
 *     dequeue inside one pass;
 *   - SEM_UNDO adjustments are recorded per (process, set) and applied when the
 *     process dies. chroot-ng traps no exit path (a SIGKILL could never be
 *     trapped either), so death is detected the way the shm side detects a lost
 *     attach: by pid incarnation, on a tick and at the idle-exit check.
 */
#include "cng/broker.h"
#include "cng/ipcreg.h"
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/sysvipc.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

#define SEM_SET_MAX    CNG_SEMMNI /* concurrent sets in one namespace */
#define MSG_QUEUE_MAX  CNG_MSGMNI /* concurrent queues */
#define SEM_UNDO_MAX   4096       /* (pid, set) SEM_UNDO rows, daemon-wide */
#define IPC_WAITER_MAX CNG_IPC_WAITER_MAX /* parked blocking connections */

/* An internal semctl command, never guest-visible: report a set's nsems with no
 * permission check, so the client can size a SETALL payload even for a set it
 * may write but not read. */
#define BROKER_SEMNSEMS (-100)

/* ---- the arena ---------------------------------------------------------- */

/* Boundary-tagged first fit over mmap'd chunks. The daemon allocates one vector
 * per semaphore set, one per undo row and one block per queued message, and
 * frees them in no particular order — enough churn to need coalescing, nothing
 * like enough to justify more than this. Chunks are never unmapped: the daemon
 * is per-namespace and exits when the namespace goes idle. */
#define ARENA_CHUNK (1u << 20)
#define ARENA_ALIGN 16

/* The header is padded to ARENA_ALIGN so that a payload is aligned exactly when
 * the header is — which, with every allocation size rounded up to the same
 * grain and chunks coming from mmap, makes the alignment hold for every block in
 * the chain rather than only the first. `struct gmsg` carries an s64, so this is
 * a correctness requirement, not tidiness. */
struct blk {
    u64 size;   /* payload bytes, not counting this header */
    u32 free;
    u32 last;   /* final block of its chunk: nothing follows to coalesce with */
    struct blk *next_free;
    u64 __pad;
};

static struct blk *g_free; /* singly-linked, no ordering */

static u64 arena_round(u64 n) {
    return (n + (ARENA_ALIGN - 1)) & ~(u64)(ARENA_ALIGN - 1);
}

/* Carve `want` payload bytes off `b`, leaving a free remainder if one worth
 * having is left over. */
static void arena_split(struct blk *b, u64 want) {
    u64 need = want + sizeof(struct blk) + ARENA_ALIGN;
    if (b->size < need)
        return; /* the remainder would not hold a header plus anything */
    struct blk *rest = (struct blk *)((char *)(b + 1) + want);
    rest->size = b->size - want - sizeof(struct blk);
    rest->free = 1;
    rest->last = b->last;
    rest->next_free = g_free;
    g_free = rest;
    b->size = want;
    b->last = 0;
}

static void *arena_alloc(u64 n) {
    if (!n)
        n = 1;
    n = arena_round(n);
    for (struct blk *b = g_free, *prev = 0; b; prev = b, b = b->next_free) {
        if (b->size < n)
            continue;
        if (prev)
            prev->next_free = b->next_free;
        else
            g_free = b->next_free;
        b->free = 0;
        b->next_free = 0;
        arena_split(b, n);
        return b + 1;
    }
    u64 chunk = n + sizeof(struct blk);
    if (chunk < ARENA_CHUNK)
        chunk = ARENA_CHUNK;
    chunk = (chunk + 4095) & ~(u64)4095;
    void *p = sys_mmap(0, chunk, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    struct blk *b = (struct blk *)p;
    b->size = chunk - sizeof(struct blk);
    b->free = 0;
    b->last = 1;
    b->next_free = 0;
    arena_split(b, n);
    return b + 1;
}

/* Free `p`, absorbing the block that follows it in the same chunk when that one
 * is also free — which is what keeps a queue that cycles messages of a settled
 * size from fragmenting the arena away. */
static void arena_free(void *p) {
    if (!p)
        return;
    struct blk *b = (struct blk *)p - 1;
    if (!b->last) {
        struct blk *nx = (struct blk *)((char *)(b + 1) + b->size);
        if (nx->free) {
            for (struct blk *c = g_free, *prev = 0; c; prev = c, c = c->next_free)
                if (c == nx) {
                    if (prev)
                        prev->next_free = c->next_free;
                    else
                        g_free = c->next_free;
                    break;
                }
            b->size += sizeof(struct blk) + nx->size;
            b->last = nx->last;
        }
    }
    b->free = 1;
    b->next_free = g_free;
    g_free = b;
}

/* ---- state -------------------------------------------------------------- */

struct sem_set {
    int used;
    s32 semid, key; /* key 0 = private or removed: unfindable by key */
    u32 nsems;
    u32 mode;
    u32 uid, gid, cuid, cgid;
    s64 otime, ctime;
    u16 *val;  /* [nsems] values, 0..SEMVMX */
    s32 *lpid; /* [nsems] sempid: pid of the last operation on each */
    s32 cpid, tpid; /* creator / last toucher: the liveness anchor, not ABI */
};

struct sem_undo { /* one process's semadj vector for one set */
    int used;
    s32 pid;
    u64 start; /* the holder's starttime: its incarnation */
    s32 semid;
    s16 *adj; /* [nsems] */
};

struct gmsg { /* one queued message; its bytes follow the header */
    struct gmsg *next;
    s64 mtype;
    u64 size;
};
#define GMSG_DATA(m) ((char *)((m) + 1))

struct msg_q {
    int used;
    s32 msqid, key;
    u32 mode;
    u32 uid, gid, cuid, cgid;
    s64 stime, rtime, ctime;
    u64 cbytes, qnum, qbytes;
    s32 lspid, lrpid;
    s32 cpid, tpid; /* liveness anchor only */
    struct gmsg *head, *tail;
};

struct waiter { /* a parked blocking operation, holding its connection open */
    int used;
    int cfd;
    u32 op; /* CNG_REQ_SEMOP / _MSGSND / _MSGRCV */
    s32 id;
    s32 pid;
    u64 start; /* a fork can duplicate the fd and mute the POLLHUP, so the
                * waiter's incarnation is the liveness fallback */
    u64 seq;   /* arrival order: FIFO fairness */
    s64 deadline_ms; /* -1 = untimed */
    struct cng_sembuf *sops;
    u32 nsops;
    int blk; /* index of the operation that blocked (GETNCNT/GETZCNT) */
    struct gmsg *msg; /* MSGSND: the message not yet enqueued (owned) */
    s64 msgtyp;
    u64 msgsz;
    s32 msgflg;
};

static struct sem_set *g_sem;
static struct sem_undo *g_undo;
static struct msg_q *g_msq;
static struct waiter *g_wait;
static s32 g_next_semid = 1, g_next_msqid = 1;
static u64 g_wait_seq = 1;
static int g_nwait, g_nundo;

/* The tables are large enough to be worth not paying for until something in the
 * namespace actually uses semaphores or message queues. Returns 0 if they could
 * not be had, in which case every operation fails ENOSPC rather than pretending. */
static int tables(void) {
    if (g_sem)
        return 1;
    unsigned long n = (unsigned long)SEM_SET_MAX * sizeof *g_sem +
                      (unsigned long)SEM_UNDO_MAX * sizeof *g_undo +
                      (unsigned long)MSG_QUEUE_MAX * sizeof *g_msq +
                      (unsigned long)IPC_WAITER_MAX * sizeof *g_wait;
    void *p = sys_mmap(0, n, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    g_sem = (struct sem_set *)p;
    g_undo = (struct sem_undo *)(g_sem + SEM_SET_MAX);
    g_msq = (struct msg_q *)(g_undo + SEM_UNDO_MAX);
    g_wait = (struct waiter *)(g_msq + MSG_QUEUE_MAX);
    return 1;
}

static s64 now_sec(void) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_REALTIME, &ts);
    return (s64)ts.tv_sec;
}

static s64 mono_ms(void) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_MONOTONIC, &ts);
    return (s64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- lookup and permissions --------------------------------------------- */

static struct sem_set *sem_find(s32 semid) {
    if (semid <= 0 || !g_sem)
        return 0;
    for (int i = 0; i < SEM_SET_MAX; i++)
        if (g_sem[i].used && g_sem[i].semid == semid)
            return &g_sem[i];
    return 0;
}

static struct msg_q *msg_find(s32 msqid) {
    if (msqid <= 0 || !g_msq)
        return 0;
    for (int i = 0; i < MSG_QUEUE_MAX; i++)
        if (g_msq[i].used && g_msq[i].msqid == msqid)
            return &g_msq[i];
    return 0;
}

/* The standard SysV access triad, advisory in this single-user sandbox: the
 * guest's (possibly faked) credentials ride in the request and there is no host
 * enforcement behind them. Guest root passes everything. `need` is 04 (read) or
 * 02 (alter), the two the kernel checks for sem and msg. */
static int ipc_access(u32 mode, u32 ouid, u32 cuid, u32 ogid, u32 cgid, u32 uid,
                      u32 gid, u32 need) {
    if (uid == 0)
        return 1;
    u32 m = mode;
    if (uid == ouid || uid == cuid)
        m >>= 6;
    else if (gid == ogid || gid == cgid)
        m >>= 3;
    return (m & need & 7) == need;
}

static int ipc_owner(u32 ouid, u32 cuid, u32 uid) {
    return uid == 0 || uid == ouid || uid == cuid;
}

static s32 sem_alloc_id(void) {
    for (int tries = 0; tries < SEM_SET_MAX * 4; tries++) {
        s32 id = g_next_semid++;
        if (g_next_semid <= 0)
            g_next_semid = 1;
        if (id > 0 && !sem_find(id))
            return id;
    }
    return -1;
}

static s32 msg_alloc_id(void) {
    for (int tries = 0; tries < MSG_QUEUE_MAX * 4; tries++) {
        s32 id = g_next_msqid++;
        if (g_next_msqid <= 0)
            g_next_msqid = 1;
        if (id > 0 && !msg_find(id))
            return id;
    }
    return -1;
}

/* ---- SEM_UNDO ----------------------------------------------------------- */

/* The undo row for (pid, set), created on demand. A row created by an attempt
 * that then blocks or fails just carries zero adjustments — harmless, and the
 * kernel allocates its undo structure up front for the same reason. */
static struct sem_undo *sem_undo_find(s32 pid, struct sem_set *s, int create) {
    int slot = -1;
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        if (g_undo[i].used) {
            if (g_undo[i].pid == pid && g_undo[i].semid == s->semid)
                return &g_undo[i];
        } else if (slot < 0) {
            slot = i;
        }
    }
    if (!create || slot < 0)
        return 0;
    s16 *adj = arena_alloc((u64)s->nsems * sizeof *adj);
    if (!adj)
        return 0;
    memset(adj, 0, (size_t)s->nsems * sizeof *adj);
    struct sem_undo *u = &g_undo[slot];
    u->used = 1;
    u->pid = pid;
    u->start = cng_proc_starttime(pid, 0);
    u->semid = s->semid;
    u->adj = adj;
    g_nundo++;
    return u;
}

static void sem_undo_free(struct sem_undo *u) {
    arena_free(u->adj);
    memset(u, 0, sizeof *u);
    g_nundo--;
}

/* Setting a value invalidates every process's pending undo for it, as in the
 * kernel. semnum < 0 clears the whole set. */
static void sem_undo_clear(s32 semid, s32 semnum) {
    struct sem_set *s = sem_find(semid);
    if (!s)
        return;
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        struct sem_undo *u = &g_undo[i];
        if (!u->used || u->semid != semid)
            continue;
        if (semnum < 0)
            memset(u->adj, 0, (size_t)s->nsems * sizeof *u->adj);
        else if ((u32)semnum < s->nsems)
            u->adj[semnum] = 0;
    }
}

/* Apply one row to its set (its holder died): semval += semadj, clamped to
 * [0, SEMVMX] as the kernel clamps it, stamping sempid and otime. Frees it. */
static void sem_undo_apply(struct sem_undo *u) {
    struct sem_set *s = sem_find(u->semid);
    if (s) {
        int touched = 0;
        for (u32 i = 0; i < s->nsems; i++) {
            if (!u->adj[i])
                continue;
            int v = (int)s->val[i] + u->adj[i];
            if (v < 0)
                v = 0;
            if (v > CNG_SEMVMX)
                v = CNG_SEMVMX;
            s->val[i] = (u16)v;
            s->lpid[i] = u->pid;
            touched = 1;
        }
        if (touched)
            s->otime = now_sec();
    }
    sem_undo_free(u);
}

/* Apply the undo rows of every process that has died, for this set only.
 *
 * The kernel runs a process's undo list as part of its exit, so a guest that
 * waits for a child and then reads the semaphore sees the adjustment already
 * made. chroot-ng traps no exit path (a SIGKILL could never be trapped either),
 * so the tick in the poll loop would apply it up to a second late — long enough
 * for exactly that read to see a value no real kernel would report. Running it
 * here, whenever the set is touched, makes it synchronous from the only vantage
 * point that can observe it: the shm side settles nattch on the same principle.
 *
 * The zombie test is the shm side's too: a process that has exited but not been
 * reaped still owns its pid, so its starttime still matches, yet the kernel has
 * already run its exit. */
static void sem_reclaim_set(struct sem_set *s) {
    if (!g_nundo)
        return;
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        struct sem_undo *u = &g_undo[i];
        if (!u->used || u->semid != s->semid)
            continue;
        int zombie = 0;
        u64 start = cng_proc_starttime(u->pid, &zombie);
        if (start != u->start || zombie)
            sem_undo_apply(u);
    }
}

static void sem_free_set(struct sem_set *s) {
    for (int i = 0; i < SEM_UNDO_MAX; i++) /* undo rows die with their set */
        if (g_undo[i].used && g_undo[i].semid == s->semid)
            sem_undo_free(&g_undo[i]);
    arena_free(s->val);
    arena_free(s->lpid);
    memset(s, 0, sizeof *s);
}

static void msg_free_queue(struct msg_q *q) {
    for (struct gmsg *m = q->head; m;) {
        struct gmsg *next = m->next;
        arena_free(m);
        m = next;
    }
    memset(q, 0, sizeof *q);
}

/* ---- the semop core ------------------------------------------------------ */

/* Attempt a whole operation vector atomically (the kernel's
 * perform_atomic_semop_slow — the general form, which is what handles a vector
 * naming the same semaphore twice): apply in order against the live values, roll
 * the applied prefix back if one cannot proceed. Returns 0 (applied — values,
 * sempids, otime and undo adjustments all updated), 1 (would block, *blk = the
 * index that blocked), or a hard -errno (-EAGAIN when the blocking operation
 * carried IPC_NOWAIT).
 *
 * The undo adjustment is applied inside the loop, not tallied afterwards, for
 * the same reason the value is: a later operation on a semaphore an earlier one
 * already touched has to see that. Deferring it left every op in a vector
 * checking its adjustment against the value the vector *started* with, so a
 * cumulative overflow — [+32767 UNDO, -32767, +32767 UNDO], which the kernel
 * refuses with ERANGE — passed all three checks and then wrapped the s16 at
 * commit, leaving a semadj of +2 where the process owed -65534. Rollback mirrors
 * the kernel's `un->semadj[n] += sem_op`. */
static s32 sem_try_op(struct sem_set *s, const struct cng_sembuf *sops, u32 nsops,
                      s32 pid, int *blk) {
    for (u32 i = 0; i < nsops; i++)
        if (sops[i].sem_num >= s->nsems)
            return -EFBIG;

    struct sem_undo *u = 0; /* this process's row, created by the first UNDO op */
    s32 result = 0;
    u32 i;
    for (i = 0; i < nsops; i++) {
        const struct cng_sembuf *op = &sops[i];
        int v = (int)s->val[op->sem_num] + op->sem_op;
        if ((op->sem_op == 0 && s->val[op->sem_num] != 0) /* wait for zero */
            || v < 0) {                                   /* wait for units */
            if (op->sem_flg & CNG_IPC_NOWAIT) {
                result = -EAGAIN;
            } else {
                result = 1;
                *blk = (int)i;
            }
            break;
        }
        if (v > CNG_SEMVMX) {
            result = -ERANGE;
            break;
        }
        if (op->sem_flg & CNG_SEM_UNDO) {
            if (!u)
                u = sem_undo_find(pid, s, 1);
            if (!u) {
                result = -ENOMEM; /* the undo table is full */
                break;
            }
            int adj = (int)u->adj[op->sem_num] - op->sem_op;
            /* The kernel's bound is the s16 range itself: -SEMAEM-1 is a
             * reachable semadj, not an overflow. */
            if (adj < -CNG_SEMAEM - 1 || adj > CNG_SEMAEM) {
                result = -ERANGE;
                break;
            }
            u->adj[op->sem_num] = (s16)adj;
        }
        s->val[op->sem_num] = (u16)v;
    }
    if (result != 0) { /* roll the applied prefix back, values and undo alike */
        while (i--) {
            s->val[sops[i].sem_num] =
                (u16)((int)s->val[sops[i].sem_num] - sops[i].sem_op);
            if (u && (sops[i].sem_flg & CNG_SEM_UNDO))
                u->adj[sops[i].sem_num] =
                    (s16)((int)u->adj[sops[i].sem_num] + sops[i].sem_op);
        }
        return result;
    }
    /* Committed. Stamp sempid on every semaphore the vector referenced — zero
     * operations included, as the kernel does — and otime on the set. */
    for (i = 0; i < nsops; i++)
        s->lpid[sops[i].sem_num] = pid;
    s->otime = now_sec();
    s->tpid = pid;
    return 0;
}

/* ---- get ---------------------------------------------------------------- */

static s32 sem_do_get(const struct cng_breq *q) {
    u64 nsems = q->size;
    if (q->key != 0) { /* keyed: an existing set wins */
        for (int i = 0; i < SEM_SET_MAX; i++) {
            struct sem_set *s = &g_sem[i];
            if (!s->used || s->key != q->key)
                continue;
            if ((q->arg & CNG_IPC_CREAT) && (q->arg & CNG_IPC_EXCL))
                return -EEXIST;
            if (nsems && s->nsems < nsems)
                return -EINVAL;
            if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                            q->gid, 04))
                return -EACCES;
            s->tpid = q->pid;
            return s->semid;
        }
        if (!(q->arg & CNG_IPC_CREAT))
            return -ENOENT;
    }
    if (nsems == 0 || nsems > CNG_SEMMSL)
        return -EINVAL;
    int slot = -1;
    for (int i = 0; i < SEM_SET_MAX; i++)
        if (!g_sem[i].used) {
            slot = i;
            break;
        }
    if (slot < 0)
        return -ENOSPC;
    s32 id = sem_alloc_id();
    if (id < 0)
        return -ENOSPC;
    u16 *val = arena_alloc(nsems * sizeof *val);
    s32 *lpid = arena_alloc(nsems * sizeof *lpid);
    if (!val || !lpid) {
        arena_free(val);
        arena_free(lpid);
        return -ENOMEM;
    }
    memset(val, 0, (size_t)nsems * sizeof *val); /* a fresh semaphore reads 0 */
    memset(lpid, 0, (size_t)nsems * sizeof *lpid);
    struct sem_set *s = &g_sem[slot];
    memset(s, 0, sizeof *s);
    s->used = 1;
    s->semid = id;
    s->key = q->key;
    s->nsems = (u32)nsems;
    s->mode = q->arg & 0777;
    s->uid = s->cuid = q->uid;
    s->gid = s->cgid = q->gid;
    s->ctime = now_sec(); /* otime stays 0 until the first semop */
    s->val = val;
    s->lpid = lpid;
    s->cpid = s->tpid = q->pid;
    return id;
}

static s32 msg_do_get(const struct cng_breq *q) {
    if (q->key != 0) {
        for (int i = 0; i < MSG_QUEUE_MAX; i++) {
            struct msg_q *mq = &g_msq[i];
            if (!mq->used || mq->key != q->key)
                continue;
            if ((q->arg & CNG_IPC_CREAT) && (q->arg & CNG_IPC_EXCL))
                return -EEXIST;
            if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid,
                            q->uid, q->gid, 04))
                return -EACCES;
            mq->tpid = q->pid;
            return mq->msqid;
        }
        if (!(q->arg & CNG_IPC_CREAT))
            return -ENOENT;
    }
    int slot = -1;
    for (int i = 0; i < MSG_QUEUE_MAX; i++)
        if (!g_msq[i].used) {
            slot = i;
            break;
        }
    if (slot < 0)
        return -ENOSPC;
    s32 id = msg_alloc_id();
    if (id < 0)
        return -ENOSPC;
    struct msg_q *mq = &g_msq[slot];
    memset(mq, 0, sizeof *mq);
    mq->used = 1;
    mq->msqid = id;
    mq->key = q->key;
    mq->mode = q->arg & 0777;
    mq->uid = mq->cuid = q->uid;
    mq->gid = mq->cgid = q->gid;
    mq->ctime = now_sec();
    mq->qbytes = CNG_MSGMNB;
    mq->cpid = mq->tpid = q->pid;
    return id;
}

/* ---- the message queue --------------------------------------------------- */

static int msg_matches(const struct gmsg *m, s64 msgtyp, s32 msgflg) {
    if (msgtyp == 0)
        return 1;
    if (msgtyp > 0)
        return (msgflg & CNG_MSG_EXCEPT) ? m->mtype != msgtyp : m->mtype == msgtyp;
    /* LONG_MIN cannot be negated; the kernel defines it as a LONG_MAX limit
     * (ipc/msg.c convert_mode), which also sidesteps the overflow. */
    s64 limit = msgtyp == (-0x7fffffffffffffffLL - 1) ? 0x7fffffffffffffffLL
                                                      : -msgtyp;
    return m->mtype <= limit;
}

/* The message an msgrcv would take: FIFO for msgtyp >= 0; for msgtyp < 0 the
 * oldest message of the lowest qualifying type. 0 = would block. */
static struct gmsg *msg_pick(struct msg_q *q, s64 msgtyp, s32 msgflg,
                             struct gmsg **prev_out) {
    struct gmsg *best = 0, *best_prev = 0, *prev = 0;
    for (struct gmsg *m = q->head; m; prev = m, m = m->next) {
        if (!msg_matches(m, msgtyp, msgflg))
            continue;
        if (msgtyp >= 0) {
            best = m;
            best_prev = prev;
            break;
        }
        if (!best || m->mtype < best->mtype) {
            best = m;
            best_prev = prev;
        }
    }
    *prev_out = best_prev;
    return best;
}

static void msg_unlink(struct msg_q *q, struct gmsg *m, struct gmsg *prev) {
    if (prev)
        prev->next = m->next;
    else
        q->head = m->next;
    if (q->tail == m)
        q->tail = prev;
    q->cbytes -= m->size;
    q->qnum--;
}

/* Room for one more message. The second test is the kernel's own guard against
 * a queue of zero-length messages growing without bound. */
static int msg_fits(const struct msg_q *q, u64 size) {
    return q->cbytes + size <= q->qbytes && q->qnum + 1 <= q->qbytes;
}

static void msg_enqueue(struct msg_q *q, struct gmsg *m, s32 pid) {
    m->next = 0;
    if (q->tail)
        q->tail->next = m;
    else
        q->head = m;
    q->tail = m;
    q->cbytes += m->size;
    q->qnum++;
    q->lspid = pid;
    q->stime = now_sec();
    q->tpid = pid;
}

/* ---- parked waiters ------------------------------------------------------ */

static void waiter_free(struct waiter *w) {
    if (w->cfd >= 0)
        sys_close(w->cfd);
    arena_free(w->sops);
    arena_free(w->msg);
    memset(w, 0, sizeof *w);
    w->cfd = -1;
    g_nwait--;
}

/* The final answer to a parked waiter — a grant, EAGAIN, EIDRM or a cancel-ack —
 * plus an optional payload (msgrcv's data). Best effort: a peer that has died
 * just closes. */
static void waiter_reply(struct waiter *w, struct cng_bresp *r,
                         const void *payload, u64 psz) {
    if (cng_broker_send(w->cfd, r, sizeof *r, -1) == 0 && payload && psz)
        cng_broker_write_full(w->cfd, payload, (unsigned)psz);
    waiter_free(w);
}

/* Park a blocking operation, taking ownership of `sops`/`msg`. Returns 1
 * (parked) or 0 (the table is full — the caller fails the operation rather than
 * sleeping in a slot that does not exist). */
static int waiter_park(int cfd, const struct cng_breq *q,
                       struct cng_sembuf *sops, u32 nsops, int blk,
                       struct gmsg *msg) {
    struct waiter *w = 0;
    for (int i = 0; i < IPC_WAITER_MAX; i++)
        if (!g_wait[i].used) {
            w = &g_wait[i];
            break;
        }
    if (!w)
        return 0;
    memset(w, 0, sizeof *w);
    w->used = 1;
    w->cfd = cfd;
    w->op = q->op;
    w->id = q->id;
    w->pid = q->pid;
    w->start = cng_proc_starttime(q->pid, 0);
    w->seq = g_wait_seq++;
    if (q->timeout_ns >= 0) {
        /* Round up to milliseconds, clamping first so a saturated (~292-year)
         * timeout cannot overflow the rounding — it just becomes very distant. */
        s64 t = q->timeout_ns;
        if (t > 0x7fffffffffffffffLL - 1000000)
            t = 0x7fffffffffffffffLL - 1000000;
        w->deadline_ms = mono_ms() + (t + 999999) / 1000000;
    } else {
        w->deadline_ms = -1;
    }
    w->sops = sops;
    w->nsops = nsops;
    w->blk = blk;
    w->msg = msg;
    w->msgtyp = q->mtype;
    w->msgsz = q->size;
    w->msgflg = q->arg;
    g_nwait++;
    return 1;
}

/* GETNCNT/GETZCNT: parked semops sleeping on `semnum` because of a decrement
 * (ncnt) or a wait-for-zero (zcnt), judged by the operation that actually
 * blocked on the last attempt — the kernel's count_semcnt. */
static s32 sem_count_waiters(s32 semid, u32 semnum, int zero) {
    s32 n = 0;
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct waiter *w = &g_wait[i];
        if (!w->used || w->op != CNG_REQ_SEMOP || w->id != semid)
            continue;
        const struct cng_sembuf *b = &w->sops[w->blk];
        if (b->sem_num == semnum && (zero ? b->sem_op == 0 : b->sem_op < 0))
            n++;
    }
    return n;
}

/* Wake everything parked on a removed object with EIDRM. `sem` picks which id
 * namespace `id` belongs to. */
static void waiters_eidrm(s32 id, int sem) {
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct waiter *w = &g_wait[i];
        if (!w->used || w->id != id)
            continue;
        if (sem ? (w->op != CNG_REQ_SEMOP)
                : (w->op != CNG_REQ_MSGSND && w->op != CNG_REQ_MSGRCV))
            continue;
        struct cng_bresp r;
        memset(&r, 0, sizeof r);
        r.ret = -EIDRM;
        waiter_reply(w, &r, 0, 0);
    }
}

/* Grant an msgrcv: truncate under MSG_NOERROR (E2BIG was ruled out already),
 * reply with the type and the data, consume the message. */
static void msg_grant_rcv(struct waiter *w, struct gmsg *m) {
    u64 n = m->size <= w->msgsz ? m->size : w->msgsz;
    struct cng_bresp r;
    memset(&r, 0, sizeof r);
    r.ret = (s32)n;
    r.mtype = m->mtype;
    waiter_reply(w, &r, GMSG_DATA(m), n);
    arena_free(m);
}

void cng_ipc_rescan(void) {
    if (!g_wait)
        return;
    int progress = 1;
    while (progress && g_nwait) {
        progress = 0;
        u64 last = 0;
        for (;;) {
            struct waiter *w = 0; /* the earliest arrival not yet visited */
            for (int i = 0; i < IPC_WAITER_MAX; i++)
                if (g_wait[i].used && g_wait[i].seq > last &&
                    (!w || g_wait[i].seq < w->seq))
                    w = &g_wait[i];
            if (!w)
                break;
            last = w->seq;
            struct cng_bresp r;
            memset(&r, 0, sizeof r);
            if (w->op == CNG_REQ_SEMOP) {
                struct sem_set *s = sem_find(w->id);
                if (!s) {
                    r.ret = -EIDRM;
                    waiter_reply(w, &r, 0, 0);
                    progress = 1;
                    continue;
                }
                int blk = w->blk;
                s32 t = sem_try_op(s, w->sops, w->nsops, w->pid, &blk);
                w->blk = blk;
                if (t == 1)
                    continue; /* still blocked */
                r.ret = t;
                waiter_reply(w, &r, 0, 0);
                progress = 1;
            } else if (w->op == CNG_REQ_MSGSND) {
                struct msg_q *q = msg_find(w->id);
                if (!q) {
                    r.ret = -EIDRM;
                    waiter_reply(w, &r, 0, 0);
                    progress = 1;
                    continue;
                }
                if (!msg_fits(q, w->msg->size))
                    continue;
                msg_enqueue(q, w->msg, w->pid);
                w->msg = 0; /* ownership moved to the queue */
                waiter_reply(w, &r, 0, 0); /* ret 0 */
                progress = 1;
            } else { /* CNG_REQ_MSGRCV */
                struct msg_q *q = msg_find(w->id);
                if (!q) {
                    r.ret = -EIDRM;
                    waiter_reply(w, &r, 0, 0);
                    progress = 1;
                    continue;
                }
                struct gmsg *prev, *m = msg_pick(q, w->msgtyp, w->msgflg, &prev);
                if (!m)
                    continue;
                if (m->size > w->msgsz && !(w->msgflg & CNG_MSG_NOERROR)) {
                    /* A message too big for a parked receiver errors it and
                     * stays on the queue — the kernel's behaviour. */
                    r.ret = -E2BIG;
                    waiter_reply(w, &r, 0, 0);
                    progress = 1;
                    continue;
                }
                msg_unlink(q, m, prev);
                q->lrpid = w->pid;
                q->rtime = now_sec();
                q->tpid = w->pid;
                msg_grant_rcv(w, m);
                progress = 1;
            }
        }
    }
}

void cng_ipc_expire(s64 now_ms) {
    if (!g_wait)
        return;
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct waiter *w = &g_wait[i];
        if (!w->used || w->deadline_ms < 0 || now_ms < w->deadline_ms)
            continue;
        struct cng_bresp r;
        memset(&r, 0, sizeof r);
        r.ret = -EAGAIN; /* a semtimedop timeout is EAGAIN, as in the kernel */
        waiter_reply(w, &r, 0, 0);
    }
}

/* ---- semctl / msgctl ----------------------------------------------------- */

static void sem_fill_stat(struct cng_bresp *r, const struct sem_set *s) {
    r->key = s->key;
    r->size = s->nsems;
    r->mode = s->mode;
    r->uid = s->uid;
    r->gid = s->gid;
    r->cuid = s->cuid;
    r->cgid = s->cgid;
    r->atime = s->otime; /* sem_otime rides in the atime slot */
    r->ctime = s->ctime;
}

/* Everything but GETALL/SETALL, which stream their vector and are handled by
 * the caller. `r` carries the stat payload out. */
static s32 sem_do_ctl(const struct cng_breq *q, struct cng_bresp *r) {
    /* SETVAL's value range is the kernel's first test of all. ksys_semctl
     * dispatches SETVAL straight into semctl_setval(), whose opening statement
     * is the range test — before the set is looked up, before semnum is bounded
     * and before ipcperms(). Checked last, as it was, every one of those
     * reported something else first. Measured: SETVAL of 99999 answers ERANGE
     * on a nonexistent id, on a bad semnum and on a set with no permissions,
     * where this answered EINVAL, EINVAL and EACCES. */
    if (q->arg == CNG_SETVAL && (q->val < 0 || q->val > CNG_SEMVMX))
        return -ERANGE;
    switch (q->arg) {
    case CNG_IPC_INFO:
    case CNG_SEM_INFO: {
        int used = 0;
        s32 maxidx = -1;
        u64 tot = 0;
        for (int i = 0; i < SEM_SET_MAX; i++)
            if (g_sem[i].used) {
                used++;
                maxidx = i;
                tot += g_sem[i].nsems;
            }
        r->info_used = used;
        r->info_tot = tot;
        return maxidx; /* -1 for none, as the kernel reports it */
    }
    case CNG_SEM_STAT:
    case CNG_SEM_STAT_ANY: {
        s32 idx = q->id;
        if (idx < 0 || idx >= SEM_SET_MAX || !g_sem[idx].used)
            return -EINVAL;
        struct sem_set *s = &g_sem[idx];
        if (q->arg == CNG_SEM_STAT &&
            !ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                        q->gid, 04))
            return -EACCES;
        sem_reclaim_set(s); /* what ipcs shows must not lag a dead holder */
        sem_fill_stat(r, s);
        return s->semid;
    }
    }

    struct sem_set *s = sem_find(q->id);
    if (!s)
        return -EINVAL;
    sem_reclaim_set(s); /* a dead holder's SEM_UNDO lands before anyone reads */
    switch (q->arg) {
    case BROKER_SEMNSEMS:
        return (s32)s->nsems;
    case CNG_IPC_STAT:
        if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                        q->gid, 04))
            return -EACCES;
        sem_fill_stat(r, s);
        return 0;
    case CNG_IPC_SET:
        if (!ipc_owner(s->uid, s->cuid, q->uid))
            return -EPERM;
        s->mode = (s->mode & ~0777u) | (q->set_mode & 0777);
        s->uid = q->set_uid;
        s->gid = q->set_gid;
        s->ctime = now_sec();
        return 0;
    case CNG_IPC_RMID:
        if (!ipc_owner(s->uid, s->cuid, q->uid))
            return -EPERM;
        waiters_eidrm(s->semid, 1); /* sleepers see EIDRM, as on the kernel */
        sem_free_set(s);
        return 0;
    }

    /* The per-semaphore commands. The two families order the remaining two
     * checks the other way round from each other, and the kernel is explicit
     * about it: semctl_setval() bounds semnum and calls ipcperms() after, while
     * semctl_main() calls ipcperms() first and bounds semnum after. Measured:
     * GETVAL with a bad semnum on a set with no permissions is EACCES, not the
     * EINVAL a single shared order gave it. */
    int alter = (q->arg == CNG_SETVAL);
    if (alter) {
        if (q->semnum < 0 || (u32)q->semnum >= s->nsems)
            return -EINVAL;
        if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                        q->gid, 02))
            return -EACCES;
    } else {
        if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                        q->gid, 04))
            return -EACCES;
        if (q->semnum < 0 || (u32)q->semnum >= s->nsems)
            return -EINVAL;
    }
    u32 n = (u32)q->semnum;
    switch (q->arg) {
    case CNG_GETVAL:
        return (s32)s->val[n];
    case CNG_GETPID:
        return s->lpid[n];
    case CNG_GETNCNT:
        return sem_count_waiters(s->semid, n, 0);
    case CNG_GETZCNT:
        return sem_count_waiters(s->semid, n, 1);
    case CNG_SETVAL: /* the range was settled at the top, ahead of everything */
        s->val[n] = (u16)q->val;
        s->lpid[n] = q->pid;
        sem_undo_clear(s->semid, (s32)n);
        s->ctime = now_sec();
        s->tpid = q->pid;
        return 0;
    }
    return -EINVAL;
}

static void msg_fill_stat(struct cng_bresp *r, const struct msg_q *q) {
    r->key = q->key;
    r->mode = q->mode;
    r->uid = q->uid;
    r->gid = q->gid;
    r->cuid = q->cuid;
    r->cgid = q->cgid;
    r->atime = q->stime; /* msg_stime / msg_rtime ride in the a/d slots */
    r->dtime = q->rtime;
    r->ctime = q->ctime;
    r->cbytes = q->cbytes;
    r->nattch = q->qnum;
    r->size = q->qbytes;
    r->cpid = q->lspid;
    r->lpid = q->lrpid;
}

static s32 msg_do_ctl(const struct cng_breq *q, struct cng_bresp *r) {
    switch (q->arg) {
    case CNG_IPC_INFO:
    case CNG_MSG_INFO: {
        int used = 0;
        s32 maxidx = -1;
        u64 tot = 0, bytes = 0;
        for (int i = 0; i < MSG_QUEUE_MAX; i++)
            if (g_msq[i].used) {
                used++;
                maxidx = i;
                tot += g_msq[i].qnum;
                bytes += g_msq[i].cbytes;
            }
        r->info_used = used;
        r->info_tot = tot;
        r->cbytes = bytes;
        return maxidx;
    }
    case CNG_MSG_STAT:
    case CNG_MSG_STAT_ANY: {
        s32 idx = q->id;
        if (idx < 0 || idx >= MSG_QUEUE_MAX || !g_msq[idx].used)
            return -EINVAL;
        struct msg_q *mq = &g_msq[idx];
        if (q->arg == CNG_MSG_STAT &&
            !ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid, q->uid,
                        q->gid, 04))
            return -EACCES;
        msg_fill_stat(r, mq);
        return mq->msqid;
    }
    }

    struct msg_q *mq = msg_find(q->id);
    if (!mq)
        return -EINVAL;
    switch (q->arg) {
    case CNG_IPC_STAT:
        if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid, q->uid,
                        q->gid, 04))
            return -EACCES;
        msg_fill_stat(r, mq);
        return 0;
    case CNG_IPC_SET:
        if (!ipc_owner(mq->uid, mq->cuid, q->uid))
            return -EPERM;
        /* Raising msg_qbytes past the default needs CAP_SYS_RESOURCE on the
         * kernel; guest root is the only credential that has it here. It rides
         * in `size` rather than `val` because msg_qbytes is 64 bits wide and
         * truncating it would turn a rejectable value into an accepted one. */
        if (q->size > CNG_MSGMNB && q->uid != 0)
            return -EPERM;
        mq->mode = (mq->mode & ~0777u) | (q->set_mode & 0777);
        mq->uid = q->set_uid;
        mq->gid = q->set_gid;
        mq->qbytes = q->size;
        mq->ctime = now_sec();
        mq->tpid = q->pid;
        return 0;
    case CNG_IPC_RMID:
        if (!ipc_owner(mq->uid, mq->cuid, q->uid))
            return -EPERM;
        waiters_eidrm(mq->msqid, 0);
        msg_free_queue(mq);
        return 0;
    }
    return -EINVAL;
}

/* ---- serving ------------------------------------------------------------ */

/* semop: the operation vector rides behind the request on the same stream. */
static int serve_semop(int cfd, const struct cng_breq *q, struct cng_bresp *r) {
    u32 nsops = (u32)q->arg;
    if (nsops == 0 || nsops > CNG_SEMOPM) {
        r->ret = nsops ? -E2BIG : -EINVAL; /* the client pre-checks both */
        return 0;
    }
    struct cng_sembuf *sops = arena_alloc((u64)nsops * sizeof *sops);
    if (!sops) {
        r->ret = -ENOMEM;
        return 0;
    }
    if (cng_broker_read_full(cfd, sops, nsops * (unsigned)sizeof *sops) != 0) {
        arena_free(sops);
        return -1; /* the peer vanished mid-request: drop the connection */
    }
    struct sem_set *s = sem_find(q->id);
    if (!s) {
        arena_free(sops);
        r->ret = -EINVAL;
        return 0;
    }
    sem_reclaim_set(s); /* the units a dead holder owed are available again */
    /* The kernel checks EFBIG (a bad sem_num) before the permission check. */
    int alter = 0, efbig = 0;
    for (u32 i = 0; i < nsops; i++) {
        if (sops[i].sem_op)
            alter = 1;
        if (sops[i].sem_num >= s->nsems)
            efbig = 1;
    }
    if (efbig) {
        arena_free(sops);
        r->ret = -EFBIG;
        return 0;
    }
    if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid, q->gid,
                    alter ? 02 : 04)) {
        arena_free(sops);
        r->ret = -EACCES;
        return 0;
    }
    int blk = 0;
    s32 t = sem_try_op(s, sops, nsops, q->pid, &blk);
    if (t == 1) {
        if (waiter_park(cfd, q, sops, nsops, blk, 0))
            return 1;
        arena_free(sops);
        r->ret = -EAGAIN; /* the waiter table is full: fail rather than lie */
        return 0;
    }
    arena_free(sops);
    r->ret = t;
    return 0;
}

/* semctl, including the two commands that stream a vector of values. */
static int serve_semctl(int cfd, const struct cng_breq *q, struct cng_bresp *r) {
    if (q->arg == CNG_SETALL) {
        /* The values are already in flight. Read them, then validate the whole
         * array before applying any of it — the kernel's order. */
        u64 n = q->size;
        if (n == 0 || n > CNG_SEMMSL)
            return -1; /* a length no client of ours sends: drop the peer */
        u16 *vals = arena_alloc(n * sizeof *vals);
        if (!vals)
            return -1;
        if (cng_broker_read_full(cfd, vals, (unsigned)(n * sizeof *vals)) != 0) {
            arena_free(vals);
            return -1;
        }
        struct sem_set *s = sem_find(q->id);
        if (!s || n != s->nsems) {
            r->ret = -EINVAL; /* gone, or its size changed under the client */
        } else if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                               q->gid, 02)) {
            r->ret = -EACCES;
        } else {
            for (u64 i = 0; i < n; i++)
                if (vals[i] > CNG_SEMVMX) {
                    r->ret = -ERANGE;
                    break;
                }
            if (r->ret == 0) {
                for (u64 i = 0; i < n; i++) {
                    s->val[i] = vals[i];
                    s->lpid[i] = q->pid;
                }
                sem_undo_clear(s->semid, -1);
                s->ctime = now_sec();
                s->tpid = q->pid;
            }
        }
        arena_free(vals);
        return 0;
    }
    if (q->arg == CNG_GETALL) {
        struct sem_set *s = sem_find(q->id);
        if (!s) {
            r->ret = -EINVAL;
            return 0;
        }
        sem_reclaim_set(s);
        if (!ipc_access(s->mode, s->uid, s->cuid, s->gid, s->cgid, q->uid,
                        q->gid, 04)) {
            r->ret = -EACCES;
            return 0;
        }
        r->ret = (s32)s->nsems; /* the client reads that many values back */
        if (cng_broker_send(cfd, r, sizeof *r, -1) == 0)
            cng_broker_write_full(cfd, s->val,
                                  (unsigned)(s->nsems * sizeof *s->val));
        return 2; /* already replied */
    }
    r->ret = sem_do_ctl(q, r);
    return 0;
}

static int serve_msgsnd(int cfd, const struct cng_breq *q, struct cng_bresp *r) {
    u64 sz = q->size;
    if (sz > CNG_MSGMAX || q->mtype <= 0)
        return -1; /* the client pre-checks both: a peer sending this is rogue */
    struct gmsg *m = arena_alloc(sizeof *m + sz);
    if (!m)
        return -1; /* the payload is still in flight: the stream is unusable */
    m->next = 0;
    m->mtype = q->mtype;
    m->size = sz;
    if (sz && cng_broker_read_full(cfd, GMSG_DATA(m), (unsigned)sz) != 0) {
        arena_free(m);
        return -1;
    }
    struct msg_q *mq = msg_find(q->id);
    if (!mq) {
        arena_free(m);
        r->ret = -EINVAL;
        return 0;
    }
    if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid, q->uid,
                    q->gid, 02)) {
        arena_free(m);
        r->ret = -EACCES;
        return 0;
    }
    if (msg_fits(mq, sz)) {
        msg_enqueue(mq, m, q->pid);
        r->ret = 0;
        return 0;
    }
    if (q->arg & CNG_IPC_NOWAIT) {
        arena_free(m);
        r->ret = -EAGAIN;
        return 0;
    }
    if (waiter_park(cfd, q, 0, 0, 0, m))
        return 1;
    arena_free(m);
    r->ret = -EAGAIN; /* the waiter table is full */
    return 0;
}

static int serve_msgrcv(int cfd, const struct cng_breq *q, struct cng_bresp *r) {
    struct msg_q *mq = msg_find(q->id);
    if (!mq) {
        r->ret = -EINVAL;
        return 0;
    }
    if (!ipc_access(mq->mode, mq->uid, mq->cuid, mq->gid, mq->cgid, q->uid,
                    q->gid, 04)) {
        r->ret = -EACCES;
        return 0;
    }
    struct gmsg *prev, *m = msg_pick(mq, q->mtype, (s32)q->arg, &prev);
    if (m) {
        if (m->size > q->size && !(q->arg & CNG_MSG_NOERROR)) {
            r->ret = -E2BIG; /* the message stays on the queue */
            return 0;
        }
        msg_unlink(mq, m, prev);
        mq->lrpid = q->pid;
        mq->rtime = now_sec();
        mq->tpid = q->pid;
        u64 n = m->size <= q->size ? m->size : q->size;
        r->ret = (s32)n;
        r->mtype = m->mtype;
        if (cng_broker_send(cfd, r, sizeof *r, -1) == 0)
            cng_broker_write_full(cfd, GMSG_DATA(m), (unsigned)n);
        arena_free(m);
        return 2; /* already replied */
    }
    if (q->arg & CNG_IPC_NOWAIT) {
        r->ret = -ENOMSG;
        return 0;
    }
    if (waiter_park(cfd, q, 0, 0, 0, 0))
        return 1;
    r->ret = -ENOMSG; /* the waiter table is full */
    return 0;
}

int cng_ipc_serve(int cfd, const struct cng_breq *q) {
    struct cng_bresp r;
    memset(&r, 0, sizeof r);
    if (!tables()) {
        r.ret = -ENOSPC;
        cng_broker_send(cfd, &r, sizeof r, -1);
        return 0;
    }
    int st = 0;
    switch (q->op) {
    case CNG_REQ_SEMGET:
        r.ret = sem_do_get(q);
        break;
    case CNG_REQ_SEMOP:
        st = serve_semop(cfd, q, &r);
        break;
    case CNG_REQ_SEMCTL:
        st = serve_semctl(cfd, q, &r);
        break;
    case CNG_REQ_MSGGET:
        r.ret = msg_do_get(q);
        break;
    case CNG_REQ_MSGSND:
        st = serve_msgsnd(cfd, q, &r);
        break;
    case CNG_REQ_MSGRCV:
        st = serve_msgrcv(cfd, q, &r);
        break;
    case CNG_REQ_MSGCTL:
        r.ret = msg_do_ctl(q, &r);
        break;
    default:
        r.ret = -EINVAL; /* including CNG_REQ_CANCEL on a fresh connection */
        break;
    }
    if (st == 1)
        return 1; /* parked: the connection lives on in a waiter slot */
    if (st == 0)
        cng_broker_send(cfd, &r, sizeof r, -1);
    return 0; /* st == 2: already replied, and st == -1: drop it */
}

/* ---- liveness ------------------------------------------------------------ */

/* Apply every undo row a dead process left behind, and drop waiters whose
 * caller is gone. The zombie test matters for the same reason it does on the
 * shm side: a process that has exited but not been reaped still owns its pid,
 * so its starttime still matches, yet the kernel has already run its exit. */
void cng_ipc_reclaim(void) {
    if (!g_sem)
        return;
    for (int i = 0; i < IPC_WAITER_MAX; i++) {
        struct waiter *w = &g_wait[i];
        if (!w->used)
            continue;
        int zombie = 0;
        u64 start = cng_proc_starttime(w->pid, &zombie);
        if (start != w->start || zombie)
            waiter_free(w); /* no reply: there is nobody left to read it */
    }
    int applied = 0;
    for (int i = 0; i < SEM_UNDO_MAX; i++) {
        struct sem_undo *u = &g_undo[i];
        if (!u->used)
            continue;
        int zombie = 0;
        u64 start = cng_proc_starttime(u->pid, &zombie);
        if (start != u->start || zombie) {
            sem_undo_apply(u); /* the kernel's exit-time undo */
            applied = 1;
        }
    }
    /* An undo raises semaphore values, which is exactly the state change a
     * parked semop is waiting for — and the daemon only rescans after serving a
     * request, so a reclaim that fires with nothing else going on woke nobody.
     * A holder that took a semaphore with SEM_UNDO and then died left every
     * sleeper on that semaphore parked forever, even though the resource it was
     * waiting for had just been released on its behalf. That is the whole point
     * of SEM_UNDO: the kernel's exit-time undo does wake them. */
    if (applied)
        cng_ipc_rescan();
}

int cng_ipc_any_live(void) {
    if (!g_sem)
        return 0;
    if (g_nwait || g_nundo)
        return 1;
    for (int i = 0; i < SEM_SET_MAX; i++) {
        struct sem_set *s = &g_sem[i];
        if (s->used && s->tpid > 0 && cng_proc_starttime(s->tpid, 0) != 0)
            return 1;
    }
    for (int i = 0; i < MSG_QUEUE_MAX; i++) {
        struct msg_q *q = &g_msq[i];
        if (q->used && q->tpid > 0 && cng_proc_starttime(q->tpid, 0) != 0)
            return 1;
    }
    return 0;
}

int cng_ipc_pending(void) {
    return g_nwait || g_nundo;
}

int cng_ipc_poll_add(struct cng_pollfd *pf, int n, int cap, s64 now_ms,
                     s64 *next_ms) {
    if (!g_wait || !g_nwait)
        return n;
    for (int i = 0; i < IPC_WAITER_MAX && n < cap; i++) {
        struct waiter *w = &g_wait[i];
        if (!w->used)
            continue;
        pf[n].fd = w->cfd;
        pf[n].events = CNG_POLLIN;
        pf[n].revents = 0;
        n++;
        if (w->deadline_ms >= 0 && w->deadline_ms - now_ms < *next_ms)
            *next_ms = w->deadline_ms - now_ms;
    }
    return n;
}

void cng_ipc_poll_ready(struct cng_pollfd *pf, int from, int n) {
    if (!g_wait)
        return;
    for (int k = from; k < n; k++) {
        if (!pf[k].revents)
            continue;
        struct waiter *w = 0;
        for (int i = 0; i < IPC_WAITER_MAX; i++)
            if (g_wait[i].used && g_wait[i].cfd == pf[k].fd) {
                w = &g_wait[i];
                break;
            }
        if (!w)
            continue;
        /* The only message a parked connection ever carries is a cancel; a read
         * that returns anything else — EOF, an error, garbage — means the waiter
         * is gone and the slot goes with it. */
        struct cng_breq cq;
        long got = CNG_SYS(__NR_recvfrom, w->cfd, &cq, sizeof cq,
                           CNG_MSG_DONTWAIT, 0, 0);
        if (got == (long)sizeof cq && cq.op == CNG_REQ_CANCEL) {
            struct cng_bresp cr;
            memset(&cr, 0, sizeof cr);
            cr.ret = -EINTR; /* the cancel-ack */
            waiter_reply(w, &cr, 0, 0);
        } else if (got >= 0 || (got != -EAGAIN && got != -EWOULDBLOCK)) {
            waiter_free(w);
        }
    }
}

void cng_ipc_free_all(void) {
    if (!g_sem)
        return;
    for (int i = 0; i < IPC_WAITER_MAX; i++)
        if (g_wait[i].used)
            waiter_free(&g_wait[i]);
    for (int i = 0; i < SEM_SET_MAX; i++)
        if (g_sem[i].used)
            sem_free_set(&g_sem[i]);
    for (int i = 0; i < MSG_QUEUE_MAX; i++)
        if (g_msq[i].used)
            msg_free_queue(&g_msq[i]);
}
