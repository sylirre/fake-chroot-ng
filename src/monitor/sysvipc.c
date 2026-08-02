/* System V semaphores and message queues, guest side (see cng/sysvipc.h).
 *
 * Ported from arm64chroot's src/sys_ipc.c. The emulator there copied every
 * argument in and out of a synthetic guest address space; here the guest's
 * memory is simply ours, so a struct is read where it lies — after a probe, since
 * this runs inside the SIGSYS handler with SIGSEGV masked and a fault there is
 * the death of the process, not an -EFAULT (see uaccess.c). The one thing to
 * keep in mind throughout: cng_user_writable() validates a range by ZEROING it,
 * so nothing may be probed for writing until everything that had to be read out
 * of it has been.
 *
 * The other difference is that there is no allocator here. Operation vectors and
 * messages are bounded by SEMOPM and MSGMAX and ride on the handler's scratch
 * stack; the one unbounded array — semctl's GETALL/SETALL vector, up to SEMMSL
 * values — is streamed through a small window instead.
 */
#include "cng/broker.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/sysvipc.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

#define IPC_64 0x100 /* callers OR this into every *ctl cmd on arm64 */

/* An internal semctl command shared with the daemon: a set's nsems with no
 * permission check, so a SETALL payload can be sized even for a write-only set. */
#define BROKER_SEMNSEMS (-100)

#define SEM_STREAM 1024 /* values per GETALL/SETALL window */

/* ---- exchanges ----------------------------------------------------------- */

/* The non-blocking shape: one request, one reply. */
static long ipc_rpc(struct cng_breq *q, struct cng_bresp *r) {
    if (cng_broker_rpc(q, r, 0) < 0)
        return -ENOSPC; /* no broker reachable: fail loud, never silently */
    return r->ret;
}

/* One blocking-capable exchange (semop / msgsnd / msgrcv). The request goes down
 * with its payload and the reply is waited for with no timeout of ours —
 * semtimedop deadlines are the daemon's business.
 *
 * The wait has to be interruptible by exactly the signals that would interrupt a
 * real one, and it cannot be interrupted by their arrival: the handler runs with
 * everything but SIGSYS masked. So it polls in slices and asks whether a signal
 * the guest would take delivery of has become pending; the slice also bounds the
 * unavoidable race between that question and the answer. On interruption
 * CNG_REQ_CANCEL goes down the same connection and the next message is
 * definitive — the daemon's grant if it won the race, otherwise the cancel-ack.
 * The ordered stream is what makes that exact: a granted operation is never
 * reported as EINTR, and a cancelled one was never applied. SysV IPC waits are
 * never restarted, so the EINTR reaches the guest as-is.
 *
 * `rbuf` (rmax bytes) receives a grant payload (msgrcv's data). A broker that
 * dies mid-wait yields EIDRM: the object died with the registry. */
static long ipc_wait_rpc(struct cng_breq *q, const void *payload, u64 plen,
                         struct cng_bresp *r, void *rbuf, u64 rmax) {
    int s = cng_broker_open(q);
    if (s < 0)
        return -EIDRM;
    struct cng_timeval tv0 = {0, 0}; /* drop the 2 s default: this may sleep */
    CNG_SYS(__NR_setsockopt, s, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO, &tv0,
            sizeof tv0, 0);
    long ret;
    /* Two writes; a signal between them cannot cancel, so both are finished and
     * the wait below takes the interruption. */
    if (cng_broker_send(s, q, sizeof *q, -1) != 0 ||
        (plen && cng_broker_write_full(s, payload, (unsigned)plen) != 0)) {
        ret = -EIDRM;
        goto out;
    }
    for (;;) {
        struct cng_pollfd pf = {s, CNG_POLLIN, 0};
        struct cng_timespec slice = {0, 100 * 1000000};
        long pr = CNG_SYS(__NR_ppoll, &pf, 1, &slice, 0, 8 /*sigsetsize*/, 0);
        if (pr > 0) { /* the daemon answered */
            ret = cng_broker_read_full(s, r, sizeof *r) == 0 ? r->ret : -EIDRM;
            break;
        }
        if (pr < 0 && pr != -EINTR) {
            ret = -EIDRM;
            break;
        }
        /* Either the slice elapsed, or the wait was interrupted by an actual
         * delivery. The latter only happens on the -R trampoline tier, which
         * runs with the guest's own mask — and there the delivery IS the
         * interruption, since the handler has already run by the time ppoll
         * returns and the signal is no longer pending to be found. Under the
         * SIGSYS handler nothing can be delivered, so the slice is what makes
         * the pending set visible at all. */
        if (pr != -EINTR && !cng_sig_deliverable())
            continue;
        struct cng_breq cq;
        memset(&cq, 0, sizeof cq);
        cq.op = CNG_REQ_CANCEL;
        cng_broker_send(s, &cq, sizeof cq, -1); /* EPIPE: a grant is en route */
        ret = cng_broker_read_full(s, r, sizeof *r) == 0 ? r->ret : -EIDRM;
        break;
    }
    if (ret > 0 && rbuf) { /* a grant streams its payload behind the reply */
        u64 n = (u64)ret;
        if (n > rmax || cng_broker_read_full(s, rbuf, (unsigned)n) != 0)
            ret = -EIDRM;
    }
out:
    sys_close(s);
    return ret;
}

/* ---- semaphores ---------------------------------------------------------- */

static long do_semget(s32 key, long nsems, s32 semflg) {
    /* nsems is a signed int, and a bad one fails before any key lookup — the
     * kernel's order, so even an existing key answers EINVAL here. */
    if (nsems < 0 || nsems > CNG_SEMMSL)
        return -EINVAL;
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMGET;
    q.key = key;
    q.size = (u64)nsems;
    q.arg = semflg;
    struct cng_bresp r;
    return ipc_rpc(&q, &r);
}

/* semop and semtimedop share this; timeout_ns is relative, -1 = untimed. */
static long do_semop(s32 semid, const void *sops_p, u64 nsops, s64 timeout_ns) {
    if (nsops == 0)
        return -EINVAL;
    if (nsops > CNG_SEMOPM)
        return -E2BIG;
    if (!cng_user_readable(sops_p, nsops * sizeof(struct cng_sembuf)))
        return -EFAULT;
    struct cng_sembuf sops[CNG_SEMOPM];
    memcpy(sops, sops_p, (size_t)nsops * sizeof *sops);
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMOP;
    q.id = semid;
    q.arg = (s32)nsops;
    q.timeout_ns = timeout_ns;
    struct cng_bresp r;
    return ipc_wait_rpc(&q, sops, nsops * sizeof *sops, &r, 0, 0);
}

static long do_semtimedop(s32 semid, const void *sops, u64 nsops,
                          const void *ts_p) {
    s64 timeout_ns = -1;
    if (ts_p) {
        if (!cng_user_readable(ts_p, sizeof(struct cng_timespec)))
            return -EFAULT;
        struct cng_timespec ts;
        memcpy(&ts, ts_p, sizeof ts);
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000)
            return -EINVAL;
        /* Saturate a >292-year timeout rather than overflowing it. */
        if (ts.tv_sec > (long)(0x7fffffffffffffffLL / 1000000000 - 1))
            timeout_ns = 0x7fffffffffffffffLL;
        else
            timeout_ns = (s64)ts.tv_sec * 1000000000 + ts.tv_nsec;
    }
    return do_semop(semid, sops, nsops, timeout_ns);
}

static void sem_fill_ds(struct cng_semid64_ds *ds, const struct cng_bresp *r) {
    memset(ds, 0, sizeof *ds);
    ds->sem_perm.key = r->key;
    ds->sem_perm.uid = r->uid;
    ds->sem_perm.gid = r->gid;
    ds->sem_perm.cuid = r->cuid;
    ds->sem_perm.cgid = r->cgid;
    ds->sem_perm.mode = r->mode;
    ds->sem_otime = r->atime;
    ds->sem_ctime = r->ctime;
    ds->sem_nsems = r->size;
}

/* GETALL: the daemon streams nsems u16 values behind its reply. They go into the
 * guest's array through a small window, so nothing here is sized by SEMMSL. */
static long sem_getall(s32 semid, void *out) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMCTL;
    q.id = semid;
    q.arg = CNG_GETALL;
    int s = cng_broker_open(&q);
    if (s < 0)
        return -EINVAL;
    long ret;
    struct cng_bresp r;
    if (cng_broker_send(s, &q, sizeof q, -1) != 0 ||
        cng_broker_recv(s, &r, sizeof r, 0) != 0) {
        ret = -EINVAL;
        goto out;
    }
    if (r.ret < 0) {
        ret = r.ret;
        goto out;
    }
    /* The whole array is probed in one go before any of it is read from the
     * socket: the probe zeroes what it validates, and a half-filled guest array
     * left behind by a failure partway would be worse than the plain EFAULT the
     * kernel gives. */
    u64 n = (u64)r.ret;
    if (!cng_user_writable(out, n * sizeof(u16))) {
        ret = -EFAULT;
        goto out;
    }
    u16 win[SEM_STREAM];
    u16 *dst = (u16 *)out;
    ret = 0;
    for (u64 done = 0; done < n;) {
        u64 k = n - done < SEM_STREAM ? n - done : SEM_STREAM;
        if (cng_broker_read_full(s, win, (unsigned)(k * sizeof *win)) != 0) {
            ret = -EINVAL;
            break;
        }
        memcpy(dst + done, win, (size_t)k * sizeof *win);
        done += k;
    }
out:
    sys_close(s);
    return ret;
}

/* SETALL: the values stream out behind the request. The daemon validates the
 * whole array before applying any of it, so a bad value still changes nothing. */
static long sem_setall(s32 semid, const void *in) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMCTL;
    q.id = semid;
    q.arg = BROKER_SEMNSEMS; /* how many values does this set take? */
    struct cng_bresp r;
    long n = ipc_rpc(&q, &r);
    if (n < 0)
        return n;
    if (!cng_user_readable(in, (u64)n * sizeof(u16)))
        return -EFAULT;

    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMCTL;
    q.id = semid;
    q.arg = CNG_SETALL;
    q.size = (u64)n;
    int s = cng_broker_open(&q);
    if (s < 0)
        return -EINVAL;
    long ret = -EINVAL;
    if (cng_broker_send(s, &q, sizeof q, -1) != 0)
        goto out;
    const u16 *src = (const u16 *)in;
    u16 win[SEM_STREAM];
    for (long done = 0; done < n;) {
        long k = n - done < SEM_STREAM ? n - done : SEM_STREAM;
        memcpy(win, src + done, (size_t)k * sizeof *win);
        if (cng_broker_write_full(s, win, (unsigned)(k * sizeof *win)) != 0)
            goto out;
        done += k;
    }
    if (cng_broker_recv(s, &r, sizeof r, 0) == 0)
        ret = r.ret;
out:
    sys_close(s);
    return ret;
}

static long do_semctl(s32 semid, s32 semnum, int cmd, u64 arg) {
    cmd &= ~IPC_64; /* arm64 has only the 64-bit ds */

    switch (cmd) {
    case CNG_GETALL:
        return sem_getall(semid, (void *)arg);
    case CNG_SETALL:
        return sem_setall(semid, (const void *)arg);
    }

    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SEMCTL;
    q.id = semid; /* a set id, or an array index for SEM_STAT */
    q.arg = cmd;
    q.semnum = semnum;
    if (cmd == CNG_SETVAL)
        q.val = (s32)arg;
    if (cmd == CNG_IPC_SET) {
        const struct cng_semid64_ds *in = (const struct cng_semid64_ds *)arg;
        if (!cng_user_readable(in, sizeof *in))
            return -EFAULT;
        q.set_mode = in->sem_perm.mode;
        q.set_uid = in->sem_perm.uid;
        q.set_gid = in->sem_perm.gid;
    }

    struct cng_bresp r;
    if (cng_broker_rpc(&q, &r, 0) < 0)
        return -EINVAL;

    /* The two enumeration commands deliver a struct and return a max index; the
     * broker's "nothing here" answer is -1, which the kernel clamps to 0 at the
     * user boundary (ipcs reads a negative return as "not configured"), so they
     * write their struct and clamp before the sign check below. */
    if (cmd == CNG_IPC_INFO || cmd == CNG_SEM_INFO) {
        struct cng_seminfo si;
        if (!cng_user_writable((void *)arg, sizeof si))
            return -EFAULT;
        memset(&si, 0, sizeof si);
        si.semmni = CNG_SEMMNI;
        si.semmsl = CNG_SEMMSL;
        si.semmns = CNG_SEMMNI * CNG_SEMMSL;
        si.semopm = CNG_SEMOPM;
        si.semvmx = CNG_SEMVMX;
        si.semmap = si.semmns; /* the legacy constants, as the kernel reports */
        si.semmnu = si.semmns;
        si.semume = CNG_SEMOPM;
        if (cmd == CNG_SEM_INFO) {
            si.semusz = r.info_used;      /* existing sets */
            si.semaem = (s32)r.info_tot;  /* semaphores over all of them */
        } else {
            si.semusz = 20; /* SEMUSZ */
            si.semaem = CNG_SEMAEM;
        }
        memcpy((void *)arg, &si, sizeof si);
        return r.ret < 0 ? 0 : r.ret;
    }

    if (r.ret < 0)
        return r.ret;
    if (cmd == CNG_IPC_STAT || cmd == CNG_SEM_STAT || cmd == CNG_SEM_STAT_ANY) {
        struct cng_semid64_ds ds;
        if (!cng_user_writable((void *)arg, sizeof ds))
            return -EFAULT;
        sem_fill_ds(&ds, &r);
        memcpy((void *)arg, &ds, sizeof ds);
    }
    return r.ret;
}

/* ---- message queues ------------------------------------------------------ */

static long do_msgget(s32 key, s32 msgflg) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_MSGGET;
    q.key = key;
    q.arg = msgflg;
    struct cng_bresp r;
    return ipc_rpc(&q, &r);
}

/* msgp is `struct msgbuf { long mtype; char mtext[]; }`. */
static long do_msgsnd(s32 msqid, const void *msgp, u64 msgsz, s32 msgflg) {
    if ((s64)msgsz < 0 || msgsz > CNG_MSGMAX)
        return -EINVAL;
    if (!cng_user_readable(msgp, sizeof(s64) + msgsz))
        return -EFAULT;
    s64 mtype;
    memcpy(&mtype, msgp, sizeof mtype);
    if (mtype < 1)
        return -EINVAL;
    char data[CNG_MSGMAX];
    if (msgsz)
        memcpy(data, (const char *)msgp + sizeof(s64), (size_t)msgsz);
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_MSGSND;
    q.id = msqid;
    q.size = msgsz;
    q.arg = msgflg;
    q.mtype = mtype;
    q.timeout_ns = -1;
    struct cng_bresp r;
    return ipc_wait_rpc(&q, data, msgsz, &r, 0, 0);
}

static long do_msgrcv(s32 msqid, void *msgp, u64 msgsz, s64 msgtyp, s32 msgflg) {
    if ((s64)msgsz < 0)
        return -EINVAL;
    if (msgflg & CNG_MSG_COPY)
        return -ENOSYS; /* checkpoint/restore; the oracle refuses it too */
    /* No message can exceed MSGMAX, so the bounce never needs more than that
     * however large a buffer the caller offered. */
    u64 cap = msgsz < CNG_MSGMAX ? msgsz : CNG_MSGMAX;
    char data[CNG_MSGMAX];
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_MSGRCV;
    q.id = msqid;
    q.size = msgsz;
    q.arg = msgflg;
    q.mtype = msgtyp;
    q.timeout_ns = -1;
    struct cng_bresp r;
    long n = ipc_wait_rpc(&q, 0, 0, &r, data, cap);
    if (n < 0)
        return n;
    /* The message is consumed whether or not the writeback lands, which is what
     * the kernel does too — it has already dequeued by the time it copies. */
    if (!cng_user_writable(msgp, sizeof(s64) + (u64)n))
        return -EFAULT;
    memcpy(msgp, &r.mtype, sizeof r.mtype);
    if (n)
        memcpy((char *)msgp + sizeof(s64), data, (size_t)n);
    return n;
}

static void msg_fill_ds(struct cng_msqid64_ds *ds, const struct cng_bresp *r) {
    memset(ds, 0, sizeof *ds);
    ds->msg_perm.key = r->key;
    ds->msg_perm.uid = r->uid;
    ds->msg_perm.gid = r->gid;
    ds->msg_perm.cuid = r->cuid;
    ds->msg_perm.cgid = r->cgid;
    ds->msg_perm.mode = r->mode;
    ds->msg_stime = r->atime;
    ds->msg_rtime = r->dtime;
    ds->msg_ctime = r->ctime;
    ds->msg_cbytes = r->cbytes;
    ds->msg_qnum = r->nattch;
    ds->msg_qbytes = r->size;
    ds->msg_lspid = r->cpid;
    ds->msg_lrpid = r->lpid;
}

static long do_msgctl(s32 msqid, int cmd, void *buf) {
    cmd &= ~IPC_64;

    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_MSGCTL;
    q.id = msqid; /* a queue id, or an array index for MSG_STAT */
    q.arg = cmd;
    if (cmd == CNG_IPC_SET) {
        const struct cng_msqid64_ds *in = (const struct cng_msqid64_ds *)buf;
        if (!cng_user_readable(in, sizeof *in))
            return -EFAULT;
        q.set_mode = in->msg_perm.mode;
        q.set_uid = in->msg_perm.uid;
        q.set_gid = in->msg_perm.gid;
        q.size = in->msg_qbytes; /* 64 bits wide: not the 32-bit `val` slot */
    }

    struct cng_bresp r;
    if (cng_broker_rpc(&q, &r, 0) < 0)
        return -EINVAL;

    if (cmd == CNG_IPC_INFO || cmd == CNG_MSG_INFO) {
        struct cng_msginfo mi;
        if (!cng_user_writable(buf, sizeof mi))
            return -EFAULT;
        memset(&mi, 0, sizeof mi);
        mi.msgmni = CNG_MSGMNI;
        mi.msgmax = CNG_MSGMAX;
        mi.msgmnb = CNG_MSGMNB;
        /* msgssz/msgseg describe a segment allocator no kernel has used since
         * 2.6, but msgctl_info fills them for MSG_INFO and IPC_INFO alike — only
         * the pool/map/tql triple is repurposed by MSG_INFO — so they belong
         * outside the branch. */
        mi.msgssz = 16;     /* MSGSSZ */
        mi.msgseg = 0xffff; /* MSGSEG, clamped as the uapi header clamps it */
        if (cmd == CNG_MSG_INFO) {
            mi.msgpool = r.info_used;    /* existing queues */
            mi.msgmap = (s32)r.info_tot; /* messages over all of them */
            mi.msgtql = (s32)r.cbytes;   /* bytes over all of them */
        } else {
            mi.msgpool = CNG_MSGMNI * (CNG_MSGMNB / 1024); /* legacy constants */
            mi.msgmap = CNG_MSGMNB;
            mi.msgtql = CNG_MSGMNB;
        }
        memcpy(buf, &mi, sizeof mi);
        return r.ret < 0 ? 0 : r.ret;
    }

    if (r.ret < 0)
        return r.ret;
    if (cmd == CNG_IPC_STAT || cmd == CNG_MSG_STAT || cmd == CNG_MSG_STAT_ANY) {
        struct cng_msqid64_ds ds;
        if (!cng_user_writable(buf, sizeof ds))
            return -EFAULT;
        msg_fill_ds(&ds, &r);
        memcpy(buf, &ds, sizeof ds);
    }
    return r.ret;
}

/* ---- dispatch ------------------------------------------------------------ */

long cng_sysvipc_handle(long nr, long a0, long a1, long a2, long a3, long a4) {
    switch (nr) {
    case __NR_semget:
        return do_semget((s32)a0, (long)(s32)a1, (s32)a2);
    case __NR_semop:
        return do_semop((s32)a0, (const void *)a1, (u64)a2, -1);
    case __NR_semtimedop:
        return do_semtimedop((s32)a0, (const void *)a1, (u64)a2,
                             (const void *)a3);
    case __NR_semctl:
        return do_semctl((s32)a0, (s32)a1, (int)a2, (u64)a3);
    case __NR_msgget:
        return do_msgget((s32)a0, (s32)a1);
    case __NR_msgsnd:
        return do_msgsnd((s32)a0, (const void *)a1, (u64)a2, (s32)a3);
    case __NR_msgrcv:
        return do_msgrcv((s32)a0, (void *)a1, (u64)a2, (s64)a3, (s32)a4);
    case __NR_msgctl:
        return do_msgctl((s32)a0, (int)a1, (void *)a2);
    default:
        return -ENOSYS;
    }
}
