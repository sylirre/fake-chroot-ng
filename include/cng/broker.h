/* Unified IPC broker: one per-namespace daemon serving the guest-PID registry
 * table AND the whole of System V IPC — shared memory, semaphores and message
 * queues.
 *
 * Ported from arm64chroot's proctab.c, whose daemon multiplexes both over a
 * single abstract-socket rendezvous. chroot-ng grew the daemon first for
 * --shared-proc (see procreg.h); this file is that daemon, generalized from a
 * one-byte handshake to a tagged request protocol so the shm side (shm.c) can
 * share it.
 *
 * Why a daemon owns the segments at all: Android denies shmget/shmat/shmdt/
 * shmctl outright and has no ownerless tmpfs, so a segment must be an ordinary
 * mappable fd — an anonymous memfd, or a file in a writable dir where
 * memfd_create is unavailable. Somebody has to hold that fd for the lifetime of
 * the segment, and it cannot be a guest process: host fd == guest fd here, so a
 * held fd would be visible to (and closable by) the guest. The daemon holds it
 * and hands out duplicates over SCM_RIGHTS; an attacher maps the fd it is given
 * and closes it, so a process holds a segment only as a mapping.
 *
 * The rendezvous name scopes the namespace:
 *   --shared-proc  per rootfs+uid — every invocation over one rootfs meets at
 *                  one daemon, so its guest processes and its segments are one
 *                  view (this is also the daemon procreg.c fetches its table
 *                  from);
 *   default        per invocation, keyed by cng_broker_session() — one launch's
 *                  process tree shares a shm namespace, separate launches stay
 *                  isolated.
 *
 * Clients keep no persistent broker fd: every exchange connects, asks, and
 * closes. The daemon uses the registries themselves as its liveness signal and
 * exits once neither a live guest nor a live segment has anchored the namespace
 * for a grace window — leaving no file, no socket name and no stray fd.
 */
#ifndef CNG_BROKER_H
#define CNG_BROKER_H

#include "cng/rt.h"

/* cng_breq.arg for CNG_REQ_SHMAT: which access the attach is asking for, which
 * is what the segment's permission triad is checked against (a plain attach
 * needs write; these two ask for read-only and for execute instead). */
#define CNG_SHMAT_RDONLY 1
#define CNG_SHMAT_EXEC   2

/* cng_breq.op */
enum {
    CNG_REQ_TAB = 1, /* hand back the procreg table memfd */
    CNG_REQ_SHMGET,  /* find-or-create a segment */
    CNG_REQ_SHMAT,   /* nattch++ and hand back the backing fd */
    CNG_REQ_SHMDT,   /* nattch-- */
    CNG_REQ_SHMFORK, /* nattch++ for an attachment a fork child inherited */
    CNG_REQ_SHMCTL,  /* stat / set / rmid / the ipcs enumeration commands */
    CNG_REQ_SEMGET,  /* find-or-create a semaphore set */
    CNG_REQ_SEMOP,   /* arg = nsops; that many cng_sembuf follow the request */
    CNG_REQ_SEMCTL,  /* SETALL streams nsems u16 after the request; GETALL
                      * streams them back after the reply */
    CNG_REQ_MSGGET,  /* find-or-create a message queue */
    CNG_REQ_MSGSND,  /* size payload bytes follow the request */
    CNG_REQ_MSGRCV,  /* a grant streams ret payload bytes after the reply */
    CNG_REQ_MSGCTL,
    CNG_REQ_CANCEL,  /* on a parked connection: abandon the wait (-> EINTR) */
};

/* One fixed-size request; small enough to be delivered atomically on a local
 * stream socket. The caller's pid and effective credentials are stamped by
 * cng_broker_rpc — the daemon has no other way to know them, and the perm
 * checks are against the guest's (possibly faked) identity, not the host's.
 *
 * The fields are shared across the three object types, which is what keeps one
 * request struct (and one daemon) serving all of them; each comment lists the
 * meanings in shm / sem / msg order. */
struct cng_breq {
    u32 op;
    s32 key;  /* *get: IPC key (0 = IPC_PRIVATE) */
    u64 size; /* shmget size | semget nsems | msgsnd/msgrcv msgsz */
    s32 id;   /* target segment / set / queue (*_STAT: an array index) */
    s32 arg;  /* *get flags | shmat CNG_SHMAT_* | *ctl cmd | semop nsops |
               * msgsnd/msgrcv msgflg */
    s32 pid;  /* caller's pid (guest pid == host pid here) */
    u32 uid, gid;                   /* caller's effective guest credentials */
    u32 set_mode, set_uid, set_gid; /* *ctl IPC_SET payload */
    s32 semnum;                     /* semctl: which semaphore in the set */
    s32 val;                        /* semctl SETVAL | msgctl IPC_SET qbytes */
    s64 mtype;                      /* msgsnd type | msgrcv msgtyp */
    s64 timeout_ns;                 /* semtimedop timeout; -1 = untimed */
};

struct cng_bresp {
    s32 ret;   /* id / 0 / a semaphore value / byte count / *_INFO max index /
                * -errno */
    s32 key;   /* ipc_perm.key (IPC_STAT / *_STAT) */
    u64 size;  /* shm segsz | sem nsems | msg qbytes */
    u64 nattch;/* shm nattch | msg qnum */
    u32 mode, uid, gid, cuid, cgid;
    s32 cpid, lpid; /* shm creator/last-op | msg lspid/lrpid */
    s64 atime;      /* shm atime | sem otime | msg stime */
    s64 dtime;      /* shm dtime | msg rtime */
    s64 ctime;
    s32 info_used;  /* *_INFO: used ids */
    u64 info_tot;   /* *_INFO: pages | semaphores | messages, over all objects */
    u64 cbytes;     /* msg: bytes on the queue (STAT), over all queues (INFO) */
    s64 mtype;      /* msgrcv grant: the delivered message's type */
    /* CNG_REQ_TAB / a successful CNG_REQ_SHMAT also carry an fd (SCM_RIGHTS). */
};

/* Per-invocation nonce keying the rendezvous when --shared-proc is off. Seeded
 * once in the root process (cng_broker_seed_session, from cng_run) and
 * fork-inherited, so one launch's whole process tree shares one namespace. A
 * caller that never runs cng_run (the -t self-tests) gets a lazy seed on first
 * use. */
void cng_broker_seed_session(void);

/* One request/response round-trip against this process's namespace daemon,
 * spawning the daemon if nobody has yet. Stamps q->pid/uid/gid. `fd_out`, when
 * non-NULL, receives an SCM_RIGHTS fd or -1. Returns 0 on a completed exchange,
 * -1 if no daemon could be reached (the caller then fails the syscall). */
int cng_broker_rpc(struct cng_breq *q, struct cng_bresp *r, int *fd_out);

/* The same connection, handed over instead of driven: for the exchanges that
 * connect-ask-close cannot express — a payload streaming behind the request, a
 * reply streaming one back, or a blocking operation that parks in the daemon and
 * is cancelled from this end. Stamps q->pid/uid/gid as cng_broker_rpc does.
 * Returns a connected socket (the caller closes it) or -1. */
int cng_broker_open(struct cng_breq *q);

/* Fetch the procreg table memfd from the per-rootfs daemon (--shared-proc),
 * spawning it if absent. Returns the fd (caller mmaps and closes it) or -1 to
 * degrade to procreg.c's file / anonymous tiers. The daemon sizes the table
 * from cng_procreg_table_size(). */
int cng_broker_table_fd(const char *rootfs_key);

/* First writable directory that can hold shared state (the procreg file tier,
 * and a segment's backing where memfd_create is unavailable), or NULL. Desktop
 * RAM-backed tmpfs is preferred; Android has no ownerless tmpfs an app may
 * write, so the app's own tmp dirs are accepted next. */
const char *cng_broker_shared_dir(void);

/* Scan chroot-ng's own (host) environment for `name` (no libc getenv here). This
 * is where every CNG_* knob is read; the guest's environment is a separate,
 * deliberately clean vector (see cng_run) and is never consulted. */
const char *cng_broker_env(const char *name);

/* The namespace key hash (fnv1a32), shared with procreg.c's file tier so the
 * socket name and the file name agree on what identifies a rootfs. */
u32 cng_broker_key_hash(const char *s);

/* ---- transport, shared with the sem/msg registry (ipcreg.c) -------------
 * The semaphore and message-queue operations stream a payload alongside the
 * fixed request (a semop's operation vector, a message's bytes), and a parked
 * waiter is answered long after its request was served — so the registry drives
 * its own connection rather than returning a reply for broker.c to send. These
 * are the same four primitives the request/response path uses. */

/* One fixed-size payload plus an optional SCM_RIGHTS fd (fd < 0: none). */
int cng_broker_send(int sock, const void *data, unsigned len, int fd);
int cng_broker_recv(int sock, void *data, unsigned len, int *fd_out);
/* Exactly `len` bytes, looping over short reads/writes. 0 on success, -1 on a
 * closed or failing peer. */
int cng_broker_read_full(int fd, void *buf, unsigned len);
int cng_broker_write_full(int fd, const void *buf, unsigned len);

#endif /* CNG_BROKER_H */
