/* Unified IPC broker: one per-namespace daemon serving the guest-PID registry
 * table AND the System V shared-memory registry.
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
};

/* One fixed-size request; small enough to be delivered atomically on a local
 * stream socket. The caller's pid and effective credentials are stamped by
 * cng_broker_rpc — the daemon has no other way to know them, and the perm
 * checks are against the guest's (possibly faked) identity, not the host's. */
struct cng_breq {
    u32 op;
    s32 key;  /* shmget: IPC key (0 = IPC_PRIVATE) */
    u64 size; /* shmget: requested size */
    s32 shmid;/* at/dt/fork/ctl: target segment (SHM_STAT: array index) */
    s32 arg;  /* shmget shmflg | shmat CNG_SHMAT_* | shmctl cmd */
    s32 pid;  /* caller's pid (guest pid == host pid here) */
    u32 uid, gid;                   /* caller's effective guest credentials */
    u32 set_mode, set_uid, set_gid; /* shmctl IPC_SET payload */
};

struct cng_bresp {
    s32 ret; /* shmid / 0 / SHM_INFO max index / -errno */
    s32 key; /* shm_perm.key (IPC_STAT / SHM_STAT) */
    u64 size, nattch;
    u32 mode, uid, gid, cuid, cgid;
    s32 cpid, lpid;
    s64 atime, dtime, ctime;
    s32 info_used; /* SHM_INFO: used_ids */
    u64 info_tot;  /* SHM_INFO: total pages over all segments */
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

#endif /* CNG_BROKER_H */
