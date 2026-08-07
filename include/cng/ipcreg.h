/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Daemon-side System V semaphore and message-queue registry (src/monitor/
 * ipcreg.c). Lives only inside the broker daemon; the guest-side half is
 * sysvipc.h. broker.c owns the rendezvous socket and the poll loop and calls
 * into here for everything else.
 *
 * Why the daemon rather than shared memory: every operation is an RPC, so all
 * mutation is single-threaded here and needs no locking, a multi-operation semop
 * is atomic for free, and a guest that dies mid-call cannot leave the registry
 * torn. It is also the only way to have SysV IPC at all on Android, where the
 * syscalls are denied outright.
 *
 * Blocking operations park: the connection stays open and is answered when the
 * operation can proceed, when its semtimedop deadline passes, when the object is
 * removed (EIDRM), when the caller cancels it (a signal became deliverable ->
 * EINTR), or when the caller dies (POLLHUP). That is why the poll loop has to
 * know about waiters at all — hence the four functions it calls each round.
 */
#ifndef CNG_IPCREG_H
#define CNG_IPCREG_H

#include "cng/broker.h"
#include "cng/rt.h"

struct cng_pollfd;

/* Parked connections the daemon can hold at once. The poll loop sizes its fd
 * array from this, so it lives here rather than in ipcreg.c. */
#define CNG_IPC_WAITER_MAX 512

/* Serve one semaphore or message-queue request on a connected client socket.
 * Reads any payload the request announces and sends the reply itself. Returns 1
 * when the connection has been parked (the caller must NOT close it), 0 when the
 * exchange is complete. */
int cng_ipc_serve(int cfd, const struct cng_breq *q);

/* Retry every parked operation, in arrival order, after any state change.
 * Repeats until a pass makes no progress: one grant can enable the next (a semop
 * releasing two units can wake two sleepers, a drained message frees queue space
 * for a parked sender, an enqueued one feeds a parked receiver). */
void cng_ipc_rescan(void);

/* Answer -EAGAIN to every waiter whose semtimedop deadline has passed. `now_ms`
 * is CLOCK_MONOTONIC milliseconds. Cheap: no /proc, so the loop calls it every
 * round rather than on the reclaim tick. */
void cng_ipc_expire(s64 now_ms);

/* Drop waiters and undo rows whose owner has died, applying each dead process's
 * SEM_UNDO adjustments as the kernel does at exit. Reads /proc, so the loop
 * calls it on a ~1 s tick and at the idle-exit check, not every round. */
void cng_ipc_reclaim(void);

/* Does a set, a queue, an undo row or a parked waiter still anchor this
 * namespace? The daemon exits only when nothing does. */
int cng_ipc_any_live(void);

/* Add every parked waiter's connection to `pf` (which already holds `n` entries)
 * and return the new count, capped at `cap`. `next_ms` is lowered to the nearest
 * deadline so a timed wait expires on time rather than at tick granularity. */
int cng_ipc_poll_add(struct cng_pollfd *pf, int n, int cap, s64 now_ms,
                     s64 *next_ms);

/* Handle whatever the poll reported on the waiter entries [from, n) of `pf`: a
 * cancel request, a dead peer, or protocol garbage. */
void cng_ipc_poll_ready(struct cng_pollfd *pf, int from, int n);

/* Are there parked waiters or undo rows to tick over? */
int cng_ipc_pending(void);

/* Release everything (daemon exit). */
void cng_ipc_free_all(void);

#endif /* CNG_IPCREG_H */
