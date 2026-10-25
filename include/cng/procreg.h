/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Guest-PID registry: the shared memory every guest process publishes its own
 * identity into, so any other guest process can be told apart from a host one
 * and described in guest terms.
 *
 * chroot-ng never issues a real execve, so the kernel's own record of a guest
 * process still describes the chroot-ng invocation that started it: its
 * /proc/<pid>/cmdline is our argv, its environ is our exec-time environment,
 * and its exe/cwd links name host paths. Each process therefore publishes the
 * guest view of itself here (argv, environ, auxv, exe, cwd) and procfs.c serves
 * that process's /proc entries from it. cmdline and environ are published as
 * where they live, too (struct cng_procargs): the kernel reads both out of the
 * process's memory at read time, so a title written over argv shows, and the
 * copies here are what is left when that memory cannot be read. Where the
 * kernel lets its own record be pointed at the guest's strings, that record
 * answers instead (procfs.c). Membership doubles as the visibility
 * rule: a numeric
 * /proc/<pid> that is not registered is not a guest process, so the path layer
 * hides it (see cng_procreg_has), and the calls that name a process by pid —
 * process_vm_*, pidfd_open, the signal family — answer ESRCH for it.
 *
 * Ported from arm64chroot's proctab.c. By default the backing is one
 * MAP_SHARED|MAP_ANONYMOUS region inherited across fork() — a guest process
 * tree here is a real fork tree, so that covers every process of one
 * invocation, and two separate invocations on one rootfs hide each other's
 * processes. With --shared-proc the view spans independent invocations
 * (ps/top in one session see the guest processes of another), via the first
 * of these that works (arm64chroot's tiers):
 *   1. broker — diskless, the normal path: a per-rootfs daemon owns an
 *      anonymous memfd (the table) and an abstract-namespace socket (the
 *      rendezvous) and hands the memfd to every invocation over SCM_RIGHTS.
 *      Clients keep no persistent broker fd (host fd == guest fd here, so a
 *      held fd would leak into the guest); the daemon uses the registry
 *      itself as its liveness signal and exits once no guest of the rootfs
 *      has been alive for a grace window — no file, no leftover socket name.
 *   2. named file — when memfd or abstract sockets are unavailable (pre-3.17
 *      kernel, a seccomp filter blocking memfd_create): a 0600 file keyed by
 *      uid+rootfs on tmpfs or an app-writable dir.
 *   3. anonymous — last resort, the per-invocation default above.
 *
 * Lock-free: slots are claimed by CAS on the pid, and the payload is written
 * under a seqlock — the writer is always the process the entry describes (or
 * its parent, at fork), and readers retry. That matters because every access
 * happens inside the SIGSYS handler, where a sleeping lock could deadlock
 * against the thread it interrupted.
 */
#ifndef CNG_PROCREG_H
#define CNG_PROCREG_H

#include "cng/rt.h"

#define CNG_PROCREG_MAX    4096  /* concurrent guest processes in the view */
#define CNG_PROCREG_CMDLINE 1024 /* per-entry caps; longer values truncate */
#define CNG_PROCREG_ENVIRON 4096
#define CNG_PROCREG_AUXV     512
#define CNG_PROCREG_PATH     512

/* Where a process's argv and environment strings are in its own memory: the
 * kernel's mm->arg_start..arg_end and env_start..env_end, which its
 * /proc/<pid>/cmdline and environ read at read time. All zero when the stack
 * was not one the loader laid out, which leaves only the copies. `kernel` says
 * the kernel's own record has been pointed at these ranges (PR_SET_MM_MAP), so
 * the host's files already are the guest's. */
struct cng_procargs {
    u64 arg_start, arg_end, env_start, env_end;
    u32 kernel;
};

/* One seqlock-consistent read of an entry's payload. Byte counts, not
 * NUL-terminated (callers append a terminator where they need one). */
struct cng_procsnap {
    char cmd[CNG_PROCREG_CMDLINE];
    char env[CNG_PROCREG_ENVIRON];
    char auxv[CNG_PROCREG_AUXV];
    char exe[CNG_PROCREG_PATH];
    char cwd[CNG_PROCREG_PATH];
    u32 cmd_len, env_len, auxv_len;
    u16 exe_len, cwd_len;
    struct cng_procargs args;
};

/* --shared-proc: back the registry per-rootfs so independent invocations share
 * one view. Set by the option parser before cng_procfs_init runs. */
extern int cng_g_shared_proc;

/* Which backing cng_procreg_init ended up with (for tests and -t proctest). */
#define CNG_PROCREG_B_NONE   0 /* no registry: /proc degrades to passthrough */
#define CNG_PROCREG_B_ANON   1 /* per-invocation anonymous mapping */
#define CNG_PROCREG_B_FILE   2 /* --shared-proc named-file fallback */
#define CNG_PROCREG_B_BROKER 3 /* --shared-proc memfd from the broker daemon */
extern int cng_g_procreg_backing;

/* Map the shared region. Call once, before the monitor is installed and before
 * the guest can fork (with a key, the broker daemon is forked from here — that
 * must happen while we are still single-threaded and unfiltered).
 * `shared_key` is the rootfs path to share the registry by (--shared-proc), or
 * NULL for the per-invocation table. A failure is not fatal: every entry point
 * below then no-ops and the /proc emulation degrades to host passthrough. */
void cng_procreg_init(const char *shared_key);

/* Publish (or update) this process's own entry. `argv`/`envp` are NULL-
 * terminated vectors, `auxv` the raw tag/value block built for the guest stack
 * (auxv_len bytes, 0 if none), `args` where the strings of both vectors lie.
 * Called at startup and after every emulated execve — the two points a real
 * kernel would rewrite the same fields. */
void cng_procreg_publish(char **argv, char **envp, const void *auxv,
                         unsigned auxv_len, const struct cng_procargs *args,
                         const char *exe_guest, const char *cwd_guest);

/* Copy this process's entry to `child`, at fork. Run by the parent (which knows
 * the child pid and holds the identical payload) rather than the child, because
 * a forked child need not make another traced syscall before something reads
 * its /proc entry. */
void cng_procreg_fork(int child);
/* The child's half: do not go on to run guest code before that copy has
 * landed. A child the scheduler ran ahead of its parent's publish found no
 * entry of its own when it forked in turn, so its child was never published:
 * invisible for good, refused by PTRACE_ATTACH and hidden from kill. Waits a
 * bounded time for the parent, then copies `forker`'s entry (the pid the clone
 * was issued from, sampled before it) itself. */
void cng_procreg_fork_child(int forker);

/* Update just our own cwd (chdir/fchdir), so another process reading
 * /proc/<pid>/cwd sees the live value. */
void cng_procreg_set_cwd(const char *cwd_guest);

/* Is `pid` a guest process? Drives both the /proc/<pid> visibility rule and the
 * other-pid handlers in procfs.c. Our own pid always counts. */
int cng_procreg_has(int pid);

/* Is `tid` a task of a guest process — the process itself, or one of its
 * threads? The kernel finds a task by any tid it has (kill, ptrace, capget all
 * do), so the questions those answer about "a guest" have to as well; the
 * registry itself is keyed by thread-group leader. A secondary thread costs a
 * probe when it is one of ours, and a read of its status file otherwise. */
int cng_procreg_has_task(int tid);

/* A walk over every guest process: slots 0 .. cng_procreg_slots()-1, and the
 * pid of the process in slot `i` — 0 for a free slot, one whose process is gone
 * or whose pid the host has reused (cng_procreg_has's guard), and for the later
 * of two slots that hold one pid, so a walk visits exactly the processes the
 * view shows, each once. Our own pid counts like any other. For the calls that
 * name every process at once: kill(2)'s group and broadcast forms. */
int cng_procreg_slots(void);
int cng_procreg_pid_at(int i);

/* Snapshot `pid`'s payload. Returns 1 on a fresh hit, 0 on miss or when the
 * entry is stale (the pid was recycled by the host — detected by comparing the
 * recorded /proc/<pid>/stat starttime). */
int cng_procreg_get(int pid, struct cng_procsnap *out);

/* Just `pid`'s cng_procargs, without the copy of everything else: asked for
 * every open and stat of a cmdline or environ, to learn whether the host file
 * already answers. No starttime check of its own, so a caller asks
 * cng_procreg_has first. Returns 1 with *out filled, 0 on a miss. */
int cng_procreg_args(int pid, struct cng_procargs *out);

/* `pid`'s incarnation: its /proc/<pid>/stat starttime, or 0 if it is gone or
 * /proc is unreadable. `zombie_out`, when non-NULL, reports whether the process
 * has exited without being reaped — it still owns its pid, so this is not a
 * reuse, but it holds no mappings (broker.c's shm attach reclaim keys on that).
 * Shared with broker.c, which has no other way to tell a live guest from a dead
 * one. */
u64 cng_proc_starttime(int pid, int *zombie_out);

/* The thread group host task `tid` belongs to (its Tgid: line), or -1 if it is
 * gone or /proc is unreadable. */
int cng_proc_tgid(int tid);

/* The shared region's byte size, for whoever creates the backing — including
 * the broker daemon, which sizes its table memfd from this. */
unsigned long cng_procreg_table_size(void);

/* Is any process in `tab` (a mapping of that size) still alive? The broker
 * daemon's liveness signal for the --shared-proc table it serves. */
int cng_procreg_table_live(const void *tab);

#endif /* CNG_PROCREG_H */
