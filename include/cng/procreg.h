/* Guest-PID registry: the shared memory every guest process publishes its own
 * identity into, so any other guest process can be told apart from a host one
 * and described in guest terms.
 *
 * chroot-ng never issues a real execve, so the kernel's own record of a guest
 * process still describes the chroot-ng invocation that started it: its
 * /proc/<pid>/cmdline is our argv, its environ is our exec-time environment,
 * and its exe/cwd links name host paths. Each process therefore publishes the
 * guest view of itself here (argv, environ, auxv, exe, cwd) and procfs.c serves
 * that process's /proc entries from it. Membership doubles as the visibility
 * rule: a numeric
 * /proc/<pid> that is not registered is not a guest process, so the path layer
 * hides it (see cng_procreg_has).
 *
 * Ported from arm64chroot's proctab.c, minus its cross-invocation backing: a
 * guest process tree here is a real fork tree, so one MAP_SHARED|MAP_ANONYMOUS
 * region inherited across fork() covers every process in the session. Two
 * separate chroot-ng invocations on one rootfs do not share a registry (they
 * see each other's processes as host ones, i.e. hidden), which is the same
 * degradation arm64chroot has without -shared-proc.
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

#define CNG_PROCREG_MAX     256  /* concurrent guest processes in the view */
#define CNG_PROCREG_CMDLINE 1024 /* per-entry caps; longer values truncate */
#define CNG_PROCREG_ENVIRON 4096
#define CNG_PROCREG_AUXV     512
#define CNG_PROCREG_PATH     512

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
};

/* Map the shared region. Call once, before the monitor is installed and before
 * the guest can fork. A failure is not fatal: every entry point below then
 * no-ops and the /proc emulation degrades to host passthrough. */
void cng_procreg_init(void);

/* Publish (or update) this process's own entry. `argv`/`envp` are NULL-
 * terminated vectors, `auxv` the raw tag/value block built for the guest stack
 * (auxv_len bytes, 0 if none). Called at startup and after every emulated
 * execve — the two points a real kernel would rewrite the same fields. */
void cng_procreg_publish(char **argv, char **envp, const void *auxv,
                         unsigned auxv_len, const char *exe_guest,
                         const char *cwd_guest);

/* Copy this process's entry to `child`, at fork. Run by the parent (which knows
 * the child pid and holds the identical payload) rather than the child, because
 * a forked child need not make another traced syscall before something reads
 * its /proc entry. */
void cng_procreg_fork(int child);

/* Update just our own cwd (chdir/fchdir), so another process reading
 * /proc/<pid>/cwd sees the live value. */
void cng_procreg_set_cwd(const char *cwd_guest);

/* Is `pid` a guest process? Drives both the /proc/<pid> visibility rule and the
 * other-pid handlers in procfs.c. Our own pid always counts. */
int cng_procreg_has(int pid);

/* Snapshot `pid`'s payload. Returns 1 on a fresh hit, 0 on miss or when the
 * entry is stale (the pid was recycled by the host — detected by comparing the
 * recorded /proc/<pid>/stat starttime). */
int cng_procreg_get(int pid, struct cng_procsnap *out);

#endif /* CNG_PROCREG_H */
