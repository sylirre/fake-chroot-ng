/* The in-process syscall monitor: a seccomp filter traps the path-bearing
 * syscalls to SIGSYS (unless the syscall's IP is inside our gate), and the
 * handler translates path arguments via cng_fs before re-issuing the real
 * syscall through the gate. See docs/DESIGN.md.
 */
#ifndef CNG_MONITOR_H
#define CNG_MONITOR_H

#include "cng/path.h"
#include "cng/ucontext.h"

/* Active filesystem view used by the dispatcher (set before install). */
extern struct cng_fs *cng_g_fs;

/* Emulate one trapped syscall: translate path args, re-issue via the gate,
 * return the kernel result. Directly callable for testing (no seccomp needed). */
long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4,
                  long a5);

/* Install a signal handler with our own rt_sigreturn restorer. Returns 0/-errno. */
int cng_sig_install(int signo, cng_sighandler_t h);

/* Build and install the seccomp filter (traps the path syscall set, allows the
 * gate IP range, allows everything else). Returns 0 or -errno. */
int cng_install_seccomp(void);

/* Point the dispatcher at fs, install the SIGSYS handler, then the filter.
 * Returns 0 on success or a negative errno (e.g. under qemu, where guest
 * seccomp filters are inert). */
int cng_install_monitor(struct cng_fs *fs);

#endif /* CNG_MONITOR_H */
