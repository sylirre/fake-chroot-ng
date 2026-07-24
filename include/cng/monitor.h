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

/* Host auxv captured at startup, reused to synthesize the auxv of programs
 * started via emulated execve. */
extern unsigned long *cng_host_auxv;

/* Fidelity config (M7). When cng_g_fake_id is set, credential syscalls report
 * cng_g_fake_uid/gid, setuid-family calls succeed silently, chown is faked, and
 * stat ownership is rewritten. cng_g_exe_guest is what /proc/self/exe reports. */
extern int cng_g_fake_id;
extern unsigned cng_g_fake_uid;
extern unsigned cng_g_fake_gid;
extern const char *cng_g_exe_guest;

/* Emulate execve/execveat in-process: load the new program, build its stack,
 * and rewrite the signal context (pc/sp/regs) to enter it — so the seccomp
 * filter and SIGSYS handler survive (a real execve would wipe them). On failure
 * it sets the return register to -errno and returns (normal execve semantics). */
void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp);

/* Emulate one trapped syscall: translate path args, re-issue via the gate,
 * return the kernel result. Directly callable for testing (no seccomp needed). */
long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4,
                  long a5);

/* Install a signal handler with our own rt_sigreturn restorer. Returns 0/-errno. */
int cng_sig_install(int signo, cng_sighandler_t h);

/* Core SIGSYS logic (exposed for testing): given the trapped signal context and
 * info, either translate+dispatch the guest syscall, or — when the trap is
 * Android's seccomp filter blocking a syscall WE re-issued from the gate —
 * convert it to -ENOSYS. Writes the result into the context's x0. */
void cng_sigsys_body(struct cng_ucontext *uc, cng_siginfo_t *si);

/* Build and install the seccomp filter (traps the path syscall set, allows the
 * gate IP range, allows everything else). Returns 0 or -errno. */
int cng_install_seccomp(void);

/* Point the dispatcher at fs, install the SIGSYS handler, then the filter.
 * Returns 0 on success or a negative errno (e.g. under qemu, where guest
 * seccomp filters are inert). */
int cng_install_monitor(struct cng_fs *fs);

#endif /* CNG_MONITOR_H */
