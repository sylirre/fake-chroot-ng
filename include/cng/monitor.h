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

/* Close every FD_CLOEXEC descriptor, as a real execve would (emulated execve
 * does not, so fork/exec launchers' O_CLOEXEC notify pipes must be closed here
 * or the parent blocks). Exposed for testing. */
void cng_close_cloexec(void);

/* Emulate one syscall: translate path args, re-issue via the gate, return the
 * kernel result. `trapped` = 1 when invoked from the SIGSYS handler (a syscall
 * reaching `default` was trapped by Android => emulate ENOSYS), 0 from an M8
 * trampoline (an unhandled syscall is ordinary => re-issue it). Directly
 * callable for testing (no seccomp needed). */
long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4, long a5,
                  int trapped);

/* One-shot-per-number diagnostic for a syscall we emulate away. */
void cng_note_blocked(int nr);

/* Verbose diagnostic (set by CNG_DEBUG=1): log intercepted syscalls whose
 * result is an error other than ENOENT, with the path where available. */
extern int cng_g_debug;

/* Resolve a guest path to a host path, following symlinks within the guest
 * (absolute link targets re-rooted into the rootfs). deref_final follows the
 * last component's own symlink. Returns 0/-errno. Uses cng_g_fs + readlink. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz);

/* Ambient-seccomp block-list: cng_blocked[nr] != 0 means Android blocks that
 * syscall, so dispatch emulates ENOSYS instead of re-issuing it. Populated by
 * cng_probe_blocked() at monitor install (a no-op result off Android). */
#define CNG_NR_MAX 512
extern unsigned char cng_blocked[CNG_NR_MAX];
void cng_probe_blocked(void);

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
