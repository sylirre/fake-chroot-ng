/* The in-process syscall monitor: a seccomp filter traps the path-bearing
 * syscalls to SIGSYS (unless the syscall's IP is inside our gate), and the
 * handler translates path arguments via cng_fs before re-issuing the real
 * syscall through the gate. See docs/DESIGN.md.
 */
#ifndef CNG_MONITOR_H
#define CNG_MONITOR_H

#include "cng/path.h"
#include "cng/ucontext.h"

/* Shared by --version and the CNG_DEBUG startup banner (which also stamps the
 * build time: this repo is copied to devices by hand, so "am I running the
 * build I just made?" is a question every device-side trace has to answer). */
/* 0.1.0 reversed -b to SRC:DST (host first), matching arm64chroot. This tree
 * reaches devices by hand-copy, so the version must distinguish a build that
 * carries the old GUEST:HOST order from one that does not. */
#define CNG_VERSION "0.1.0"

/* Active filesystem view used by the dispatcher (set before install). */
extern struct cng_fs *cng_g_fs;

/* Host auxv captured at startup, reused to synthesize the auxv of programs
 * started via emulated execve. */
extern unsigned long *cng_host_auxv;

/* Fidelity config (M7): fake user identity (--fake-id).
 *
 * When cng_g_fake_id is set the guest is presented a synthetic credential set
 * (cng_g_cred) seeded from the configured uid:gid. Credential syscalls read and
 * mutate this set following real POSIX privilege rules (so a privilege drop
 * actually changes what getuid() reports, and a non-root fake id cannot regain
 * uid 0); ownership/mode changes and denied access() checks are faked as
 * succeeding while the effective uid is 0 (cng_fake_root); and stat ownership is
 * remapped so files owned by the real invoking user (cng_g_host_uid/gid) appear
 * owned by the fake id. The set is process-wide and, because the guest forks for
 * real, is inherited across fork() exactly as the kernel would. cng_g_exe_guest
 * is what /proc/self/exe reports. */
#define CNG_NGROUPS_MAX 64

struct cng_cred {
    unsigned ruid, euid, suid, fsuid;    /* real, effective, saved-set, fs uid */
    unsigned rgid, egid, sgid, fsgid;    /* real, effective, saved-set, fs gid */
    unsigned groups[CNG_NGROUPS_MAX];    /* supplementary groups */
    int ngroups;
};

extern int cng_g_fake_id;                /* --fake-id active */
extern int cng_g_fake_id_explicit;       /* an id was requested via -u/--fake-id
                                          * (vs. only implied by --setuid-root):
                                          * when 0, the identity defaults to the
                                          * real invoking id, not 0:0 */
extern unsigned cng_g_fake_uid;          /* configured id = stat remap target */
extern unsigned cng_g_fake_gid;          /* (fixed; live ids live in cng_g_cred) */
extern unsigned cng_g_host_uid;          /* real invoking uid, captured at start */
extern unsigned cng_g_host_gid;          /* real invoking gid */
extern struct cng_cred cng_g_cred;       /* live credential set */
extern const char *cng_g_exe_guest;

/* Show setuid/setgid *executables* as owned by root (uid/gid 0), and — on exec —
 * elevate the fake identity's effective id to 0. This is what lets a setuid-root
 * binary such as `su` gain root under a non-root fake id. Both imply --fake-id
 * (the credential subsystem they depend on). See cng_exec_vis_* / cng_cred_exec. */
extern int cng_g_setuid_root;
extern int cng_g_setgid_root;

/* File-type / set-id mode bits used by the fake-id ownership fixups. */
#define CNG_S_IFMT  0170000u
#define CNG_S_IFREG 0100000u
#define CNG_S_ISUID 0004000u
#define CNG_S_ISGID 0002000u

/* Seed the live credential set from cng_g_fake_uid/gid (r=e=s=fs, no groups).
 * Call once cng_g_fake_uid/gid (and cng_g_host_uid/gid) are set. */
void cng_cred_seed(void);

/* Establish the fake identity at startup from the real invoking id: record it as
 * the stat-remap source, and — when no id was requested explicitly (the identity
 * is only implied by --setuid-root/--setgid-root) — default the fake id to it
 * rather than 0:0, then seed the live set. Called once by cng_run. */
void cng_cred_setup(unsigned host_uid, unsigned host_gid);

/* Apply setuid/setgid-on-exec to the fake credential set: if `host` (the ELF
 * being exec'd) is a setuid/setgid regular file, its effective/saved/fs id
 * becomes the file's visible owner/group — root under --setuid-root/--setgid-root
 * (see cng_exec_vis_*). No-op unless a fake identity is active and at least one
 * of the flags is set. Applied by the emulated execve and the initial run. */
void cng_cred_exec(const char *host);

/* Emulate a credential syscall (get/set uid/gid family, groups, capabilities)
 * against cng_g_cred. Only the first three args are consumed by any of them;
 * the rest are forwarded for the (rare) non-faking re-issue path. */
long cng_cred_handle(long nr, long a0, long a1, long a2, long a3, long a4,
                     long a5);

/* True when a fake identity is active AND its effective uid is 0: root's DAC
 * bypass applies (ownership/mode changes and denied access() checks are faked). */
static inline int cng_fake_root(void) {
    return cng_g_fake_id && cng_g_cred.euid == 0;
}

/* Remap a host-side owner for stat results: a file owned by the real invoking
 * user is shown as owned by the fake id; every other owner passes through. A
 * no-op unless a fake identity is active. */
static inline unsigned cng_remap_uid(unsigned u) {
    return (cng_g_fake_id && u == cng_g_host_uid) ? cng_g_fake_uid : u;
}
static inline unsigned cng_remap_gid(unsigned g) {
    return (cng_g_fake_id && g == cng_g_host_gid) ? cng_g_fake_gid : g;
}

/* Visible owner/group of a file with mode `mode`: a setuid/setgid *regular* file
 * is shown as owned by root (0) when the matching --setuid-root/--setgid-root is
 * set — so setuid-root binaries like `su` appear (and, on exec, act) as root;
 * otherwise the plain host->fake remap applies. */
static inline unsigned cng_exec_vis_uid(unsigned u, unsigned mode) {
    if (cng_g_setuid_root && (mode & CNG_S_ISUID) &&
        (mode & CNG_S_IFMT) == CNG_S_IFREG)
        return 0;
    return cng_remap_uid(u);
}
static inline unsigned cng_exec_vis_gid(unsigned g, unsigned mode) {
    if (cng_g_setgid_root && (mode & CNG_S_ISGID) &&
        (mode & CNG_S_IFMT) == CNG_S_IFREG)
        return 0;
    return cng_remap_gid(g);
}

/* Emulate execve/execveat in-process: load the new program, build its stack,
 * and rewrite the signal context (pc/sp/regs) to enter it — so the seccomp
 * filter and SIGSYS handler survive (a real execve would wipe them). On failure
 * it sets the return register to -errno and returns (normal execve semantics). */
void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp);

/* Trampoline-path (-R) counterpart: same emulation from an ordinary call
 * context — on success it enters the new program and never returns; on failure
 * it returns -errno for the trampoline to hand back to the guest. */
long cng_execve_tramp(int dirfd, const char *path, char **argv, char **envp);

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

/* The exec-time environment, stashed at startup for the few places that need
 * an env lookup after argv/envp are out of reach (procreg.c's shared_dir). */
extern char **cng_g_envp;

/* Resolve a guest path to a host path, following symlinks within the guest
 * (absolute link targets re-rooted into the rootfs). deref_final follows the
 * last component's own symlink. Returns 0/-errno. Uses cng_g_fs + readlink. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz);

/* The fd behind a host path that names one of this process's own descriptors
 * ("/proc/self/fd/<n>" and its thread-self / own-pid spellings), else -1. */
int cng_proc_self_fd(const char *host);

/* Serve an open the host refused (`err`) on a path naming one of our own fds,
 * from that descriptor: a duplicate when the inode grants the access anyway
 * (a non-DAC refusal, e.g. SELinux on a memfd), or a mode-borrowing reopen
 * under fake-root. Returns the new fd, or `err`. */
long cng_fd_reopen(const char *host, long flags, long mode, long err);

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

/* Upper bound on the filter's instruction count: prologue + clone block +
 * synthesized-fd block + one check per trapped syscall + the two tail RETs. */
#define CNG_SECCOMP_MAX_INSNS 128

/* Emit the filter into `f` (which must hold CNG_SECCOMP_MAX_INSNS entries) and
 * return its length, or -1 if the buffer is too small. Split out of the install
 * so a self-test can inspect and simulate it: the filter only ever runs on a
 * real AArch64 kernel (qemu-user does not honor guest seccomp), so this is the
 * only place its behaviour can be checked before shipping to a device. */
struct sock_filter;
int cng_build_seccomp(struct sock_filter *f, int cap);

/* Point the dispatcher at fs, install the SIGSYS handler, then the filter.
 * Returns 0 on success or a negative errno (e.g. under qemu, where guest
 * seccomp filters are inert). */
int cng_install_monitor(struct cng_fs *fs);

#endif /* CNG_MONITOR_H */
