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

/* The kernel identity the guest is told about, by uname(2) and by
 * /proc/version, which must agree — faking one and leaking the other through
 * the second is the failure mode, since anything that cross-checks them (and
 * distro install scripts do) then sees a contradiction.
 *
 * Fixed rather than passed through: the host release is meaningless inside the
 * rootfs and, on Android, carries `-android14-11-...`/`-perf` vendor suffixes
 * that identify the device. It also lifts the effective floor for a modern
 * glibc rootfs, which refuses to start below its build-time minimum. */
#define CNG_KREL "6.1.0-chroot-ng"
#define CNG_KVER "#1 SMP chroot-ng"

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
/* How many supplementary groups the synthetic set holds. The kernel's own
 * NGROUPS_MAX is 65536, and setgroups(2) beyond this answers -EINVAL, which is
 * the right kind of answer but at the wrong number: 64 was low enough that
 * initgroups(3) for a user in a directory-service environment could trip it,
 * and take `su` and `login` down with it. Not the kernel's figure, though —
 * struct cng_cred is copied by value in the setreuid and setregid paths, on
 * the SIGSYS handler's 256 KiB scratch stack, so 65536 entries would be a
 * 256 KiB copy there. 1024 is past anything real and costs 4 KiB. */
#define CNG_NGROUPS_MAX 1024

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

/* File-type / set-id mode bits: the fake-id ownership fixups test for a regular
 * file, the -w/--work-dir check for a directory. */
#define CNG_S_IFMT  0170000u
#define CNG_S_IFREG 0100000u
#define CNG_S_IFDIR 0040000u
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
                        char **argv, char **envp, int flags);

/* Trampoline-path (-R) counterpart: same emulation from an ordinary call
 * context — on success it enters the new program and never returns; on failure
 * it returns -errno for the trampoline to hand back to the guest. */
long cng_execve_tramp(int dirfd, const char *path, char **argv, char **envp,
                      int flags);

/* The program break before the first guest program ran. A real execve drops the
 * heap with the address space; ours keeps the address space, so the break is
 * wound back to this at each exec. 0 = never recorded, and nothing is done. */
extern unsigned long cng_g_brk0;

/* Record / forget a POSIX timer the guest created. A real execve deletes them
 * all, and nothing enumerates a process's timers, so the dispatcher hands over
 * every id as it is created (see cng_exec_reset). */
void cng_timer_note(int id);
void cng_timer_forget(int id);

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

/* The -R trampoline's entry point (tramp.S calls it with the frame it built):
 * runs one rewritten syscall site, with the ptrace stops around it. */
struct cng_uregs;
void cng_tramp_dispatch(struct cng_uregs *r);

/* One-shot-per-number diagnostic for a syscall we emulate away. */
void cng_note_blocked(int nr);

/* Verbose diagnostic (set by CNG_DEBUG=1): log intercepted syscalls whose
 * result is an error other than ENOENT, with the path where available. */
extern int cng_g_debug;

/* chroot-ng's OWN (host) environment, stashed at startup for the few places that
 * need an env lookup after argv/envp are out of reach (procreg.c's shared_dir,
 * the CNG_* knobs). Never the guest's: the guest gets a clean environment built
 * from -E/--env (see cng_run), and the two must not be confused — a CNG_* knob
 * is read from here, an -E entry is only ever handed to the guest. */
extern char **cng_g_host_envp;

/* Resolve a guest path to a host path, following symlinks within the guest
 * (absolute link targets re-rooted into the rootfs). deref_final follows the
 * last component's own symlink. Returns 0/-errno. Uses cng_g_fs + readlink. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz);

/* Resolve (dirfd, path) to a HOST path: absolute names and AT_FDCWD through the
 * rootfs, a real dirfd through the guest path it names — so a relative name is
 * contained exactly as an absolute one is. `deref` follows the final component's
 * own symlink. Returns 0/-1. */
int cng_resolve_at(long dirfd, const char *path, int deref, char *out,
                   size_t sz);

/* The fd behind a host path that names one of this process's own descriptors
 * ("/proc/self/fd/<n>" and its thread-self / own-pid spellings), else -1. */
int cng_proc_self_fd(const char *host);

/* Serve an open the host refused (`err`) on a path naming one of our own fds,
 * from that descriptor: a duplicate when the inode grants the access anyway
 * (a non-DAC refusal, e.g. SELinux on a memfd), or a mode-borrowing reopen
 * under fake-root. Returns the new fd, or `err`. */
long cng_fd_reopen(const char *host, long flags, long mode, long err);

/* Is a guest byte range safe to dereference from the handler? Every signal but
 * SIGSYS is masked there, so a SIGSEGV on a bad guest pointer is unblockable and
 * kills the guest where a real kernel would have answered -EFAULT. Ask before
 * dereferencing anything the guest handed us and return -EFAULT on 0. The write
 * form zeroes the range it validates, so use it immediately before filling the
 * buffer. Both answer 1 when they cannot ask (see uaccess.c). */
int cng_user_readable(const void *p, unsigned long n);
int cng_user_writable(void *p, unsigned long n);

/* Settle which probe mechanism this host supports, returning 1 for the
 * process_vm_* pair and 0 for the memfd fallback. Called once at monitor
 * install so the question is never asked from inside the SIGSYS handler, where
 * a refused syscall would need nested delivery to be survivable. */
int cng_uaccess_probe_setup(void);

/* Length of a guest string / entry count of a guest pointer vector, measured
 * without ever reading past accessible memory. Returns the count, -EFAULT when
 * it runs off readable memory, or -E2BIG when `max` passes with no terminator —
 * the same two answers execve(2) gives for the same inputs. */
long cng_user_strlen(const char *s, unsigned long max);
long cng_user_veclen(char *const *v, unsigned long max);

/* Ambient-seccomp block-list: cng_blocked[nr] != 0 means Android blocks that
 * syscall, so dispatch emulates ENOSYS instead of re-issuing it. Populated by
 * cng_probe_blocked() at monitor install (a no-op result off Android). */
#define CNG_NR_MAX 512
extern unsigned char cng_blocked[CNG_NR_MAX];
void cng_probe_blocked(void);

/* Install a signal handler with our own rt_sigreturn restorer. Returns 0/-errno. */
int cng_sig_install(int signo, cng_sighandler_t h);

/* Run `fn(arg)` on this thread's per-thread scratch stack, returning 1 when it
 * switched and 0 when the caller must run it in place (no slot, or already on
 * the stack). The path dispatcher needs far more stack than a guest thread is
 * likely to have — see sigsys.c — so both tiers enter it through this.
 * cng_scratch_leave gives the stack back for a call that never returns. */
int cng_run_scratch(void (*fn)(void *), void *arg);
void cng_scratch_leave(void);

/* The same allocator for a TID the caller names, with the slot's stack top (0
 * when there is no slot). Exposed for testing: filling the table takes hundreds
 * of threads, and what happens then — a slot whose thread has exited is taken
 * over — has no other way to be reached. */
int cng_scratch_slot_for(long tid, unsigned long *hi_out);

/* Core SIGSYS logic (exposed for testing): given the trapped signal context and
 * info, either translate+dispatch the guest syscall, or — when the trap is
 * Android's seccomp filter blocking a syscall WE re-issued from the gate —
 * convert it to -ENOSYS. Writes the result into the context's x0. */
void cng_sigsys_body(struct cng_ucontext *uc, cng_siginfo_t *si);

/* Build and install the seccomp filter (traps the path syscall set, allows the
 * gate IP range, allows everything else). Returns 0 or -errno. */
int cng_install_seccomp(void);

/* Stack a second filter on the calling task when it enters a ptrace role:
 * _traceall traps every syscall (a tracee must stop on all of them), _tracer
 * traps only wait4/waitid/kill/process_vm_* (a tracer's answers must account
 * for emulated stops). Both keep the gate allowlist. Filters cannot be
 * removed, so each is installed at most once per task (see cng_pt_arm_*). */
int cng_install_seccomp_traceall(void);
int cng_install_seccomp_tracer(void);

/* ...and the same split the base filter has, so a self-test can simulate them.
 * Neither can be observed any other way: they are only installed once a guest
 * traces, and guest filters do not run under qemu-user at all. */
#define CNG_SECCOMP_TRACEALL_INSNS 24
#define CNG_SECCOMP_TRACER_INSNS   24
struct sock_filter;
int cng_build_seccomp_traceall(struct sock_filter *f, int cap);
int cng_build_seccomp_tracer(struct sock_filter *f, int cap);

/* Upper bound on the filter's instruction count: prologue + clone block +
 * synthesized-fd block + one check per trapped syscall + the two tail RETs. */
/* Raised from 128 for the AF_UNIX and credential additions. The kernel's own
 * limit is 4096 instructions, so there is ample headroom; the tail's per-syscall
 * jump offset is a u8, which stays valid while the trapped set is under 255. */
#define CNG_SECCOMP_MAX_INSNS 256

/* Emit the filter into `f` (which must hold CNG_SECCOMP_MAX_INSNS entries) and
 * return its length, or -1 if the buffer is too small. Split out of the install
 * so a self-test can inspect and simulate it: the filter only ever runs on a
 * real AArch64 kernel (qemu-user does not honor guest seccomp), so this is the
 * only place its behaviour can be checked before shipping to a device. */
struct sock_filter;
int cng_build_seccomp(struct sock_filter *f, int cap);

/* 1 if `nr` is in the designed-ENOSYS set: a syscall we must refuse because it
 * reaches the filesystem by a route the path traps cannot see (io_uring's SQE
 * ring, above all). The seccomp filter answers these with RET_ERRNO on its own;
 * this is for the -R trampoline tier, which runs with no filter at all. */
int cng_denied_syscall(long nr);

/* Point the dispatcher at fs, install the SIGSYS handler, then the filter.
 * Returns 0 on success or a negative errno (e.g. under qemu, where guest
 * seccomp filters are inert). */
int cng_install_monitor(struct cng_fs *fs);

#endif /* CNG_MONITOR_H */
