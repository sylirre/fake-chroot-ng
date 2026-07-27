/* Guest ptrace(2) emulation.
 *
 * chroot-ng runs the guest natively and in-process, so a guest tracer cannot be
 * given the host kernel's ptrace: the host would show it *our* re-issued
 * syscalls, host paths with the rootfs prefix attached, and no post-execve
 * SIGTRAP at all (our execve never enters the kernel's exec path). ptrace is
 * therefore emulated the same way every other kernel service here is —
 * by the monitor, from inside the processes involved.
 *
 * Model (ported from arm64chroot's ptracetab.c, which owns the guest register
 * file; here the register file is the one the kernel handed us at a stop):
 *
 *   - A MAP_SHARED anonymous registry, created before the guest's first fork
 *     and therefore mapped at the same address in every guest process, holds
 *     one link per traced *task*, keyed by tid (a main thread's tid is its
 *     pid). Tracing is per-task, as in the kernel.
 *   - A tracee reaches monitor code at exactly the points a ptrace stop is
 *     defined: a seccomp SIGSYS trap (syscall stops), one of our signal
 *     handlers (signal/fault stops), the emulated execve, clone and exit. At
 *     those points the full register file is addressable — the AArch64
 *     sigcontext's regs/sp/pc/pstate tail IS a `struct user_pt_regs` — so the
 *     tracee publishes the stop and then parks in a service loop, answering
 *     PEEK/POKE/GETREGSET/SETREGSET/CONT/... about *itself* over a futex
 *     mailbox in its own link.
 *   - The tracer posts commands into that mailbox and discovers stops by
 *     scanning the registry from its wait4/waitid.
 *
 * Nothing here needs host ptrace permission, /proc/pid/mem or
 * process_vm_readv — all of which Android's SELinux policy can and does deny.
 *
 * Seeing every syscall needs one more thing: our base filter only traps the
 * path-bearing set, so a task that becomes a tracee stacks a second filter
 * that traps everything (see cng_pt_arm_tracee / seccomp.c). A task that
 * becomes a tracer stacks a much narrower one, so that an ordinary guest —
 * which is every guest that never traces — keeps a native, interruptible
 * wait4 and pays nothing at all for this file.
 */
#ifndef CNG_PTRACE_H
#define CNG_PTRACE_H

#include "cng/rt.h"
#include "cng/ucontext.h"

/* The AArch64 user register file, in the kernel's `struct user_pt_regs` layout
 * — which is also the tail of `struct sigcontext`, so a pointer to the
 * sigcontext's regs[0] is a valid one of these (cng_pt_uregs). */
struct cng_uregs {
    u64 x[31]; /* x0..x30 */
    u64 sp;
    u64 pc;
    u64 pstate;
};

static inline struct cng_uregs *cng_pt_uregs(struct cng_ucontext *uc) {
    return (struct cng_uregs *)&uc->uc_mcontext.regs[0];
}

/* ---- ptrace(2) requests (arch-generic values) ---- */
#define CNG_PTRACE_TRACEME          0
#define CNG_PTRACE_PEEKTEXT         1
#define CNG_PTRACE_PEEKDATA         2
#define CNG_PTRACE_PEEKUSR          3
#define CNG_PTRACE_POKETEXT         4
#define CNG_PTRACE_POKEDATA         5
#define CNG_PTRACE_POKEUSR          6
#define CNG_PTRACE_CONT             7
#define CNG_PTRACE_KILL             8
#define CNG_PTRACE_SINGLESTEP       9
#define CNG_PTRACE_ATTACH           16
#define CNG_PTRACE_DETACH           17
#define CNG_PTRACE_SYSCALL          24
#define CNG_PTRACE_SETOPTIONS       0x4200
#define CNG_PTRACE_GETEVENTMSG      0x4201
#define CNG_PTRACE_GETSIGINFO       0x4202
#define CNG_PTRACE_SETSIGINFO       0x4203
#define CNG_PTRACE_GETREGSET        0x4204
#define CNG_PTRACE_SETREGSET        0x4205
#define CNG_PTRACE_SEIZE            0x4206
#define CNG_PTRACE_INTERRUPT        0x4207
#define CNG_PTRACE_LISTEN           0x4208
#define CNG_PTRACE_GETSIGMASK       0x420a
#define CNG_PTRACE_SETSIGMASK       0x420b
#define CNG_PTRACE_GET_SYSCALL_INFO 0x420e

/* PTRACE_SETOPTIONS bits. */
#define CNG_PTRACE_O_TRACESYSGOOD   0x0001
#define CNG_PTRACE_O_TRACEFORK      0x0002
#define CNG_PTRACE_O_TRACEVFORK     0x0004
#define CNG_PTRACE_O_TRACECLONE     0x0008
#define CNG_PTRACE_O_TRACEEXEC      0x0010
#define CNG_PTRACE_O_TRACEVFORKDONE 0x0020
#define CNG_PTRACE_O_TRACEEXIT      0x0040
#define CNG_PTRACE_O_EXITKILL       0x00100000
#define CNG_PTRACE_O_MASK           0x003000ff

/* PTRACE_EVENT_* (the wait status' high byte). */
#define CNG_PTRACE_EVENT_FORK        1
#define CNG_PTRACE_EVENT_VFORK       2
#define CNG_PTRACE_EVENT_CLONE       3
#define CNG_PTRACE_EVENT_EXEC        4
#define CNG_PTRACE_EVENT_VFORK_DONE  5
#define CNG_PTRACE_EVENT_EXIT        6
#define CNG_PTRACE_EVENT_STOP        128

/* NT_* regsets GETREGSET/SETREGSET understand. */
#define CNG_NT_PRSTATUS         1
#define CNG_NT_PRFPREG          2
#define CNG_NT_ARM_TLS          0x401
#define CNG_NT_ARM_SYSTEM_CALL  0x404

/* The signal chroot-ng reserves to kick a running task to a stop point
 * (PTRACE_ATTACH/SEIZE/INTERRUPT, a cooperative group-stop, and arming a
 * tracer's own interception). SIGRTMAX: glibc claims SIGRTMIN..SIGRTMIN+2 and
 * Go preempts with SIGURG, so the top of the RT range is the quietest slot.
 * A guest-directed signal of the same number is told apart by the magic in
 * si_value and forwarded to the guest's own handler. */
#define CNG_PT_KICKSIG   64 /* the intent; cng_g_kicksig is what is used */
#define CNG_PT_KICK_ATTACH 0x50544b21 /* "PTK!" — adopt attach/interrupt/stopsig */
#define CNG_PT_KICK_WAKE   0x50545721 /* "PTW!" — no-op; EINTRs a blocked wait */
#define CNG_PT_KICK_ARM    0x50544121 /* "PTA!" — install the tracer filter here */

/* --no-ptrace: refuse guest ptrace outright (-EPERM) and keep the registry
 * unmapped. The machinery is otherwise inert until a guest actually traces. */
extern int cng_g_no_ptrace;

/* 1 once the SIGSYS handler is installed. The stacked filters below are gated
 * on it — trapping with nothing to catch the signal kills the task. */
extern int cng_g_sigsys_ready;

/* Map the shared registry. Called once from cng_run before the monitor is
 * installed and before the guest can fork. Failure is not fatal: ptrace then
 * answers -EPERM, as if the session had --no-ptrace. */
void cng_pt_init(void);

/* Is the calling task a tracee (stops must be reported)? A plain global read
 * in the common case — the per-task lookup only happens once this is true. */
int cng_pt_active(void);

/* Is the calling task armed for syscall stops (last resume was PTRACE_SYSCALL)?
 * The SIGSYS/trampoline paths test this before doing anything ptrace-related. */
int cng_pt_syscall_armed(void);

/* ---- tracee-side stop reports ---- */

/* Syscall-entry stop. Returns 1 if the tracer left the syscall runnable — with
 * the number to run (possibly redirected) in *nr_out and the arguments in
 * r->x[0..5] — or 0 if the tracer cancelled it, in which case x0 already holds
 * the result to report. Also the no-op path when the task is not armed. */
int cng_pt_syscall_entry(struct cng_uregs *r, long *nr_out);

/* Syscall-exit stop, with `r->x[0]` already holding the result. The tracer may
 * overwrite it, so the caller must not touch x0 afterwards. */
void cng_pt_syscall_exit(struct cng_uregs *r);

/* Post-execve stop (PTRACE_EVENT_EXEC, or a plain SIGTRAP without the option).
 * Called by the emulated execve once the new image is in place. */
void cng_pt_report_exec(struct cng_uregs *r);

/* Was the last resume a PTRACE_SINGLESTEP? And the step stop that follows a
 * syscall, which completes without a breakpoint (both no-ops when untraced or
 * not stepping). */
int cng_pt_stepping(void);
void cng_pt_step_report(struct cng_uregs *r);

/* Parent side of a followed clone/fork: the event stop carrying the new child's
 * pid for PTRACE_GETEVENTMSG. `event` is 0 to do nothing. */
void cng_pt_report_event(struct cng_uregs *r, int event, u64 msg);

/* Which PTRACE_EVENT_* (if any) the tracer of the calling task wants for a
 * clone with these flags, and whether the child should auto-attach. 0 = none. */
int cng_pt_clone_event(unsigned long clone_flags);

/* Child side of a fork/clone, called in the new process. `event` non-zero means
 * the parent's tracer follows this creation: the child auto-attaches to the same
 * tracer and parks in its initial stop. Zero leaves it untraced. Also resets the
 * inherited tracee state either way. */
void cng_pt_fork_child(struct cng_uregs *r, int event);

/* PTRACE_EVENT_EXIT stop (option TRACEEXIT), then publication of the death to
 * the tracer. `wstatus` is the wait-status word: (code & 0xff) << 8 for exit(),
 * or the signal number for a death by signal. Both no-op when untraced.
 * _exit_stop parks before the process dies; _exit_report drops the link (or
 * leaves a synthetic exit the tracer collects, when it cannot host-reap us). */
void cng_pt_exit_stop(struct cng_uregs *r, int wstatus);
void cng_pt_exit_report(int wstatus);

/* Wake every tracer polling in wait4 (a guest process died). */
void cng_pt_wake_waiters(void);

/* Signal-delivery / fault stop: report `sig` to the tracer and return the signal
 * to actually deliver (0 = suppressed, or a substitute the tracer chose).
 * `si_code`/`addr` carry the precise siginfo of a fault stop (0/0 otherwise).
 * Returns `sig` unchanged when the task is not traced. */
int cng_pt_report_signal(struct cng_uregs *r, int sig, int si_code, u64 addr);

/* The kick signal arrived (see CNG_PT_KICK_*): adopt a pending attach, service
 * a pending PTRACE_INTERRUPT or a cooperative group-stop. Called from the
 * kick handler with the interrupted context. */
void cng_pt_service_kick(struct cng_uregs *r);

/* Queue the reserved kick signal at one task with one of the CNG_PT_KICK_*
 * magics in si_value. */
void cng_pt_kick(s32 tgid, s32 tid, int magic);

/* Record the register frame this entry into monitor code is running on, and
 * the signal frame it came from when there is one (an -R trampoline has none,
 * and answers NT_PRFPREG with -EINVAL). Every entry point that can reach a stop
 * sets it; the wait and exit paths read it back for the guest's signal mask and
 * for the registers of an exit stop. Both are no-ops, and both read back NULL,
 * until something in the process takes on a ptrace role. */
void cng_pt_set_frame(struct cng_uregs *r, struct cng_ucontext *uc);
struct cng_uregs *cng_pt_cur_regs(void);
struct cng_ucontext *cng_pt_cur_uc(void);

/* Write into the task's own memory the way PTRACE_POKETEXT does: through a
 * write-protected page, and coherent with the instruction stream afterwards.
 * Returns 0 or -EIO. Shared with the single-step breakpoint planter. */
long cng_pt_poke_text(u64 addr, const void *src, unsigned len);

/* ---- tracer-side entry points (called from the dispatcher) ---- */

/* ptrace(request, pid, addr, data) from the guest. */
long cng_pt_syscall(long req, long pid, u64 addr, u64 data);

/* wait4 / waitid, which must report emulated stops alongside real children.
 * Both return the syscall result. */
long cng_pt_wait4(long pid, u64 status, long options, u64 rusage,
                  const struct cng_ucontext *uc);
long cng_pt_waitid(long idtype, long id, u64 infop, long options, u64 rusage,
                   const struct cng_ucontext *uc);

/* process_vm_readv/writev where the peer is one of our stopped tracees: served
 * over the mailbox, because the host may refuse the real thing. Returns 1 and
 * sets *out when it handled the call, 0 to let it run natively. */
int cng_pt_vm_rw(long nr, long pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt,
                 long *out);

/* A stop signal (SIGSTOP/SIGTSTP/...) or SIGCONT aimed at a task with tracees:
 * routed into cooperative group-stops instead of a real host stop, which would
 * freeze the tracee inside its service loop and deadlock the tracer. Returns 1
 * when the signal was consumed (the caller must not also send it). */
int cng_pt_signal_route(long pid, int sig);

/* A child was reaped by the host wait: drop any link it still holds. */
void cng_pt_note_reaped(long pid);

/* Arm interception for a task that became a tracer (stacks the narrow filter
 * and kicks its sibling threads to do the same) or a tracee (stacks the
 * trap-everything filter). Idempotent per task. */
void cng_pt_arm_tracer(void);
void cng_pt_arm_tracee(void);

/* True once this task carries the trap-everything filter: the dispatcher's
 * default case must then re-issue an unhandled syscall instead of reading it as
 * "Android blocked this one". */
int cng_pt_traceall(void);

/* ---- single-step (ptstep.c) ---- */
/* Next PC after the instruction at r->pc, evaluated against the frame's
 * registers and PSTATE. Returns 0 if the instruction cannot be decoded. */
u64 cng_pt_next_pc(const struct cng_uregs *r);
/* Plant / remove the temporary breakpoint that implements one step. */
int cng_pt_step_plant(struct cng_uregs *r);
void cng_pt_step_clear(void);
/* Is `pc` our own step breakpoint (rather than one the tracer poked)? */
int cng_pt_step_hit(u64 pc);

/* ---- signal disposition mirror (ptsig.c) ---- */
/* Record what the guest asked rt_sigaction for and, when the task is traced,
 * keep our own handler installed instead. Returns 1 if it fully handled the
 * call (result in *out), 0 to let the dispatcher re-issue it. */
int cng_pt_sigaction(int sig, u64 act, u64 oact, u64 sz, long *out);
/* Install our handler for every catchable signal (entering traced state) or
 * put the guest's own dispositions back (leaving it). */
void cng_pt_sig_trace_enter(void);
void cng_pt_sig_trace_leave(void);
/* Install the kick handler. Called once per process at monitor install, and
 * again after the emulated execve resets dispositions. cng_pt_pick_kicksig
 * settles which signal number that is (see cng_g_kicksig) — SIGRTMAX where it
 * can be queued, the first lower one that can be otherwise. */
extern int cng_g_kicksig;
void cng_pt_sig_install_kick(void);
void cng_pt_pick_kicksig(void);
/* The emulated execve's counterpart to the kernel resetting dispositions:
 * caught signals go back to default, ignored ones stay ignored, and what must
 * survive (the kick handler, and our own hooks if still traced) is reinstalled. */
void cng_pt_sig_exec_reset(void);

#endif /* CNG_PTRACE_H */
