/* SIGSYS handler + signal installation.
 *
 * On a seccomp RET_TRAP the kernel delivers SIGSYS with the interrupted
 * context: args in x0..x5, syscall nr in x8, and pc already advanced past the
 * svc. We emulate the syscall (translating paths) and write the result into x0;
 * on return the restorer runs rt_sigreturn and the guest continues.
 */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

#include <asm/unistd.h>

/* Kernel struct sigaction for AArch64 (generic layout). */
struct cng_ksigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    cng_sigset_t mask;
};

extern void cng_sigrestore(void); /* src/monitor/sig.S */

int cng_sig_install(int signo, cng_sighandler_t h) {
    struct cng_ksigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.handler = (void *)h;
    /* SA_NODEFER keeps SIGSYS unmasked inside the handler: when we re-issue a
     * translated syscall through the gate and Android's own seccomp filter
     * blocks it, a *nested* SIGSYS must be deliverable (a masked seccomp SIGSYS
     * force-kills). The nested trap is caught by the gate-net below.
     *
     * SA_ONSTACK delivers the signal on the thread's registered alt-stack. This
     * matters for small-stack guests: the kernel pushes the ~4.5 KiB signal
     * frame (siginfo + ucontext incl. the FP/SVE reserved area) onto the
     * interrupted stack *before* our handler can switch to its scratch stack, so
     * on Go's ~8 KiB goroutine stacks that delivery alone overflows. Go (and any
     * runtime that calls sigaltstack) provides a per-thread alt-stack; where none
     * is registered the flag is a no-op and delivery uses the (large) normal
     * stack, as before. The heavy dispatcher still runs on our own scratch
     * stack — the alt-stack only has to hold the frame + handler prologue. */
    sa.flags = CNG_SA_SIGINFO | CNG_SA_RESTORER | CNG_SA_RESTART |
               CNG_SA_NODEFER | CNG_SA_ONSTACK;
    /* Mask every other signal for the duration of the handler. With SA_ONSTACK
     * the kernel delivers our frame on the alt-stack; we then switch SP to the
     * scratch stack, leaving that frame behind on the alt-stack. If another
     * signal (notably Go's very frequent SIGURG async-preemption) were delivered
     * while we run on the scratch stack, the kernel — seeing SP no longer on the
     * alt-stack — would place its frame at the alt-stack top, clobbering our
     * abandoned frame; returning through it then crashes/corrupts. Blocking all
     * signals during the handler closes that window (they queue and fire on
     * sigreturn). SIGSYS stays unmasked (SA_NODEFER) so the gate-net can still
     * catch a nested trap; our own re-issues avoid Android-blocked syscalls via
     * the block-list, so a nested SIGSYS does not arise in practice. */
    sa.mask.sig[0] = ~0UL & ~(1UL << (CNG_SIGSYS - 1));
    sa.restorer = (void *)cng_sigrestore;
    long r = cng_syscall6(signo, (long)&sa, 0, sizeof(cng_sigset_t), 0, 0,
                          __NR_rt_sigaction);
    return (int)r;
}

/* The trapped syscall itself: the cases the handler must own (they need the
 * signal context), then the dispatcher for everything else. Returns 1 when the
 * result is in x0 and the caller still owes a syscall-exit stop, 0 when the
 * context was redirected instead — an emulated execve enters the new program
 * and reports its own post-exec stop, so there is no exit stop to give. */
static int sigsys_syscall(struct cng_ucontext *uc, long nr) {
    unsigned long long *r = uc->uc_mcontext.regs;
    struct cng_uregs *ur = cng_pt_uregs(uc);

    /* rt_sigprocmask: apply the guest's requested mask but never let SIGSYS be
     * blocked (a masked seccomp SIGSYS force-kills). We edit uc_sigmask, which
     * sigreturn restores — re-issuing the syscall here would be undone by that
     * same restore. */
    if (nr == __NR_rt_sigprocmask) {
        int how = (int)r[0];
        unsigned long *pset = (unsigned long *)r[1];
        unsigned long *pold = (unsigned long *)r[2];
        unsigned long cur = uc->uc_sigmask.sig[0];
        /* The kernel refuses a sigsetsize that is not its own before it looks at
         * anything else — the check that stops a caller assuming some other
         * width from half-working — and this call is answered entirely here, so
         * nothing else was going to make it. */
        if (r[3] != sizeof(cng_sigset_t)) {
            r[0] = (unsigned long long)(long)-EINVAL;
            return 1;
        }
        /* Both are guest pointers we dereference ourselves rather than handing
         * to the kernel, so a bad one must come back -EFAULT (see uaccess.c).
         * They are taken in the kernel's order — the new mask read and applied
         * first, the old one written after — which is also what makes the two
         * pointers safe to alias. `sigprocmask(how, &m, &m)` is a legal call,
         * and the writability probe validates a range by ZEROING it: probing
         * the old-mask pointer before reading the new mask out of the same
         * address handed us a zeroed set, so SIG_UNBLOCK cleared the guest's
         * whole mask and SIG_BLOCK became a silent no-op. */
        if (pset) {
            if (!cng_user_readable(pset, sizeof *pset)) {
                r[0] = (unsigned long long)(long)-EFAULT;
                return 1;
            }
            /* ...and only then `how`, which the kernel validates inside
             * sigprocmask() and only when a new mask was supplied. Anything but
             * the three it defines was silently taken as SIG_SETMASK here, so a
             * miscalled SIG_BLOCK REPLACED the mask it meant to add to. */
            if (how != 0 && how != 1 && how != 2) {
                r[0] = (unsigned long long)(long)-EINVAL;
                return 1;
            }
            unsigned long set = *pset;
            unsigned long neu = (how == 0)   ? (cur | set)   /* SIG_BLOCK */
                                : (how == 1) ? (cur & ~set)  /* SIG_UNBLOCK */
                                             : set;          /* SIG_SETMASK */
            uc->uc_sigmask.sig[0] = neu & ~(1UL << (CNG_SIGSYS - 1));
        }
        if (pold) {
            if (!cng_user_writable(pold, sizeof *pold)) {
                r[0] = (unsigned long long)(long)-EFAULT;
                return 1;
            }
            *pold = cur;
        }
        r[0] = 0;
        return 1;
    }

    /* execve/execveat are emulated in-process (they'd otherwise wipe us). */
    if (nr == __NR_execve) {
        cng_emulate_execve(uc, CNG_AT_FDCWD, (const char *)r[0], (char **)r[1],
                           (char **)r[2], 0);
        return cng_is_err((long)r[0]); /* success redirected the context */
    }
#ifdef __NR_execveat
    if (nr == __NR_execveat) {
        cng_emulate_execve(uc, (int)r[0], (const char *)r[1], (char **)r[2],
                           (char **)r[3], (int)r[4]);
        return cng_is_err((long)r[0]);
    }
#endif

    /* clone with CLONE_VFORK (only these trap; see seccomp.c): a vfork-style
     * spawn shares the parent's address space and suspends us until the child
     * execs. Our execve is emulated in-process, so a shared-VM child would load
     * the new program over the parent and never issue the real execve that
     * resumes it. Convert to a plain COW fork, with two stack adjustments:
     *  - pass child_stack=0 to the real clone so the forked child inherits (COW)
     *    the parent's current SP — which here is the *scratch stack* our handler
     *    frames sit on. The child must unwind those frames and sigreturn; giving
     *    it the caller-supplied child stack instead sets its SP into a buffer
     *    with no such frames -> Bus error before it can even execve.
     *  - then point uc->sp at that caller-supplied child stack for the child, so
     *    after sigreturn it resumes on the stack the guest's clone wrapper
     *    expects (musl's __clone/posix_spawn stored the child fn+arg there).
     *    child_stack==0 is a bare vfork: the child just continues on the
     *    parent's stack, so leave uc->sp alone. */
    if (nr == __NR_clone) {
        unsigned long child_stack = (unsigned long)r[1];
        unsigned long orig_flags = (unsigned long)r[0];
        /* Decided before the fork, from the flags the guest asked for: the
         * conversion below erases CLONE_VFORK, and a tracer following vforks
         * must still see EVENT_VFORK rather than EVENT_FORK. */
        int ev = cng_pt_clone_event(orig_flags);
        long flags = (long)(orig_flags & ~(unsigned long)(CNG_CLONE_VM |
                                                          CNG_CLONE_VFORK));
        long ret = cng_syscall6(flags, 0, (long)r[2], (long)r[3], (long)r[4],
                                (long)r[5], __NR_clone);
        if (ret == 0) {
            /* The child inherited both the mappings and the attach list, so
             * the broker must count those attaches again (shm.c). */
            cng_shm_fork_child();
            if (child_stack)
                uc->uc_mcontext.sp = child_stack;
            r[0] = 0;
            cng_pt_fork_child(ur, ev);
            return 1;
        }
        if (ret > 0) {
            /* Publish the child into the PID registry: it cannot do that for
             * itself, because nothing guarantees it makes another trapped
             * syscall before something reads its /proc entry — and a tracer
             * attaching to it by pid needs it to be a known guest process. */
            cng_procreg_fork((int)ret);
            r[0] = (unsigned long long)ret;
            cng_pt_report_event(ur, ev, (u64)ret);
            /* A real vfork would have suspended us until the child exec'd or
             * exited; ours does not, so the "vfork done" event is reported as
             * soon as the child exists. */
            if (orig_flags & CNG_CLONE_VFORK)
                cng_pt_report_event(ur, CNG_PTRACE_EVENT_VFORK_DONE, (u64)ret);
            return 1;
        }
        r[0] = (unsigned long long)ret;
        return 1;
    }

    long res = cng_dispatch(nr, (long)r[0], (long)r[1], (long)r[2], (long)r[3],
                            (long)r[4], (long)r[5], /*trapped=*/1);
    if (cng_g_debug && res < 0 && res != -ENOENT)
        cng_dprintf(2, "[cng] dispatch nr=%ld -> errno=%ld\n", nr, -res);
    r[0] = (unsigned long long)res;
    return 1;
}

void cng_sigsys_body(struct cng_ucontext *uc, cng_siginfo_t *si) {
    unsigned long long *r = uc->uc_mcontext.regs;

    /* Only seccomp traps are ours to emulate; a guest-directed kill(SIGSYS)
     * (si_code != SYS_SECCOMP) is left alone. */
    if (si->si_code != CNG_SYS_SECCOMP)
        return;

    /* Gate-net: the trapped svc is our own gate, i.e. Android blocked a syscall
     * we re-issued. Return -ENOSYS instead of re-dispatching (which would loop
     * or, if masked, force-kill). */
    unsigned long ca = (unsigned long)si->_u._sigsys.call_addr;
    if (ca >= (unsigned long)__cng_gate_start &&
        ca < (unsigned long)__cng_gate_end) {
        int bnr = si->_u._sigsys.syscall;
        cng_note_blocked(bnr);
        /* Record it so `reissue` short-circuits future calls without going
         * through the gate — a re-issue that traps here is the only source of a
         * nested SIGSYS, so this keeps nesting to at most once per syscall. */
        if (bnr >= 0 && bnr < CNG_NR_MAX)
            cng_blocked[bnr] = 1;
        r[0] = (unsigned long long)(long)-ENOSYS;
        return;
    }

    long nr = (long)r[8];

    /* Untraced — which is every guest until something in the session starts
     * tracing — goes straight to the syscall with no ptrace work at all. A
     * tracee's syscall is wrapped in the two stops the kernel would have given
     * it: the tracer sees the arguments before the call and may rewrite them,
     * redirect the call or cancel it outright (proot's whole method), and sees
     * the result afterwards. */
    cng_pt_set_frame(cng_pt_uregs(uc), uc);
    if (!cng_pt_active()) {
        sigsys_syscall(uc, nr);
        return;
    }
    struct cng_uregs *ur = cng_pt_uregs(uc);
    if (!cng_pt_syscall_entry(ur, &nr)) {
        cng_pt_syscall_exit(ur); /* cancelled: x0 is the tracer's own answer */
        return;
    }
    if (!sigsys_syscall(uc, nr))
        return; /* redirected into a new program, which reported its own stop */
    cng_pt_syscall_exit(ur);
    /* A single-step over a syscall stops once the syscall is done and before
     * the next instruction — where TIF_SINGLESTEP reports it — so it needs no
     * breakpoint. */
    cng_pt_step_report(ur);
}

/* Per-thread scratch stacks for the handler. The path dispatcher needs tens of
 * KiB (multiple PATH_MAX buffers deep); a seccomp SIGSYS can fire on any thread,
 * and Go goroutine stacks are only ~8 KiB, so we run the dispatcher on a large
 * stack of our own keyed by TID. Slots are claimed lock-free. If the table is
 * full or mmap fails we fall back to the interrupted stack — which is not a
 * fault but something worse: cng_dispatch's frame is bigger than a guard page,
 * so on a small stack it steps over the guard and writes into ordinary guest
 * memory below, silently. That is the reason a slot has to be recoverable.
 *
 * The table is sized above any realistic count of threads alive *at once*, which
 * is not the same as the number of TIDs a process gets through: a runtime that
 * spawns short-lived threads (Go, a JVM's GC workers) runs through hundreds, and
 * a slot keyed by a TID that has since exited was never coming back into use. So
 * when the table is full, a slot whose thread is gone is taken over, stack and
 * all. Nothing else frees one: there is no thread-exit hook — exit_group is not
 * trapped, and a SIGKILL never could be. */
extern long cng_run_on_stack(void *newsp, void *fn, void *a0, void *a1);

#define CNG_SCR_N  256
#define CNG_SCR_SZ (256 * 1024)
static struct {
    long tid;
    unsigned long lo, hi;
    int busy;
    /* The signal frame the dispatcher on this stack is running for. Its
     * uc_sigmask is the guest's own mask — the one sigreturn will restore —
     * which the blocking IPC waits need and cannot get any other way, since the
     * live mask while the handler runs is ours. */
    struct cng_ucontext *uc;
} cng_scr[CNG_SCR_N];

/* Claim `*p` from `want` to `tid` (inline LL/SC so we need no libgcc atomics
 * helper; works on any ARMv8). Returns 1 if this call performed the store. */
static int cng_claim_slot(volatile long *p, long want, long tid) {
    long old;
    int fail;
    __asm__ volatile("1: ldaxr %[old], [%[p]]\n"
                     "   cmp   %[old], %[want]\n"
                     "   b.ne  2f\n"             /* already someone else's */
                     "   stlxr %w[f], %[tid], [%[p]]\n"
                     "   cbnz  %w[f], 1b\n"      /* store lost; retry */
                     "   b     3f\n"
                     "2: clrex\n"
                     "   mov   %w[f], #1\n"
                     "3:\n"
                     : [old] "=&r"(old), [f] "=&r"(fail)
                     : [p] "r"(p), [want] "r"(want), [tid] "r"(tid)
                     : "cc", "memory");
    return fail == 0;
}

/* Map a stack into a slot this thread has just claimed. 0, or -1 with the slot
 * given back. `hi` is what publishes it: see the re-entry note below. */
static int scr_map(unsigned i) {
    void *base = sys_mmap(0, CNG_SCR_SZ, CNG_PROT_READ | CNG_PROT_WRITE,
                          CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (base == CNG_MAP_FAILED || cng_is_err((long)base)) {
        cng_scr[i].tid = 0;
        return -1;
    }
    cng_scr[i].lo = (unsigned long)base;
    __atomic_store_n(&cng_scr[i].hi, ((unsigned long)base + CNG_SCR_SZ) & ~15UL,
                     __ATOMIC_RELEASE);
    return 0;
}

/* Is `tid` still a thread of this process? tgkill with signal 0 does the
 * existence check and delivers nothing — one syscall, where a /proc read would
 * be several, and this runs inside the handler. */
static int scr_tid_live(long tid) {
    return CNG_SYS(__NR_tgkill, sys_getpid(), tid, 0, 0, 0, 0) == 0;
}

/* Find this thread's scratch slot (allocating one on first use). Returns the
 * slot index, or -1 if the table is full of live threads or mmap failed. */
static int cng_scratch_slot(long tid) {
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = cng_scr[i].tid;
        if (t == tid)
            /* Ours, but the stack is published after the TID, so a re-entry
             * landing between the two would be handed a slot with no stack and
             * switch SP to 0 — an unblockable SIGSEGV. The window is one mmap
             * wide and reachable on the -R tier, where a guest signal can be
             * delivered on the way out of that very syscall and reach a
             * rewritten `svc` from the handler. Run in place until it closes. */
            return __atomic_load_n(&cng_scr[i].hi, __ATOMIC_ACQUIRE) ? (int)i
                                                                     : -1;
        if (t == 0 && cng_claim_slot(&cng_scr[i].tid, 0, tid))
            return scr_map(i) == 0 ? (int)i : -1;
        /* slot taken by another thread (or we lost the CAS): keep probing */
    }
    /* Full: take over a slot whose thread has exited, stack and all. The busy
     * flag and the frame pointer are that thread's, not ours. */
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = cng_scr[i].tid;
        if (t == 0 || t == tid || scr_tid_live(t))
            continue;
        if (!cng_claim_slot(&cng_scr[i].tid, t, tid))
            continue; /* another thread reclaimed it first */
        cng_scr[i].busy = 0;
        cng_scr[i].uc = 0;
        /* Its owner can have died between claiming the slot and mapping it. */
        if (!cng_scr[i].hi && scr_map(i) != 0)
            return -1;
        return (int)i;
    }
    return -1;
}

/* Testing: the allocator, for a TID the caller names rather than its own, with
 * the slot's stack top so a caller can tell a mapped slot from a claimed one.
 * There is no other way to fill the table — it takes hundreds of threads. */
int cng_scratch_slot_for(long tid, unsigned long *hi_out) {
    int i = cng_scratch_slot(tid);
    if (hi_out)
        *hi_out = i >= 0 ? cng_scr[i].hi : 0;
    return i;
}

/* Run the dispatcher on this thread's scratch stack. A nested trap (the outer
 * invocation's slot is already busy) runs on the current stack instead — that
 * is the shallow gate-net path, which does not touch the deep buffers, so it
 * fits wherever the kernel delivered it. The busy flag (not an SP-range test) is
 * what detects nesting: with SA_ONSTACK the nested signal is delivered on the
 * alt-stack, not on the scratch stack, so a range test would miss it and wrongly
 * re-switch, clobbering the outer dispatcher frame. */
static void sigsys_handler(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    long tid = sys_gettid();
    int i = cng_scratch_slot(tid);
    if (i < 0 || cng_scr[i].busy) {
        cng_sigsys_body((struct cng_ucontext *)ucv, si);
        return;
    }
    cng_scr[i].busy = 1;
    cng_scr[i].uc = (struct cng_ucontext *)ucv;
    cng_run_on_stack((void *)cng_scr[i].hi, (void *)cng_sigsys_body, ucv, si);
    cng_scr[i].uc = 0;
    cng_scr[i].busy = 0;
}

/* Run `fn(arg)` on this thread's scratch stack; 0 when there was none to switch
 * to and the caller has to run it where it stands.
 *
 * The SIGSYS handler is not the only way into the path dispatcher. The -R
 * trampoline tier reaches the very same code from an ordinary call, on whatever
 * stack the rewritten `svc` site happened to be executing on — which is the
 * stack the handler above refuses to use, for reasons that do not change with
 * the tier: `cng_dispatch`'s own frame is ~24 KiB and a translated openat runs
 * ~66 KiB deep, against musl's 128 KiB thread stacks, Go's ~8 KiB goroutine
 * stacks, and whatever size a guest hands sigaltstack.
 *
 * Nesting is detected by the same busy flag the handler uses, and for the same
 * reason an SP range test will not do it: the re-entry need not be on the
 * scratch stack. A guest that registers a sigaltstack takes its own signals on
 * that alt-stack, and one delivered while we are mid-dispatch — the kernel
 * delivers it on the way out of a syscall we issued ourselves — reaches a
 * rewritten `svc` from there. SP is then the guest's alt-stack, nowhere near
 * the scratch stack an outer invocation is still using, and switching onto it
 * again overwrites those frames. The SP test is kept alongside for the direct
 * re-entry it does catch. */
int cng_run_scratch(void (*fn)(void *), void *arg) {
    int i = cng_scratch_slot(sys_gettid());
    if (i < 0)
        return 0;
    unsigned long sp = (unsigned long)&i;
    if (cng_scr[i].busy || (sp >= cng_scr[i].lo && sp < cng_scr[i].hi))
        return 0; /* already in use: run in place, as a nested trap does */
    cng_scr[i].busy = 1;
    cng_run_on_stack((void *)cng_scr[i].hi, (void *)fn, arg, 0);
    cng_scr[i].busy = 0;
    return 1;
}

/* Give the stack back for a call that will not return through cng_run_scratch:
 * the -R tier's emulated execve enters the new program directly. Left set, the
 * flag would send every later SIGSYS on this thread back onto the guest's own
 * stack — the thing this all exists to avoid. */
void cng_scratch_leave(void) {
    int i = cng_scratch_slot(sys_gettid());
    if (i >= 0)
        cng_scr[i].busy = 0;
}

/* Is a signal pending that the guest would take delivery of?
 *
 * A blocking System V IPC wait has to end in EINTR exactly when a real one
 * would, and it cannot find out the usual way: the handler runs with every
 * signal but SIGSYS masked (see cng_sig_install), so a signal arriving mid-wait
 * queues instead of interrupting anything. The pending set is therefore polled
 * against the mask the signal frame will restore — the guest's own — and against
 * the disposition, since a signal the guest ignores would not have interrupted a
 * real semop either. A signal that is pending only because *we* blocked it, and
 * whose default action is to be discarded, is likewise not an interruption.
 *
 * The -R trampoline tier has no signal frame; there the live mask is already the
 * guest's, so it is read straight from the kernel. */
int cng_sig_deliverable(void) {
    unsigned long pend = 0;
    if (CNG_SYS(__NR_rt_sigpending, &pend, sizeof pend, 0, 0, 0, 0) < 0 || !pend)
        return 0;

    unsigned long blocked = 0;
    long tid = sys_gettid();
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    struct cng_ucontext *uc = 0;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        if (__atomic_load_n(&cng_scr[i].tid, __ATOMIC_ACQUIRE) == tid) {
            uc = cng_scr[i].uc;
            break;
        }
    }
    if (uc)
        blocked = uc->uc_sigmask.sig[0];
    else if (CNG_SYS(__NR_rt_sigprocmask, 0 /*SIG_BLOCK*/, 0, &blocked,
                     sizeof blocked, 0, 0) < 0)
        blocked = 0;

    unsigned long live = pend & ~blocked;
    for (int sig = 1; sig <= 64 && live; sig++) {
        unsigned long bit = 1UL << (sig - 1);
        if (!(live & bit))
            continue;
        live &= ~bit;
        /* SIGCHLD, SIGCONT, SIGURG and SIGWINCH are discarded at delivery when
         * the disposition is still the default, so their arrival is not an
         * interruption; every other default action is (it terminates). */
        struct cng_ksigaction sa;
        memset(&sa, 0, sizeof sa);
        if (CNG_SYS(__NR_rt_sigaction, sig, 0, &sa, sizeof(cng_sigset_t), 0,
                    0) < 0)
            return 1; /* cannot ask: assume it interrupts, as the kernel would */
        if (sa.handler == (void *)1) /* SIG_IGN */
            continue;
        if (!sa.handler && /* SIG_DFL */
            (sig == 17 /*CHLD*/ || sig == 18 /*CONT*/ || sig == 23 /*URG*/ ||
             sig == 28 /*WINCH*/))
            continue;
        return 1;
    }
    return 0;
}

int cng_install_monitor(struct cng_fs *fs) {
    cng_g_fs = fs;
    if (cng_sig_install(CNG_SIGSYS, sigsys_handler) < 0)
        return -1;
    /* From here a trapping filter is survivable. Anything that stacks one on
     * demand (the ptrace roles) must not do so before this point: a
     * SECCOMP_RET_TRAP with no handler for the signal kills the process. */
    cng_g_sigsys_ready = 1;
    /* The ptrace kick signal is answered by every guest process, whether or not
     * it ever traces anything: it is how a tracer reaches a running task
     * (PTRACE_ATTACH), and how a process is told its child asked to be traced. */
    cng_pt_sig_install_kick();
    /* Measure which syscalls Android blocks (before our own filter is active)
     * so dispatch emulates them rather than trapping on a re-issue. */
    cng_probe_blocked();
    /* ...and settle which guest-pointer probe this host supports, here rather
     * than on the first trapped syscall: the question is itself a syscall, and
     * asking it from inside the handler would need nested SIGSYS delivery. */
    cng_uaccess_probe_setup();
    int r = cng_install_seccomp();
    /* NO_NEW_PRIVS is now set; on Android that can revoke anon executable memory,
     * so switch the loader to file-backed mapping if so (before the guest execs). */
    cng_loader_check_execmem();
    return r;
}
