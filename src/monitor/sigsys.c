/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* SIGSYS handler + signal installation.
 *
 * On a seccomp RET_TRAP the kernel delivers SIGSYS with the interrupted
 * context: args in x0..x5, syscall nr in x8, and pc already advanced past the
 * svc. We emulate the syscall (translating paths) and write the result into x0;
 * on return the restorer runs rt_sigreturn and the guest continues.
 */
#include "cng/broker.h" /* cng_broker_env: no getenv in a freestanding build */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

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
     * the block-list, so a nested SIGSYS does not arise in practice. The cost
     * is that nothing reaches a call made in here, which is why a call that
     * can block is not made in here at all (the bounce, below). */
    sa.mask.sig[0] = ~0UL & ~(1UL << (CNG_SIGSYS - 1));
    sa.restorer = (void *)cng_sigrestore;
    long r = cng_syscall6(signo, (long)&sa, 0, sizeof(cng_sigset_t), 0, 0,
                          __NR_rt_sigaction);
    return (int)r;
}

/* ---- the mask-taking waits ------------------------------------------------
 *
 * rt_sigsuspend, rt_sigtimedwait, ppoll, pselect6, epoll_pwait and
 * epoll_pwait2 install a signal mask of the caller's for their duration. The
 * mask is a guest sigset, and a guest sigset can name SIGSYS — sigfillset()
 * does — which no guest thread may ever have blocked: a thread parked in
 * ppoll(&fullmask) could not be reached by the de_thread an emulated execve
 * on another thread needs, and the exec would wait for it as long as the
 * poll lasted. So these are trapped when they carry a mask (the filter tests
 * the argument; a plain poll or epoll_wait, which is what libc's
 * poll()/epoll_wait() are, never traps), and SIGSYS is taken out of the copy
 * the kernel is handed.
 *
 * The handler cannot run them itself, though. It runs with every other
 * signal blocked — the kernel would install the guest's mask for the wait,
 * and every guest signal that arrived would then run its handler nested
 * inside ours, on our stack, free to siglongjmp out and leave the outer
 * frame and the scratch-stack bookkeeping behind. So the wait is bounced: the
 * guest's registers are saved into a record on the guest's own stack below
 * sp, the mask argument is pointed at the stripped copy in that record, and
 * the frame is set to resume at the gate's own svc (cng_bounce_wait) with sp
 * lowered past the record. sigreturn then runs the wait in the guest's own
 * context, on the guest's own mask, with the guest's handlers delivered
 * where they belong; the svc after it traps (cng_bounce_svc_end), and the
 * handler puts the registers back from the record and resumes the guest
 * after its own svc with the wait's result. Two traps per masked wait. The
 * -R trampoline tier reaches these from ordinary context and needs none of
 * this: dispatch.c strips the copy and re-issues in place.
 *
 * The masked waits were the first calls bounced, and not the last: every
 * trapped call that can block has the same problem in the handler, with the
 * guest's mask or without one. Run there, it cannot be interrupted by anything
 * but SIGKILL — a server in accept() ignored SIGTERM and ^C until a
 * connection came, a FIFO open until the other end did, and a ptrace attach
 * hung its tracer, since the kick is masked too. So the dispatcher answers
 * such a call with a request to be bounced (CNG_EBOUNCE_*, see monitor.h), and
 * it is, in one of two ways. One the dispatcher would make exactly as the
 * guest made it — a tracee's read(), a recv on an inet socket — runs from
 * cng_bounce_wait like a wait, its own registers in place (BOUNCE_RAW). One
 * that has paths or socket addresses to translate runs the dispatcher itself
 * from guest context (BOUNCE_DISP): sigreturn resumes at cng_bounce_dispatch,
 * which calls into it with the record as the register file, as the -R
 * trampoline calls into it with its own, and the completion trap puts the
 * registers back from the record, result and all. Either way the call blocks
 * on the guest's own mask, and a signal ends or restarts it by the kernel's
 * own rules. */
struct cng_bounce {
    unsigned long magic;
    unsigned long long regs[31], sp, pc, pstate; /* a struct cng_uregs */
    unsigned long set;    /* the stripped sigset */
    unsigned long sel[2]; /* pselect6's {sigset *, size} */
    long nr;              /* the call made, which a tracer may have redirected */
    int kind;             /* BOUNCE_* */
    int owed;             /* its entry stop was reported: an exit stop is owed */
};
#define CNG_BOUNCE_MAGIC 0x636e67426f756e63UL
#define BOUNCE_WAIT 0 /* a mask-taking wait, its mask the record's copy */
#define BOUNCE_RAW  1 /* the guest's call as it stands */
#define BOUNCE_DISP 2 /* the dispatch, from guest context */

/* Where the record goes: below the guest's sp, 16-aligned as sp must be. */
static unsigned long bounce_rec(const struct cng_ucontext *uc) {
    return (uc->uc_mcontext.sp - sizeof(struct cng_bounce)) & ~15UL;
}

/* The record of the guest's registers as the frame has them. */
static void bounce_fill(struct cng_bounce *b, const struct cng_ucontext *uc,
                        int kind, long nr) {
    memset(b, 0, sizeof *b);
    b->magic = CNG_BOUNCE_MAGIC;
    b->kind = kind;
    b->nr = nr;
    b->owed = cng_pt_entry_owed();
    for (int i = 0; i < 31; i++)
        b->regs[i] = uc->uc_mcontext.regs[i];
    b->sp = uc->uc_mcontext.sp;
    b->pc = uc->uc_mcontext.pc;
    b->pstate = uc->uc_mcontext.pstate;
}

/* A bounce of the guest's own call (BOUNCE_RAW) or of its dispatch
 * (BOUNCE_DISP). 0 when there is no room below the guest's sp, and the caller
 * makes the call in the handler, as every call was made before. */
static int bounce_call(struct cng_ucontext *uc, long nr, int kind) {
    struct cng_bounce b;
    bounce_fill(&b, uc, kind, nr);
    unsigned long rec = bounce_rec(uc);
    if (cng_user_copyout((void *)rec, &b, sizeof b) < 0)
        return 0;
    uc->uc_mcontext.sp = rec;
    if (kind == BOUNCE_RAW) {
        uc->uc_mcontext.regs[8] = (unsigned long long)nr;
        uc->uc_mcontext.pc = (unsigned long long)(unsigned long)cng_bounce_wait;
    } else {
        uc->uc_mcontext.pc =
            (unsigned long long)(unsigned long)cng_bounce_dispatch;
    }
    return 1;
}

/* cng_bounce_dispatch's call into the dispatcher, with the record. */
void cng_bounce_dispatch_c(struct cng_bounce *b) {
    cng_dispatch_bounced((struct cng_uregs *)&b->regs[0], b->nr, b->owed);
}

/* Which argument carries the sigset pointer, and where its size is; -1 for
 * pselect6, whose sixth argument is a {sigset *, size} pair. */
static int wait_mask_arg(long nr, int *size_arg) {
    switch (nr) {
    case __NR_rt_sigsuspend:
        *size_arg = 1;
        return 0;
    case __NR_rt_sigtimedwait:
        *size_arg = 3;
        return 0;
    case __NR_ppoll:
        *size_arg = 4;
        return 3;
    case __NR_epoll_pwait:
    case __NR_epoll_pwait2:
        *size_arg = 5;
        return 4;
    case __NR_pselect6:
        *size_arg = -1;
        return -1;
    }
    return -2;
}

int cng_is_masked_wait(long nr) {
    int sz;
    return wait_mask_arg(nr, &sz) != -2;
}

/* Run the wait from guest context (see above). Returns 0 when the frame was
 * redirected, 1 with the result in x0 when the call was answered here — a
 * mask the kernel would refuse (EINVAL, EFAULT) is refused at once; a stack
 * the record cannot be written to is the one case the wait is re-issued from
 * the handler with the stripped copy, which is what every blocking re-issue
 * from here has always been. */
static int bounce_start(struct cng_ucontext *uc, long nr) {
    unsigned long long *r = uc->uc_mcontext.regs;
    int size_arg, mi = wait_mask_arg(nr, &size_arg);
    struct cng_bounce b;
    bounce_fill(&b, uc, BOUNCE_WAIT, nr);
    unsigned long sel[2] = {0, 0};
    const unsigned long *setp = 0;
    unsigned long setsz = 0;
    if (mi >= 0) {
        setp = (const unsigned long *)r[mi];
        setsz = r[size_arg];
    } else if (r[5]) {
        if (cng_user_copyin(sel, (void *)r[5], sizeof sel) < 0) {
            r[0] = (unsigned long long)(long)-EFAULT;
            return 1;
        }
        setp = (const unsigned long *)sel[0];
        setsz = sel[1];
    }
    if (setp) {
        if (setsz != sizeof(cng_sigset_t)) {
            r[0] = (unsigned long long)(long)-EINVAL;
            return 1;
        }
        if (cng_user_copyin(&b.set, setp, sizeof b.set) < 0) {
            r[0] = (unsigned long long)(long)-EFAULT;
            return 1;
        }
        b.set &= ~(1UL << (CNG_SIGSYS - 1));
    }
    unsigned long rec = bounce_rec(uc);
    if (setp && mi < 0) {
        b.sel[0] = rec + __builtin_offsetof(struct cng_bounce, set);
        b.sel[1] = sel[1];
    } else if (mi < 0) {
        b.sel[0] = 0;
        b.sel[1] = sel[1];
    }
    if (cng_user_copyout((void *)rec, &b, sizeof b) < 0) {
        /* No room below the guest's sp: run it here, stripped. */
        if (cng_g_debug)
            cng_dprintf(2, "[cng] wait nr=%ld: no stack for the bounce\n", nr);
        unsigned long lsel[2] = {setp ? (unsigned long)&b.set : 0, sel[1]};
        long a[6];
        for (int i = 0; i < 6; i++)
            a[i] = (long)r[i];
        if (mi >= 0) {
            if (setp)
                a[mi] = (long)&b.set;
        } else if (r[5]) {
            a[5] = (long)lsel;
        }
        r[0] = (unsigned long long)cng_syscall6(a[0], a[1], a[2], a[3], a[4],
                                                a[5], nr);
        return 1;
    }
    if (mi >= 0) {
        if (setp)
            r[mi] = rec + __builtin_offsetof(struct cng_bounce, set);
    } else if (r[5]) {
        r[5] = rec + __builtin_offsetof(struct cng_bounce, sel);
    }
    /* The number the svc makes is the one the tracer left (an entry stop can
     * redirect it), not necessarily the x8 the guest trapped with. */
    r[8] = (unsigned long long)nr;
    uc->uc_mcontext.sp = rec;
    uc->uc_mcontext.pc = (unsigned long long)(unsigned long)cng_bounce_wait;
    return 0;
}

/* The guest's registers back from the record `b`, its own pc and sp, and the
 * call's result in x0 — the svc's, `res`, or the dispatch's own (BOUNCE_DISP
 * keeps it in the record). */
static void bounce_restore(struct cng_ucontext *uc, const struct cng_bounce *b,
                           unsigned long long res) {
    unsigned long long *r = uc->uc_mcontext.regs;
    for (int i = 1; i < 31; i++)
        r[i] = b->regs[i];
    r[0] = b->kind == BOUNCE_DISP ? b->regs[0] : res;
    uc->uc_mcontext.sp = b->sp;
    uc->uc_mcontext.pc = b->pc;
    uc->uc_mcontext.pstate = b->pstate;
}

/* The completion trap. Returns 1 with the record in *b when the frame had one
 * behind it (a frame without is left alone), 0 otherwise. */
static int bounce_finish(struct cng_ucontext *uc, struct cng_bounce *b) {
    if (cng_user_copyin(b, (void *)uc->uc_mcontext.sp, sizeof *b) < 0 ||
        b->magic != CNG_BOUNCE_MAGIC)
        return 0;
    bounce_restore(uc, b, uc->uc_mcontext.regs[0]);
    return 1;
}

/* The waits the kernel answers ERESTARTNOHAND when a signal cuts them short:
 * it turns that into EINTR only when a handler is run, and a ptrace stop is
 * not one, so an attach restarts them. Their timeouts are written back as
 * they run, so making one again is the kernel's own restart. */
static int bounce_nohand(long nr) {
    return nr == __NR_ppoll || nr == __NR_pselect6 || nr == __NR_rt_sigsuspend;
}

int cng_bounce_unwind(struct cng_ucontext *uc, int stop, int *owed,
                      long *rval) {
    unsigned long pc = (unsigned long)uc->uc_mcontext.pc;
    unsigned long long *r = uc->uc_mcontext.regs;
    unsigned long wait = (unsigned long)cng_bounce_wait,
                  disp = (unsigned long)cng_bounce_dispatch,
                  done = (unsigned long)__cng_gate_end;
    int at_wait = pc == wait, after_wait = pc == wait + 4,
        at_disp = pc == disp || pc == disp + 4,
        after_disp = pc == disp + 8 || pc == disp + 12, at_done = pc == done;
    if (!at_wait && !after_wait && !at_disp && !after_disp && !at_done)
        return CNG_UNWIND_NONE;
    struct cng_bounce b;
    if (cng_user_copyin(&b, (void *)uc->uc_mcontext.sp, sizeof b) < 0 ||
        b.magic != CNG_BOUNCE_MAGIC)
        return CNG_UNWIND_NONE;
    /* Undone: the call had not been made, or was cut short and is to be made
     * again — at the svc of a raw or wait bounce (not reached, or a restart the
     * kernel has pending), or at the dispatch's entry. A wait of the restarting
     * kind that the kick ended with EINTR is undone as well, stop or not: the
     * kick, not the guest, ended it. Without a stop, nothing else is touched:
     * a pending restart is the kernel's to make, and the completion trap
     * finishes a call that is over. */
    int restart = after_wait && (s64)r[0] == -EINTR && bounce_nohand(b.nr) &&
                  b.kind != BOUNCE_DISP;
    int undo = restart || (stop && (at_wait || at_disp));
    if (!undo && !stop)
        return CNG_UNWIND_NONE;
    *owed = b.owed;
    if (undo) {
        bounce_restore(uc, &b, b.regs[0]);
        uc->uc_mcontext.pc = b.pc - 4;
        *rval = restart ? -514 /*ERESTARTNOHAND*/ : -512 /*ERESTARTSYS*/;
        return CNG_UNWIND_UNDONE;
    }
    /* Done: the svc returned (x0 its result), or the dispatch did (its result
     * in the record), with only the completion trap left to make. The
     * dispatch reported its own exit stop. */
    bounce_restore(uc, &b, r[0]);
    if (b.kind == BOUNCE_DISP)
        *owed = 0;
    *rval = (long)uc->uc_mcontext.regs[0];
    return CNG_UNWIND_DONE;
}

/* sigaltstack, answered from the frame. The guest's alternate stack is what the
 * kernel saved in uc_stack at delivery and what rt_sigreturn puts back —
 * sigsys_on_scratch disarms the live one for the length of the handler, so that
 * nothing nests onto it — and a call re-issued as it stands changes the
 * disarmed one and is undone by that same restore. Only a tracee's
 * trap-everything filter sends this call here, and it is the call bionic makes
 * on the way out of every thread that has a stack of its own: disable it, then
 * unmap it. Re-issued, the disable was lost at the sigreturn, the thread was
 * handed the stale stack again at its next trap, and the kernel wrote that
 * trap's frame into the unmapped pages and killed the process with a SIGSEGV
 * nothing can catch.
 *
 * What the kernel judges stays the kernel's: the new stack is applied for real
 * (it validates the flags and the size, and the live one is disarmed anyway),
 * read back into the frame, and disarmed again. Two answers cannot come from
 * it, because it measures "on the stack" against the stack pointer it runs on,
 * which is ours: the old stack's SS_ONSTACK is the frame's (the guest's own sp
 * at the trap), and so is the EPERM for changing the stack one is on. The old
 * stack is written out last, after the new one has taken effect, as the
 * kernel's own sigaltstack does. */
static long sigsys_altstack(struct cng_ucontext *uc, const void *uss,
                            void *uoss) {
    cng_stack_t neu, now, off = {0, CNG_SS_DISABLE, 0};
    cng_stack_t old = uc->uc_stack;
    if (uss) {
        if (cng_user_copyin(&neu, uss, sizeof neu) < 0)
            return -EFAULT;
        if (old.ss_flags & CNG_SS_ONSTACK)
            return -EPERM;
        long r = CNG_SYS(__NR_sigaltstack, (long)&neu, 0, 0, 0, 0, 0);
        if (r < 0)
            return r;
        if (CNG_SYS(__NR_sigaltstack, 0, (long)&now, 0, 0, 0, 0) == 0)
            uc->uc_stack = now;
        if (now.ss_size)
            CNG_SYS(__NR_sigaltstack, (long)&off, 0, 0, 0, 0, 0);
    }
    if (uoss && cng_user_copyout(uoss, &old, sizeof old) < 0)
        return -EFAULT;
    return 0;
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
        unsigned long set;
        if (pset) {
            if (cng_user_copyin(&set, pset, sizeof set) < 0) {
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
            unsigned long neu = (how == 0)   ? (cur | set)   /* SIG_BLOCK */
                                : (how == 1) ? (cur & ~set)  /* SIG_UNBLOCK */
                                             : set;          /* SIG_SETMASK */
            uc->uc_sigmask.sig[0] = neu & ~(1UL << (CNG_SIGSYS - 1));
            cng_sig_note_mask(2 /*SETMASK: the mask that results*/, neu);
        }
        if (pold && cng_user_copyout(pold, &cur, sizeof cur) < 0) {
            r[0] = (unsigned long long)(long)-EFAULT;
            return 1;
        }
        r[0] = 0;
        return 1;
    }

    /* sigaltstack is the same kind of call: state the sigreturn restores from
     * the frame, so it is answered there (sigsys_altstack). */
    if (nr == __NR_sigaltstack) {
        r[0] = (unsigned long long)sigsys_altstack(uc, (const void *)r[0],
                                                   (void *)r[1]);
        return 1;
    }

    /* execve/execveat are emulated in-process (they'd otherwise wipe us). */
    if (nr == __NR_execve) {
        cng_emulate_execve(uc, CNG_AT_FDCWD, (const char *)r[0], (char **)r[1],
                           (char **)r[2], 0);
        return cng_is_err((long)r[0]); /* success redirected the context */
    }
    if (nr == __NR_execveat) {
        cng_emulate_execve(uc, (int)r[0], (const char *)r[1], (char **)r[2],
                           (char **)r[3], (int)r[4]);
        return cng_is_err((long)r[0]);
    }

    /* clone: the vfork-style kinds the filter traps are converted to a COW
     * fork, and the child's stack goes into the context for sigreturn to
     * install (cng_clone_convert has the whole story). */
    if (nr == __NR_clone) {
        cng_clone_convert(ur);
        return 1;
    }

    /* A wait that installs a mask of its own: run from guest context. */
    if (cng_is_masked_wait(nr))
        return bounce_start(uc, nr);

    long res = cng_dispatch(nr, (long)r[0], (long)r[1], (long)r[2], (long)r[3],
                            (long)r[4], (long)r[5], CNG_DISP_HANDLER);
    /* A call that can block, sent out of the handler (see the bounce above),
     * or made here after all when the guest's stack has no room for it. */
    if (res == -CNG_EBOUNCE_RAW || res == -CNG_EBOUNCE_DISP) {
        if (bounce_call(uc, nr,
                        res == -CNG_EBOUNCE_RAW ? BOUNCE_RAW : BOUNCE_DISP))
            return 0;
        res = cng_dispatch(nr, (long)r[0], (long)r[1], (long)r[2], (long)r[3],
                           (long)r[4], (long)r[5], CNG_DISP_TRAP);
    }
    /* A wait made here that a ptrace kick is waiting to interrupt: undone, so
     * that the kick lands at the guest's svc, which is where the kernel shows
     * a call it is going to restart, and the svc makes it again after. An
     * entry stop reported for it owes an exit stop first, with the restart
     * code the kernel's tracer sees there. */
    if (res == -CNG_ERESTART) {
        unsigned long long a0 = r[0];
        r[0] = (unsigned long long)(long)-512 /*ERESTARTSYS*/;
        cng_pt_syscall_exit(ur);
        /* ...where a tracer that changes the code takes the restart away, as
         * do_signal decides it from x0 after that stop. */
        if ((long)r[0] == -512) {
            r[0] = a0;
            uc->uc_mcontext.pc -= 4;
        }
        return 0;
    }
    if (cng_g_debug && res < 0 && res != -ENOENT)
        cng_dprintf(2, "[cng] dispatch nr=%ld -> errno=%ld\n", nr, -res);
    r[0] = (unsigned long long)res;
    return 1;
}

void cng_sigsys_body(struct cng_ucontext *uc, cng_siginfo_t *si) {
    unsigned long long *r = uc->uc_mcontext.regs;

    /* Only seccomp traps are ours to emulate. A guest-directed SIGSYS never
     * gets this far — sigsys_handler delivers it to the guest's own disposition
     * before switching stacks — so this is a guard for a caller handing the
     * body a frame of its own making, which leaves it untouched. */
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
    /* A trap out of the guest: the filter is live, and a trap a SIGSYS of
     * ours displaces is something that can happen here (cng_seccomp_traps). */
    cng_g_traps_live = 1;

    long nr = (long)r[8];

    /* The completion of a bounce (see bounce_start and bounce_call): not a
     * syscall of the guest's, and its site is ours — never one to rewrite.
     * What is owed is the exit stop of the syscall that was bounced, whose
     * entry stop was reported when it trapped (it was recorded then, since a
     * guest handler that ran over the bounced call reported stops of its own
     * since), unless the bounce was a dispatch, which gave it itself. */
    if (ca == (unsigned long)cng_bounce_svc_end) {
        struct cng_bounce b;
        if (bounce_finish(uc, &b) && b.kind != BOUNCE_DISP &&
            cng_pt_active()) {
            struct cng_uregs *ur = cng_pt_uregs(uc);
            cng_pt_set_frame(ur, uc);
            cng_pt_entry_set(b.owed);
            cng_pt_syscall_exit(ur);
            cng_pt_step_report(ur);
        }
        return;
    }

    /* This trap is also the only proof that exists about the word behind it:
     * the CPU fetched and executed it as `svc #0`. The AoT rewriter has to
     * decide that by reading bytes, and it is exactly the sites it could not
     * reach — a natively mapped library, a JIT's output, an object whose
     * headers named no code — that arrive here. Patch it, so the site costs
     * this trap once. (`rt_sigreturn` is the site that must never become a
     * trampoline call; the filter does not trap it, and if it ever did, this
     * is where that would stop being true.)
     *
     * A site that is a branch now is also the way to make this very call:
     * resumed at the site, the thread runs it through the trampoline, from
     * its own context and on its own mask, as every later call from there
     * will be. Made here instead, the first call from each site ran with every
     * signal blocked — the one that blocks, for as long as it blocked. */
    if (nr != __NR_rt_sigreturn && cng_rewrite_site(ca - 4)) {
        uc->uc_mcontext.pc = ca - 4;
        return;
    }

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
    /* The guest's own mask asks for every signal blocked (cng_sig_note_mask).
     * Not the live mask, which keeps SIGSYS open whatever the guest asked: this
     * is what the exec's de_thread reads to leave a thread that is leaving. */
    int sigfull;
    /* The innermost dispatch this thread is running from guest context
     * (cng_run_scratch_in), for a ptrace stop that lands inside it. */
    struct cng_gframe *gf;
    /* A ptrace request carried by SIGSYS that landed where no stop can be
     * taken, left for the handler it interrupted to take (sigsys_kick); and
     * how deep this thread is in our other handlers' own work, which is
     * such a place (cng_sig_in_handler). */
    int attach;
    int inh;
    /* The frame a handler of ours last returned this thread to: part of the
     * register file, enough to tell it from any frame the guest has since
     * run to (cng_sig_returned_to). */
    struct {
        unsigned long long pc, sp, x0, x1, x2, x8, x30;
    } back;
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

/* One stack, straight from the kernel, with an inaccessible page on each side.
 * Returns the base of the usable part, or 0.
 *
 * The guards are not there for overflow alone. The kernel merges adjacent
 * anonymous mappings of equal permissions into one VMA, and a bare stack lands
 * wherever the allocator put it — in the middle of a guest's own mappings, a
 * thread's stack and the page the guest then maps beside it among them. The
 * VMA that results holds our stack pointer, and an mprotect(PROT_EXEC) on any
 * page of it is judged by SELinux as a stack being made executable (see the
 * mprotect case in dispatch.c), which an Android app domain is refused: the
 * JVM's startup probe died of exactly that, issued from the handler's own
 * stack. A PROT_NONE page on each side cannot merge with a read-write
 * neighbour, so this VMA is ours alone. */
static unsigned long scr_mmap(void) {
    unsigned long g = cng_page_size, len = CNG_SCR_SZ + 2 * g;
    void *map = sys_mmap(0, len, CNG_PROT_NONE,
                         CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (map == CNG_MAP_FAILED || cng_is_err((long)map))
        return 0;
    unsigned long base = (unsigned long)map + g;
    if (sys_mprotect((void *)base, CNG_SCR_SZ,
                     CNG_PROT_READ | CNG_PROT_WRITE) < 0) {
        sys_munmap(map, len);
        return 0;
    }
    return base;
}

/* The whole of what scr_mmap mapped, guards included. */
static void scr_unmap(unsigned long base) {
    sys_munmap((void *)(base - cng_page_size), CNG_SCR_SZ + 2 * cng_page_size);
}

/* Map a stack into a slot this thread has just claimed. 0, or -1 with the slot
 * given back. `hi` is what publishes it: see the re-entry note below. */
static int scr_map(unsigned i) {
    unsigned long base = scr_mmap();
    if (!base) {
        cng_scr[i].tid = 0;
        return -1;
    }
    cng_scr[i].lo = (unsigned long)base;
    __atomic_store_n(&cng_scr[i].hi, ((unsigned long)base + CNG_SCR_SZ) & ~15UL,
                     __ATOMIC_RELEASE);
    return 0;
}

/* Does [lo, hi) hold anything a dispatch on a scratch stack is standing on?
 * The exec reclaim asks, and there are two such things.
 *
 * The stack itself is the monitor's memory, not the outgoing program's, and it
 * is the one region of ours that appears after the floor is taken and is not
 * in the own-map registry — this table already records every slot's bounds, so
 * asking it cannot drift out of step the way a second record would.
 *
 * The signal frame is the guest's. The SIGSYS tier returns into the new program
 * through rt_sigreturn, and what that reads is the frame the kernel built when
 * it delivered the trap — which sits on the guest's alternate signal stack
 * whenever the guest registered one. bionic registers one for every thread, so
 * an emulated execve by an Android guest returned through a frame the sweep had
 * just unmapped: SIGSEGV on the first exec, measured. The frame is dead one
 * generation later, when the next trap's frame is somewhere else, so keeping
 * the mapping it lies in costs one alternate stack and not a chain of them. */
int cng_scr_hit(unsigned long lo, unsigned long hi) {
    for (int i = 0; i < CNG_SCR_N; i++) {
        if (!__atomic_load_n(&cng_scr[i].hi, __ATOMIC_ACQUIRE))
            continue; /* never mapped, or not published yet */
        unsigned long b = cng_scr[i].lo;
        if (lo < b + CNG_SCR_SZ + cng_page_size && b - cng_page_size < hi)
            return 1; /* the guards are ours too: see scr_mmap */
        unsigned long f = (unsigned long)__atomic_load_n(&cng_scr[i].uc,
                                                         __ATOMIC_ACQUIRE);
        if (f && f >= lo && f < hi)
            return 1;
    }
    return 0;
}

/* Is `tid` still a thread of this process? tgkill with signal 0 does the
 * existence check and delivers nothing — one syscall, where a /proc read would
 * be several, and this runs inside the handler. */
static int scr_tid_live(long tid) {
    return CNG_SYS(__NR_tgkill, sys_getpid(), tid, 0, 0, 0, 0) == 0;
}

/* CNG_SCRATCH_NONE=1: answer as a process whose table has no slot to give —
 * 256 live threads already holding one, or an mmap the host refused. A working
 * host does not reach that on its own, and what happens when it does is the
 * whole question here, so it is settled once at monitor install rather than
 * read per dispatch. Same testing convention as CNG_PROCREG_NONE. */
static int cng_g_scratch_none;

/* Find this thread's scratch slot (allocating one on first use). Returns the
 * slot index, or -1 if the table is full of live threads or mmap failed. */
static int cng_scratch_slot(long tid) {
    if (cng_g_scratch_none)
        return -1;
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
        cng_scr[i].sigfull = 0;
        cng_scr[i].gf = 0;
        cng_scr[i].attach = 0;
        cng_scr[i].inh = 0;
        memset(&cng_scr[i].back, 0, sizeof cng_scr[i].back);
        /* Its owner can have died between claiming the slot and mapping it. */
        if (!cng_scr[i].hi && scr_map(i) != 0)
            return -1;
        return (int)i;
    }
    return -1;
}

/* A thread of a program that calls pthread_exit on a detached thread — bionic
 * and musl both — blocks every signal, unmaps its own stack and exits, the
 * three of them without a syscall the filter traps. The first is there so that
 * no signal frame is wanted once the second has happened, and we do not let it
 * mean that: SIGSYS is never blocked for real (a trap taken while it is would
 * kill the process), so the exec's de_thread request can arrive between the
 * unmap and the exit, where the kernel has nowhere to put the frame and force-
 * kills the whole process with a SIGSEGV nothing can catch (measured: a chain
 * of short-lived detached threads under an exec, one run in four).
 *
 * So what the guest asked for is kept, per thread, for de_thread to read: a
 * thread that has asked for every signal to be blocked is, for a moment, left
 * alone and waited for, like the kernel's de_thread does for one already
 * exiting. It is a hint with a deadline (execve.c gives it a few milliseconds,
 * and up to a second while it is not asleep), not a refusal: a thread that
 * really does sit with everything blocked — the sigwait thread of a daemon —
 * is told after that as it always was. `how` and
 * `set` are the call's own; the SIGSYS tier, which computes the resulting mask,
 * passes it as a SETMASK. */
void cng_sig_note_mask(int how, unsigned long set) {
    int full = (set | (1UL << (CNG_SIGSYS - 1))) == ~0UL;
    int i = cng_scratch_slot(sys_gettid());
    if (i < 0) {
        if (full && how != 1 && cng_dethread_doomed())
            cng_dethread_die();
        return;
    }
    int cur = __atomic_load_n(&cng_scr[i].sigfull, __ATOMIC_RELAXED);
    if (how == 2 /*SETMASK*/)
        cur = full;
    else if (how == 0 /*BLOCK*/ && full)
        cur = 1;
    else if (how == 1 /*UNBLOCK*/ && set)
        cur = 0;
    /* The mask first, then whether an exec is killing this thread: de_thread
     * says so first and reads the mask after, and the four are sequentially
     * consistent, so one side always sees the other. A thread whose whole
     * mask the exec read too early sees the exec, and exits here: it was
     * told without its mask, and the request, sent microseconds after the
     * read, used to be delivered as its unmap returned, onto no stack. */
    __atomic_store_n(&cng_scr[i].sigfull, cur, __ATOMIC_SEQ_CST);
    if (cur && cng_dethread_doomed())
        cng_dethread_die();
}

/* Has thread `tid` asked for every signal to be blocked? Read by another thread
 * and never allocates: a thread with no slot has asked for nothing. */
int cng_sig_all_blocked(long tid) {
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = __atomic_load_n(&cng_scr[i].tid, __ATOMIC_ACQUIRE);
        if (t == tid)
            return __atomic_load_n(&cng_scr[i].sigfull, __ATOMIC_SEQ_CST);
        if (t == 0)
            return 0;
    }
    return 0;
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

/* Runs on the scratch stack, and the first thing it does is take the guest's
 * alt-stack out of the picture for the duration.
 *
 * The kernel picks where a signal frame goes with sigsp(): SA_ONSTACK plus an SP
 * that is not currently on the alt-stack means the alt-stack TOP. That is how
 * our own frame got there — and having moved SP to the scratch stack, it is also
 * true of a *nested* SIGSYS, which SA_NODEFER deliberately leaves deliverable so
 * the gate-net can catch a re-issue Android's own filter blocks. So the nested
 * frame is written at the alt-stack top: the same address as the outer one.
 * Measured on the host and under qemu — delta from the outer frame, exactly 0.
 * The outer frame is then rubble, and the sigreturn that reads it resumes a
 * context from the middle of our own re-issue; in the repro that is an endless
 * loop of the handler re-entering itself, with every signal but SIGSYS masked.
 *
 * Disarming the alt-stack sends the nested frame to the current SP instead —
 * the scratch stack, below the dispatcher's own frames, where it belongs. It
 * needs no undo: the kernel saves the alt-stack settings in each signal frame
 * and rt_sigreturn restores them, so the guest gets its own back at every exit
 * from here, including the nested one's.
 *
 * The check is free: uc_stack is what the kernel saved in the frame, so a guest
 * with no alt-stack registered — most of them — costs nothing, and one that has
 * registered it is exactly the guest at risk. */
int cng_g_sigsys_nest = 0;
unsigned long cng_g_sigsys_frame[2];
int cng_g_traps_live;

static void sigsys_on_scratch(void *ucv, void *si) {
    struct cng_ucontext *uc = ucv;
    if (uc->uc_stack.ss_size && !(uc->uc_stack.ss_flags & CNG_SS_DISABLE)) {
        cng_stack_t off = {0, CNG_SS_DISABLE, 0};
        CNG_SYS(__NR_sigaltstack, (long)&off, 0, 0, 0, 0, 0);
    }
    /* Test aid: reach the nested state from a host with no ambient filter, by
     * raising a real SIGSYS from right here — on the scratch stack, with the
     * outer frame wherever the kernel put it. */
    if (cng_g_sigsys_nest) {
        cng_g_sigsys_nest = 0;
        cng_g_sigsys_frame[0] = (unsigned long)uc;
        cng_sigsys_fabricate();
    }
    cng_sigsys_body(uc, si);
}

/* Queue a SIGSYS at this thread that the handler takes for a seccomp trap of
 * the gate's own svc: si_code SYS_SECCOMP (which the kernel lets a task send
 * itself) and a call address inside the gate, so the body's gate-net answers
 * it with -ENOSYS in x0 and dispatches nothing. A tgkill'd SIGSYS will not do:
 * that is a guest-directed signal now, delivered to the guest's disposition
 * before the handler ever switches stacks, and what the nesttest has to reach
 * is the stack switch. */
void cng_sigsys_fabricate(void) {
    cng_siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = CNG_SIGSYS;
    si.si_code = CNG_SYS_SECCOMP;
    si._u._sigsys.call_addr = (void *)__cng_gate_start;
    si._u._sigsys.syscall = -1; /* no real number: nothing is marked blocked */
    si._u._sigsys.arch = 0xC00000B7u; /* AUDIT_ARCH_AARCH64 */
    CNG_SYS(__NR_rt_tgsigqueueinfo, sys_getpid(), sys_gettid(), CNG_SIGSYS, &si,
            0, 0);
}

/* A stack for a call that cannot have this thread's slot: the table is full of
 * live threads, its mmap failed, or an outer dispatch on this thread is on it
 * already (a nested trap). Mapped for the one call and given back after it.
 *
 * The alternative was the interrupted stack, and that is not a fallback but the
 * failure itself: cng_dispatch's own frame is ~24 KiB and a translated openat
 * runs ~66 KiB deep, against Go's ~8 KiB goroutine stacks, musl's 128 KiB
 * thread stacks and whatever size a guest hands sigaltstack — and because the
 * frame is bigger than a guard page it steps clean over the guard into ordinary
 * guest memory, where nothing faults and nothing is reported. Three
 * syscalls (map, protect, unmap), on a path taken at most once per blocked
 * syscall number (the gate-net records it) or by the 257th live thread, buy
 * that away.
 *
 * If even this mmap fails there is no stack to be had anywhere and the caller
 * runs where it stands, which is where it always ran. */
static unsigned long scr_temp(void) { return scr_mmap(); }

static void scr_temp_free(unsigned long base) { scr_unmap(base); }

/* Run the dispatcher on this thread's scratch stack, or on a stack taken for
 * the call when the slot cannot be had. The busy flag (not an SP-range test) is
 * what detects nesting: with SA_ONSTACK the nested signal is delivered on the
 * alt-stack, not on the scratch stack, so a range test would miss it and wrongly
 * re-switch, clobbering the outer dispatcher frame. */
/* An exec handed to this thread, the group leader, by a sibling (execve.c):
 * carried out on a stack of ours, with the guest's alt-stack disarmed like a
 * dispatch, since the commit is the dispatcher's own code. */
static void takeover_on_scratch(void *ucv, void *si) {
    (void)si;
    struct cng_ucontext *uc = ucv;
    if (uc->uc_stack.ss_size && !(uc->uc_stack.ss_flags & CNG_SS_DISABLE)) {
        cng_stack_t off = {0, CNG_SS_DISABLE, 0};
        CNG_SYS(__NR_sigaltstack, (long)&off, 0, 0, 0, 0, 0);
    }
    cng_exec_takeover_frame(uc);
}

/* ---- a ptrace request carried by SIGSYS ----
 *
 * The kick that stops a running task for its tracer (PTRACE_ATTACH, SEIZE's
 * INTERRUPT, a routed stop signal) is a real-time signal, and a thread can
 * block it: GLib's worker threads block nearly everything, gmain among them.
 * The kernel attaches with SIGSTOP, which no mask holds back, so a crashed
 * Chrome's crashpad stopped every thread and the kick to gmain sat pending
 * for good, the reporter waiting on it, the browser never exiting. SIGSYS is
 * the one signal of ours a guest can never block, so a tracer whose target
 * holds the kick blocked sends the request as a SIGSYS too (ptrace.c,
 * pt_kick_attach), and it is taken here.
 *
 * Where it lands decides what can be done with it. In guest code, or in a
 * stub or a dispatch running in guest context, the stop is taken at once, the
 * same way the kick's handler takes one (cng_pt_sigsys_kick). Anywhere else
 * in chroot-ng — a dispatch this handler is making, or one of our other
 * handlers — the frame is ours and no stop can be taken on it, so the request
 * is noted and left: the handler underneath takes it on its way out, a wait it
 * polls ends for it (cng_sig_kick_pending), and the tracer sends it again
 * while it is not taken.
 *
 * SIGSYS also costs something the kick does not: it is a standard signal, of
 * which a thread holds one pending at most, so a trap the thread takes while
 * ours is pending is merged into ours and lost — the kernel skips the call
 * and hands the handler our siginfo instead. cng_pt_sigsys_kick makes such a
 * call again, which takes knowing whether the call behind the frame trapped
 * at all (cng_seccomp_traps) and whether a handler of ours answered it and
 * just returned (the frame noted below). */
static int sigsys_is_kick(const cng_siginfo_t *si) {
    return si->si_code == -1 /*SI_QUEUE*/ &&
           (int)si->_u._pad[1] == CNG_PT_KICK_ATTACH;
}

/* Note the frame a handler of ours is returning this thread to. */
static void scr_note_back(int i, const struct cng_ucontext *uc) {
    if (i < 0)
        return;
    const unsigned long long *r = uc->uc_mcontext.regs;
    cng_scr[i].back.pc = uc->uc_mcontext.pc;
    cng_scr[i].back.sp = uc->uc_mcontext.sp;
    cng_scr[i].back.x0 = r[0];
    cng_scr[i].back.x1 = r[1];
    cng_scr[i].back.x2 = r[2];
    cng_scr[i].back.x8 = r[8];
    cng_scr[i].back.x30 = r[30];
}

void cng_sig_note_return(const struct cng_ucontext *uc) {
    scr_note_back(cng_scratch_slot(sys_gettid()), uc);
}

void cng_sig_in_handler(int d) {
    int i = cng_scratch_slot(sys_gettid());
    if (i >= 0)
        cng_scr[i].inh += d;
}

int cng_sig_take_deferred(void) {
    int i = cng_scratch_slot(sys_gettid());
    if (i < 0 || !cng_scr[i].attach)
        return 0;
    cng_scr[i].attach = 0;
    return 1;
}

int cng_sig_returned_to(const struct cng_ucontext *uc) {
    int i = cng_scratch_slot(sys_gettid());
    if (i < 0)
        return 0;
    const unsigned long long *r = uc->uc_mcontext.regs;
    return cng_scr[i].back.pc == uc->uc_mcontext.pc &&
           cng_scr[i].back.sp == uc->uc_mcontext.sp &&
           cng_scr[i].back.x0 == r[0] && cng_scr[i].back.x1 == r[1] &&
           cng_scr[i].back.x2 == r[2] && cng_scr[i].back.x8 == r[8] &&
           cng_scr[i].back.x30 == r[30];
}

/* Is `pc` in one of the bounce stubs, which run in guest context? */
static int pc_in_stub(unsigned long pc) {
    unsigned long w = (unsigned long)cng_bounce_wait,
                  d = (unsigned long)cng_bounce_dispatch;
    return pc == w || pc == w + 4 || pc == (unsigned long)__cng_gate_end ||
           pc == (unsigned long)cng_bounce_svc_end || (pc >= d && pc <= d + 12);
}

/* The request, served on the scratch stack with the guest's alt-stack out of
 * the way, as a dispatch is (sigsys_on_scratch). `direct` is non-null for one
 * delivered straight onto the frame (see cng_pt_sigsys_kick). */
static void kick_on_scratch(void *ucv, void *direct) {
    struct cng_ucontext *uc = ucv;
    if (uc->uc_stack.ss_size && !(uc->uc_stack.ss_flags & CNG_SS_DISABLE)) {
        cng_stack_t off = {0, CNG_SS_DISABLE, 0};
        CNG_SYS(__NR_sigaltstack, (long)&off, 0, 0, 0, 0, 0);
    }
    cng_pt_sigsys_kick(uc, direct != 0);
}

static void sigsys_kick(struct cng_ucontext *uc) {
    int i = cng_scratch_slot(sys_gettid());
    unsigned long pc = (unsigned long)uc->uc_mcontext.pc;
    /* Left for later: inside a dispatch this handler is making, inside the
     * work of another handler of ours (one taking a stop, above all — a stop
     * nested in it would be a second stop, its writes undone when that
     * handler returns), or in any other code of ours but a dispatch running
     * in guest context, which is where the kick's own stops are taken too. */
    int later = i >= 0 && ((cng_scr[i].busy && cng_scr[i].uc) || cng_scr[i].inh);
    if (!later && pc >= (unsigned long)__cng_image_start &&
        pc < (unsigned long)__cng_image_end && !pc_in_stub(pc) &&
        !(i >= 0 && cng_scr[i].gf))
        later = 1;
    if (later) {
        if (i >= 0)
            cng_scr[i].attach = 1;
        return;
    }
    /* The first pass is the request itself, delivered onto this frame; a
     * further one is a request left for it meanwhile, which displaced
     * nothing here. */
    int direct = 1;
    do {
        if (i >= 0)
            cng_scr[i].attach = 0;
        if (i >= 0 && !cng_scr[i].busy) {
            cng_scr[i].busy = 1;
            cng_scr[i].uc = uc;
            cng_run_on_stack((void *)cng_scr[i].hi, (void *)kick_on_scratch, uc,
                             direct ? (void *)1 : 0);
            cng_scr[i].uc = 0;
            cng_scr[i].busy = 0;
        } else {
            /* A dispatch from guest context holds the stack: in place, as the
             * kick's handler serves one. */
            if (i >= 0)
                cng_scr[i].inh++;
            cng_pt_sigsys_kick(uc, direct);
            if (i >= 0)
                cng_scr[i].inh--;
        }
        scr_note_back(i, uc);
        direct = 0;
    } while (i >= 0 && cng_scr[i].attach);
}

static void sigsys_handler(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    /* A request from another thread of this process (execve.c's de_thread):
     * die here and now — wherever this thread was, in the guest or nested
     * inside a dispatch of its own — or carry the exec it planned. */
    void (*fn)(void *, void *) = sigsys_on_scratch;
    /* A sibling's exec is killing this thread: whatever this SIGSYS is, it is
     * the request too. One sent while another SIGSYS was pending (a trap's)
     * was merged into it, and execve.c tells a thread only once. */
    int req = cng_dethread_request(si);
    if (!req && cng_dethread_doomed())
        req = CNG_DT_DIE;
    switch (req) {
    case CNG_DT_DIE:
        cng_dethread_die(); /* killed by a sibling's exec */
    case CNG_DT_EXEC:
        fn = takeover_on_scratch;
        break;
    default:
        /* A SIGSYS that is not a seccomp trap is the guest's signal — kill(2),
         * tgkill, sigqueue — and goes to the guest's own disposition, from the
         * frame the kernel built and on the stack it chose, with no scratch
         * stack and none of the bookkeeping below: a handler the guest
         * installed may siglongjmp out and never come back, which a busy flag
         * or a disarmed alt-stack would not survive. It used to be consumed
         * here and nothing happened, where the default action is a core dump. */
        if (sigsys_is_kick(si)) {
            sigsys_kick((struct cng_ucontext *)ucv);
            return;
        }
        if (si->si_code != CNG_SYS_SECCOMP) {
            cng_pt_deliver_sigsys(si, ucv);
            cng_sig_note_return((struct cng_ucontext *)ucv);
            return;
        }
    }
    long tid = sys_gettid();
    int i = cng_scratch_slot(tid);
    if (i < 0 || cng_scr[i].busy) {
        if (cng_g_sigsys_frame[0]) /* the test above: this is the nested one */
            cng_g_sigsys_frame[1] = (unsigned long)ucv;
        unsigned long base = scr_temp();
        if (!base) {
            if (fn == sigsys_on_scratch)
                cng_sigsys_body((struct cng_ucontext *)ucv, si);
            else
                cng_exec_takeover_frame((struct cng_ucontext *)ucv);
            return;
        }
        cng_run_on_stack((void *)(base + CNG_SCR_SZ), (void *)fn, ucv, si);
        scr_temp_free(base);
        return;
    }
    cng_scr[i].busy = 1;
    cng_scr[i].uc = (struct cng_ucontext *)ucv;
    cng_run_on_stack((void *)cng_scr[i].hi, (void *)fn, ucv, si);
    scr_note_back(i, (struct cng_ucontext *)ucv);
    /* A request that came in while this handler was busy (sigsys_kick): the
     * frame is the guest's again, and it is taken on that, here. */
    while (cng_scr[i].attach) {
        cng_scr[i].attach = 0;
        cng_run_on_stack((void *)cng_scr[i].hi, (void *)kick_on_scratch, ucv,
                         0);
        scr_note_back(i, (struct cng_ucontext *)ucv);
    }
    cng_scr[i].uc = 0;
    cng_scr[i].busy = 0;
}

/* Run `fn(arg)` on a stack of ours; 0 only when none could be had at all and the
 * caller has to run it where it stands.
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
 * re-entry it does catch. Either way the nested call gets a stack of its own
 * rather than the guest's, which is the one thing the guest's cannot survive. */
static int cng_run_scratch_on(int i, unsigned long sp, void (*fn)(void *),
                              void *arg);

int cng_run_scratch(void (*fn)(void *), void *arg) {
    return cng_run_scratch_in(fn, arg, 0);
}

/* The record is published with a plain store: the only reader is a kick
 * handler on this same thread, which a signal delivery orders after it. */
int cng_run_scratch_in(void (*fn)(void *), void *arg, struct cng_gframe *f) {
    int i = cng_scratch_slot(sys_gettid());
    unsigned long sp = (unsigned long)&i;
    if (f && i >= 0) {
        f->prev = cng_scr[i].gf;
        cng_scr[i].gf = f;
    }
    int ran = cng_run_scratch_on(i, sp, fn, arg);
    if (f && i >= 0)
        cng_scr[i].gf = f->prev;
    return ran;
}

struct cng_gframe *cng_gframe_cur(void) {
    long tid = sys_gettid();
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = __atomic_load_n(&cng_scr[i].tid, __ATOMIC_ACQUIRE);
        if (t == tid)
            return cng_scr[i].gf;
        if (t == 0)
            return 0;
    }
    return 0;
}

/* The switch itself, for a slot already looked up (`i`, -1 for none) from a
 * caller standing at `sp`. */
static int cng_run_scratch_on(int i, unsigned long sp, void (*fn)(void *),
                              void *arg) {
    if (i >= 0 && !cng_scr[i].busy &&
        !(sp >= cng_scr[i].lo && sp < cng_scr[i].hi)) {
        cng_scr[i].busy = 1;
        cng_run_on_stack((void *)cng_scr[i].hi, (void *)fn, arg, 0);
        cng_scr[i].busy = 0;
        return 1;
    }
    /* No slot, or an outer dispatch is on it. Running in place is what the
     * guest's own alt-stack cannot survive, so take a stack for this call.
     *
     * `fn` need not come back: the -R tier's emulated execve enters the new
     * program from inside it (cng_scratch_leave), and then this mapping is
     * never given back. That is 256 KiB against an exec that already keeps the
     * whole of the previous program's address space, on a path reached only by
     * an exec from inside a nested dispatch. */
    unsigned long base = scr_temp();
    if (!base)
        return 0;
    cng_run_on_stack((void *)(base + CNG_SCR_SZ), (void *)fn, arg, 0);
    scr_temp_free(base);
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
 * guest's, so it is read straight from the kernel (`uc` is then NULL). A caller
 * that already holds the frame passes it; cng_sig_deliverable() below finds it. */
int cng_sig_deliverable_in(const struct cng_ucontext *uc) {
    unsigned long pend = 0;
    if (CNG_SYS(__NR_rt_sigpending, &pend, sizeof pend, 0, 0, 0, 0) < 0 || !pend)
        return 0;

    unsigned long blocked = 0;
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
        /* The ptrace kick is ours, not the guest's: queued at a tracer on every
         * event of its tracees and never in its mask, so it is pending more
         * often than not while the tracer waits here — and no wait the guest
         * could have made is ended by it. Where it does end a native wait
         * (that is its other job) the call is simply made again. */
        if (sig == cng_g_kicksig)
            continue;
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

/* Is a ptrace kick waiting for a wait made inside the handler to end — queued,
 * and not blocked by the mask the frame will restore? A kick the guest's own
 * mask holds back would not be delivered at the restart either. */
int cng_sig_kick_pending(const struct cng_ucontext *uc) {
    unsigned long pend = 0, bit = 1UL << (cng_g_kicksig - 1);
    if (!uc)
        return 0;
    /* ...or one carried by SIGSYS, left for this handler (sigsys_kick). */
    int i = cng_scratch_slot(sys_gettid());
    if (i >= 0 && cng_scr[i].attach)
        return 1;
    if (uc->uc_sigmask.sig[0] & bit)
        return 0;
    return CNG_SYS(__NR_rt_sigpending, &pend, sizeof pend, 0, 0, 0, 0) == 0 &&
           (pend & bit);
}

/* The frame the dispatch on this thread's scratch stack is running for, or 0
 * when it is not in the handler. */
static struct cng_ucontext *scr_cur_uc(void) {
    long tid = sys_gettid();
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        if (__atomic_load_n(&cng_scr[i].tid, __ATOMIC_ACQUIRE) == tid)
            return cng_scr[i].uc;
    }
    return 0;
}

int cng_sig_kick_waiting(void) { return cng_sig_kick_pending(scr_cur_uc()); }

/* The same question for the frame this thread is in, found by its tid: for a
 * caller that is not handed one. */
int cng_sig_deliverable(void) { return cng_sig_deliverable_in(scr_cur_uc()); }

/* Testing: the SIGSYS handler on its own — no filter, no blocked-syscall probe,
 * no ptrace plumbing. Enough for a fabricated SIGSYS to reach the real handler
 * and be delivered where the kernel would really put it. */
int cng_sigsys_install_only(void) {
    return cng_sig_install(CNG_SIGSYS, sigsys_handler);
}

int cng_install_monitor(struct cng_fs *fs) {
    cng_g_fs = fs;
    int sr = cng_sig_install(CNG_SIGSYS, sigsys_handler);
    if (sr < 0)
        return sr; /* -errno: cng_run reports it, so it has to be the real one */
    /* From here a trapping filter is survivable. Anything that stacks one on
     * demand (the ptrace roles) must not do so before this point: a
     * SECCOMP_RET_TRAP with no handler for the signal kills the process. */
    cng_g_sigsys_ready = 1;
    cng_g_scratch_none = cng_broker_env("CNG_SCRATCH_NONE") != 0;
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
