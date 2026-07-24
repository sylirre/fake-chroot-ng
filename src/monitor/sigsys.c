/* SIGSYS handler + signal installation.
 *
 * On a seccomp RET_TRAP the kernel delivers SIGSYS with the interrupted
 * context: args in x0..x5, syscall nr in x8, and pc already advanced past the
 * svc. We emulate the syscall (translating paths) and write the result into x0;
 * on return the restorer runs rt_sigreturn and the guest continues.
 */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/rt.h"
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

    /* rt_sigprocmask: apply the guest's requested mask but never let SIGSYS be
     * blocked (a masked seccomp SIGSYS force-kills). We edit uc_sigmask, which
     * sigreturn restores — re-issuing the syscall here would be undone by that
     * same restore. */
    if (nr == __NR_rt_sigprocmask) {
        int how = (int)r[0];
        unsigned long *pset = (unsigned long *)r[1];
        unsigned long *pold = (unsigned long *)r[2];
        unsigned long cur = uc->uc_sigmask.sig[0];
        if (pold)
            *pold = cur;
        if (pset) {
            unsigned long set = *pset;
            unsigned long neu = (how == 0)   ? (cur | set)   /* SIG_BLOCK */
                                : (how == 1) ? (cur & ~set)  /* SIG_UNBLOCK */
                                             : set;          /* SIG_SETMASK */
            uc->uc_sigmask.sig[0] = neu & ~(1UL << (CNG_SIGSYS - 1));
        }
        r[0] = 0;
        return;
    }

    /* execve/execveat are emulated in-process (they'd otherwise wipe us). */
    if (nr == __NR_execve) {
        cng_emulate_execve(uc, CNG_AT_FDCWD, (const char *)r[0], (char **)r[1],
                           (char **)r[2]);
        return;
    }
#ifdef __NR_execveat
    if (nr == __NR_execveat) {
        cng_emulate_execve(uc, (int)r[0], (const char *)r[1], (char **)r[2],
                           (char **)r[3]);
        return;
    }
#endif

    long res = cng_dispatch(nr, (long)r[0], (long)r[1], (long)r[2], (long)r[3],
                            (long)r[4], (long)r[5], /*trapped=*/1);
    if (cng_g_debug && res < 0 && res != -ENOENT)
        cng_dprintf(2, "[cng] dispatch nr=%ld -> errno=%ld\n", nr, -res);
    r[0] = (unsigned long long)res;
}

/* Per-thread scratch stacks for the handler. The path dispatcher needs tens of
 * KiB (multiple PATH_MAX buffers deep); a seccomp SIGSYS can fire on any thread,
 * and Go goroutine stacks are only ~8 KiB, so we run the dispatcher on a large
 * stack of our own keyed by TID. Slots are claimed lock-free and never freed
 * (a recycled TID safely reuses its slot; the table is sized well above any
 * realistic live-thread count). If the table is full or mmap fails we fall back
 * to the interrupted stack. */
extern long cng_run_on_stack(void *newsp, void *fn, void *a0, void *a1);

#define CNG_SCR_N  256
#define CNG_SCR_SZ (256 * 1024)
static struct {
    long tid;
    unsigned long lo, hi;
    int busy;
} cng_scr[CNG_SCR_N];

/* Claim `*p` from 0 to `tid` (inline LL/SC so we need no libgcc atomics helper;
 * works on any ARMv8). Returns 1 if this call performed the store. */
static int cng_claim_slot(volatile long *p, long tid) {
    long old;
    int fail;
    __asm__ volatile("1: ldaxr %[old], [%[p]]\n"
                     "   cbnz  %[old], 2f\n"     /* already taken */
                     "   stlxr %w[f], %[tid], [%[p]]\n"
                     "   cbnz  %w[f], 1b\n"      /* store lost; retry */
                     "   b     3f\n"
                     "2: clrex\n"
                     "   mov   %w[f], #1\n"
                     "3:\n"
                     : [old] "=&r"(old), [f] "=&r"(fail)
                     : [p] "r"(p), [tid] "r"(tid)
                     : "cc", "memory");
    return fail == 0;
}

/* Find this thread's scratch slot (allocating one on first use). Returns the
 * slot index, or -1 if the table is full or mmap failed. */
static int cng_scratch_slot(long tid) {
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = cng_scr[i].tid;
        if (t == tid)
            return (int)i;
        if (t == 0 && cng_claim_slot(&cng_scr[i].tid, tid)) {
            void *base =
                sys_mmap(0, CNG_SCR_SZ, CNG_PROT_READ | CNG_PROT_WRITE,
                         CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
            if (base == CNG_MAP_FAILED || cng_is_err((long)base)) {
                cng_scr[i].tid = 0;
                return -1;
            }
            cng_scr[i].lo = (unsigned long)base;
            cng_scr[i].hi = ((unsigned long)base + CNG_SCR_SZ) & ~15UL;
            return (int)i;
        }
        /* slot taken by another thread (or we lost the CAS): keep probing */
    }
    return -1;
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
    cng_run_on_stack((void *)cng_scr[i].hi, (void *)cng_sigsys_body, ucv, si);
    cng_scr[i].busy = 0;
}

int cng_install_monitor(struct cng_fs *fs) {
    cng_g_fs = fs;
    if (cng_sig_install(CNG_SIGSYS, sigsys_handler) < 0)
        return -1;
    /* Measure which syscalls Android blocks (before our own filter is active)
     * so dispatch emulates them rather than trapping on a re-issue. */
    cng_probe_blocked();
    int r = cng_install_seccomp();
    /* NO_NEW_PRIVS is now set; on Android that can revoke anon executable memory,
     * so switch the loader to file-backed mapping if so (before the guest execs). */
    cng_loader_check_execmem();
    return r;
}
