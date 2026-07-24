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
     * force-kills). The nested trap is caught by the gate-net below. */
    sa.flags = CNG_SA_SIGINFO | CNG_SA_RESTORER | CNG_SA_RESTART |
               CNG_SA_NODEFER;
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
        cng_note_blocked(si->_u._sigsys.syscall);
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

/* Top of this thread's scratch stack, or 0 to keep the current stack (table
 * full/alloc failed, or we are already running on the scratch stack — a nested
 * gate-net trap, which is shallow and safe to run below the outer frame). */
static void *cng_scratch_top(void) {
    long tid = sys_gettid();
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % CNG_SCR_N;
    for (unsigned k = 0; k < CNG_SCR_N; k++) {
        unsigned i = (h + k) % CNG_SCR_N;
        long t = cng_scr[i].tid;
        if (t == tid) {
            if (sp > cng_scr[i].lo && sp <= cng_scr[i].hi)
                return 0; /* nested: already on this scratch stack */
            return (void *)cng_scr[i].hi;
        }
        if (t == 0 && cng_claim_slot(&cng_scr[i].tid, tid)) {
            void *base =
                sys_mmap(0, CNG_SCR_SZ, CNG_PROT_READ | CNG_PROT_WRITE,
                         CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
            if (base == CNG_MAP_FAILED || cng_is_err((long)base)) {
                cng_scr[i].tid = 0;
                return 0;
            }
            cng_scr[i].lo = (unsigned long)base;
            cng_scr[i].hi = ((unsigned long)base + CNG_SCR_SZ) & ~15UL;
            return (void *)cng_scr[i].hi;
        }
        /* slot taken by another thread (or we lost the CAS): keep probing */
    }
    return 0;
}

static void sigsys_handler(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    void *top = cng_scratch_top();
    if (top)
        cng_run_on_stack(top, (void *)cng_sigsys_body, ucv, si);
    else
        cng_sigsys_body((struct cng_ucontext *)ucv, si);
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
