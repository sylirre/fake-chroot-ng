/* SIGSYS handler + signal installation.
 *
 * On a seccomp RET_TRAP the kernel delivers SIGSYS with the interrupted
 * context: args in x0..x5, syscall nr in x8, and pc already advanced past the
 * svc. We emulate the syscall (translating paths) and write the result into x0;
 * on return the restorer runs rt_sigreturn and the guest continues.
 */
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

    r[0] = (unsigned long long)cng_dispatch(nr, (long)r[0], (long)r[1],
                                            (long)r[2], (long)r[3], (long)r[4],
                                            (long)r[5], /*trapped=*/1);
}

static void sigsys_handler(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    cng_sigsys_body((struct cng_ucontext *)ucv, si);
}

int cng_install_monitor(struct cng_fs *fs) {
    cng_g_fs = fs;
    if (cng_sig_install(CNG_SIGSYS, sigsys_handler) < 0)
        return -1;
    /* Measure which syscalls Android blocks (before our own filter is active)
     * so dispatch emulates them rather than trapping on a re-issue. */
    cng_probe_blocked();
    return cng_install_seccomp();
}
