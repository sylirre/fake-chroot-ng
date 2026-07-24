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
    sa.flags = CNG_SA_SIGINFO | CNG_SA_RESTORER | CNG_SA_RESTART;
    sa.restorer = (void *)cng_sigrestore;
    long r = cng_syscall6(signo, (long)&sa, 0, sizeof(cng_sigset_t), 0, 0,
                          __NR_rt_sigaction);
    return (int)r;
}

static void sigsys_handler(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    (void)si;
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    unsigned long long *r = uc->uc_mcontext.regs;
    long nr = (long)r[8];

    /* execve/execveat are emulated in-process (they'd otherwise wipe us). */
    if (nr == __NR_execve) {
        cng_emulate_execve(uc, CNG_AT_FDCWD, (const char *)r[0],
                           (char **)r[1], (char **)r[2]);
        return;
    }
#ifdef __NR_execveat
    if (nr == __NR_execveat) {
        cng_emulate_execve(uc, (int)r[0], (const char *)r[1], (char **)r[2],
                           (char **)r[3]);
        return;
    }
#endif

    long ret = cng_dispatch(nr, (long)r[0], (long)r[1], (long)r[2], (long)r[3],
                            (long)r[4], (long)r[5]);
    r[0] = (unsigned long long)ret;
}

int cng_install_monitor(struct cng_fs *fs) {
    cng_g_fs = fs;
    if (cng_sig_install(CNG_SIGSYS, sigsys_handler) < 0)
        return -1;
    return cng_install_seccomp();
}
