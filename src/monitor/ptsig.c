/* Signal mediation for traced tasks, and the reserved kick signal.
 *
 * Everything else in the monitor lets the guest's signals reach the guest's own
 * handlers untouched — that is the cheapest and most faithful thing to do. A
 * ptrace tracee cannot work that way: the kernel stops a traced task *before*
 * delivering any signal to it, lets the tracer see it, and lets the tracer
 * suppress it, substitute another, or read the registers at the point of the
 * fault. gdb is built out of exactly that: a breakpoint is a `brk` the tracer
 * poked into the text, and it reaches the tracer as a SIGTRAP stop.
 *
 * So while a task is traced we take its signals over: our handler is installed
 * for every catchable signal, mirroring the flags and mask the guest asked for
 * (so restart semantics, SA_ONSTACK and blocking behave as the guest expects),
 * the stop is reported, and only then is the signal handed to the guest's own
 * disposition — its handler, or the default action emulated in place. Leaving
 * traced state puts the guest's real dispositions back.
 *
 * The kick signal is separate and always installed: it is how a tracer reaches
 * a *running* task (PTRACE_ATTACH/SEIZE/INTERRUPT, a cooperative group-stop) and
 * how a process learns it has become a tracer. A guest-directed signal of the
 * same number is told apart by the magic in si_value and forwarded.
 */
#include "cng/monitor.h"
#include "cng/ptrace.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

#define PT_NSIG 64

#define SIG_KILL_  9
#define SIG_STOP_  19
#define SIG_CHLD_  17
#define SIG_TRAP_  5
#define SIG_CONT_  18

/* Kernel struct sigaction for AArch64 (generic layout). */
struct pt_ksigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    cng_sigset_t mask;
};

extern void cng_sigrestore(void); /* src/monitor/sig.S */

/* What the guest asked for, per signal. Ordinary memory: dispositions are
 * inherited across fork exactly like this table is, and the emulated execve
 * resets both together (cng_pt_sig_exec_reset). */
static struct pt_ksigaction g_disp[PT_NSIG + 1];
static unsigned char g_disp_set[PT_NSIG + 1];
/* Our handler is currently installed for this signal (this process). */
static unsigned char g_hooked[PT_NSIG + 1];

static int sig_default_ignores(int s) {
    return s == SIG_CHLD_ || s == SIG_CONT_ || s == 23 /*URG*/ ||
           s == 28 /*WINCH*/;
}
static int sig_default_stops(int s) {
    return s == SIG_STOP_ || s == 20 || s == 21 || s == 22;
}
/* A signal we must never take over: SIGKILL/SIGSTOP cannot be caught, and
 * SIGSYS is the monitor's own. */
static int sig_reserved(int s) {
    return s == SIG_KILL_ || s == SIG_STOP_ || s == CNG_SIGSYS;
}

static long sys_rt_sigaction(int s, const struct pt_ksigaction *a,
                             struct pt_ksigaction *o) {
    return CNG_SYS(__NR_rt_sigaction, s, a, o, sizeof(cng_sigset_t), 0, 0);
}

/* ---- delivering a signal to the guest's own disposition ---- */

/* Die the way the default action would, after telling the tracer. Restores the
 * real disposition and re-raises, so the parent's wait sees WIFSIGNALED with
 * the right signal rather than a synthetic exit code. */
static void pt_die_by_signal(int sig) {
    cng_pt_exit_report(sig);
    struct pt_ksigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    sys_rt_sigaction(sig, &dfl, 0);
    unsigned long unblock = 1UL << (sig - 1);
    CNG_SYS(__NR_rt_sigprocmask, 1 /*SIG_UNBLOCK*/, &unblock, 0,
            sizeof(cng_sigset_t), 0, 0);
    CNG_SYS(__NR_tgkill, sys_getpid(), sys_gettid(), sig, 0, 0, 0);
    /* A blocked-or-ignored corner: leave no doubt about the outcome. */
    CNG_SYS(__NR_exit_group, sig & 0x7f, 0, 0, 0, 0, 0);
}

/* Run the guest's disposition for `sig` now that the tracer has approved it. */
static void pt_deliver_to_guest(int sig, cng_siginfo_t *si, void *uc) {
    void *h = g_disp_set[sig] ? g_disp[sig].handler : 0;
    unsigned long flags = g_disp_set[sig] ? g_disp[sig].flags : 0;
    if (h == (void *)1) /* SIG_IGN */
        return;
    if (!h) {           /* SIG_DFL */
        if (sig_default_ignores(sig))
            return;
        if (sig_default_stops(sig))
            return; /* the stop was the report; the tracer resumed us */
        pt_die_by_signal(sig);
        return;
    }
    if (flags & CNG_SA_SIGINFO)
        ((void (*)(int, cng_siginfo_t *, void *))h)(sig, si, uc);
    else
        ((void (*)(int))h)(sig);
}

/* si_addr of a fault siginfo (offset 16 on arm64: after signo/errno/code and
 * the pointer-alignment pad — the same place _pad starts). */
static u64 pt_si_addr(const cng_siginfo_t *si) {
    return (u64)si->_u._pad[0];
}

static int sig_is_fault(int s) {
    return s == 4 /*ILL*/ || s == SIG_TRAP_ || s == 7 /*BUS*/ ||
           s == 8 /*FPE*/ || s == 11 /*SEGV*/;
}

/* ---- our handler for a traced task's signals ---- */

static void pt_trace_handler(int sig, cng_siginfo_t *si, void *ucv) {
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    struct cng_uregs *r = cng_pt_uregs(uc);
    cng_pt_set_frame(r, uc);

    /* Our own single-step breakpoint, not a guest SIGTRAP: report the step
     * (which also unwinds the planted instruction, so a tracer reading the text
     * back never sees it). */
    if (sig == SIG_TRAP_ && cng_pt_step_hit(r->pc)) {
        cng_pt_step_report(r);
        return;
    }
    int code = si->si_code;
    u64 addr = sig_is_fault(sig) ? pt_si_addr(si) : 0;
    int deliver = cng_pt_report_signal(r, sig, code, addr);
    if (deliver == 0)
        return; /* suppressed by the tracer */
    if (deliver != sig) {
        /* Substituted: raise the replacement instead. It goes through the same
         * mediation (our handler is installed for it too). */
        CNG_SYS(__NR_tgkill, sys_getpid(), sys_gettid(), deliver, 0, 0, 0);
        return;
    }
    pt_deliver_to_guest(sig, si, uc);
}

/* ---- the kick signal ---- */

/* Which signal number the kick actually uses. SIGRTMAX is the intent (glibc
 * claims SIGRTMIN..+2 and Go preempts with SIGURG, so the top of the range is
 * the quietest slot), but it has to be *deliverable*: qemu-user reserves the
 * host's top real-time signals for itself and refuses to queue the guest's, so
 * the number is probed downwards at startup rather than assumed. Chosen once,
 * before the guest can fork, so every process in the session agrees. */
int cng_g_kicksig = CNG_PT_KICKSIG;
static volatile int g_kick_seen;

static void pt_kick_handler(int sig, cng_siginfo_t *si, void *ucv) {
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    /* si_code SI_QUEUE with one of our magics in si_value (offset 24, i.e.
     * _pad[1]) is ours; anything else is a guest-directed signal that happens
     * to use the same number, and must reach the guest untouched. */
    if (si->si_code == -1) {
        int magic = (int)si->_u._pad[1];
        switch (magic) {
        case CNG_PT_KICK_WAKE:
            g_kick_seen++;
            return; /* the EINTR it inflicts is the whole point */
        case CNG_PT_KICK_ARM:
            cng_pt_arm_tracer();
            return;
        case CNG_PT_KICK_ATTACH:
            cng_pt_set_frame(cng_pt_uregs(uc), uc);
            cng_pt_service_kick(cng_pt_uregs(uc));
            return;
        }
    }
    pt_deliver_to_guest(sig, si, ucv);
}

/* Install `h` for `sig` with flags mirroring what the guest asked for, so
 * restart semantics, SA_ONSTACK delivery and the blocked-signal set during the
 * handler all behave as the guest expects. SIGSYS is never blocked (a masked
 * seccomp SIGSYS force-kills) and our restorer is always ours. */
static void pt_install(int sig, cng_sighandler_t h) {
    struct pt_ksigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.handler = (void *)h;
    unsigned long gf = g_disp_set[sig] ? g_disp[sig].flags : 0;
    void *gh = g_disp_set[sig] ? g_disp[sig].handler : 0;
    sa.flags = CNG_SA_SIGINFO | CNG_SA_RESTORER | CNG_SA_ONSTACK |
               (gf & (CNG_SA_RESTART | CNG_SA_NODEFER));
    /* A disposition of ignore (explicit or by default) never interrupts a
     * syscall; our handler would, so ask the kernel to restart instead. */
    if (!gh || gh == (void *)1)
        sa.flags |= CNG_SA_RESTART;
    sa.mask = g_disp_set[sig] ? g_disp[sig].mask : (cng_sigset_t){{0}};
    sa.mask.sig[0] &= ~(1UL << (CNG_SIGSYS - 1));
    sa.restorer = (void *)cng_sigrestore;
    sys_rt_sigaction(sig, &sa, 0);
}

/* Put back what the guest actually asked for. */
static void pt_restore_guest(int sig) {
    struct pt_ksigaction sa;
    memset(&sa, 0, sizeof sa);
    if (g_disp_set[sig]) {
        sa = g_disp[sig];
        sa.flags |= CNG_SA_RESTORER;
        sa.mask.sig[0] &= ~(1UL << (CNG_SIGSYS - 1));
        if (!sa.restorer)
            sa.restorer = (void *)cng_sigrestore;
    }
    sys_rt_sigaction(sig, &sa, 0);
}

void cng_pt_sig_install_kick(void) {
    if (cng_g_no_ptrace)
        return;
    struct pt_ksigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.handler = (void *)pt_kick_handler;
    /* Deliberately no SA_RESTART: the kick's other job is to interrupt a tracer
     * still blocked in a *native* wait4 — the window between its child's
     * PTRACE_TRACEME and its own first trapped wait — so that the retry lands
     * in the one that can see emulated stops. */
    sa.flags = CNG_SA_SIGINFO | CNG_SA_RESTORER | CNG_SA_ONSTACK;
    sa.mask.sig[0] = ~0UL & ~(1UL << (CNG_SIGSYS - 1));
    sa.restorer = (void *)cng_sigrestore;
    sys_rt_sigaction(cng_g_kicksig, &sa, 0);
}

/* Settle on a kick signal: install the handler for a candidate, queue one to
 * ourselves, and keep the first number that is both accepted by the kernel and
 * actually delivered. Run once at startup while we are still single-threaded
 * and the guest has no dispositions of its own to disturb. */
void cng_pt_pick_kicksig(void) {
    if (cng_g_no_ptrace)
        return;
    for (int s = CNG_PT_KICKSIG; s >= 33; s--) {
        cng_g_kicksig = s;
        cng_pt_sig_install_kick();
        int before = g_kick_seen;
        cng_pt_kick((s32)sys_getpid(), (s32)sys_gettid(), CNG_PT_KICK_WAKE);
        if (g_kick_seen != before)
            return;
        struct pt_ksigaction dfl; /* unusable: put it back and try the next */
        memset(&dfl, 0, sizeof dfl);
        sys_rt_sigaction(s, &dfl, 0);
    }
    cng_g_kicksig = CNG_PT_KICKSIG; /* none worked; ptrace attach will not */
    cng_pt_sig_install_kick();
}

void cng_pt_sig_trace_enter(void) {
    for (int s = 1; s <= PT_NSIG; s++) {
        if (sig_reserved(s) || s == cng_g_kicksig)
            continue;
        /* SIG_IGN on SIGCHLD is not a disposition we can emulate: it is what
         * tells the kernel to reap children automatically, and a handler of
         * ours would silently turn that off and leave zombies. Left alone; the
         * cost is that its delivery stops are not reported. */
        if (s == SIG_CHLD_ && g_disp_set[s] && g_disp[s].handler == (void *)1)
            continue;
        pt_install(s, pt_trace_handler);
        g_hooked[s] = 1;
    }
}

void cng_pt_sig_trace_leave(void) {
    for (int s = 1; s <= PT_NSIG; s++) {
        if (!g_hooked[s])
            continue;
        g_hooked[s] = 0;
        pt_restore_guest(s);
    }
}

/* A real execve resets dispositions; the emulated one calls this so our mirror
 * and the guest's table agree, and re-arms what must survive. */
void cng_pt_sig_exec_reset(void) {
    for (int s = 1; s <= PT_NSIG; s++) {
        /* Caught signals become SIG_DFL, ignored ones stay ignored — the
         * kernel's rule, applied to our record of them. */
        if (g_disp_set[s] && g_disp[s].handler != (void *)1) {
            g_disp_set[s] = 0;
            memset(&g_disp[s], 0, sizeof g_disp[s]);
        }
        g_hooked[s] = 0;
    }
    cng_pt_sig_install_kick();
    if (cng_pt_active())
        cng_pt_sig_trace_enter();
}

int cng_pt_sigaction(int sig, u64 act, u64 oact, u64 sz, long *out) {
    if (sig < 1 || sig > PT_NSIG || sz != sizeof(cng_sigset_t))
        return 0; /* not ours to model: let the kernel answer */
    int mine = g_hooked[sig] || sig == cng_g_kicksig;
    if (!mine) {
        /* Not intercepting this one, but keep the mirror current: it is what a
         * later trace_enter installs from, and what the kick handler forwards
         * a guest-directed signal to.
         *
         * The test used to be `!mine && !cng_pt_active()`, which treated "the
         * task is traced" as "we own every signal". We do not: g_hooked already
         * records exactly the ones whose real disposition we took over, and
         * trace_enter deliberately skips SIGKILL, SIGSTOP and a SIGCHLD the
         * guest had already set to SIG_IGN. For those three the call fell into
         * the branch below and was answered from the mirror alone — so while
         * traced, sigaction(SIGKILL, act) reported success where the kernel
         * answers EINVAL (measured), and a guest that had been auto-reaping its
         * children and then installed a real SIGCHLD handler never got one:
         * the kernel went on discarding the children and its wait() answered
         * ECHILD. */
        if (act) {
            if (!cng_user_readable((void *)act, sizeof(struct pt_ksigaction)))
                return 0; /* let the re-issue produce the EFAULT */
            memcpy(&g_disp[sig], (void *)act, sizeof(struct pt_ksigaction));
            g_disp_set[sig] = 1;
        }
        return 0;
    }
    /* We own the real disposition for this signal: answer from the mirror and
     * never let the guest's handler reach the kernel, or the next delivery
     * would bypass the stop (or, for the kick signal, take over our slot). */
    struct pt_ksigaction old = g_disp[sig];
    int had = g_disp_set[sig];
    if (act) {
        if (!cng_user_readable((void *)act, sizeof(struct pt_ksigaction))) {
            *out = -EFAULT;
            return 1;
        }
        memcpy(&g_disp[sig], (void *)act, sizeof(struct pt_ksigaction));
        g_disp_set[sig] = 1;
        if (g_hooked[sig])
            pt_install(sig, pt_trace_handler); /* re-mirror flags/mask */
    }
    if (oact) {
        if (!cng_user_writable((void *)oact, sizeof(struct pt_ksigaction))) {
            *out = -EFAULT;
            return 1;
        }
        struct pt_ksigaction o;
        memset(&o, 0, sizeof o);
        if (had)
            o = old;
        memcpy((void *)oact, &o, sizeof o);
    }
    *out = 0;
    return 1;
}
