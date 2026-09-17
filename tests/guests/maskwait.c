/* The waits that install a signal mask of their own, and the signalfd that
 * reads from one, under the emulation (M6).
 *
 * The emulation traps these when they carry a mask and takes SIGSYS out of
 * the copy it hands the kernel (a thread parked with SIGSYS blocked could not
 * be reached by an exec's de_thread). On the SIGSYS tier the wait is then run
 * from the guest's own context, through a stub, since the handler cannot run
 * it itself. Everything else about the call has to come out as the kernel has
 * it: the mask the call installs is in force for the wait (a signal it
 * unblocks arrives, its handler runs, the wait is interrupted), the caller's
 * own mask is back afterwards, the result and errno are the kernel's, and a
 * full mask — SIGSYS included — still works as a mask.
 *
 * Differential: the same binary run with no emulation under it prints the
 * same lines. Byte-comparable output only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static volatile int handled;
static void on_usr1(int s) {
    (void)s;
    handled++;
}

/* SIGUSR1 to the main thread, a little later. */
static pthread_t main_thr;
static void *kicker(void *a) {
    (void)a;
    usleep(60 * 1000);
    pthread_kill(main_thr, SIGUSR1);
    return 0;
}
static void kick_later(void) {
    pthread_t t;
    pthread_create(&t, 0, kicker, 0);
    pthread_detach(t);
}

static int usr1_blocked(void) {
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, SIGUSR1);
}

int main(void) {
    main_thr = pthread_self();
    signal(SIGUSR1, on_usr1);
    /* SIGUSR1 blocked normally; each wait's own mask lets it through. */
    sigset_t blk;
    sigemptyset(&blk);
    sigaddset(&blk, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &blk, NULL);
    sigset_t open_;
    sigfillset(&open_);
    sigdelset(&open_, SIGUSR1);
    sigset_t full;
    sigfillset(&full);
    int fds[2];
    if (pipe(fds) != 0)
        return 1;
    struct pollfd p = {fds[0], POLLIN, 0};
    struct timespec ts = {2, 0}, tick = {0, 100 * 1000 * 1000};

    /* 1. ppoll: interrupted by the signal its mask lets through. */
    handled = 0;
    kick_later();
    int r = ppoll(&p, 1, &ts, &open_);
    printf("ppoll: r=%d errno=%s handled=%d blocked_after=%d\n", r,
           r < 0 ? strerror(errno) : "-", handled, usr1_blocked());

    /* 2. ppoll with a FULL mask (SIGSYS included) and a timeout: times out. */
    r = ppoll(&p, 1, &tick, &full);
    printf("ppoll-full: r=%d\n", r);

    /* 3. pselect, likewise. */
    handled = 0;
    kick_later();
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(fds[0], &rs);
    r = pselect(fds[0] + 1, &rs, NULL, NULL, &ts, &open_);
    printf("pselect: r=%d errno=%s handled=%d blocked_after=%d\n", r,
           r < 0 ? strerror(errno) : "-", handled, usr1_blocked());
    /* ...and with a sigmask pointer of NULL inside the pair (pselect with no
     * mask still passes the pair on this libc), which must not fault. */
    FD_ZERO(&rs);
    FD_SET(fds[0], &rs);
    struct timespec zero = {0, 0};
    r = pselect(fds[0] + 1, &rs, NULL, NULL, &zero, NULL);
    printf("pselect-nomask: r=%d\n", r);

    /* 4. epoll_pwait. */
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, {0}};
    epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev);
    handled = 0;
    kick_later();
    r = epoll_pwait(ep, &ev, 1, 2000, &open_);
    printf("epoll_pwait: r=%d errno=%s handled=%d blocked_after=%d\n", r,
           r < 0 ? strerror(errno) : "-", handled, usr1_blocked());

    /* 5. sigsuspend. */
    handled = 0;
    kick_later();
    r = sigsuspend(&open_);
    printf("sigsuspend: r=%d errno=%s handled=%d blocked_after=%d\n", r,
           r < 0 ? strerror(errno) : "-", handled, usr1_blocked());

    /* 6. sigtimedwait with the signal in its set: dequeued, no handler. */
    handled = 0;
    kick_later();
    siginfo_t si;
    r = sigtimedwait(&blk, &si, &ts);
    printf("sigtimedwait: r=%d signo=%d handled=%d\n", r, r > 0 ? si.si_signo : 0,
           handled);
    /* ...and with a full set, times out. */
    struct timespec t2 = {0, 50 * 1000 * 1000};
    r = sigtimedwait(&full, &si, &t2);
    printf("sigtimedwait-full: r=%d errno=%s\n", r, r < 0 ? strerror(errno) : "-");

    /* 7. signalfd over a full mask: reads the blocked SIGUSR1. */
    int sfd = signalfd(-1, &full, SFD_CLOEXEC);
    handled = 0;
    kick_later();
    struct signalfd_siginfo fsi;
    ssize_t n = read(sfd, &fsi, sizeof fsi);
    printf("signalfd: n=%d signo=%u handled=%d\n", (int)n,
           n == (ssize_t)sizeof fsi ? fsi.ssi_signo : 0, handled);

    /* 8. a mask the kernel refuses: the wrong sigsetsize is EINVAL before
     * anything else, a bad pointer EFAULT. */
    r = (int)syscall(SYS_ppoll, &p, 1, &tick, &open_, 4);
    printf("ppoll-badsize: r=%d errno=%s\n", r, r < 0 ? strerror(errno) : "-");
    r = (int)syscall(SYS_ppoll, &p, 1, &tick, (void *)8, 8);
    printf("ppoll-badptr: r=%d errno=%s\n", r, r < 0 ? strerror(errno) : "-");
    r = (int)syscall(SYS_rt_sigsuspend, (void *)8, 8);
    printf("sigsuspend-badptr: r=%d errno=%s\n", r, r < 0 ? strerror(errno) : "-");
    return 0;
}
