/* A blocking wait and the signals that arrive during it (M8, -R).
 *
 * The -R tier used to make every wait4/waitid out of 50 ms polls of the ptrace
 * registry, whether or not anything was traced. Besides costing a shell 51 ms
 * per fork and waitpid, that loop swallowed the interruption: a handler that
 * ran during one of its sleeps did not end the wait, which the kernel's does
 * unless the handler asked for SA_RESTART. Now an untraced -R wait is the
 * kernel's own, and this checks it answers as the kernel does:
 *
 *   - no SA_RESTART: waitpid and waitid fail with EINTR, the handler having run;
 *   - SA_RESTART: the wait carries on through the signals and returns the child;
 *   - nothing arriving: the child's own status.
 *
 * The signal comes from a thread that repeats it every 20 ms until the wait has
 * returned, so one that lands before the wait begins is followed by one that
 * lands during it. The children of the EINTR cases are released once the wait
 * is over, and give up on their own after a few seconds, so a wait that sleeps
 * through every signal shows up as a returned child rather than as a hang.
 *
 * Differential: the same binary run with no emulation under it prints the same
 * lines. Byte-comparable output only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile int handled;
static void on_usr1(int s) {
    (void)s;
    handled = 1;
}

static pthread_t main_thr;
static volatile int done;
static void *kicker(void *a) {
    (void)a;
    struct timespec ts = {0, 20 * 1000 * 1000};
    while (!done) {
        nanosleep(&ts, 0);
        if (!done)
            pthread_kill(main_thr, SIGUSR1);
    }
    return 0;
}

static void handler(int restart) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &sa, 0);
}

/* A child that exits with `code` once `rfd` is readable or closed, or with 99
 * when nothing comes for `secs` seconds. */
static pid_t child(int rfd, int wfd, int secs, int code) {
    pid_t p = fork();
    if (p == 0) {
        close(wfd);
        struct pollfd pfd = {rfd, POLLIN, 0};
        _exit(poll(&pfd, 1, secs * 1000) > 0 ? code : 99);
    }
    return p;
}

static void verdict(const char *what, int r, int err, pid_t kid, int st) {
    if (r < 0)
        printf("%s: -1 %s, handler %s\n", what, err == EINTR ? "EINTR" : "?",
               handled ? "ran" : "did not run");
    else
        printf("%s: %s, exit %d, handler %s\n", what,
               r == kid ? "the child" : "another", WIFEXITED(st) ? WEXITSTATUS(st) : -1,
               handled ? "ran" : "did not run");
}

/* One wait under a stream of SIGUSR1; `id` picks waitid over waitpid. */
static void one(const char *what, int restart, int id, int secs, int code) {
    int p[2];
    if (pipe(p) < 0) {
        printf("%s: no pipe\n", what);
        return;
    }
    pid_t kid = child(p[0], p[1], secs, code);
    close(p[0]);
    handler(restart);
    handled = 0;
    done = 0;
    pthread_t t;
    pthread_create(&t, 0, kicker, 0);
    int st = 0, r, err;
    if (id) {
        siginfo_t si;
        memset(&si, 0, sizeof si);
        r = waitid(P_PID, (id_t)kid, &si, WEXITED);
        err = errno;
        if (r == 0) {
            r = si.si_pid;
            st = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : 0x7f;
        }
    } else {
        r = waitpid(kid, &st, 0);
        err = errno;
    }
    done = 1;
    pthread_join(t, 0);
    verdict(what, r, err, kid, st);
    close(p[1]); /* releases the child of an interrupted wait */
    if (r != kid)
        waitpid(kid, 0, 0);
}

int main(void) {
    main_thr = pthread_self();
    one("waitpid, no SA_RESTART", 0, 0, 5, 3);
    one("waitid, no SA_RESTART", 0, 1, 5, 3);
    /* Restarted, the wait has to last until the child goes: it gives up after
     * a second, to a stream of fifty-odd signals. */
    one("waitpid, SA_RESTART", 1, 0, 1, 99);
    one("waitid, SA_RESTART", 1, 1, 1, 99);
    /* And with nothing arriving, the child's own exit. */
    signal(SIGUSR1, SIG_IGN);
    int p[2];
    if (pipe(p) == 0) {
        pid_t kid = child(p[0], p[1], 5, 7);
        close(p[0]);
        close(p[1]);
        int st = 0;
        handled = 0;
        int r = waitpid(kid, &st, 0);
        verdict("waitpid, no signal", r, errno, kid, st);
    }
    return 0;
}
