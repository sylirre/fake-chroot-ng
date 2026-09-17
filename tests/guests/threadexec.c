/* execve from a multithreaded process (M6).
 *
 * A real execve kills every other thread of the group (de_thread) and, when
 * the caller is not the group leader, gives the caller the leader's identity:
 * the program that comes out of the exec is one thread whose tid is its pid.
 * The emulation used to do neither — the old threads went on running the old
 * program beside the new one — and this guest asks the program that comes out
 * of the exec what it sees, differentially against the kernel.
 *
 * The helper threads are parked in every shape a thread can be parked in,
 * including the ones that install a signal mask of their own with every
 * signal in it (ppoll, pselect, epoll_pwait, sigsuspend, sigwait): a thread
 * that cannot be reached would hang the exec, so the exec completing in time
 * is part of the answer.
 *
 *   threadexec leader     the main thread execs "threadexec report"
 *   threadexec nonleader  a thread other than the main one does
 *   threadexec report     print whether tid == pid and the thread count
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <unistd.h>

static int pipefd[2];
static volatile unsigned long spins;

static void *spinner(void *a) {
    (void)a;
    for (;;)
        spins++;
    return 0;
}
static void *reader(void *a) {
    (void)a;
    char c;
    for (;;)
        if (read(pipefd[0], &c, 1) < 0 && errno != EINTR)
            break;
    return 0;
}
static void *poller(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    struct pollfd p = {pipefd[0], POLLIN, 0};
    for (;;)
        ppoll(&p, 1, NULL, &all);
    return 0;
}
static void *selecter(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    fd_set r;
    for (;;) {
        FD_ZERO(&r);
        FD_SET(pipefd[0], &r);
        pselect(pipefd[0] + 1, &r, NULL, NULL, NULL, &all);
    }
    return 0;
}
static void *epoller(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, {0}};
    epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &ev);
    for (;;)
        epoll_pwait(ep, &ev, 1, -1, &all);
    return 0;
}
static void *suspender(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    for (;;)
        sigsuspend(&all);
    return 0;
}
static void *waiter(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    int sig;
    for (;;)
        sigwait(&all, &sig);
    return 0;
}

static char *self;

static void *execer(void *a) {
    (void)a;
    usleep(50 * 1000); /* let the others park */
    char *av[] = {self, "report", NULL};
    execv(self, av);
    printf("exec failed %d\n", errno);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: threadexec leader|nonleader|report\n");
        return 2;
    }
    self = argv[0];
    if (!strcmp(argv[1], "report")) {
        int threads = -1;
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        while (f && fgets(line, sizeof line, f))
            if (!strncmp(line, "Threads:", 8))
                threads = atoi(line + 8);
        if (f)
            fclose(f);
        printf("report: tid==pid=%d threads=%d\n",
               (long)syscall(SYS_gettid) == (long)getpid(), threads);
        return 0;
    }
    if (pipe(pipefd) != 0)
        return 1;
    pthread_t t;
    void *(*fns[])(void *) = {spinner, reader, poller, selecter,
                              epoller, suspender, waiter};
    for (unsigned i = 0; i < sizeof fns / sizeof fns[0]; i++)
        pthread_create(&t, 0, fns[i], 0);
    if (!strcmp(argv[1], "nonleader")) {
        pthread_create(&t, 0, execer, 0);
        pthread_join(t, 0); /* never: the exec replaces us */
        printf("exec thread returned\n");
        return 1;
    }
    execer(0);
    return 1;
}
