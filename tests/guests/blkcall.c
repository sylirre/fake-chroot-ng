/* A signal against a blocking call the emulation makes for the guest.
 *
 * On the SIGSYS tier every trapped call is made from the handler, which runs
 * with every signal masked, so one that blocked could be interrupted by
 * nothing but SIGKILL: a server in accept() ignored SIGTERM and ^C until a
 * connection came, a FIFO open until the other end did, and a handler the
 * guest installed ran only once the call was over. The calls that can block
 * are now made from guest context, where the kernel's own rules apply: the
 * handler runs at once, a call whose handler has SA_RESTART is made again and
 * goes on waiting, one without fails with EINTR, and a signal whose default
 * action is to terminate does.
 *
 * Each leg blocks the main thread in one call; a helper thread signals it,
 * and later does what ends the call (a connect, a datagram, the FIFO's other
 * end), noting whether the handler had run by then. Differential: the same
 * binary with no emulation under it prints the same lines.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int handled;
/* Where the handler ran: on the stack the thread was on when it made the
 * call, as the kernel delivers a handler with no alternate stack — not on a
 * stack of the emulation's, which a collector scanning the thread's stack
 * from its suspend handler's sp would walk instead (asked for with "sp"). */
static unsigned long stack_top;
static volatile int on_own_stack;
static void on_usr1(int s) {
    unsigned long here = (unsigned long)&here;
    (void)s;
    handled++;
    on_own_stack = here < stack_top && stack_top - here < (8ul << 20);
}
static int show_sp;

enum { END_CONNECT, END_SENDTO, END_FIFO, END_UNIX };

static pthread_t main_thr;
static struct {
    int how;
    struct sockaddr_in in;
    char path[108];
    char from[108];
    int ran; /* the handler had run when the call was ended */
} later;

static void *helper(void *a) {
    (void)a;
    usleep(150 * 1000);
    pthread_kill(main_thr, SIGUSR1);
    usleep(400 * 1000);
    later.ran = handled;
    int s;
    switch (later.how) {
    case END_CONNECT:
        s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *)&later.in, sizeof later.in);
        break;
    case END_SENDTO:
        s = socket(AF_INET, SOCK_DGRAM, 0);
        sendto(s, "d", 1, 0, (struct sockaddr *)&later.in, sizeof later.in);
        close(s);
        break;
    case END_FIFO:
        s = open(later.path, O_WRONLY | O_NONBLOCK); /* no reader: ENXIO */
        usleep(100 * 1000);
        close(s);
        break;
    case END_UNIX: {
        struct sockaddr_un u = {AF_UNIX, {0}}, me = {AF_UNIX, {0}};
        strcpy(u.sun_path, later.path);
        strcpy(me.sun_path, later.from);
        s = socket(AF_UNIX, SOCK_DGRAM, 0);
        bind(s, (struct sockaddr *)&me, sizeof me);
        sendto(s, "u", 1, 0, (struct sockaddr *)&u, sizeof u);
        close(s);
        break;
    }
    }
    return 0;
}

static void arm(int restart) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &sa, 0);
    handled = 0;
    later.ran = 0;
}

static pthread_t start(int how) {
    later.how = how;
    pthread_t t;
    pthread_create(&t, 0, helper, 0);
    return t;
}

static void report(const char *what, int restart, long r, int err) {
    printf("%s, %s: %s, handler %s, %s\n", what,
           restart ? "SA_RESTART" : "no SA_RESTART",
           r >= 0 ? "returned" : err == EINTR ? "EINTR" : "failed",
           handled ? "ran" : "did not run",
           r < 0 ? "-" : later.ran ? "while it blocked" : "only after");
    if (show_sp)
        printf("...on the thread's own stack: %s\n", on_own_stack ? "yes" : "no");
}

static int inet_socket(int type) {
    int s = socket(AF_INET, type, 0);
    memset(&later.in, 0, sizeof later.in);
    later.in.sin_family = AF_INET;
    later.in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t l = sizeof later.in;
    if (bind(s, (struct sockaddr *)&later.in, sizeof later.in) != 0 ||
        getsockname(s, (struct sockaddr *)&later.in, &l) != 0)
        exit(1);
    return s;
}

static void leg_accept(int restart) {
    int s = inet_socket(SOCK_STREAM);
    listen(s, 1);
    arm(restart);
    pthread_t t = start(END_CONNECT);
    errno = 0;
    long r = accept(s, 0, 0);
    report("accept", restart, r, errno);
    pthread_join(t, 0);
    if (r >= 0)
        close((int)r);
    close(s);
}

static void leg_recvfrom(int restart) {
    int s = inet_socket(SOCK_DGRAM);
    arm(restart);
    pthread_t t = start(END_SENDTO);
    char c;
    errno = 0;
    long r = recvfrom(s, &c, 1, 0, 0, 0);
    report("recvfrom", restart, r, errno);
    pthread_join(t, 0);
    close(s);
}

static void leg_fifo(const char *dir, int restart) {
    snprintf(later.path, sizeof later.path, "%s/blkcall.fifo", dir);
    unlink(later.path);
    mkfifo(later.path, 0600);
    arm(restart);
    pthread_t t = start(END_FIFO);
    errno = 0;
    long r = open(later.path, O_RDONLY);
    report("FIFO open", restart, r, errno);
    pthread_join(t, 0);
    if (r >= 0)
        close((int)r);
    unlink(later.path);
}

/* An AF_UNIX receive that wants the sender's address: the dispatcher maps a
 * path back into the guest's spelling, so this one is not the guest's call as
 * it stands, and is made by the whole dispatch from guest context. */
static void leg_unix(const char *dir, int restart) {
    snprintf(later.path, sizeof later.path, "%s/blkcall.sock", dir);
    snprintf(later.from, sizeof later.from, "%s/blkcall.peer", dir);
    unlink(later.path);
    unlink(later.from);
    struct sockaddr_un u = {AF_UNIX, {0}}, from;
    strcpy(u.sun_path, later.path);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (bind(s, (struct sockaddr *)&u, sizeof u) != 0)
        exit(1);
    arm(restart);
    pthread_t t = start(END_UNIX);
    char c;
    socklen_t fl = sizeof from;
    errno = 0;
    long r = recvfrom(s, &c, 1, 0, (struct sockaddr *)&from, &fl);
    report("AF_UNIX recvfrom", restart, r, errno);
    if (r >= 0)
        printf("...from %s\n",
               !strcmp(from.sun_path, later.from) ? "the sender's path" : "elsewhere");
    pthread_join(t, 0);
    close(s);
    unlink(later.path);
    unlink(later.from);
}

/* SIGTERM at its default action, against a child blocked in accept. */
static void leg_term(void) {
    int s = inet_socket(SOCK_STREAM);
    listen(s, 1);
    pid_t pid = fork();
    if (pid == 0) {
        accept(s, 0, 0);
        _exit(0);
    }
    usleep(200 * 1000);
    kill(pid, SIGTERM);
    int st = 0, i;
    for (i = 0; i < 40 && waitpid(pid, &st, WNOHANG) == 0; i++)
        usleep(50 * 1000);
    if (i == 40) {
        printf("SIGTERM in accept: not killed\n");
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);
    } else {
        printf("SIGTERM in accept: %s\n",
               WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM ? "killed by it"
                                                          : "something else");
    }
    close(s);
}

int main(int argc, char **argv) {
    unsigned long top = (unsigned long)&top;
    stack_top = top;
    setvbuf(stdout, 0, _IOLBF, 0);
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    show_sp = argc > 2 && !strcmp(argv[2], "sp");
    main_thr = pthread_self();
    for (int restart = 1; restart >= 0; restart--) {
        leg_accept(restart);
        leg_recvfrom(restart);
        leg_fifo(dir, restart);
        leg_unix(dir, restart);
    }
    leg_term();
    return 0;
}
