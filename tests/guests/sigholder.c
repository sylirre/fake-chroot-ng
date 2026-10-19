/* A host process for the signal legs of the hidden-process view (M85).
 * Started outside chroot-ng, so a guest's view does not show it, and counting
 * every SIGURG that reaches it anyway — SIGURG because its default is to be
 * ignored, so one that leaks to anything else the user runs does no harm.
 *
 * Usage: sigholder FILE [own]. With `own` it leads a process group of its
 * own; otherwise it stays in the one it was started in, which is the guest's
 * when both come from one shell without job control. Writes "ready pid=N"
 * to FILE once the handler is in place, and "urg=N" when SIGTERM ends it.
 * Bounded by alarm(), so a test that never stops it cannot leave it behind. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t urg, done;

static void on_urg(int s) {
    (void)s;
    urg++;
}

static void on_term(int s) {
    (void)s;
    done = 1;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (argc > 2 && !strcmp(argv[2], "own") && setpgid(0, 0) != 0)
        return 3;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_urg;
    sigaction(SIGURG, &sa, NULL);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigset_t term, old;
    sigemptyset(&term);
    sigaddset(&term, SIGTERM);
    sigprocmask(SIG_BLOCK, &term, &old);
    alarm(300);
    FILE *f = fopen(argv[1], "w");
    if (!f)
        return 4;
    fprintf(f, "ready pid=%d\n", (int)getpid());
    fflush(f);
    while (!done)
        sigsuspend(&old);
    fprintf(f, "urg=%d\n", (int)urg);
    fclose(f);
    return 0;
}
