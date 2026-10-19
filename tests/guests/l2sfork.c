/* A fork by another thread while one links (M10 regression, -R -l).
 *
 * Every change of a group's count is made under the store lock, an flock on a
 * file of the emulation's own, which belongs to the open file and not to the
 * descriptor. A fork while one thread held it handed the child a duplicate of
 * that open file, and giving the lock back by closing the descriptor left it
 * held by the child's copy: the next change, by any process, waited until the
 * child exec'd or exited.
 *
 * One thread links and unlinks a name of a group for a while; another forks
 * children that wait without exec'ing, four seconds at most (alarm) or until
 * the pipe is closed at the end. With real hardlinks no pair takes more than
 * a scheduler's worth of time; a pair held up by a child's copy of the lock
 * waits out the child, which the two-second line tells from a slow host. */
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile int g_stop;
static int g_pipe[2];

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000;
}

static void *forker(void *a) {
    (void)a;
    while (!g_stop) {
        pid_t p = fork();
        if (p == 0) {
            char c;
            alarm(4);
            close(g_pipe[1]);
            (void)!read(g_pipe[0], &c, 1);
            _exit(0);
        }
        usleep(20000);
        while (waitpid(-1, 0, WNOHANG) > 0)
            ;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && chdir(argv[1]) != 0)
        return 1;
    FILE *f = fopen("f", "w");
    if (!f || fputs("l2sfork\n", f) < 0 || fclose(f) != 0 || link("f", "g") ||
        pipe(g_pipe) != 0) {
        printf("l2sfork: no group to work on\n");
        return 1;
    }
    pthread_t t;
    if (pthread_create(&t, 0, forker, 0) != 0)
        return 1;
    long worst = 0, bad = 0, end = now_ms() + 6000;
    while (now_ms() < end) {
        long t0 = now_ms();
        bad += link("f", "m") != 0;
        bad += unlink("m") != 0;
        if (now_ms() - t0 > worst)
            worst = now_ms() - t0;
    }
    g_stop = 1;
    pthread_join(t, 0);
    close(g_pipe[1]);
    while (wait(0) > 0)
        ;
    printf("l2sfork: stalled=%d bad=%ld\n", worst >= 2000, bad);
    return 0;
}
