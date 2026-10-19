/* A link and an unlink of a hardlinked file from a signal handler that
 * interrupted another (M10 regression, -R -l).
 *
 * Every change of a group's count is made under the store lock, an flock on a
 * file of the emulation's own, held across the several syscalls the change
 * takes. On the -R tier the dispatcher runs on the guest's own signal mask, so
 * a handler delivered while the thread held the lock — on the way out of any
 * of those syscalls — that linked or unlinked a name itself opened the lock
 * file again and waited for the lock its own thread held: forever, since an
 * flock is held by the open file, and the second open is another one.
 *
 * A loop links and unlinks a name of a group, and before each pair arms a
 * one-shot timer whose handler does the same with a name of its own. The delay
 * is swept across the time one pair takes here, measured first, as mntsig.c
 * sweeps its own. With real hardlinks every link and unlink succeeds and the
 * group ends as it began, two names; a hang is the bug itself. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 400

static volatile long g_handled, g_bad;

static void on_alarm(int sig) {
    (void)sig;
    if (link("f", "h") != 0 || unlink("h") != 0)
        g_bad++;
    g_handled++;
}

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static void arm(long us) {
    struct itimerval it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_usec = us;
    setitimer(ITIMER_REAL, &it, 0);
}

static int pair(void) { return link("f", "m") != 0 || unlink("m") != 0; }

int main(int argc, char **argv) {
    if (argc > 1 && chdir(argv[1]) != 0)
        return 1;
    FILE *f = fopen("f", "w");
    if (!f || fputs("l2ssig\n", f) < 0 || fclose(f) != 0 || link("f", "g")) {
        printf("l2ssig: no group to work on\n");
        return 1;
    }
    long bad = 0, span = 0;
    for (int i = 0; i < 8; i++) {
        long t0 = now_us();
        bad += pair();
        long d = now_us() - t0;
        if (!span || d < span)
            span = d;
    }
    if (span > 999999)
        span = 999999;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, 0);
    for (int i = 0; i < ROUNDS; i++) {
        arm(1 + span * (i % 64) / 64);
        bad += pair();
    }
    arm(0);
    struct stat st;
    int nl = stat("f", &st) == 0 ? (int)st.st_nlink : -1;
    printf("l2ssig: handled>0=%d bad=%ld nlink=%d\n", g_handled > 0,
           bad + g_bad, nl);
    return 0;
}
