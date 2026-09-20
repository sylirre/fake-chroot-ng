/* execve from a process with more threads than a table holds, and from one
 * whose threads keep making threads (M6).
 *
 * A real execve reaches every other thread of the group, however many there
 * are and whenever they were made. The emulation's de_thread used to list
 * the siblings once into a table of 4096 and tell those: the 4097th and
 * every one after it went on running the old program beside the new one,
 * without a word — and so did a thread a sibling cloned between being listed
 * and taking its request, which nothing ever told. Both shapes here, each
 * answered by the program that comes out of the exec, differentially
 * against the kernel:
 *
 *   spawnexec many N   N threads parked in a read, then the main thread execs
 *   spawnexec chain N  N chains, each thread cloning its successor at birth
 *                      and living a millisecond, run for a while, then the
 *                      main thread execs: one missed newcomer keeps a chain
 *                      going for good, so the count after the exec says
 *                      whether any was missed
 *   spawnexec report   print the thread count
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int pipefd[2];
static char *self;

static void *parked(void *a) {
    (void)a;
    char c;
    for (;;)
        if (read(pipefd[0], &c, 1) < 0 && errno != EINTR)
            break;
    return 0;
}

static pthread_attr_t detached;

static void *chain(void *a) {
    pthread_t t;
    pthread_create(&t, &detached, chain, a);
    usleep(1000);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: spawnexec many N | chain N | report\n");
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
        printf("report: threads=%d\n", threads);
        return 0;
    }
    int n = argc > 2 ? atoi(argv[2]) : 0;
    pthread_attr_init(&detached);
    pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&detached, 64 * 1024);
    if (!strcmp(argv[1], "many")) {
        if (pipe(pipefd) != 0)
            return 1;
        int made = 0;
        for (int i = 0; i < n; i++) {
            pthread_t t;
            if (pthread_create(&t, &detached, parked, 0) != 0)
                break;
            made++;
        }
        printf("made: %d\n", made);
        fflush(stdout);
    } else if (!strcmp(argv[1], "chain")) {
        for (int i = 0; i < n; i++) {
            pthread_t t;
            pthread_create(&t, &detached, chain, 0);
        }
        usleep(100 * 1000); /* the chains run a while */
    } else {
        return 2;
    }
    char *av[] = {self, "report", NULL};
    execv(self, av);
    printf("exec failed %d\n", errno);
    return 1;
}
