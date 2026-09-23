/* A synthesized /proc file's refresh tracking against racing readers (M11
 * regression).
 *
 * A refreshable /proc file (uptime, loadavg, stat) is served from a memfd in
 * a small reserved descriptor range, and an entry records the descriptor,
 * the kind of file, and the memfd's identity, so a read from offset 0 can
 * regenerate it. The descriptor used to be published before the other two:
 * a sibling thread reading that number in the interval judged it against the
 * identity the entry had before — a mismatch that retired the entry — and the
 * file never refreshed again.
 *
 * Reader threads pread every number of the reserved range at offset 0, over
 * and over; the main thread opens a batch of /proc/uptime files into it,
 * reads each, waits long enough for the clock to move, rewinds and reads
 * each again. A rewind that reads the same bytes is a refresh lost ("lost").
 * The readers' own preads regenerate the files too, so an unchanged file
 * means nobody could. */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS  200
#define BATCH   8
#define READERS 3
#define RANGE   16 /* CNG_SYNTH_FD_SLOTS */

static volatile int g_stop;
static int g_base;

static void *reader(void *arg) {
    (void)arg;
    char buf[64];
    while (!g_stop)
        for (int n = g_base; n < g_base + RANGE && !g_stop; n++)
            if (pread(n, buf, sizeof buf, 0) < 0)
                continue;
    return 0;
}

static long rd(int fd, char *b, size_t n) {
    long r = read(fd, b, n - 1);
    b[r > 0 ? r : 0] = '\0';
    return r;
}

int main(void) {
    int probe = open("/proc/uptime", O_RDONLY);
    if (probe < 0) {
        printf("procrace: no /proc/uptime\n");
        return 1;
    }
    g_base = probe; /* the lowest number of the range, while nothing holds it */
    close(probe);
    pthread_t t[READERS];
    for (int i = 0; i < READERS; i++)
        pthread_create(&t[i], 0, reader, 0);
    int lost = 0, samples = 0;
    struct timespec nap = {0, 12000000};
    for (int r = 0; r < ROUNDS; r++) {
        int fd[BATCH];
        char a[BATCH][64], b[64];
        for (int i = 0; i < BATCH; i++) {
            fd[i] = open("/proc/uptime", O_RDONLY);
            if (fd[i] >= 0 && rd(fd[i], a[i], sizeof a[i]) <= 0)
                a[i][0] = '\0';
        }
        nanosleep(&nap, 0);
        for (int i = 0; i < BATCH; i++) {
            if (fd[i] < 0)
                continue;
            lseek(fd[i], 0, SEEK_SET);
            if (rd(fd[i], b, sizeof b) > 0 && a[i][0]) {
                lost += !strcmp(a[i], b);
                samples++;
            }
            close(fd[i]);
        }
    }
    g_stop = 1;
    for (int i = 0; i < READERS; i++)
        pthread_join(t[i], 0);
    printf("procrace: samples>0=%d lost=%d\n", samples > 0, lost);
    return 0;
}
