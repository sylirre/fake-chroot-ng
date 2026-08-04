/* Threads under the trampoline tier (M8).
 *
 * A thread is made with clone(CLONE_VM|CLONE_THREAD|...), and -R rewrites the
 * `svc` that issues it like any other. That site cannot be handled the way the
 * others are: the child comes back from the call with SP pointing at the stack
 * the guest just allocated for it, where none of the trampoline's frames exist.
 * The dispatcher used to take it and strip CLONE_VM — which with CLONE_THREAD
 * is exactly what the kernel answers EINVAL to — so pthread_create did not work
 * under -R at all.
 *
 * Each thread then does real work through the tier it was created on: an open
 * of a guest path (which is a rewritten site, translated on a stack of the
 * thread's own) and a getpid/gettid pair, so a thread that came up with a
 * damaged register file or no scratch stack shows as a wrong count rather than
 * as a hang. Prints one summary line, byte-comparable against a plain run.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NTHREADS 8

static const char *g_path;

struct arg {
    int idx;
    int read_ok;   /* the guest path opened and held the expected bytes */
    int tid_ok;    /* a thread has its own tid and the process's pid */
    long fpsum;    /* FP work across the syscalls: a clobber shows here */
};

static void *body(void *p) {
    struct arg *a = p;
    char buf[64];
    memset(buf, 0, sizeof buf);
    double acc = a->idx + 0.5;

    FILE *f = fopen(g_path, "r");
    if (f) {
        if (fgets(buf, sizeof buf, f))
            a->read_ok = !strncmp(buf, "THREADS-OK", 10);
        fclose(f);
    }
    acc *= 2.0; /* live across the calls above and the ones below */

    long tid = syscall(SYS_gettid), pid = getpid();
    a->tid_ok = (tid != pid || a->idx < 0) ? 1 : 0;
    acc += 1.0;
    a->fpsum = (long)(acc * 100.0);
    return 0;
}

int main(int argc, char **argv) {
    g_path = argc > 1 ? argv[1] : "/etc/threads-marker";
    pthread_t t[NTHREADS];
    struct arg a[NTHREADS];
    int started = 0;

    for (int i = 0; i < NTHREADS; i++) {
        memset(&a[i], 0, sizeof a[i]);
        a[i].idx = i;
        if (pthread_create(&t[i], 0, body, &a[i]) != 0)
            break;
        started++;
    }
    int reads = 0, tids = 0, fp = 0;
    for (int i = 0; i < started; i++) {
        pthread_join(t[i], 0);
        reads += a[i].read_ok;
        tids += a[i].tid_ok;
        /* ((i + 0.5) * 2 + 1) * 100 */
        fp += a[i].fpsum == (long)((i + 0.5) * 2.0 * 100.0 + 100.0);
    }
    printf("threads: started=%d reads=%d tids=%d fp=%d\n", started, reads, tids,
           fp);
    return started == NTHREADS && reads == NTHREADS && tids == NTHREADS &&
                   fp == NTHREADS
               ? 0
               : 1;
}
