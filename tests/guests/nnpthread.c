/* no_new_privs is per TASK, and the emulation has to answer per task too.
 *
 * Installing the monitor sets the real bit — an unprivileged seccomp filter
 * cannot go in without it — so prctl(PR_GET_NO_NEW_PRIVS) is answered from our
 * own bookkeeping rather than by the kernel, and what that bookkeeping tracked
 * was one flag for the whole process. Linux tracks it in task_struct: a thread
 * setting it says nothing about its siblings, a task created afterwards
 * inherits its creator's bit, and fork carries it across.
 *
 * Output is protocol only, so the same source built for the host is the oracle
 * — every line but one has to match it byte for byte. The exception is
 * spawned_by_unset, the one shape an in-process emulation cannot see: knowing
 * which task created a new thread means trapping thread creation, and a
 * thread-creating clone is the call this design cannot trap. It is printed
 * anyway, and the harness asserts both answers, so the divergence is a written
 * fact rather than a silence.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif

/* Straight to the syscall: a libc wrapper may cache or refuse, and it is the
 * syscall the monitor traps. */
static int nnp_get(void) {
    return (int)syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
}
static void nnp_set(void) {
    syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

static pthread_barrier_t b_set, b_seen;

/* A sibling that sets the bit, then waits while main looks at itself. */
static void *setter(void *unused) {
    (void)unused;
    int before = nnp_get();
    nnp_set();
    printf("setter_before=%d\n", before);
    printf("setter_after=%d\n", nnp_get());
    pthread_barrier_wait(&b_set);
    pthread_barrier_wait(&b_seen);
    return 0;
}

static void *reader(void *out) {
    *(int *)out = nnp_get();
    return 0;
}

/* What a thread created by THIS task reads. */
static int spawn_read(void) {
    pthread_t t;
    int v = -1;
    if (pthread_create(&t, 0, reader, &v) != 0)
        return -2;
    pthread_join(t, 0);
    return v;
}

/* What a child forked by THIS task reads. Over a pipe, since the answer has to
 * come back from another process; the child never touches stdio, so the
 * buffered output it inherited cannot be printed twice. */
static int fork_read(void) {
    int fd[2];
    if (pipe(fd) != 0)
        return -2;
    pid_t p = fork();
    if (p == 0) {
        int v = nnp_get();
        ssize_t w = write(fd[1], &v, sizeof v);
        _exit(w == (ssize_t)sizeof v ? 0 : 1);
    }
    close(fd[1]);
    int v = -2, st = 0;
    if (read(fd[0], &v, sizeof v) != (ssize_t)sizeof v)
        v = -2;
    close(fd[0]);
    if (p > 0)
        waitpid(p, &st, 0);
    return v;
}

int main(void) {
    printf("start=%d\n", nnp_get());
    pthread_barrier_init(&b_set, 0, 2);
    pthread_barrier_init(&b_seen, 0, 2);
    pthread_t s;
    if (pthread_create(&s, 0, setter, 0) != 0) {
        printf("nothread\n");
        return 1;
    }
    pthread_barrier_wait(&b_set);
    /* A sibling has the bit and this task does not: the whole point. */
    printf("self_after_sibling_set=%d\n", nnp_get());
    /* A child of a task WITHOUT the bit takes that, not the sibling's. */
    printf("forked_by_unset=%d\n", fork_read());
    /* ...and the same for a thread, which is the shape that cannot be seen. */
    printf("spawned_by_unset=%d\n", spawn_read());
    pthread_barrier_wait(&b_seen);
    pthread_join(s, 0);

    nnp_set();
    printf("self_after_set=%d\n", nnp_get());
    printf("spawned_by_set=%d\n", spawn_read());
    printf("forked_by_set=%d\n", fork_read());
    return 0;
}
