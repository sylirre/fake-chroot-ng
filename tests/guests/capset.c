/* capset, judged as the kernel judges it (M7).
 *
 * Under --fake-id the capability set is all of them for a fake root and none
 * for anyone else, and a capset was accepted whole for the one and refused
 * whole for the other. But the kernel lets any process drop what it has,
 * nothing included: Chrome's zygote drops every capability in each child it
 * forks and CHECKs the answer, so as any user but root its first child died
 * ("credentials.cc: Check failed: . : Operation not permitted").
 *
 * Usage: capset [ID]. With ID, each row first takes ID as its every id, which
 * leaves a process that was root without capabilities. Every row runs in a
 * child of its own, since a capset that succeeds changes the set the next one
 * is judged against, and prints NAME=RESULT errno=E.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define V1 0x19980330u
#define V3 0x20080522u

struct hdr {
    unsigned version;
    int pid;
};
struct data {
    unsigned eff, perm, inh;
};

static long id = -1;

/* Low word's three sets, then the high word's. */
static long set3(unsigned ver, int pid, unsigned e0, unsigned p0, unsigned i0,
                 unsigned e1, unsigned p1, unsigned i1) {
    struct hdr h = {ver, pid};
    struct data d[2] = {{e0, p0, i0}, {e1, p1, i1}};
    return syscall(SYS_capset, &h, d);
}

static long r_get(void) {
    struct hdr h = {V3, 0};
    struct data d[2];
    if (syscall(SYS_capget, &h, d) != 0)
        return -1;
    return d[0].eff == 0xffffffffu ? 1 : d[0].eff == 0 ? 0 : 2;
}
static long r_none(void) { return set3(V3, 0, 0, 0, 0, 0, 0, 0); }
static long r_none_v1(void) {
    struct hdr h = {V1, 0};
    struct data d = {0, 0, 0};
    return syscall(SYS_capset, &h, &d);
}
static long r_permit(void) { return set3(V3, 0, 0, 1, 0, 0, 0, 0); }
static long r_eff_unpermitted(void) { return set3(V3, 0, 1, 0, 0, 0, 0, 0); }
static long r_inherit(void) { return set3(V3, 0, 0, 0, 1, 0, 0, 0); }
/* Capability 63, which no kernel has: sys_capset clears it first. */
static long r_beyond(void) {
    return set3(V3, 0, 0, 0, 0, 1u << 31, 1u << 31, 1u << 31);
}
static long r_self_pid(void) { return set3(V3, getpid(), 0, 0, 0, 0, 0, 0); }
static long r_other_pid(void) { return set3(V3, getppid(), 0, 0, 0, 0, 0, 0); }
static long r_bad_version(void) {
    return set3(0x12345678u, 0, 0, 0, 0, 0, 0, 0);
}
static long r_bad_data(void) {
    struct hdr h = {V3, 0};
    return syscall(SYS_capset, &h, (void *)0);
}

/* From a second thread: the pid the kernel takes for "current" is the
 * thread's own id. */
static long thread_r;
static int thread_tid;
static void *in_thread(void *a) {
    thread_r = set3(V3, thread_tid ? (int)syscall(SYS_gettid) : getpid(), 0, 0,
                    0, 0, 0, 0);
    if (thread_r < 0)
        thread_r = -errno;
    return a;
}
static long on_thread(void) {
    pthread_t t;
    if (pthread_create(&t, 0, in_thread, 0) != 0 || pthread_join(t, 0) != 0)
        return -1000;
    if (thread_r < 0) {
        errno = (int)-thread_r;
        return -1;
    }
    return thread_r;
}
static long r_thread_tid(void) {
    thread_tid = 1;
    return on_thread();
}
static long r_thread_pid(void) {
    thread_tid = 0;
    return on_thread();
}

static void row(const char *name, long (*fn)(void)) {
    pid_t k = fork();
    if (k == 0) {
        if (id >= 0 && (setgroups(0, 0) || setresgid(id, id, id) ||
                        setresuid(id, id, id))) {
            printf("%s become errno=%d\n", name, errno);
            _exit(1);
        }
        errno = 0;
        long r = fn();
        printf("%s=%ld errno=%d\n", name, r, r < 0 ? errno : 0);
        _exit(0);
    }
    int st;
    waitpid(k, &st, 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1)
        id = strtol(argv[1], 0, 10);
    row("full", r_get); /* 1 all of them, 0 none */
    row("none", r_none);
    row("none_v1", r_none_v1);
    row("permit", r_permit);
    row("eff_unpermitted", r_eff_unpermitted);
    row("inherit", r_inherit);
    row("beyond", r_beyond);
    row("self_pid", r_self_pid);
    row("other_pid", r_other_pid);
    row("thread_tid", r_thread_tid);
    row("thread_pid", r_thread_pid);
    row("bad_version", r_bad_version);
    row("bad_data", r_bad_data);
    return 0;
}
