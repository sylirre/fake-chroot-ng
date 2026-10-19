/* The hidden-process view by pid, for the signal family (M85). argv[1] and
 * argv[2] are two host processes the view hides (tests/guests/sigholder.c):
 * one in the guest's own process group, one leading a group of its own. Each
 * call aimed at them is printed with its answer; then the group and broadcast
 * forms are sent among processes of the guest's own, and what each of them
 * received is printed. Whether the holders received anything is theirs to
 * report.
 *
 * With `control` (argv[3]) kill(-1) is left out: that run is the one under
 * --no-proc, where it would reach every process of the user. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void rc(const char *what, long r) {
    if (r < 0)
        printf("%s=-1 errno=%d\n", what, errno);
    else
        printf("%s=0\n", what);
}

static int *cnt; /* SIGURGs received: [0] us, [1] c1, [2] c2, [3] c3 */
static volatile sig_atomic_t role;

static void on_urg(int s) {
    (void)s;
    __atomic_fetch_add(&cnt[role], 1, __ATOMIC_SEQ_CST);
}

static int counts_are(int a, int b, int c, int d) {
    return __atomic_load_n(&cnt[0], __ATOMIC_SEQ_CST) == a &&
           __atomic_load_n(&cnt[1], __ATOMIC_SEQ_CST) == b &&
           __atomic_load_n(&cnt[2], __ATOMIC_SEQ_CST) == c &&
           __atomic_load_n(&cnt[3], __ATOMIC_SEQ_CST) == d;
}

/* Delivery is asynchronous: give it up to 10 s to arrive. */
static void await(int a, int b, int c, int d) {
    struct timespec ts = {0, 2000000};
    for (int i = 0; i < 5000 && !counts_are(a, b, c, d); i++)
        nanosleep(&ts, NULL);
}

/* A guest process parked until SIGTERM, with `r` as its counter. It reports
 * on `w` once its handler (inherited) and role are in place. */
static void park(int r, int w) {
    role = r;
    alarm(60);
    if (write(w, "x", 1) != 1)
        _exit(1);
    for (;;)
        pause();
}

static volatile pid_t thread_tid;
static void *thread_main(void *arg) {
    (void)arg;
    thread_tid = (pid_t)syscall(SYS_gettid);
    pause();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3)
        return 2;
    pid_t a = atoi(argv[1]), b = atoi(argv[2]);
    int control = argc > 3 && !strcmp(argv[3], "control");
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    cnt = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
               -1, 0);
    if (cnt == MAP_FAILED)
        return 3;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_urg;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGURG, &sa, NULL);

    printf("holder-shares-group=%d\n", getpgid(a) == getpgid(0));

    /* Hidden processes, one at a time. The forged si_code and the zero tid
     * are refused before the kernel looks for a process at all, and keep
     * those answers. */
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGURG;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    rc("kill-hidden-0", kill(a, 0));
    rc("kill-hidden", kill(a, SIGURG));
    rc("tkill-hidden", syscall(SYS_tkill, a, SIGURG));
    rc("tgkill-hidden", syscall(SYS_tgkill, a, a, SIGURG));
    rc("tgkill-hidden-tid0", syscall(SYS_tgkill, a, 0, SIGURG));
    rc("sigqueue-hidden", syscall(SYS_rt_sigqueueinfo, a, SIGURG, &si));
    rc("tgsigqueue-hidden",
       syscall(SYS_rt_tgsigqueueinfo, a, a, SIGURG, &si));
    si.si_code = SI_USER;
    rc("sigqueue-hidden-forged", syscall(SYS_rt_sigqueueinfo, a, SIGURG, &si));
    rc("kill-parent", kill(getppid(), 0));
    rc("kill-hidden-group-0", kill(-b, 0));
    rc("kill-hidden-group", kill(-b, SIGURG));
    rc("kill-intmin", kill(INT_MIN, 0));

    /* Processes of our own: c1 in our group, c2 leading one with c3 in it. */
    int p[2];
    char c;
    if (pipe(p) < 0)
        return 3;
    pid_t c1 = fork();
    if (c1 == 0)
        park(1, p[1]);
    pid_t c2 = fork();
    if (c2 == 0) {
        setpgid(0, 0);
        if (fork() == 0)
            park(3, p[1]);
        park(2, p[1]);
    }
    setpgid(c2, c2);
    for (int i = 0; i < 3; i++)
        if (read(p[0], &c, 1) != 1)
            return 3;
    pthread_t th;
    pthread_create(&th, NULL, thread_main, NULL);
    while (!thread_tid)
        sched_yield();

    rc("kill-child", kill(c1, 0));
    rc("tgkill-self", syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), 0));
    rc("tkill-thread", syscall(SYS_tkill, thread_tid, 0));
    rc("tgkill-thread", syscall(SYS_tgkill, getpid(), thread_tid, 0));
    rc("kill-group-own", kill(0, SIGURG));
    await(1, 1, 0, 0);
    rc("kill-group-child", kill(-c2, SIGURG));
    await(1, 1, 1, 1);
    if (!control) {
        rc("kill-all", kill(-1, SIGURG));
        await(1, 2, 2, 2);
    }
    rc("kill-group-child-0", kill(-c2, 0));
    struct timespec settle = {0, 200000000};
    nanosleep(&settle, NULL);
    printf("counts us=%d c1=%d c2=%d c3=%d\n", cnt[0], cnt[1], cnt[2], cnt[3]);

    kill(-c2, SIGTERM);
    kill(c1, SIGTERM);
    waitpid(c1, NULL, 0);
    waitpid(c2, NULL, 0);
    printf("done\n");
    return 0;
}
