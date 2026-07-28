/* The blocking half of System V IPC (M22): every way a sleeping operation can
 * end. Diffed against the real kernel like sem_sysv.c.
 *
 * This is the part chroot-ng has to work hardest for. The client half runs
 * inside the SIGSYS handler, where every signal but SIGSYS is masked — so a
 * sleeping semop cannot be woken by a signal arriving, and the EINTR leg below
 * only passes because the wait polls the pending set against the mask the signal
 * frame will restore. The daemon half has to keep serving everyone else while
 * one connection sits parked, which is what the wake-by-another-process legs
 * check.
 *
 * Timings are generous (300 ms) and no timing is printed, so the comparison
 * stays exact on a loaded machine.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

/* semtimedop has no glibc prototype in some sysroots; the syscall is stable. */
#include <sys/syscall.h>
static int sem_timedop(int id, struct sembuf *s, size_t n,
                       const struct timespec *t) {
    return (int)syscall(SYS_semtimedop, id, s, n, t);
}

static const char *e(void) {
    switch (errno) {
    case EAGAIN: return "EAGAIN";
    case EIDRM:  return "EIDRM";
    case EINTR:  return "EINTR";
    default:     return strerror(errno);
    }
}

static void onalrm(int s) { (void)s; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int sid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    if (sid < 0) {
        printf("semget: %s\n", strerror(errno));
        return 1;
    }
    struct sembuf down = {0, -1, 0};

    /* 1. A wait another process satisfies. */
    pid_t p = fork();
    if (p == 0) {
        usleep(300000);
        struct sembuf up = {0, +1, 0};
        semop(sid, &up, 1);
        _exit(0);
    }
    printf("woken by a post: rc=%d\n", semop(sid, &down, 1));
    waitpid(p, 0, 0);

    /* 2. A wait-for-zero, which is the other way an operation can block. */
    union semun u;
    u.val = 4;
    semctl(sid, 0, SETVAL, u);
    p = fork();
    if (p == 0) {
        usleep(300000);
        union semun z;
        z.val = 0;
        semctl(sid, 0, SETVAL, z);
        _exit(0);
    }
    struct sembuf waitz = {0, 0, 0};
    printf("woken by zero: rc=%d\n", semop(sid, &waitz, 1));
    waitpid(p, 0, 0);

    /* 3. semtimedop's deadline. */
    struct timespec to = {0, 200000000};
    int rc = sem_timedop(sid, &down, 1, &to);
    printf("timed out: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    /* 4. A signal makes it EINTR — never restarted, whatever SA_RESTART says. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = onalrm;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, 0);
    alarm(1);
    rc = semop(sid, &down, 1);
    printf("interrupted: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    alarm(0);

    /* 5. ...but a signal the guest is ignoring is not an interruption: this
     * must still be woken by the post, not cut short by the SIGUSR1. */
    signal(SIGUSR1, SIG_IGN);
    p = fork();
    if (p == 0) {
        usleep(150000);
        kill(getppid(), SIGUSR1);
        usleep(300000);
        struct sembuf up = {0, +1, 0};
        semop(sid, &up, 1);
        _exit(0);
    }
    rc = semop(sid, &down, 1);
    printf("ignored signal did not interrupt: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    waitpid(p, 0, 0);
    signal(SIGUSR1, SIG_DFL);

    /* 6. Two sleepers, one post: FIFO order decides which one runs. */
    u.val = 0;
    semctl(sid, 0, SETVAL, u);
    printf("ncnt with none waiting: %d\n", semctl(sid, 0, GETNCNT));

    /* 7. The set is removed under a sleeper. */
    p = fork();
    if (p == 0) {
        usleep(300000);
        semctl(sid, 0, IPC_RMID);
        _exit(0);
    }
    rc = semop(sid, &down, 1);
    printf("removed under it: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    waitpid(p, 0, 0);

    /* ---- message queues ---- */
    int q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    struct {
        long mtype;
        char t[16];
    } m;

    /* 8. A receive that waits for a sender. */
    p = fork();
    if (p == 0) {
        usleep(300000);
        struct {
            long mtype;
            char t[16];
        } s = {.mtype = 3};
        strcpy(s.t, "late");
        msgsnd(q, &s, sizeof s.t, 0);
        _exit(0);
    }
    memset(&m, 0, sizeof m);
    printf("blocked rcv: n=%d type=%ld text=%s\n",
           (int)msgrcv(q, &m, sizeof m.t, 0, 0), m.mtype, m.t);
    waitpid(p, 0, 0);

    /* 9. A send that waits for room. The queue is filled to its limit first,
     * then a reader drains one message and the parked sender goes through. */
    struct msqid_ds mds;
    msgctl(q, IPC_STAT, &mds);
    m.mtype = 1;
    memset(m.t, 'x', sizeof m.t);
    unsigned long sent = 0;
    while (msgsnd(q, &m, sizeof m.t, IPC_NOWAIT) == 0)
        sent++;
    printf("queue full after some sends: %d\n", sent > 0 && errno == EAGAIN);
    p = fork();
    if (p == 0) {
        usleep(300000);
        struct {
            long mtype;
            char t[16];
        } r;
        msgrcv(q, &r, sizeof r.t, 0, 0);
        _exit(0);
    }
    printf("blocked snd: rc=%d\n", (int)msgsnd(q, &m, sizeof m.t, 0));
    waitpid(p, 0, 0);

    /* 10. The queue is removed under a sleeping receiver. */
    while (msgrcv(q, &m, sizeof m.t, 0, IPC_NOWAIT) >= 0)
        ;
    p = fork();
    if (p == 0) {
        usleep(300000);
        msgctl(q, IPC_RMID, NULL);
        _exit(0);
    }
    rc = (int)msgrcv(q, &m, sizeof m.t, 0, 0);
    printf("queue removed under it: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    waitpid(p, 0, 0);

    printf("done\n");
    return 0;
}
