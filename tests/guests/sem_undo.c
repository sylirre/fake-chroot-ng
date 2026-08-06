/* SEM_UNDO (M22): units a process took must be credited back when it dies,
 * however it dies. Diffed against the real kernel like the other two.
 *
 * This is the leg with no counterpart in chroot-ng's design: the kernel runs a
 * process's undo list as part of its exit, and chroot-ng traps no exit path at
 * all — deliberately, since a SIGKILL could never be trapped either. The
 * adjustment is applied by the broker instead, from the pid's incarnation, when
 * the set is next touched. The waitpid() before each read is what makes that
 * observable: if the emulation deferred the undo to a timer tick, the value read
 * straight after the reap would be one no kernel ever reports.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <unistd.h>
#include "sysvipc.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int sid = semget(IPC_PRIVATE, 2, IPC_CREAT | 0600);
    if (sid < 0) {
        printf("semget: %s\n", strerror(errno));
        return 1;
    }
    union cng_semun u;
    u.val = 2;
    semctl(sid, 0, SETVAL, u);
    printf("start: %d\n", semctl(sid, 0, GETVAL));

    /* 1. An ordinary exit. */
    pid_t p = fork();
    if (p == 0) {
        struct sembuf d = {0, -2, SEM_UNDO};
        semop(sid, &d, 1);
        _exit(0);
    }
    waitpid(p, 0, 0);
    printf("after exit: %d\n", semctl(sid, 0, GETVAL));

    /* 2. A SIGKILL — no exit hook could have caught this one. */
    p = fork();
    if (p == 0) {
        struct sembuf d = {0, -2, SEM_UNDO};
        semop(sid, &d, 1);
        pause();
        _exit(0);
    }
    usleep(300000);
    printf("while held: %d\n", semctl(sid, 0, GETVAL));
    kill(p, SIGKILL);
    waitpid(p, 0, 0);
    printf("after kill: %d\n", semctl(sid, 0, GETVAL));

    /* 3. Without SEM_UNDO nothing comes back. */
    p = fork();
    if (p == 0) {
        struct sembuf d = {0, -2, 0};
        semop(sid, &d, 1);
        _exit(0);
    }
    waitpid(p, 0, 0);
    printf("without undo: %d\n", semctl(sid, 0, GETVAL));

    /* 4. The adjustments net out: a child that takes and then gives back the
     * same units leaves nothing behind to undo. */
    u.val = 5;
    semctl(sid, 0, SETVAL, u);
    p = fork();
    if (p == 0) {
        struct sembuf d = {0, -3, SEM_UNDO}, up = {0, +3, SEM_UNDO};
        semop(sid, &d, 1);
        semop(sid, &up, 1);
        _exit(0);
    }
    waitpid(p, 0, 0);
    printf("balanced: %d\n", semctl(sid, 0, GETVAL));

    /* 5. SETVAL cancels every pending undo for that semaphore, so the child's
     * death must not move the value the parent just wrote. */
    p = fork();
    if (p == 0) {
        struct sembuf d = {0, -2, SEM_UNDO};
        semop(sid, &d, 1);
        pause();
        _exit(0);
    }
    usleep(300000);
    u.val = 9;
    semctl(sid, 0, SETVAL, u);
    kill(p, SIGKILL);
    waitpid(p, 0, 0);
    printf("setval cancels undo: %d\n", semctl(sid, 0, GETVAL));

    /* 6. An undo credit can release a sleeper: the parent waits for units the
     * dying child owes it. */
    u.val = 0;
    semctl(sid, 1, SETVAL, u);
    p = fork();
    if (p == 0) {
        struct sembuf up = {1, +1, SEM_UNDO}; /* holds a unit it will give back */
        semop(sid, &up, 1);
        usleep(300000);
        _exit(0);
    }
    usleep(600000); /* let the child post and die */
    struct sembuf take = {1, -1, IPC_NOWAIT};
    int rc = semop(sid, &take, 1);
    printf("undo removed the posted unit: rc=%d %s\n", rc,
           rc < 0 && errno == EAGAIN ? "EAGAIN" : rc == 0 ? "-" : strerror(errno));
    waitpid(p, 0, 0);

    /* 7. ...and it must WAKE a sleeper, not merely change the value under it.
     * A holder dies owing units; someone is already blocked waiting for exactly
     * those units. The kernel's exit-time undo releases them and the sleeper
     * proceeds. Where the undo is applied by a daemon that only re-examines
     * parked waiters after serving a request, nothing re-examines them here —
     * and the sleeper waits forever for a resource that is already free. The
     * alarm is what turns that into a printable answer rather than a hung run. */
    u.val = 1;
    semctl(sid, 0, SETVAL, u);
    pid_t holder = fork();
    if (holder == 0) {
        struct sembuf d = {0, -1, SEM_UNDO};
        semop(sid, &d, 1);
        pause();
        _exit(0);
    }
    usleep(300000); /* the holder has taken it: the value is now 0 */
    pid_t sleeper = fork();
    if (sleeper == 0) {
        struct sembuf d = {0, -1, 0};
        alarm(5);
        _exit(semop(sid, &d, 1) == 0 ? 0 : errno == EINTR ? 3 : 4);
    }
    usleep(300000); /* the sleeper is parked */
    kill(holder, SIGKILL);
    waitpid(holder, 0, 0);
    int wst = 0;
    waitpid(sleeper, &wst, 0);
    printf("undo wakes a sleeper: %s\n",
           !WIFEXITED(wst)          ? "signal"
           : WEXITSTATUS(wst) == 0  ? "yes"
           : WEXITSTATUS(wst) == 3  ? "no (timed out)"
                                    : "error");

    semctl(sid, 0, IPC_RMID);
    printf("done\n");
    return 0;
}
