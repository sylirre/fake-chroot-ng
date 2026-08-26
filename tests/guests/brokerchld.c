/* The broker daemon is started from inside a guest process. This asks what the
 * guest was able to notice about that (tests/m12_shm.sh).
 *
 * Starting it is a double fork, and the middle child of a double fork is a
 * child of whichever guest process happened to make the first System V IPC
 * call. Two things follow from that if it is an ordinary fork: its exit sends
 * the guest a SIGCHLD for a process the guest never started, and a wait() on
 * another thread can reap it and be handed that process's exit status. The
 * first is the half that can be measured without winning a race, so it is what
 * this asks — with the guest's own child as the control, since a run that
 * cannot see a SIGCHLD at all would pass the interesting half for free.
 *
 * The mechanism that hides it is a clone with no exit signal, so the run first
 * asks whether it can have one: qemu-user implements exactly one fork,
 * clone(SIGCHLD), and refuses every other flag word, so on a cross host the
 * broker is forced back onto the visible fork and there is nothing to assert.
 * The probe goes through the same path chroot-ng's own does (the monitor traps
 * clone and re-issues it), so it answers for the monitor and not just for the
 * guest.
 *
 * The disposition matters: SIGCHLD's default action is "ignore", and the kernel
 * discards a signal whose action is ignore rather than queueing it, so the
 * handler has to be armed before anything forks.
 *
 * Output is fixed text, so it says nothing about the host it ran on.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sysvipc.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif

static volatile sig_atomic_t chld;

static void on_chld(int sig) {
    (void)sig;
    chld++;
}

static void nap(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, 0);
}

int main(void) {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = on_chld;
    if (sigaction(SIGCHLD, &sa, 0) != 0) {
        printf("sigaction: e=%d\n", errno);
        return 1;
    }

    /* Control: a child of the guest's own is still a child of the guest's, and
     * both halves must work — the signal arrives and wait() hands it over. */
    pid_t p = fork();
    if (p == 0)
        _exit(3);
    if (p < 0) {
        printf("fork: e=%d\n", errno);
        return 1;
    }
    int st = 0;
    pid_t r = waitpid(p, &st, 0);
    nap(100);
    printf("own: chld=%d reaped=%d status=%d\n", chld > 0, r == p,
           WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* Can a child have no exit signal here at all? */
    long q = syscall(SYS_clone, 0UL, 0UL, 0UL, 0UL, 0UL);
    if (q == 0)
        _exit(0);
    printf("quiet: %d\n", q >= 0);
    if (q > 0)
        while (waitpid((pid_t)q, &st, __WALL) < 0 && errno == EINTR)
            ;

    /* The broker: the first SysV IPC call in an invocation has to start the
     * daemon, so this one call is the whole spawn. Nothing of it may reach the
     * guest — no signal, and no child left to wait for. */
    chld = 0;
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    nap(200);
    int w = (int)waitpid(-1, &st, WNOHANG);
    printf("broker: got=%d chld=%d wait=%d e=%d\n", id >= 0, (int)chld, w,
           w < 0 ? errno : 0);
    if (id >= 0)
        shmctl(id, IPC_RMID, 0);
    return 0;
}
