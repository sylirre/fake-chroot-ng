/* dtstall MS PROG ARGS... -- run PROG under ptrace, every thread of it, and
 * hold each de_thread request (a SIGSYS with si_code SI_DETHREAD, which only
 * chroot-ng's emulated execve sends) at its delivery for MS milliseconds
 * before letting it through; every other signal goes through untouched (M6).
 *
 * The exec tells each sibling to die with that signal and waits for it to be
 * gone. A delivered request is no longer pending, so one sent after it is
 * delivered too, on top -- a signal frame each, on the thread's alternate
 * stack (bionic's is 16 KiB) or on its own. It used to be sent every 100 us
 * round to every thread still listed, and a thread the scheduler left waiting
 * at the handler's first instruction collected a frame a round until there
 * was no room for the next one, and the kernel killed the whole process with
 * a SIGSEGV: a few runs in a hundred on a slow device. Holding the delivery
 * is that wait, every time.
 *
 * Exits with PROG's status (128 + the signal that killed it), or prints a
 * lone SKIP line when the host will not let it trace its own child. Runs
 * where AArch64 binaries run directly: a host tracer under qemu-user sees
 * the emulator's signals, not the guest's.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SI_DETHREAD /* glibc names it; bionic and musl do not */
#define SI_DETHREAD (-7)
#endif

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: dtstall MS PROG ARGS...\n");
        return 2;
    }
    long ms = atol(argv[1]);
    pid_t c = fork();
    if (c < 0)
        return 1;
    if (c == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
            _exit(125);
        raise(SIGSTOP);
        execvp(argv[2], argv + 2);
        _exit(127);
    }
    int st;
    if (waitpid(c, &st, 0) != c || !WIFSTOPPED(st)) {
        puts("SKIP: cannot trace a child here");
        return 0;
    }
    ptrace(PTRACE_SETOPTIONS, c, 0,
           PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL);
    ptrace(PTRACE_CONT, c, 0, 0);
    int rc = 1;
    for (;;) {
        pid_t p = waitpid(-1, &st, __WALL);
        if (p < 0)
            break;
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (p == c)
                rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            continue;
        }
        int sig = WSTOPSIG(st);
        /* An event stop, or the stop a new thread starts in: nothing to
         * deliver. */
        if ((st >> 16) || sig == SIGSTOP) {
            ptrace(PTRACE_CONT, p, 0, 0);
            continue;
        }
        if (sig == SIGSYS) {
            siginfo_t si;
            memset(&si, 0, sizeof si);
            ptrace(PTRACE_GETSIGINFO, p, 0, &si);
            if (si.si_code == SI_DETHREAD) {
                struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
                nanosleep(&t, 0);
            }
        }
        ptrace(PTRACE_CONT, p, 0, sig);
    }
    return rc;
}
