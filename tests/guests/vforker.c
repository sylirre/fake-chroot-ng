/* The vfork-style clones a libc issues, each followed by what the child does
 * with it: vfork(3) then _exit, vfork(3) then execve, and posix_spawn — which
 * in glibc is clone(CLONE_VM|CLONE_VFORK) on a stack of its own, and in musl
 * __clone on one too. The parent prints how each child ended.
 *
 * argv[1] is the program the exec'ing children run, and the exit status the
 * parent prints is that program's: chroot-ng gets a guest path, the kernel
 * reference run the same file by its host name, so the two outputs must match
 * byte for byte. Everything a vfork child touches before it execs is the
 * parent's memory — here nothing but the exec itself and a fallback _exit, as
 * the manual requires. */
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void ended(const char *tag, int st) {
    if (WIFEXITED(st))
        printf("%s: exited %d\n", tag, WEXITSTATUS(st));
    else if (WIFSIGNALED(st))
        printf("%s: signaled %d\n", tag, WTERMSIG(st));
    else
        printf("%s: status 0x%x\n", tag, st);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: vforker PROGRAM\n");
        return 2;
    }
    char *av[] = {argv[1], "from-vforker", 0};
    int st;
    pid_t p;

    st = 0;
    p = vfork();
    if (p == 0)
        _exit(7);
    if (p < 0 || waitpid(p, &st, 0) != p) {
        perror("vfork");
        return 3;
    }
    ended("vfork-exit", st);

    st = 0;
    p = vfork();
    if (p == 0) {
        execve(av[0], av, environ);
        _exit(9);
    }
    if (p < 0 || waitpid(p, &st, 0) != p) {
        perror("vfork");
        return 3;
    }
    ended("vfork-exec", st);

    st = 0;
    int e = posix_spawn(&p, av[0], 0, 0, av, environ);
    if (e) {
        printf("posix_spawn: error %d\n", e);
        return 3;
    }
    if (waitpid(p, &st, 0) != p) {
        perror("waitpid");
        return 3;
    }
    ended("spawn-exec", st);
    return 0;
}
