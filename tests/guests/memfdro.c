/* Reopening a memfd through its own /proc link (M7).
 *
 * memfd_create only makes O_RDWR files, and an open of /proc/self/fd/N is the
 * one way to another description of one: Chrome takes the read-only half of
 * every shared-memory region that way, and an interpreter reads a script run
 * from a memfd that way (apk 3's package scripts). Android's policy refuses an
 * app that open, so what chroot-ng hands back where the host refuses is
 * checked here as well as what the host gives where it does not: never a
 * description wider than the one asked for, except for the script the
 * interpreter was run to read.
 *
 * Run with no arguments it prints one row per case. Run as a #! interpreter
 * ("#!/bin/memfdro interp") it opens the script it was handed and says how
 * that went.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int reopen(int fd, int flags) {
    char p[40];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    return open(p, flags);
}

/* memfd_create's flags, spelled out: bionic declares none of it before API
 * 30, which is what the device's guest compiler builds against. */
#define M_CLOEXEC 1u
#define M_SEAL 2u /* MFD_ALLOW_SEALING */

/* A memfd holding `s`, its offset left at the end as a writer leaves it. */
static int filled(const char *s, unsigned flags) {
    int fd = (int)syscall(SYS_memfd_create, "memfdro", flags);
    if (fd >= 0 && write(fd, s, strlen(s)) != (long)strlen(s)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Run the script in `fd` through the path the guest names it by, or through
 * the descriptor itself with execveat's AT_EMPTY_PATH. */
static void run_script(const char *tag, int fd, int at) {
    pid_t pid = fork();
    if (pid == 0) {
        char p[40], e[40];
        snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
        snprintf(e, sizeof e, "MEMFDRO=%s", tag);
        char *argv[] = {"script", NULL}, *envp[] = {e, NULL};
        if (at)
            syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        else
            execve(p, argv, envp);
        printf("%s exec errno=%d\n", tag, errno);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("%s status=%d\n", tag, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 3 && !strcmp(argv[1], "interp")) {
        /* The interpreter's side: open the script by the name it was given,
         * read-only, as every shell does. */
        int fd = open(argv[2], O_RDONLY);
        char b[2] = {0, 0};
        int head = fd >= 0 && read(fd, b, 2) == 2 && b[0] == '#' && b[1] == '!';
        const char *tag = getenv("MEMFDRO");
        printf("%s interp open=%d head=%d\n", tag ? tag : "?",
               fd >= 0 ? 0 : errno, head);
        return 0;
    }

    /* A read-only open of a writable memfd: read-only, or refused. */
    int fd = filled("data", M_CLOEXEC | M_SEAL);
    int ro = reopen(fd, O_RDONLY | O_CLOEXEC);
    if (ro < 0) {
        printf("ro open=%d\n", errno);
    } else {
        int acc = fcntl(ro, F_GETFL) & O_ACCMODE;
        printf("ro open=0 accmode=%d write=%d\n", acc,
               write(ro, "x", 1) < 0 ? errno : 0);
        close(ro);
    }

    /* The same access mode, reading from the start like any fresh open. */
    int rw = reopen(fd, O_RDWR | O_CLOEXEC);
    if (rw < 0) {
        printf("rw open=%d\n", errno);
    } else {
        char b[5] = {0};
        long n = read(rw, b, 4);
        printf("rw open=0 accmode=%d read=%s\n", fcntl(rw, F_GETFL) & O_ACCMODE,
               n == 4 ? b : "?");
        close(rw);
    }
    close(fd);

    /* A script run from a memfd the interpreter inherits, by both spellings
     * of the exec. */
    fd = filled("#!/bin/memfdro interp\n", M_SEAL);
    run_script("script", fd, 0);
    run_script("script-at", fd, 1);
    close(fd);

    /* ...and one the exec closed: the interpreter is handed a name for a
     * descriptor that is gone, which no reopen can serve. */
    fd = filled("#!/bin/memfdro interp\n", M_CLOEXEC | M_SEAL);
    run_script("cloexec", fd, 0);
    close(fd);
    return 0;
}
