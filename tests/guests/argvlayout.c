/* The initial stack's strings must be laid out the way the kernel lays them
 * out, not merely be reachable through argv/envp: one contiguous ascending
 * run of argv[0..argc-1], then envp[0..envc-1], then the AT_EXECFN path, with
 * a zero word right after it at the top of the stack. setproctitle-style code
 * leans on that shape — libuv's uv_setup_args, which every node process runs,
 * takes argv[argc-1] + strlen + 1 - argv[0] as the room it may overwrite and
 * memsets the part of it a new title does not use.
 *
 * Checks every adjacency and prints "layout: ok argc=N envc=M" or the first
 * break. Given no "again" argument it then re-execs itself with more, so the
 * stack an emulated execve builds is checked by the same code. */
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

extern char **environ;

static int check(int argc, char **argv) {
    char *at = argv[0];
    for (int i = 0; i < argc; i++) {
        if (argv[i] != at) {
            printf("layout: FAIL argv[%d] at %p, expected %p\n", i,
                   (void *)argv[i], (void *)at);
            return 1;
        }
        at += strlen(argv[i]) + 1;
    }
    /* libuv's arithmetic, done the way it does it. */
    long room = (long)(argv[argc - 1] + strlen(argv[argc - 1]) + 1 - argv[0]);
    long want = 0;
    for (int i = 0; i < argc; i++)
        want += (long)strlen(argv[i]) + 1;
    if (room != want) {
        printf("layout: FAIL title room %ld, expected %ld\n", room, want);
        return 1;
    }
    int envc = 0;
    for (; environ[envc]; envc++) {
        if (environ[envc] != at) {
            printf("layout: FAIL envp[%d] at %p, expected %p\n", envc,
                   (void *)environ[envc], (void *)at);
            return 1;
        }
        at += strlen(environ[envc]) + 1;
    }
    char *fn = (char *)getauxval(AT_EXECFN);
    if (fn != at) {
        printf("layout: FAIL AT_EXECFN at %p, expected %p\n", (void *)fn,
               (void *)at);
        return 1;
    }
    at += strlen(fn) + 1;
    unsigned long top;
    memcpy(&top, at, sizeof top);
    if (top != 0 || ((unsigned long)at & 7)) {
        printf("layout: FAIL word after AT_EXECFN at %p is 0x%lx\n", (void *)at,
               top);
        return 1;
    }
    printf("layout: ok argc=%d envc=%d\n", argc, envc);
    return 0;
}

int main(int argc, char **argv) {
    if (check(argc, argv))
        return 1;
    if (argc > 1 && !strcmp(argv[1], "again"))
        return 0;
    fflush(stdout);
    char *av[] = {argv[0], "again", "x", "yy", "zzz", 0};
    char *ev[] = {"A=1", "BB=22", 0};
    execve(argv[0], av, ev);
    perror("execve");
    return 2;
}
