/* /proc/<pid>/cmdline and environ are read out of the process's memory at read
 * time, from the ranges its exec laid the strings out in: what a program writes
 * over its own strings is what those files say from then on. setproctitle(3)
 * and its kin rely on that (node's process.title, the status lines nginx and
 * postgres keep in argv), and so does every ps and top that prints them.
 *
 * The program re-execs itself first, so the strings it rewrites are a known
 * set, and then checks, on its own files and on a forked child's:
 *   start            both files as the exec left them;
 *   environ          a byte of the environment rewritten shows;
 *   kid cmdline      a child's title, read by its parent;
 *   kid environ      ...and the byte the child rewrote in its environment;
 *   title            a short title over argv[0] and the rest of argv zeroed
 *                    (libuv's and nginx's way): the title and then the zeros,
 *                    over the whole argv range;
 *   overflow         a title run past the end of argv into the environment
 *                    (setproctitle's way): the title up to its NUL, no more;
 *   overflow environ ...and the environment range shows what it ran over.
 * One line each, "name: ok" or "name: FAIL" with both byte strings.
 *
 * Two lines go before them. "mm_map: yes|no" is the first run asking whether
 * the kernel takes PR_SET_MM_MAP, which says how the next line should come
 * out where that run is the kernel itself. "record: kernel|ours" says whether
 * /proc/self/stat's arg_start (field 48) names our argv[0], i.e. whether the
 * kernel's own record describes these strings. */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_MAP_SIZE
#define PR_SET_MM_MAP_SIZE 15
#endif

extern char **environ;

static long slurp(const char *path, char *buf, long cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    long n = 0, r;
    while (n < cap && (r = read(fd, buf + n, (size_t)(cap - n))) > 0)
        n += r;
    close(fd);
    return n;
}

static void show(const char *s, long n) {
    putchar('[');
    for (long i = 0; i < n; i++)
        putchar(s[i] ? s[i] : '|');
    putchar(']');
}

static void verdict(const char *name, const char *path, const char *want,
                    long wn) {
    static char got[16384];
    long n = slurp(path, got, sizeof got);
    if (n == wn && !memcmp(got, want, (size_t)wn)) {
        printf("%s: ok\n", name);
        return;
    }
    printf("%s: FAIL got %ld ", name, n);
    show(got, n < 0 ? 0 : n);
    printf(" want %ld ", wn);
    show(want, wn);
    putchar('\n');
}

static unsigned long stat_field(int field) {
    char b[1024];
    long n = slurp("/proc/self/stat", b, sizeof b - 1);
    if (n <= 0)
        return 0;
    b[n] = '\0';
    char *p = strrchr(b, ')');
    if (!p)
        return 0;
    p++;
    for (int i = 3; i <= field; i++) {
        if (*p != ' ')
            return 0; /* the file ends before it: qemu-user's has 44 */
        p++;
        if (i == field)
            return strtoul(p, 0, 10);
        while (*p && *p != ' ')
            p++;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "a")) {
        unsigned sz = 0;
        printf("mm_map: %s\n",
               prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &sz, 0, 0) == 0 ? "yes"
                                                                    : "no");
        fflush(stdout);
        char *av[] = {argv[0], "a", "bb", "ccc", 0};
        char *ev[] = {"A=1", "LONG=0123456789", 0};
        execve(argv[0], av, ev);
        perror("execve");
        return 2;
    }
    char *base = argv[0];
    long room = argv[argc - 1] + strlen(argv[argc - 1]) + 1 - base;
    int envc = 0;
    while (environ[envc])
        envc++;
    if (envc < 2 || environ[0] != base + room) {
        printf("layout: FAIL the environment does not follow argv\n");
        return 1;
    }
    char *envp0 = environ[0];
    long envlen = environ[envc - 1] + strlen(environ[envc - 1]) + 1 - envp0;
    printf("record: %s\n",
           stat_field(48) == (unsigned long)base ? "kernel" : "ours");

    static char want[8192];
    char kidpath[64];

    memcpy(want, base, (size_t)room);
    verdict("start", "/proc/self/cmdline", want, room);
    memcpy(want, envp0, (size_t)envlen);
    verdict("start environ", "/proc/self/environ", want, envlen);

    environ[1][0] = 'X'; /* LONG= -> XONG= */
    memcpy(want, envp0, (size_t)envlen);
    verdict("environ", "/proc/self/environ", want, envlen);

    int p[2];
    if (pipe(p)) {
        perror("pipe");
        return 1;
    }
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        memcpy(base, "kid", 3);
        memset(base + 3, 0, (size_t)(room - 3));
        envp0[0] = 'B'; /* A=1 -> B=1 */
        char c = 1;
        if (write(p[1], &c, 1) != 1)
            _exit(1);
        for (;;)
            pause();
    }
    char c;
    if (kid < 0 || read(p[0], &c, 1) != 1) {
        printf("kid: FAIL no child\n");
        return 1;
    }
    memset(want, 0, (size_t)room);
    memcpy(want, "kid", 3);
    snprintf(kidpath, sizeof kidpath, "/proc/%d/cmdline", (int)kid);
    verdict("kid cmdline", kidpath, want, room);
    memcpy(want, envp0, (size_t)envlen);
    want[0] = 'B';
    snprintf(kidpath, sizeof kidpath, "/proc/%d/environ", (int)kid);
    verdict("kid environ", kidpath, want, envlen);
    kill(kid, SIGKILL);
    waitpid(kid, 0, 0);

    memcpy(base, "title", 5);
    memset(base + 5, 0, (size_t)(room - 5));
    memset(want, 0, (size_t)room);
    memcpy(want, "title", 5);
    verdict("title", "/proc/self/cmdline", want, room);

    /* Four bytes past argv's end, then the NUL: the last byte of the argv range
     * is no longer one, and the environment has twenty to run into. */
    memset(base, 'T', (size_t)(room + 4));
    base[room + 4] = '\0';
    memset(want, 'T', (size_t)(room + 4));
    want[room + 4] = '\0';
    verdict("overflow", "/proc/self/cmdline", want, room + 5);
    memcpy(want, envp0, (size_t)envlen);
    verdict("overflow environ", "/proc/self/environ", want, envlen);
    return 0;
}
