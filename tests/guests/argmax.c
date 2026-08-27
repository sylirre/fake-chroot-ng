/* MAX_ARG_STRLEN: how long a single argv string an execve takes (M6).
 *
 * fs/exec.c bounds each string at 32 *pages* and answers -E2BIG past it, so the
 * number is 128 KiB on a 4 KiB kernel and 512 KiB on the 16 KiB ones the
 * Android devices run — which is why the emulation reads the page size rather
 * than carrying a constant. The boundary itself is exact: strnlen_user counts
 * the terminator, so a string of 32 pages minus one byte is the longest that
 * fits, and one byte more is refused.
 *
 * Each leg forks and execs this same binary with a string of the length under
 * test, so a refusal is an errno the child prints and an acceptance is the
 * exec'd program printing its own argv length back. Protocol plus that length,
 * which is a function of the page size both sides see, so the output is
 * byte-comparable against a run with no chroot-ng under it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *ename(int e) {
    switch (e) {
    case E2BIG:  return "E2BIG";
    case ENOENT: return "ENOENT";
    case EFAULT: return "EFAULT";
    case 0:      return "none";
    default:     return "other";
    }
}

/* Exec `self` with one argv string of `len` bytes, in a child of our own: the
 * legs that are accepted never come back. */
static void leg(const char *name, const char *self, size_t len) {
    char *big = malloc(len + 1);
    if (!big) {
        printf("argmax %s nomem\n", name);
        return;
    }
    memset(big, 'x', len);
    big[len] = '\0';
    pid_t p = fork();
    if (p == 0) {
        char *a[] = {(char *)self, "child", big, 0};
        errno = 0;
        execv(self, a);
        printf("argmax %s %s\n", name, ename(errno));
        fflush(stdout);
        _exit(0);
    }
    int st;
    if (p > 0)
        waitpid(p, &st, 0);
    free(big);
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "child")) {
        printf("argmax ran len=%zu\n", strlen(argv[2]));
        return 0;
    }
    if (argc < 2) {
        printf("argmax usage\n");
        return 2;
    }
    size_t max = 32 * (size_t)sysconf(_SC_PAGESIZE);
    leg("under", argv[1], max - 1);
    leg("at", argv[1], max);
    leg("over", argv[1], max + 1);
    return 0;
}
