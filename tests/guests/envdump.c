/* Dumps the environment the loader handed over, one entry per line plus a count.
 * The guest environment is not the host's — only -E/--env entries and an
 * inherited TERM/COLORTERM reach it — so the count is as much of the assertion
 * as the contents: it is what proves nothing else crossed over.
 *
 * envp is read from main's third argument, i.e. straight off the stack the loader
 * built, rather than from libc's `environ` copy.
 */
#include <stdio.h>

int main(int argc, char **argv, char **envp) {
    (void)argc;
    (void)argv;
    int n = 0;
    for (char **e = envp; *e; e++, n++)
        printf("env: %s\n", *e);
    printf("env count=%d\n", n);
    fflush(stdout);
    return 0;
}
