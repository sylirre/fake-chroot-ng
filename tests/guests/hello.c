/* Test guest for the loader. Exercises argc/argv, environment, and a syscall,
 * then exits with a distinctive code so the harness can confirm the loader
 * transferred control and the stack/auxv were built correctly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("guest: argc=%d argv0=%s\n", argc, argv[0]);
    for (int i = 1; i < argc; i++)
        printf("guest: argv%d=%s\n", i, argv[i]);
    const char *t = getenv("CNG_TEST");
    printf("guest: CNG_TEST=%s\n", t ? t : "(unset)");
    printf("guest: pid=%d\n", (int)getpid());
    fflush(stdout);
    return 42;
}
