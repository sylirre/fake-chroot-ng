/* Prints what /proc/self/exe reports for the running program, which a real kernel
 * guarantees to be an absolute, symlink-resolved path — glibc goes as far as
 * asserting the leading '/' inside _dl_get_origin, so a relative answer aborts
 * the guest before main. Used to pin the initial program's own link, the one no
 * emulated execve ever republishes.
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n < 0) {
        printf("exe=(readlink failed)\n");
        fflush(stdout);
        return 1;
    }
    buf[n] = '\0';
    printf("exe=%s\n", buf);

    /* comm rides along: it is derived from the same recorded program, so a change
     * to one shows up here rather than in a surprise somewhere else. */
    FILE *f = fopen("/proc/self/comm", "r");
    char comm[64] = "(none)";
    if (f) {
        if (fgets(comm, sizeof comm, f)) {
            char *nl = comm;
            while (*nl && *nl != '\n')
                nl++;
            *nl = '\0';
        }
        fclose(f);
    }
    printf("comm=%s\n", comm);
    fflush(stdout);
    return 0;
}
