/* Prints what /proc/self/exe reports for the running program, which a real kernel
 * guarantees to be an absolute, symlink-resolved path — glibc goes as far as
 * asserting the leading '/' inside _dl_get_origin, so a relative answer aborts
 * the guest before main. Used to pin the initial program's own link, the one no
 * emulated execve ever republishes.
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* The same links read the other way a program can spell them: against an open
 * directory fd, with a bare component. That is what GNU coreutils does for
 * every entry of `ls -l /proc/self/`, and the magic-link fixups used to be
 * reached only for an absolute name or AT_FDCWD — so this spelling was handed
 * to the kernel and answered with the HOST path: the monitor's own binary for
 * "exe", and for "cwd" where the rootfs lives on the device. Both must read
 * exactly as the absolute spelling does. */
static void at_links(void) {
    char buf[4096];
    int d = open("/proc/self", O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        printf("at_exe=(no dirfd)\nat_cwd=(no dirfd)\n");
        return;
    }
    ssize_t n = readlinkat(d, "exe", buf, sizeof buf - 1);
    buf[n > 0 ? n : 0] = '\0';
    printf("at_exe=%s\n", n > 0 ? buf : "(readlinkat failed)");
    n = readlinkat(d, "cwd", buf, sizeof buf - 1);
    buf[n > 0 ? n : 0] = '\0';
    printf("at_cwd=%s\n", n > 0 ? buf : "(readlinkat failed)");
    close(d);
}

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
    at_links();

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
