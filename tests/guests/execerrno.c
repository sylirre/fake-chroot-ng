/* What an exec that fails answers (M6).
 *
 * Every way of failing used to collapse into two answers — ENOENT if the file
 * could not be opened, ENOEXEC otherwise, and ENOENT for anything about the
 * ELF interpreter. The kernel distinguishes five, and the two roles do not
 * answer alike; the table is in exec_load_errno (src/monitor/execve.c), all of
 * it measured on the host.
 *
 * argv[1..] are guest paths to exec, each a program broken in one way. Prints
 * one line per attempt: the name it was given and the errno. Nothing here ever
 * execs successfully, so the output is the whole result and is byte-comparable
 * against a run with no chroot-ng in the way — on a host that can run the guest
 * directly. Under qemu-user it cannot be: qemu re-execs itself for an exec,
 * so a broken interpreter is its own loader's complaint rather than the
 * kernel's answer.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        char *a[] = {argv[i], 0};
        errno = 0;
        execv(argv[i], a);
        /* Only reached because it failed: an exec that works never returns. */
        printf("%s -> %d\n", strrchr(argv[i], '/') ? strrchr(argv[i], '/') + 1
                                                   : argv[i],
               errno);
        fflush(stdout);
    }
    return 0;
}
