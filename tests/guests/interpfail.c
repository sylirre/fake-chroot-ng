/* A failed exec has to leave the calling program running.
 *
 * A binary whose PT_INTERP names a file that is not there is the ordinary way
 * an exec fails inside a partially populated rootfs — a tree without the loader
 * its binaries were linked against, a musl program under glibc — and the kernel
 * answers it with ENOENT to a caller that is still running: it opens and
 * validates the ELF interpreter before it touches the old address space.
 *
 * chroot-ng mapped the program first and looked for the interpreter afterwards.
 * An ET_EXEC image goes down MAP_FIXED at its link-time vaddr, which for two
 * binaries out of one toolchain is the caller's own text — so the errno was
 * handed back to a program whose code had just been replaced, and what the shell
 * saw was a segfault where the kernel gives an errno and a live process.
 *
 * argv[1] is the target to exec, named per side: the differential runs this
 * built for the host (the kernel's own answer) and built for AArch64 (ours).
 * After the failure it proves it can still run — a call into .text and a read of
 * .rodata, neither of which survives having the image overwritten.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static const char probe[] = "still-here";

__attribute__((noinline)) static int checksum(void) {
    int s = 0;
    for (const char *p = probe; *p; p++)
        s += *p;
    return s;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: interpfail TARGET\n");
        return 2;
    }
    char *av[] = {argv[1], 0};
    errno = 0;
    execv(argv[1], av);
    printf("exec=%s\n", errno == ENOENT    ? "ENOENT"
                        : errno == EACCES  ? "EACCES"
                        : errno == ENOEXEC ? "ENOEXEC"
                        : errno == EIO     ? "EIO"
                                           : "other");
    printf("alive=1 sum=%d\n", checksum());
    fflush(stdout);
    return 44;
}
