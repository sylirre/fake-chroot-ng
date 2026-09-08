/* POSIX shared memory, which is /dev/shm and nothing else (tests/m12_shm.sh).
 *
 * shm_open() is an open() under /dev/shm with the name validated and a slash
 * required; there is no syscall behind it and no kernel object other than the
 * file. So a guest gets working POSIX shm exactly when it has a writable
 * /dev/shm — which on Android it does not, there being no such directory on the
 * host at all. chroot-ng serves one from under $TMPDIR there, and this is the
 * program that says whether a real libc agrees.
 *
 * Everything is done twice over: created and mapped, then reopened *by name*
 * and read back through a second mapping, which a plain file in a plain
 * directory could not fake — the name has to resolve to the same object. Then
 * unlinked, and the reopen that must fail.
 *
 * Prints one line per step so a diff against the same program run with no
 * emulation under it is exact.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define NAME "/cng_shm_posix"
#define SIZE 4096
#define PAYLOAD "POSIX-SHM-OK"

int main(void) {
    shm_unlink(NAME); /* a previous run that died before its own unlink */

    int fd = shm_open(NAME, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        printf("posix: shm_open errno=%d\n", errno);
        return 1;
    }
    printf("posix: created\n");

    if (ftruncate(fd, SIZE) != 0) {
        printf("posix: ftruncate errno=%d\n", errno);
        return 2;
    }
    char *p = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        printf("posix: mmap errno=%d\n", errno);
        return 3;
    }
    memcpy(p, PAYLOAD, sizeof PAYLOAD);

    /* The name, not the descriptor: this is the half that needs a directory. */
    int fd2 = shm_open(NAME, O_RDONLY, 0);
    if (fd2 < 0) {
        printf("posix: reopen errno=%d\n", errno);
        return 4;
    }
    struct stat st;
    if (fstat(fd2, &st) != 0 || st.st_size != SIZE) {
        printf("posix: size %ld\n", fstat(fd2, &st) ? -1L : (long)st.st_size);
        return 5;
    }
    char *q = mmap(0, SIZE, PROT_READ, MAP_SHARED, fd2, 0);
    if (q == MAP_FAILED) {
        printf("posix: remap errno=%d\n", errno);
        return 6;
    }
    printf("posix: read %s\n", q);

    munmap(p, SIZE);
    munmap(q, SIZE);
    close(fd);
    close(fd2);

    if (shm_unlink(NAME) != 0) {
        printf("posix: unlink errno=%d\n", errno);
        return 7;
    }
    int gone = shm_open(NAME, O_RDONLY, 0);
    printf("posix: after-unlink %s\n", gone < 0 ? "gone" : "still-there");
    if (gone >= 0)
        close(gone);
    printf("posix: done\n");
    return 0;
}
