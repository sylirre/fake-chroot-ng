/* Reads /etc/greeting and writes it to stdout. Used to prove that the guest's
 * own openat is translated into the rootfs — under qemu this works only via M8
 * svc-rewriting (seccomp is inert there). */
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/greeting", O_RDONLY);
    if (fd < 0) {
        write(2, "OPEN-FAIL\n", 10);
        return 3;
    }
    char b[64];
    long n = read(fd, b, sizeof b);
    if (n > 0)
        write(1, b, n);
    close(fd);
    return 0;
}
