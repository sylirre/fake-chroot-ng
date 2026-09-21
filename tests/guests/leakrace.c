/* Host data passing through a guest buffer (M7/M11).
 *
 * Three answers the monitor rewrites after the kernel has produced them: an
 * fd link's target (readlinkat, a host path), a /proc listing (getdents64,
 * the host's pids) and a peer's credentials (SO_PEERCRED, the real uid). Each
 * used to be produced by the kernel straight into the guest's buffer and
 * corrected there a syscall later, so for that interval the host's answer sat
 * in the guest's memory. This guest runs the call on one thread and, on
 * another, scans the buffer the whole time for what must never be in it,
 * counting the times it was.
 *
 *   leakrace readlink FD_PATH NEEDLE   readlink /proc/self/fd/N of a file
 *                                      opened at FD_PATH; NEEDLE is a piece of
 *                                      the HOST spelling (the test knows where
 *                                      the rootfs is) that no guest path holds
 *   leakrace dents                     getdents64 of /proc; a numeric name that
 *                                      is not our own pid is a host process
 *   leakrace peercred UID              SO_PEERCRED on a socketpair under a fake
 *                                      identity; UID is the real one, which
 *                                      the remap must never let through
 *
 * Prints "leakrace MODE: iters=N leaks=M" and exits 0; the leg asserts M == 0.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Bounded twice over: at most this many calls, and at most a few seconds of
 * them — a /proc listing under an emulator runs to milliseconds a call. */
#define ITERS 20000
#define SECONDS 3

static volatile int stop;
static volatile unsigned char buf[65536];
static const char *needle;
static unsigned bad_uid;
static long self_pid;
static long leaks;

/* Does the buffer, as it stands this instant, carry the needle? Read once per
 * scan into a private copy so the comparison is against one snapshot. */
static int scan_readlink(void) {
    char snap[4096];
    memcpy(snap, (const void *)buf, sizeof snap);
    snap[sizeof snap - 1] = 0;
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= sizeof snap; i++)
        if (!memcmp(snap + i, needle, nl))
            return 1;
    return 0;
}

static int scan_dents(void) {
    unsigned char snap[sizeof buf];
    memcpy(snap, (const void *)buf, sizeof snap);
    size_t o = 0;
    while (o + 19 < sizeof snap) {
        unsigned short reclen;
        memcpy(&reclen, snap + o + 16, 2);
        if (reclen < 19 || o + reclen > sizeof snap)
            break;
        const char *nm = (const char *)snap + o + 19;
        if (*nm >= '0' && *nm <= '9') {
            long pid = strtol(nm, 0, 10);
            if (pid != self_pid)
                return 1;
        }
        o += reclen;
    }
    return 0;
}

static int scan_peercred(void) {
    unsigned uid;
    memcpy(&uid, (const void *)(buf + 4), sizeof uid);
    return uid == bad_uid;
}

static void *scanner(void *arg) {
    int (*scan)(void) = arg;
    while (!stop)
        leaks += scan();
    return 0;
}

static int more(long iters) {
    static struct timespec t0;
    struct timespec now;
    if (!t0.tv_sec)
        clock_gettime(CLOCK_MONOTONIC, &t0);
    clock_gettime(CLOCK_MONOTONIC, &now);
    return iters < ITERS && now.tv_sec - t0.tv_sec < SECONDS;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: leakrace readlink FD_PATH NEEDLE | dents | peercred UID\n");
        return 2;
    }
    self_pid = getpid();
    pthread_t t;
    long iters = 0;
    if (!strcmp(argv[1], "readlink") && argc >= 4) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) {
            printf("leakrace: open %s failed\n", argv[2]);
            return 1;
        }
        needle = argv[3];
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
        pthread_create(&t, 0, scanner, scan_readlink);
        for (; more(iters); iters++)
            if (readlink(link, (char *)buf, 4096) < 0)
                break;
    } else if (!strcmp(argv[1], "dents")) {
        int fd = open("/proc", O_RDONLY | O_DIRECTORY);
        if (fd < 0) {
            printf("leakrace: open /proc failed\n");
            return 1;
        }
        pthread_create(&t, 0, scanner, scan_dents);
        for (; more(iters); iters++) {
            lseek(fd, 0, SEEK_SET);
            if (syscall(SYS_getdents64, fd, buf, sizeof buf) < 0)
                break;
        }
    } else if (!strcmp(argv[1], "peercred") && argc >= 3) {
        bad_uid = (unsigned)strtoul(argv[2], 0, 10);
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            printf("leakrace: socketpair failed\n");
            return 1;
        }
        pthread_create(&t, 0, scanner, scan_peercred);
        for (; more(iters); iters++) {
            socklen_t l = 12;
            if (getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, (void *)buf, &l) != 0)
                break;
        }
    } else {
        printf("leakrace: bad arguments\n");
        return 2;
    }
    stop = 1;
    pthread_join(t, 0);
    printf("leakrace %s: iters=%ld leaks=%ld\n", argv[1], iters, leaks);
    return 0;
}
