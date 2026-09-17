/* The path-resolution race (M49).
 *
 * The monitor walks a guest name to a host path and then makes the syscall
 * on that host path, which the kernel resolves again from scratch. Between
 * the two a directory on the way can be swapped for an absolute symlink, and
 * the second resolution then follows it from the HOST root: the call lands
 * outside the rootfs.
 *
 * Two threads. The flipper turns /w/d back and forth between a real directory
 * (holding files with guest contents) and a symlink to HOST, an absolute host
 * path handed in by the harness — to the guest that symlink names nothing
 * (the target is re-rooted into the rootfs), so a call that ever reaches
 * HOST's files went through the race. The caller loops over the path-bearing
 * families and counts what each answered: the guest's contents, the host's,
 * or an error (ENOENT/ELOOP while the flip is in flight). Any host answer is
 * the escape. The mutating calls are aimed at names that exist only on the
 * host side — a success IS the host answer — and leave their mark on HOST
 * for the harness to read back after the run: a file unlinked, a directory
 * removed or made, a file truncated, a directory chdir'd into.
 *
 *   pathrace HOST SECONDS
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

static const char *host;
static volatile int stop;

static void *flipper(void *arg) {
    (void)arg;
    while (!stop) {
        rename("/w/d", "/w/d2");
        if (symlink(host, "/w/d") < 0 && errno != EEXIST)
            continue;
        unlink("/w/d");
        rename("/w/d2", "/w/d");
    }
    return 0;
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* The guest's file says "guest", the host's says "host". */
static int classify_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 2;
    char b[16];
    ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n <= 0)
        return 2;
    b[n] = '\0';
    return strncmp(b, "guest", 5) == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: pathrace HOST SECONDS\n");
        return 2;
    }
    host = argv[1];
    double budget = atof(argv[2]);
    pthread_t t;
    pthread_create(&t, 0, flipper, 0);

    /* [family][answer]: 0 guest, 1 host, 2 error */
    long n[9][3] = {{0}};
    double t0 = now();
    long iter = 0;
    while (now() - t0 < budget) {
        int k = (int)(iter++ % 9);
        int cls;
        struct stat st;
        char lb[32], cwd[64];
        switch (k) {
        case 0: /* open + read */
            cls = classify_read("/w/d/x");
            break;
        case 1: /* stat: the sizes differ, "guest\n" against "host\n" */
            cls = stat("/w/d/x", &st) ? 2 : st.st_size == 6 ? 0 : 1;
            break;
        case 2: /* readlink: the guest's link says GUEST, the host's HOST */
            cls = readlink("/w/d/lnk", lb, sizeof lb - 1);
            if (cls < 0)
                cls = 2;
            else {
                lb[cls] = '\0';
                cls = strcmp(lb, "GUEST") == 0 ? 0 : 1;
            }
            break;
        case 3: /* access: the guest's is executable, the host's is not */
            cls = access("/w/d/x", X_OK) == 0 ? 0 : errno == EACCES ? 1 : 2;
            break;
        case 4: /* unlink: only HOST has a victim, which must survive */
            cls = unlink("/w/d/victim") == 0 ? 1 : errno == ENOENT ? 0 : 2;
            break;
        case 5: /* rmdir: only HOST has a hostdir */
            cls = rmdir("/w/d/hostdir") == 0 ? 1 : errno == ENOENT ? 0 : 2;
            break;
        case 6: /* mkdir under a directory only HOST has */
            cls = mkdir("/w/d/hostdir/made", 0755) == 0 ? 1
                  : errno == ENOENT                    ? 0
                                                       : 2;
            break;
        case 7: /* truncate: only HOST has a big, which must keep its size */
            cls = truncate("/w/d/big", 1) == 0 ? 1 : errno == ENOENT ? 0 : 2;
            break;
        default: /* chdir: only HOST has a sub */
            cls = chdir("/w/d/sub") == 0 ? 1 : errno == ENOENT ? 0 : 2;
            if (cls == 1 && getcwd(cwd, sizeof cwd))
                n[8][2] += strncmp(cwd, "/w/", 3) != 0; /* and told the truth */
            if (chdir("/") < 0)
                cls = 2;
            break;
        }
        n[k][cls]++;
    }
    stop = 1;
    pthread_join(t, 0);
    /* Leave the tree as it was found. */
    rename("/w/d2", "/w/d");
    unlink("/w/d");

    long host_hits = 0, guest_hits = 0, errs = 0;
    for (int k = 0; k < 9; k++) {
        guest_hits += n[k][0];
        host_hits += n[k][1];
        errs += n[k][2];
    }
    printf("pathrace: iters=%ld guest=%ld host=%ld err=%ld [open=%ld stat=%ld "
           "readlink=%ld access=%ld unlink=%ld rmdir=%ld mkdir=%ld "
           "truncate=%ld chdir=%ld]\n",
           iter, guest_hits, host_hits, errs, n[0][1], n[1][1], n[2][1],
           n[3][1], n[4][1], n[5][1], n[6][1], n[7][1], n[8][1]);
    return 0;
}
