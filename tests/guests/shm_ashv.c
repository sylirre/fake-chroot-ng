/* The guest half of the libandroid-shmem leg (tests/m12_shm.sh).
 *
 * Termux's X servers attach a client's segment through libandroid-shmem, not
 * the kernel: the shmid's high half names the creator's "/dev/shm/%08x"
 * socket, which hands the backing over. This makes a segment the way an X
 * client does (0600, cairo's mode), stores a string in it, publishes the id in
 * DIR/id and waits for DIR/done -- written once ashv_attach, a host process
 * outside chroot-ng, has read the string and written its own -- then prints
 * what it finds.
 *
 *   shm_ashv DIR
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#include "sysvipc.h"

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    if (id < 0) {
        printf("guest: shmget errno=%d\n", errno);
        return 1;
    }
    char *p = shmat(id, NULL, 0);
    if (p == (char *)-1) {
        printf("guest: shmat errno=%d\n", errno);
        return 1;
    }
    strcpy(p, "guest-wrote-this");

    char path[512], tmp[512];
    snprintf(path, sizeof path, "%s/id", argv[1]);
    snprintf(tmp, sizeof tmp, "%s/id.tmp", argv[1]);
    FILE *f = fopen(tmp, "w");
    if (!f || fprintf(f, "%d\n", id) < 0 || fclose(f) != 0 ||
        rename(tmp, path) != 0) {
        printf("guest: cannot publish the id\n");
        return 1;
    }

    /* Bounded: a host side that never finishes must not wedge the suite. */
    snprintf(path, sizeof path, "%s/done", argv[1]);
    struct timespec ms = {0, 10 * 1000 * 1000};
    for (int i = 0; i < 3000 && access(path, F_OK) != 0; i++)
        nanosleep(&ms, NULL);
    printf("guest: id-positive=%d back=%s\n", id > 0, p);
    shmctl(id, IPC_RMID, NULL);
    shmdt(p);
    return 0;
}
