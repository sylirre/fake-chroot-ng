/* A Termux process attaching a guest's segment, for the libandroid-shmem leg
 * (tests/m12_shm.sh). Built against Termux's libandroid-shmem and run outside
 * chroot-ng: its shmat is the one Termux's X servers make (termux-x11 embeds a
 * copy, Xvfb and Xvnc link it), so this is the consumer itself rather than a
 * reading of its protocol. Reads what the guest stored, makes the IPC_STAT an
 * X server makes next, writes a reply and detaches.
 *
 *   ashv_attach SHMID
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    int id = atoi(argv[1]);
    char *p = shmat(id, NULL, 0);
    if (p == (char *)-1) {
        printf("host: shmat errno=%d\n", errno);
        return 1;
    }
    struct shmid_ds ds;
    int st = shmctl(id, IPC_STAT, &ds);
    printf("host: saw=%s stat=%d size-ok=%d\n", p, st,
           st == 0 && ds.shm_segsz >= 8192);
    strcpy(p, "host-wrote-this");
    shmdt(p);
    return 0;
}
