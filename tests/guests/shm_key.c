/* Keyed segment across two independent chroot-ng invocations, to pin down the
 * shm namespace's scope (tests/m12_shm.sh).
 *
 * By default a namespace is per invocation: a segment one launch creates by key
 * must be invisible to the next, the way two containers do not share IPC.
 * --shared-proc widens the namespace to the rootfs — the same switch that makes
 * one invocation's guest processes visible to another — so there the second
 * launch must find the segment and read what the first stored.
 *
 *   shm_key <hexkey> create <text>   create it and store <text>
 *   shm_key <hexkey> find            print found=0|1 and, if found, the text
 *   shm_key <hexkey> rmid            remove it if it exists (test cleanup)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sysvipc.h"

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    key_t key = (key_t)strtoul(argv[1], NULL, 16);
    const char *mode = argv[2];
    const size_t SZ = 4096;

    int creat = strcmp(mode, "create") == 0 ? (IPC_CREAT | 0600) : 0;
    int id = shmget(key, SZ, creat);
    if (id < 0) {
        printf("found=0\n");
        return strcmp(mode, "find") == 0 ? 0 : 1;
    }
    if (strcmp(mode, "rmid") == 0) {
        shmctl(id, IPC_RMID, NULL);
        printf("removed\n");
        return 0;
    }
    char *p = shmat(id, NULL, 0);
    if (p == (char *)-1) { perror("shmat"); return 1; }
    if (creat) {
        snprintf(p, SZ, "%s", argc > 3 ? argv[3] : "");
        printf("created\n");
    } else {
        printf("found=1 text=%s\n", p);
    }
    shmdt(p);
    return 0;
}
