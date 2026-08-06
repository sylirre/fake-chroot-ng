/* A keyed semaphore set and message queue across two independent chroot-ng
 * invocations, to pin the sem/msg namespace's scope (tests/m20_sysvipc.sh).
 *
 * The counterpart to shm_key.c, and the one part of this milestone with nothing
 * to diff against: the host kernel has exactly one IPC namespace here, so only
 * the emulation can be asked whether two launches share one. By default they do
 * not — a set one launch creates by key must be invisible to the next, the way
 * two containers do not share IPC. --shared-proc widens the namespace to the
 * rootfs, the same switch that makes one invocation's guest processes visible to
 * another, and there the second launch must find the set and read the value the
 * first left in it.
 *
 *   sem_key <hexkey> create <n>   create the set and the queue, store <n>
 *   sem_key <hexkey> find         print found=0|1 and, if found, the value
 *   sem_key <hexkey> rmid         remove both if they exist (test cleanup)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include "sysvipc.h"

int main(int argc, char **argv) {
    if (argc < 3)
        return 2;
    key_t key = (key_t)strtoul(argv[1], NULL, 16);
    const char *mode = argv[2];
    int creat = strcmp(mode, "create") == 0 ? (IPC_CREAT | 0600) : 0;

    int sid = semget(key, 1, creat);
    int qid = msgget(key, creat);
    if (sid < 0 || qid < 0) {
        printf("found=0\n");
        return strcmp(mode, "find") == 0 ? 0 : 1;
    }
    if (strcmp(mode, "rmid") == 0) {
        semctl(sid, 0, IPC_RMID);
        msgctl(qid, IPC_RMID, NULL);
        printf("removed\n");
        return 0;
    }

    struct {
        long mtype;
        char t[16];
    } m;
    if (creat) {
        union cng_semun u;
        u.val = argc > 3 ? atoi(argv[3]) : 0;
        semctl(sid, 0, SETVAL, u);
        m.mtype = 1;
        snprintf(m.t, sizeof m.t, "%s", argc > 3 ? argv[3] : "");
        msgsnd(qid, &m, sizeof m.t, 0);
        printf("created\n");
        return 0;
    }
    memset(&m, 0, sizeof m);
    int n = (int)msgrcv(qid, &m, sizeof m.t, 0, IPC_NOWAIT);
    printf("found=1 val=%d msg=%s\n", semctl(sid, 0, GETVAL),
           n > 0 ? m.t : "(none)");
    return 0;
}
