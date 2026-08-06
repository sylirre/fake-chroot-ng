/* System V shm across execve, checked against the real kernel.
 *
 * A real execve replaces the address space, so every attachment goes with it.
 * chroot-ng's execve is emulated in-process and keeps the address space, so it
 * has to drop them explicitly (cng_shm_detach_all, called at the commit point
 * in src/monitor/execve.c) — this is the guest-level check that it does.
 *
 *   shm_exec            create a segment, attach it, then exec ourselves
 *   shm_exec <shmid>    report the attach count we were left with, then clean up
 *
 * Prints only counts, never the shmid, so the emulation and the real kernel
 * produce identical output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sysvipc.h"

int main(int argc, char **argv) {
    struct shmid_ds ds;

    if (argc > 1) { /* the exec'd image: our attach must be gone */
        int id = atoi(argv[1]);
        if (shmctl(id, IPC_STAT, &ds) < 0) { perror("IPC_STAT after exec"); return 1; }
        printf("nattch_after_exec=%lu\n", (unsigned long)ds.shm_nattch);
        shmctl(id, IPC_RMID, NULL);
        printf("done\n");
        return 0;
    }

    int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    if (id < 0) { perror("shmget"); return 1; }
    char *p = shmat(id, NULL, 0);
    if (p == (char *)-1) { perror("shmat"); shmctl(id, IPC_RMID, NULL); return 1; }
    if (shmctl(id, IPC_STAT, &ds) < 0) { perror("IPC_STAT"); return 1; }
    printf("nattch_before_exec=%lu\n", (unsigned long)ds.shm_nattch);

    char idbuf[32];
    snprintf(idbuf, sizeof idbuf, "%d", id);
    fflush(stdout); /* the exec'd image must not re-emit our buffer */
    execl(argv[0], argv[0], idbuf, (char *)NULL);
    perror("execl");
    shmctl(id, IPC_RMID, NULL);
    return 1;
}
