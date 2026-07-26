/* shmctl SHM_INFO + SHM_STAT: the enumeration path ipcs(1) uses. Create a
 * segment, then walk the id array via SHM_INFO (highest index) + SHM_STAT (by
 * index) and confirm we rediscover our own segment with the right size and
 * creator pid. Only booleans are printed — never counts, ids or addresses,
 * which differ between the host's global SysV namespace and chroot-ng's
 * per-invocation one — so this matches the real kernel byte for byte.
 *
 * Ported from arm64chroot's tests/c/shm_stat.c.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* SHM_INFO/SHM_STAT + struct shm_info (glibc __USE_MISC) */
#endif
#include <stdio.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(void) {
    const size_t SZ = 12288;   /* 3 pages: a distinctive size to match on */
    int myid = shmget(IPC_PRIVATE, SZ, IPC_CREAT | 0600);
    if (myid < 0) { perror("shmget"); return 1; }

    struct shm_info info;
    int maxid = shmctl(0, SHM_INFO, (struct shmid_ds *)&info);
    if (maxid < 0) { printf("shm_info_failed\n"); shmctl(myid, IPC_RMID, 0); return 1; }

    int found = 0, size_ok = 0, cpid_ok = 0;
    for (int i = 0; i <= maxid; i++) {
        struct shmid_ds ds;
        int id = shmctl(i, SHM_STAT, &ds);   /* perm-checked; skips ones we can't read */
        if (id < 0) continue;
        if (id == myid) {
            found = 1;
            size_ok = (ds.shm_segsz == SZ);
            cpid_ok = (ds.shm_cpid == getpid());
        }
    }
    printf("found=%d size_ok=%d cpid_ok=%d\n", found, size_ok, cpid_ok);

    shmctl(myid, IPC_RMID, 0);
    printf("done\n");
    return 0;
}
