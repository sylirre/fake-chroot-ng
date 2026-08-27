/* The two fixed-size tables System V shared memory is tracked in, asked to hold
 * more than they were sized for (tests/m12_shm.sh).
 *
 * Neither limit exists in the kernel, so both show up as a divergence rather
 * than as an error:
 *
 *  - the per-process attach list, which is what shmdt(addr) resolves an address
 *    back to a shmid and a length with, and what an exec detaches from. An
 *    attach it had no room for was simply not recorded, so shmdt of it answered
 *    EINVAL — a detach the kernel performs.
 *
 *  - the broker's per-segment list of attaching processes, which is how an
 *    attach held by a process that dies without detaching is reclaimed. An
 *    attacher it had no room for left its count on nattch for good, so a guest
 *    reading nattch after waitpid() saw attachments belonging to processes that
 *    no longer exist.
 *
 * Both are asked with more than the old caps (128 attachments, 32 attaching
 * processes) and with numbers a real kernel is happy to give: SHMSEG is not
 * enforced on Linux, and one segment can be attached by as many processes as
 * there are.
 *
 * The output is counts only — no ids, addresses or pids — so it can be diffed
 * byte for byte against the same program run with no emulation under it.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sysvipc.h"

#define NATT  200 /* attachments of one segment, in one process */
#define NPROC 40  /* processes attaching one segment */

int main(void) {
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (id < 0) {
        printf("shmget: e=%d\n", errno);
        return 1;
    }

    /* 1) one segment, attached many times over. Every address must come back
     *    out of the table when it is detached. */
    static void *at[NATT];
    int nat = 0;
    for (int i = 0; i < NATT; i++) {
        void *p = shmat(id, NULL, 0);
        if (p == (void *)-1)
            break;
        at[nat++] = p;
    }
    int ndt = 0;
    for (int i = 0; i < nat; i++)
        if (shmdt(at[i]) == 0)
            ndt++;
    printf("attach: n=%d detached=%d\n", nat, ndt);

    /* 2) one segment, attached by many processes that then die without
     *    detaching. Once they are all reaped, nothing of theirs may be left on
     *    nattch — the parent's own attach is all that is. */
    void *keep = shmat(id, NULL, 0);
    if (keep == (void *)-1) {
        printf("keep: e=%d\n", errno);
        shmctl(id, IPC_RMID, NULL);
        return 1;
    }
    int forked = 0;
    for (int i = 0; i < NPROC; i++) {
        pid_t p = fork();
        if (p == 0) {
            void *q = shmat(id, NULL, 0);
            _exit(q == (void *)-1 ? 1 : 0);
        }
        if (p < 0)
            break;
        forked++;
        int st;
        waitpid(p, &st, 0);
    }
    struct shmid_ds ds;
    memset(&ds, 0, sizeof ds);
    int rc = shmctl(id, IPC_STAT, &ds);
    printf("procs: forked=%d rc=%d nattch=%ld\n", forked, rc,
           rc == 0 ? (long)ds.shm_nattch : -1L);

    shmdt(keep);
    shmctl(id, IPC_RMID, NULL);
    return 0;
}
