/* System V shared memory from a real guest program, checked against the host
 * kernel's own SysV shm (the same binary run straight under qemu-aarch64).
 *
 * Ported from arm64chroot's tests/c/shm_sysv.c, which was written for exactly
 * this comparison. It prints only *semantic* outcomes — never shmids, attach
 * addresses or timestamps — so chroot-ng's broker-backed emulation (src/monitor/
 * shm.c, no host SysV IPC at all) and the real kernel produce byte-identical
 * output. tests/m12_shm.sh also re-runs it with CNG_SHM_FORCE_FILE=1 to cover
 * the file-backed backing tier.
 *
 * Buffering note: stdout is block-buffered when captured (not a tty), so the
 * parent flushes before fork() and the child flushes before _exit() — otherwise
 * the child would inherit and re-emit the parent's buffered lines.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>

int main(void) {
    const size_t SZ = 8192;

    int id = shmget(IPC_PRIVATE, SZ, IPC_CREAT | 0600);
    if (id < 0) { perror("shmget"); return 1; }

    char *p = shmat(id, NULL, 0);
    if (p == (char *)-1) { perror("shmat"); return 1; }

    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) < 0) { perror("IPC_STAT"); return 1; }
    printf("segsz_ok=%d nattch=%lu\n",
           (int)(ds.shm_segsz == SZ), (unsigned long)ds.shm_nattch);

    strcpy(p, "parent-wrote-this");

    fflush(stdout);                 /* empty the buffer before it is forked */
    pid_t pid = fork();
    if (pid == 0) {                 /* child inherits the attachment (shared) */
        printf("child_reads=%s\n", p);
        strcpy(p, "child-wrote-this");
        fflush(stdout);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    printf("parent_reads=%s\n", p); /* sees the child's store: same memory */

    if (shmctl(id, IPC_STAT, &ds) < 0) { perror("IPC_STAT 2"); return 1; }
    printf("nattch_after_child=%lu\n", (unsigned long)ds.shm_nattch);

    if (shmdt(p) < 0) { perror("shmdt"); return 1; }
    if (shmctl(id, IPC_RMID, NULL) < 0) { perror("IPC_RMID"); return 1; }

    /* Removed with no attachers: re-attaching by that id must now fail. */
    char *q = shmat(id, NULL, 0);
    printf("attach_after_rmid=%s\n", q == (char *)-1 ? "EINVAL" : "unexpected-ok");
    if (q != (char *)-1) shmdt(q);

    /* Keyed lookup. A per-pid key avoids colliding with a leftover segment in
     * the host namespace when this runs against the real kernel; only the
     * semantic result is printed. */
    key_t key = (key_t)(0x51000000 + (getpid() & 0xffffff));
    int a = shmget(key, SZ, IPC_CREAT | 0600);
    int b = shmget(key, SZ, 0);
    printf("keyed_same=%d\n", (int)(a >= 0 && a == b));
    int e = shmget(key, SZ, IPC_CREAT | IPC_EXCL | 0600);
    printf("excl_refused=%d\n", (int)(e == -1));
    if (a >= 0) shmctl(a, IPC_RMID, NULL);

    printf("done\n");
    return 0;
}
