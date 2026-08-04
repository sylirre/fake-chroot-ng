/* The shm corner cases that are easy to get subtly wrong, each printed as the
 * errno name so the emulation and the real thing can be diffed.
 *
 * Three of these caught real divergences when this was ported:
 *   - SHM_EXEC is a *permission* request, not just a mapping flag: attaching a
 *     0600 segment with it must fail EACCES (no execute bit), the way the
 *     kernel checks S_IXUGO. The broker's permission triad had no execute leg.
 *   - SHM_LOCK/SHM_UNLOCK succeed for the segment's owner. arm64chroot answers
 *     EINVAL; there is nothing to pin here, but refusing is the wrong answer.
 *   - SHM_RND turns an unaligned address into a rounded one, so the failure
 *     that follows is EPERM from the mapping, not EINVAL from the check.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* SHM_EXEC, SHM_LOCK */
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static const char *r_of(void *r) {
    return r == (void *)-1 ? strerror(errno) : "ok";
}

int main(void) {
    int id = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    if (id < 0) { perror("shmget"); return 1; }
    void *r;

    /* SHM_REMAP with no address: nothing to replace, so it is a plain attach. */
    r = shmat(id, NULL, SHM_REMAP);
    printf("remap_no_addr=%s\n", r_of(r));
    if (r != (void *)-1) shmdt(r);

    /* An unaligned address is refused; with SHM_RND it is rounded down first
     * (and then fails on its own merits — page 0 is not mappable). */
    printf("unaligned=%s\n", r_of(shmat(id, (void *)0x1234, 0)));
    r = shmat(id, (void *)0x1234, SHM_RND);
    printf("unaligned_rnd=%s\n", r_of(r));
    if (r != (void *)-1) shmdt(r);

    /* SHM_EXEC needs execute permission on the segment, which 0600 lacks. */
    r = shmat(id, NULL, SHM_RDONLY | SHM_EXEC);
    printf("rdonly_exec=%s\n", r_of(r));
    if (r != (void *)-1) shmdt(r);

    printf("shmdt_bogus=%s\n", shmdt((void *)0x1234) < 0 ? strerror(errno) : "ok");
    printf("shmctl_bad_cmd=%s\n", shmctl(id, 99, NULL) < 0 ? strerror(errno) : "ok");
    printf("shmctl_lock=%s\n", shmctl(id, SHM_LOCK, NULL) < 0 ? strerror(errno) : "ok");
    printf("shmctl_unlock=%s\n", shmctl(id, SHM_UNLOCK, NULL) < 0 ? strerror(errno) : "ok");

    /* An executable segment: SHM_EXEC is then permitted. */
    int x = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0700);
    r = shmat(x, NULL, SHM_EXEC);
    printf("exec_mode_attach=%s\n", r_of(r));
    if (r != (void *)-1) shmdt(r);
    shmctl(x, IPC_RMID, NULL);

    /* Sizes no mapping could represent. The page round-up wraps to 0 for
     * anything within a page of 2^64; substituting one page for it (which is
     * what the emulation used to do) hands the guest a mapping far shorter than
     * the segment it asked for, and every later shmdt then computes a length
     * from a record that never matched. The kernel refuses the size outright,
     * so the answer is an errno on both sides. */
    for (size_t i = 0; i < 3; i++) {
        static const size_t szs[3] = {(size_t)-1, (size_t)-4096, 0};
        static const char *const nm[3] = {"max", "nearmax", "zero"};
        int h = shmget(IPC_PRIVATE, szs[i], IPC_CREAT | 0600);
        printf("shmget_%s=%s\n", nm[i], h < 0 ? strerror(errno) : "ok");
        if (h >= 0)
            shmctl(h, IPC_RMID, NULL);
    }

    shmctl(id, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}
