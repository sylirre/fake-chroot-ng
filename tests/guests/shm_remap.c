/* SHM_REMAP: attaching over an address that already carries an attachment.
 *
 * What is mapped there is replaced, so the attachment that was there is gone —
 * and the bookkeeping has to follow, or shmdt() resolves the address to the one
 * no longer present: it unmaps that entry's length instead of the new mapping's
 * (punching a hole in a live attachment) and detaches the wrong segment, whose
 * nattch then never reaches zero.
 *
 * Two shapes, which the kernel treats differently:
 *   - a full cover closes the replaced VMA, so the old segment's nattch drops
 *     at remap time and the later shmdt detaches the new segment;
 *   - a partial cover *splits* it, so the old segment keeps its nattch, the
 *     address resolves to the new mapping, and the orphaned tail stays mapped
 *     and can never be detached.
 *
 * This is a host-native differential, not a qemu one. Measured with no
 * chroot-ng in the picture: qemu-aarch64 answers the partial case with
 * nattch 0 and the whole range unmapped, where the kernel keeps nattch and
 * leaves the tail — qemu tracks attachments in a table of its own keyed by
 * start address and detaches the whole recorded region, which is the same
 * mistake under test here. So the reference side is built for the host, as M18
 * does for ptrace and M22 for msgsnd.
 *
 * Everything happens inside a reserved window, so a MAP_FIXED attach cannot
 * land on anything of this program's own. Only booleans, return codes and
 * nattch counts are printed — never an address or an id.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "sysvipc.h"

static const char *r_of(void *r) {
    return r == (void *)-1 ? strerror(errno) : "ok";
}

static long nattch(int id) {
    struct shmid_ds d;
    return shmctl(id, IPC_STAT, &d) == 0 ? (long)d.shm_nattch : -1;
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    void *res =
        mmap(0, 1u << 20, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *X = res == MAP_FAILED
                  ? 0
                  : (void *)(((unsigned long)res + 0xffffUL) & ~0xffffUL);
    int small = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    int big = shmget(IPC_PRIVATE, 65536, IPC_CREAT | 0600);
    unsigned char v;

    printf("base=%s ids=%d\n", X ? "ok" : "no-reservation",
           small >= 0 && big >= 0);
    if (!X || small < 0 || big < 0)
        return 1;

    /* Cover: one page of `small`, then all 16 pages of `big` over it. */
    printf("cover_a=%s\n", r_of(shmat(small, X, SHM_REMAP)));
    printf("cover_a_natt=%ld/%ld\n", nattch(small), nattch(big));
    printf("cover_b=%s\n", r_of(shmat(big, X, SHM_REMAP)));
    printf("cover_b_natt=%ld/%ld\n", nattch(small), nattch(big));
    printf("cover_dt=%d\n", shmdt(X));
    printf("cover_dt_natt=%ld/%ld\n", nattch(small), nattch(big));
    /* The whole 64 KiB has to be gone, not just the first page. */
    printf("cover_mapped=%d%d\n", mincore(X, 4096, &v) == 0,
           mincore((char *)X + 4096, 4096, &v) == 0);

    /* Partial: `big`, then one page of `small` over its front. */
    printf("part_a=%s\n", r_of(shmat(big, X, SHM_REMAP)));
    printf("part_b=%s\n", r_of(shmat(small, X, SHM_REMAP)));
    printf("part_natt=%ld/%ld\n", nattch(small), nattch(big));
    printf("part_dt=%d\n", shmdt(X));
    printf("part_natt2=%ld/%ld\n", nattch(small), nattch(big));
    printf("part_mapped=%d%d\n", mincore(X, 4096, &v) == 0,
           mincore((char *)X + 4096, 4096, &v) == 0);

    shmctl(small, IPC_RMID, NULL);
    shmctl(big, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}
