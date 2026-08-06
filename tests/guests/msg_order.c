/* Which of msgsnd's refusals comes first.
 *
 * The kernel splits the work in a particular order and the errno depends on it:
 * SYSCALL_DEFINE4(msgsnd) reads mtype with get_user() before it looks at
 * anything else, the real do_msgsnd() then bounds msgsz, then rejects mtype < 1,
 * and only load_msg() afterwards touches mtext. So a bad msgp beats an
 * out-of-range msgsz, and a bad mtype beats an unreadable mtext. Validating the
 * whole buffer in one go, after the size check — which is what the emulation
 * did — gets both of those backwards.
 *
 * Built twice and diffed: this needs a HOST-native reference rather than the
 * qemu-aarch64 one the rest of the SysV differential uses, because qemu's own
 * msgsnd copies the guest's buffer in with a single lock_user() over
 * sizeof(long) + msgsz and so reproduces the very ordering under test. Measured:
 * against the real kernel a type-0 message whose mtext runs off the mapping is
 * EINVAL, and under qemu-user it is EFAULT.
 *
 * `edge` puts mtype in the last readable bytes of a mapping with mtext running
 * straight off the end of it, so mtype and mtext have different readability.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <unistd.h>
#include "sysvipc.h"

static int q;

static void probe(const char *tag, const void *p, size_t sz) {
    errno = 0;
    int r = (int)msgsnd(q, p, sz, IPC_NOWAIT);
    printf("%s: rc=%d %s\n", tag, r,
           r == 0             ? "-"
           : errno == EFAULT  ? "EFAULT"
           : errno == EINVAL  ? "EINVAL"
           : errno == EACCES  ? "EACCES"
           : errno == EAGAIN  ? "EAGAIN"
                              : strerror(errno));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    printf("msgget: %s\n", q >= 0 ? "ok" : "failed");
    if (q < 0)
        return 1;

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char *pg = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pg == MAP_FAILED) {
        printf("mapping: failed\n");
        return 1;
    }
    munmap(pg + page, page);
    long *edge = (long *)(pg + page - sizeof(long));
    size_t huge = (size_t)1 << 40;

    /* mtype is read before the size is bounded, so this is EFAULT and not the
     * EINVAL the size alone would give. */
    probe("badptr+badsize", (void *)0x10, huge);
    probe("badptr", (void *)0x10, 64);
    /* ...and the size is bounded, and mtype rejected, before mtext is touched:
     * both of these are EINVAL and not the EFAULT mtext alone would give. */
    *edge = 1;
    probe("badtext+badsize", edge, huge);
    *edge = 0;
    probe("type0+badtext", edge, 64);
    /* The control: with nothing else wrong, unreadable mtext IS EFAULT. */
    *edge = 1;
    probe("badtext", edge, 64);
    /* ...and a message that is fine goes through. */
    struct {
        long mtype;
        char t[8];
    } ok = {1, "body"};
    probe("good", &ok, sizeof ok.t);

    msgctl(q, IPC_RMID, NULL);
    printf("done\n");
    return 0;
}
