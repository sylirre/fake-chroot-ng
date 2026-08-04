/* Does a translated syscall stay inside the stack the guest gave it?
 *
 * The path dispatcher is deep — cng_dispatch's frame alone is ~24 KiB and an
 * openat translation chain runs to ~66 KiB — so the SIGSYS tier switches to a
 * dedicated 256 KiB scratch stack before entering it. The -R trampoline tier
 * calls the same dispatcher from an ordinary context, on whatever stack the
 * rewritten `svc` site happened to be running on.
 *
 * Guests do run syscalls on small stacks: musl gives a thread 128 KiB, Go gives
 * a goroutine ~8 KiB, and anything with a sigaltstack runs handlers on one.
 * This drives that case at its root by moving SP into a small region and making
 * the call from there — no threads, no signals, nothing whose size limits vary
 * by libc.
 *
 * It answers with a canary rather than a crash, because a crash is the lucky
 * outcome: the dispatcher's frame is larger than a guard page, so it steps
 * clean over the guard and lands in ordinary guest memory, where nothing faults
 * and nothing is reported. 256 KiB of 0xA5 below the guard is what that hits.
 *
 * Prints "clobbered=N" for the number of canary bytes the syscall disturbed.
 * Anything but 0 means the monitor wrote outside the stack it was given. Exits
 * 0 when clean, 1 when not, 2 when the setup could not be made.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PG    4096
#define CANSZ (256 * 1024)

/* One translated path syscall. openat is the deepest of them — it resolves the
 * name through the rootfs and its binds — which is the point. noinline so the
 * call really happens with SP inside the small region. */
static __attribute__((noinline)) void do_syscall(void) {
    int fd = openat(AT_FDCWD, "/etc/hostname", O_RDONLY);
    if (fd >= 0)
        close(fd);
}

int main(int argc, char **argv) {
    size_t kib = argc > 1 ? (size_t)atoi(argv[1]) : 16;
    size_t sz = kib * 1024;
    size_t total = CANSZ + PG + sz + PG;

    unsigned char *m = mmap(0, total, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        printf("setup=nomap\n");
        return 2;
    }
    /* [canary][guard][small stack][guard] — the stack grows down out of its
     * region, so the guard catches a small overrun and the canary catches the
     * large one that steps over it. */
    memset(m, 0xA5, CANSZ);
    if (mprotect(m + CANSZ, PG, PROT_NONE) ||
        mprotect(m + CANSZ + PG + sz, PG, PROT_NONE)) {
        printf("setup=noguard\n");
        return 2;
    }
    unsigned long top = (unsigned long)(m + CANSZ + PG + sz) & ~15UL;

    /* Run one syscall with SP in that region and put it back afterwards.
     * x19/x20 hold the old SP and return address across the call because they
     * are callee-saved: whatever runs underneath restores them. */
    void (*fn)(void) = do_syscall;
    __asm__ volatile("mov x19, sp\n\t"
                     "mov x20, x30\n\t"
                     "mov sp, %[top]\n\t"
                     "blr %[fn]\n\t"
                     "mov sp, x19\n\t"
                     "mov x30, x20\n\t"
                     :
                     : [top] "r"(top), [fn] "r"(fn)
                     : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                       "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                       "x17", "x19", "x20", "x30", "memory", "cc");

    size_t bad = 0;
    for (size_t i = 0; i < CANSZ; i++)
        if (m[i] != 0xA5)
            bad++;
    printf("clobbered=%zu\n", bad);
    return bad ? 1 : 0;
}
