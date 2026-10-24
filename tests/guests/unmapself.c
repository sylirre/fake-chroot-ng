/* A detached thread that frees its own stack on the way out.
 *
 * A thread cannot munmap the stack it is standing on from C, so libc does it in
 * four instructions of assembly that touch no stack at all — unmap, then exit:
 *
 *     musl   __unmapself:               mov x8,#215; svc 0; mov x8,#93; svc 0
 *     bionic _exit_with_stack_teardown: mov w8,#215; svc 0; mov x0,#0;
 *                                       mov w8,#93; svc 0
 *
 * bionic writes the number into w8, as every Android from 8 to 15 has it;
 * written here with x8, this passed while the rewriter recognised only that,
 * and rewrote the real thing.
 *
 * Every detached thread of a musl or bionic program ends this way (the JVM's
 * all are, being created detached). The -R rewriter replaces each `svc` with a
 * branch to a trampoline, which builds its frame on the caller's stack and reads
 * every register back from it: after the munmap that stack is gone, and the
 * thread died of a SEGV on the way out — which takes the whole process with it.
 *
 * The sequence is written out here as it stands in libc, and run on a stack the
 * guest mapped for the purpose, so what is asked is the thread's exit and not
 * any libc's idea of one — which is also why the thread is made with a bare
 * clone(2), not pthread_create: a glibc that is handed a thread's stack keeps
 * the descriptor on it in a list, and its next pthread_create would write into
 * what the teardown has freed. Each round starts a thread on a fresh stack,
 * which frees it and exits; the program counts the rounds it survived and
 * prints `survived=N`. Anything short of N means the process died with its
 * thread.
 *
 * Argument: the variant, `musl` (the default) or `bionic`.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define STACK  (128 * 1024)
#define ROUNDS 20

static int bionic;
static volatile int running;

/* Written as top-level assembly rather than as a naked function: gcc has no
 * `naked` for AArch64 before 14, and a compiler that adds a prologue would put
 * the very thing under test — a use of the stack — between the two calls. */
__asm__(".text\n"
        ".balign 4\n"
        ".global cng_teardown_musl\n"
        ".type cng_teardown_musl, %function\n"
        "cng_teardown_musl:\n"
        "    mov x8, #215\n"
        "    svc #0\n"
        "    mov x8, #93\n"
        "    svc #0\n"
        ".size cng_teardown_musl, .-cng_teardown_musl\n"
        ".global cng_teardown_bionic\n"
        ".type cng_teardown_bionic, %function\n"
        "cng_teardown_bionic:\n"
        "    mov w8, #215\n"
        "    svc #0\n"
        "    mov x0, #0\n"
        "    mov w8, #93\n"
        "    svc #0\n"
        ".size cng_teardown_bionic, .-cng_teardown_bionic\n");
extern void cng_teardown_musl(void *base, unsigned long len)
    __attribute__((noreturn));
extern void cng_teardown_bionic(void *base, unsigned long len)
    __attribute__((noreturn));

/* Runs on the new stack with the parent's thread pointer, so it touches nothing
 * of libc's: one store, then the teardown. */
static int thread_fn(void *arg) {
    __atomic_store_n(&running, 0, __ATOMIC_RELEASE);
    if (bionic)
        cng_teardown_bionic(arg, STACK);
    cng_teardown_musl(arg, STACK);
}

int main(int argc, char **argv) {
    bionic = argc > 1 && !strcmp(argv[1], "bionic");
    int survived = 0;
    for (int i = 0; i < ROUNDS; i++) {
        char *stk = mmap(0, STACK, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stk == MAP_FAILED)
            return 2;
        __atomic_store_n(&running, 1, __ATOMIC_RELEASE);
        if (clone(thread_fn, stk + STACK,
                  CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                      CLONE_THREAD | CLONE_SYSVSEM,
                  stk) < 0)
            return 2;
        /* Past the point where it has started; the teardown follows at once,
         * and whether it killed the process is known a few milliseconds on. */
        while (__atomic_load_n(&running, __ATOMIC_ACQUIRE))
            ;
        struct timespec ts = {0, 20 * 1000 * 1000};
        nanosleep(&ts, 0);
        survived++;
    }
    printf("survived=%d\n", survived);
    return 0;
}
