/* The lazy -R patch through real traps (M71).
 *
 * Code this program writes at run time is code no loader saw, so its `svc`
 * sites are patched on their first SIGSYS trap — where a live seccomp filter
 * traps them at all. The patcher keeps a record of each mapping a site first
 * trapped out of; this program changes the mapping under such a record the way
 * a JIT does, then runs a site the record covers:
 *
 *   jit     the text made writable since: it must stay writable after the
 *           patch (the record's read-only protection was put back).
 *   shared  a MAP_SHARED memfd's executable view over the same address: the
 *           memfd must not be written (the branch went into it, and into its
 *           writable view).
 *   full    more sites than one pool holds, all run: every one patched before
 *           the pool filled must still run (the pool was unmapped).
 *   race    a sibling thread unmapping and replacing the page while sites in
 *           it trap: the process must survive (the patcher's own load, store
 *           or flush faulted in a handler with every signal masked). A fault
 *           of the program's own — running a page that is not there — is
 *           caught and carried on from.
 *
 * Prints one line of tokens, -1 for a leg not run (argv[1] names the one leg
 * to run; all by default). Needs a host whose seccomp filter traps; where
 * none does, nothing is patched and `patched=` says so.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define SVC 0xD4000001u
#define BLK 32 /* bytes of one block; its svc is at +12 */
#define ERANGE_ 34

/* getcwd(NULL, 0): a syscall the filter traps, answered -ERANGE before any
 * buffer is looked at, so every block returns the same thing. */
static const uint32_t blk[BLK / 4] = {
    0xD2800000u, /* mov x0, #0 */
    0xD2800001u, /* mov x1, #0 */
    0xD2800228u, /* mov x8, #17 (getcwd) */
    SVC,         /* svc #0 */
    0xD65F03C0u, /* ret */
    0xD503201Fu, 0xD503201Fu, 0xD503201Fu, /* nop */
};

static long pg;
static long want = -ERANGE_;

static void fill(void *p, int n) {
    for (int i = 0; i < n; i++)
        memcpy((char *)p + BLK * i, blk, sizeof blk);
    __builtin___clear_cache((char *)p, (char *)p + BLK * n);
}

static long run(void *p, int i) {
    long (*fn)(void) = (long (*)(void))((char *)p + BLK * i);
    return fn();
}

static int patched(void *p, int i) {
    uint32_t w = *(volatile uint32_t *)((char *)p + BLK * i + 12);
    return (w & 0xFC000000u) == 0x14000000u; /* a `b`, where the svc was */
}

static sigjmp_buf jb;
static __thread volatile int armed;
static void on_fault(int sig) {
    (void)sig;
    if (armed)
        siglongjmp(jb, 1);
    _exit(99);
}

/* A write into the page, which faults if it has lost write. */
static int writable(void *p) {
    int ok = 0;
    armed = 1;
    if (!sigsetjmp(jb, 1)) {
        ((volatile char *)p)[pg - 1] = 1;
        ok = 1;
    }
    armed = 0;
    return ok;
}

static char *region; /* one reservation, so no leg reuses another's address */
static volatile int stop;
static long race_remaps;

/* The page goes away, and a new one is built elsewhere and moved into its
 * place whole: this thread never writes the page where sites run from. (A
 * thread that did, while a patch there was between its read of the page and
 * its restore, could find the page's protection put back under it — the
 * residue the threat model in docs/DESIGN.md states, and not this leg's
 * subject.) */
static void *remapper(void *arg) {
    char *p = arg;
    while (!stop) {
        /* Built before the page goes, or the kernel hands this one the very
         * address and the move onto it is EINVAL. */
        void *q = mmap(0, pg, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (q == MAP_FAILED)
            continue;
        fill(q, (int)(pg / BLK));
        mprotect(q, pg, PROT_READ | PROT_EXEC);
        munmap(p, pg);
        for (volatile int k = 0; k < 2000; k++)
            ; /* a while with no page there */
        if (mremap(q, pg, pg, MREMAP_MAYMOVE | MREMAP_FIXED, p) == MAP_FAILED)
            munmap(q, pg);
        else
            race_remaps++;
    }
    return 0;
}

static int want_leg(const char *only, const char *leg) {
    return !only || !strcmp(only, leg);
}

int main(int argc, char **argv) {
    const char *only = argc > 1 ? argv[1] : 0;
    int jit = -1, shared = -1, full = -1, race = -1;
    pg = sysconf(_SC_PAGESIZE);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    int nfull = 4096; /* past any pool: 128 KiB of trampolines */
    long flen = ((long)BLK * nfull + pg - 1) / pg * pg;
    region = mmap(0, 8 * pg + flen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                  0);
    if (region == MAP_FAILED) {
        printf("lazystale: mmap failed\n");
        return 1;
    }
    int npatched = 0;

    /* jit */
    char *j = region + pg;
    if (want_leg(only, "jit")) {
    mprotect(j, pg, PROT_READ | PROT_WRITE);
    fill(j, 2);
    mprotect(j, pg, PROT_READ | PROT_EXEC);
    int jok = run(j, 0) == want;
    npatched += patched(j, 0);
    mprotect(j, pg, PROT_READ | PROT_WRITE | PROT_EXEC);
    jok &= run(j, 1) == want;
    jit = jok && writable(j) && run(j, 1) == want;
    }

    /* shared */
    char *s = region + 3 * pg;
    if (want_leg(only, "shared")) {
    mprotect(s, pg, PROT_READ | PROT_WRITE);
    fill(s, 1);
    mprotect(s, pg, PROT_READ | PROT_EXEC);
    int sok = run(s, 0) == want;
    npatched += patched(s, 0);
    int mfd = memfd_create("lazystale", MFD_CLOEXEC);
    shared = 0;
    if (mfd >= 0 && ftruncate(mfd, pg) == 0) {
        char *rw = mmap(0, pg, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
        if (rw != MAP_FAILED) {
            fill(rw, 1);
            if (mmap(s, pg, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, mfd,
                     0) == s) {
                sok &= run(s, 0) == want;
                shared = sok && *(volatile uint32_t *)(rw + 12) == SVC;
            }
        }
    }
    }

    /* full */
    char *f = region + 5 * pg;
    if (want_leg(only, "full")) {
    mprotect(f, flen, PROT_READ | PROT_WRITE);
    fill(f, nfull);
    mprotect(f, flen, PROT_READ | PROT_EXEC);
    int fran = 0, fp = 0;
    for (int i = 0; i < nfull; i++) {
        fran += run(f, i) == want;
        fp += patched(f, i);
    }
    npatched += fp;
    int again = 0;
    armed = 1;
    if (!sigsetjmp(jb, 1))
        again = run(f, 0) == want && fp > 0 && run(f, fp - 1) == want;
    armed = 0;
    full = fran == nfull && again;
    }

    /* race: this thread runs sites while another replaces the page under
     * them; a run into a page that is gone is the program's own fault. */
    char *r = region + 5 * pg + flen + pg;
    if (want_leg(only, "race")) {
    mprotect(r, pg, PROT_READ | PROT_WRITE);
    fill(r, (int)(pg / BLK));
    mprotect(r, pg, PROT_READ | PROT_EXEC);
    pthread_t t;
    long runs = 0;
    pthread_create(&t, 0, remapper, r);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0;; i++) {
        armed = 1;
        if (!sigsetjmp(jb, 1))
            run(r, i % (int)(pg / BLK));
        armed = 0;
        runs++;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (t1.tv_sec - t0.tv_sec >= 2)
            break;
    }
    stop = 1;
    pthread_join(t, 0);
    race = runs > 0 && race_remaps > 0;
    }

    printf("lazystale: jit=%d shared=%d full=%d race=%d patched>0=%d\n", jit,
           shared, full, race, npatched > 0);
    return 0;
}
