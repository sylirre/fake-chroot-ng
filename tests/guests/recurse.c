/* Test guest for the stack guard. Recurses with a frame the compiler cannot
 * shrink, either to a depth that fits the 64 MiB guest stack with room to
 * spare ("deep": proves the guard took nothing away from the usable part) or
 * without limit ("overflow": the way a real stack overflow ends, which under
 * a main stack is SIGSEGV at the guard gap — and under the old unguarded
 * mapping was a write into whatever the kernel had placed below it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 4 KiB per frame, touched from the bottom up so no page is skipped and no
 * store is dead. */
static long descend(long depth, long limit) {
    volatile char frame[4096];
    memset((char *)frame, (int)(depth & 0x7f), sizeof frame);
    if (limit >= 0 && depth >= limit)
        return frame[0] + frame[sizeof frame - 1];
    return descend(depth + 1, limit) + frame[sizeof frame / 2];
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "deep";
    if (!strcmp(mode, "deep")) {
        /* 48 MiB of the 64: past any 8 MiB rlimit, short of the mapping. */
        long r = descend(0, 48L * 1024 * 1024 / 4096);
        printf("recurse: deep ok r=%ld\n", r);
        fflush(stdout);
        return 0;
    }
    printf("recurse: overflowing\n");
    fflush(stdout);
    long r = descend(0, -1);
    printf("recurse: survived the overflow r=%ld\n", r); /* must not print */
    fflush(stdout);
    return 3;
}
