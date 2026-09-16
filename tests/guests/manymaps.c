/* An exec chain by a program with far more mappings than one sweep pass holds
 * (tests/m6_execve.sh).
 *
 * The emulated execve gives the outgoing program's own mappings back by
 * walking /proc/self/maps, collecting what was never the monitor's, and
 * unmapping it — a bounded table's worth per pass, walking again while a pass
 * fills it. The passes used to be capped at eight of forty-eight, so the 385th
 * reclaimable mapping and everything after it survived the exec, and a
 * program with many of them leaked them once per generation.
 *
 * So: map COUNT single pages that cannot merge (protections alternate, and a
 * guard page sits between neighbours), exec self N times, and report the
 * VmSize the chain gained end to end — execchain's shape, with the mappings.
 *
 *   manymaps COUNT N          start a chain of N execs, COUNT pages each
 *   manymaps COUNT n first    a link in it (internal)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static long vmsize_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmSize:", 7)) {
            kb = strtol(line + 7, NULL, 10);
            break;
        }
    fclose(f);
    return kb;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: manymaps COUNT N\n");
        return 2;
    }
    int count = atoi(argv[1]);
    int n = atoi(argv[2]);
    long pg = sysconf(_SC_PAGESIZE);
    /* One reservation, then a page in every other slot with alternating
     * protections: no two of them abut, so the kernel keeps them as COUNT
     * separate VMAs, which is the point. */
    char *base = mmap(NULL, (size_t)pg * 2 * (size_t)count + pg, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        printf("chain: nomem\n");
        return 2;
    }
    for (int i = 0; i < count; i++) {
        int prot = (i & 1) ? PROT_READ : PROT_READ | PROT_WRITE;
        if (mprotect(base + (size_t)pg * (2 * (size_t)i + 1), (size_t)pg, prot) != 0) {
            printf("chain: noprot\n");
            return 2;
        }
    }
    long now = vmsize_kb();
    if (now < 0) {
        printf("chain: nostatus\n");
        return 2;
    }
    long first = argc > 3 ? strtol(argv[3], NULL, 10) : now;

    if (n <= 0) {
        printf("chain: growth_kb=%ld\n", now - first);
        return 0;
    }
    char nn[16], ff[32];
    snprintf(nn, sizeof nn, "%d", n - 1);
    snprintf(ff, sizeof ff, "%ld", first);
    char *av[5] = {argv[0], argv[1], nn, ff, NULL};
    execv(argv[0], av);
    printf("chain: execfail\n");
    return 1;
}
