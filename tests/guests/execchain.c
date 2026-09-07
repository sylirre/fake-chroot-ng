/* What an exec chain costs the address space (tests/m6_execve.sh).
 *
 * A real execve throws the whole mm away. The emulated one cannot — the monitor
 * lives in that address space — so it gives back what its own loader mapped for
 * the program being replaced (the image, the interpreter's image, the stack
 * built for it) and then sweeps everything else that was never the monitor's.
 * Left behind, those accumulated: 66.8 MB of address space per generation
 * before the reclaim, 64 MiB of it the stack; and 8.25 GB per generation more
 * once the guest's own allocator was counted, which on a bionic guest killed
 * the chain outright at 64 execs.
 *
 * So: exec self N times and report the VmSize the chain gained end to end. The
 * same program run with no emulation under it gains nothing, which is what this
 * is compared against — the number is not asserted against a constant, since
 * VmSize is whatever the host underneath happens to need.
 *
 *   execchain N          start a chain of N execs
 *   execchain n first    a link in it (internal: `first` is generation N's
 *                        VmSize, carried down so the last link can subtract)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (argc < 2) {
        printf("usage: execchain N\n");
        return 2;
    }
    int n = atoi(argv[1]);
    long now = vmsize_kb();
    if (now < 0) {
        printf("chain: nostatus\n");
        return 2;
    }
    long first = argc > 2 ? strtol(argv[2], NULL, 10) : now;

    if (n <= 0) {
        printf("chain: growth_kb=%ld\n", now - first);
        return 0;
    }
    char nn[16], ff[32];
    snprintf(nn, sizeof nn, "%d", n - 1);
    snprintf(ff, sizeof ff, "%ld", first);
    char *av[4] = {argv[0], nn, ff, NULL};
    execv(argv[0], av);
    printf("chain: execfail\n");
    return 1;
}
