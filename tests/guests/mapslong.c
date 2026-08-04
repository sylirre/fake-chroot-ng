/* What /proc/self/maps says about a file this process mapped (M11).
 *
 * usage: mapslong <path-to-map> <host-marker>
 *
 * The guest's mappings are the emulator's real mappings, so its /proc/self/maps
 * is a rewrite of the host's: the pathname column of a file-backed line is
 * translated back to the guest spelling, and a line naming something outside
 * the guest's view is dropped. Nothing that names a host path may survive.
 *
 * <host-marker> is a string that appears in the host path and cannot appear in
 * the guest one, so counting lines that contain it counts leaks. Counting lines
 * that contain <path-to-map> counts the mapping the guest should be able to
 * find. Both are counts, never paths: the host side of this test is a mktemp
 * directory that differs every run.
 *
 * `malformed` is the third count, and the one that catches a leak the marker
 * cannot see: every maps row begins with an address range, so a row whose first
 * non-hex character is not '-' is not a maps row at all. That is what a piece
 * of an over-long line looks like when it is re-parsed as a fresh one.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: mapslong <path> <host-marker>\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("open failed\n");
        return 1;
    }
    void *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        printf("mmap failed\n");
        return 1;
    }

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        printf("maps failed\n");
        return 1;
    }
    /* Generous: an over-long line reaches us split, and each piece is a line
     * here — which is the whole point, so the buffer must not split it again. */
    static char line[65536];
    int leak = 0, mine = 0, lines = 0, bad = 0;
    while (fgets(line, sizeof line, f)) {
        lines++;
        if (strstr(line, argv[2]))
            leak++;
        if (strstr(line, argv[1]))
            mine++;
        const char *p = line;
        while (strchr("0123456789abcdefABCDEF", *p) && *p)
            p++;
        if (p == line || *p != '-')
            bad++;
    }
    fclose(f);
    printf("lines=%d hostleak=%d mapped=%d malformed=%d\n", lines > 0, leak,
           mine, bad);
    return 0;
}
