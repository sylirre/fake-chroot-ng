/* Is the in-process monitor installed at all?
 *
 * Installing it sets PR_SET_NO_NEW_PRIVS — mandatory for an unprivileged
 * seccomp filter — and /proc/self/status reports that bit, so the guest can be
 * asked whether it is running under a monitor without needing the monitor to
 * intercept anything. Which matters, because on a host where the seccomp tier
 * is inert (qemu-user applies no guest filter) nothing else about an installed
 * monitor is visible from inside the guest unless -R is also in play.
 *
 * Prints the line verbatim: "NoNewPrivs:\t0" or "NoNewPrivs:\t1", or "absent"
 * where /proc has no such field to report.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        printf("nostatus\n");
        return 2;
    }
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "NoNewPrivs:", 11) != 0)
            continue;
        char *p = line + 11;
        while (*p == ' ' || *p == '\t')
            p++;
        printf("nnp=%c\n", *p);
        fclose(f);
        return 0;
    }
    fclose(f);
    printf("absent\n");
    return 2;
}
