/* Prints the guest's working directory two ways that have to agree: getcwd(2),
 * which the monitor answers from its own bookkeeping, and /proc/self/cwd, which
 * comes from the process registry. A trailing argument is opened relative to
 * the cwd — getcwd can only report a name, and what actually matters about a
 * working directory is what relative paths resolve against.
 */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buf[4096];

    if (getcwd(buf, sizeof buf))
        printf("cwd=%s\n", buf);
    else
        printf("cwd=(getcwd failed)\n");

    ssize_t n = readlink("/proc/self/cwd", buf, sizeof buf - 1);
    if (n >= 0) {
        buf[n] = '\0';
        printf("proccwd=%s\n", buf);
    } else {
        printf("proccwd=(readlink failed)\n");
    }

    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (!f) {
            printf("rel=(open failed)\n");
        } else {
            char line[256];
            if (!fgets(line, sizeof line, f))
                line[0] = '\0';
            char *nl = line;
            while (*nl && *nl != '\n')
                nl++;
            *nl = '\0';
            printf("rel=%s\n", line);
            fclose(f);
        }
    }
    fflush(stdout);
    return 0;
}
