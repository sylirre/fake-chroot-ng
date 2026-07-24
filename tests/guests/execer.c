/* Execs /bin/hello through the guest view. Proves that an execve issued from a
 * rewritten svc site (-R) is emulated in-process with path translation —
 * re-issuing it raw would look up /bin/hello on the host and fail (or escape
 * the monitor entirely). */
#include <unistd.h>

int main(void) {
    char *av[] = {"/bin/hello", "from-execer", 0};
    execv(av[0], av);
    write(2, "EXEC-FAIL\n", 10);
    return 3;
}
