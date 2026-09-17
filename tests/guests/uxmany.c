/* Many pathname sockets held open at once (M15).
 *
 * A pathname is bound through a spelling of the emulator's own, and what
 * getsockname then reports has to be mapped back to the name the guest
 * bound: a record the binding process keeps, keyed by the socket's identity.
 * The record used to be eight entries in a ring: the ninth bind overwrote
 * the first's, whose getsockname then handed the guest the internal
 * spelling. Bind N sockets under DIR, all held open, and read each one
 * back.
 *
 *   uxmany DIR N
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: uxmany DIR N\n");
        return 2;
    }
    int n = atoi(argv[2]), bound = 0, ok = 0, internal = 0;
    int fd[64];
    if (n > 64)
        n = 64;
    for (int i = 0; i < n; i++) {
        struct sockaddr_un a;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof a.sun_path, "%s/s%d.sock", argv[1], i);
        unlink(a.sun_path);
        fd[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd[i] < 0 || bind(fd[i], (struct sockaddr *)&a, sizeof a) != 0)
            continue;
        bound++;
    }
    for (int i = 0; i < n; i++) {
        struct sockaddr_un want, got;
        memset(&want, 0, sizeof want);
        snprintf(want.sun_path, sizeof want.sun_path, "%s/s%d.sock", argv[1], i);
        socklen_t len = sizeof got;
        memset(&got, 0, sizeof got);
        if (fd[i] < 0 || getsockname(fd[i], (struct sockaddr *)&got, &len) != 0)
            continue;
        if (!strcmp(got.sun_path, want.sun_path))
            ok++;
        else if (!strncmp(got.sun_path, "/proc/self/fd/", 14))
            internal++;
    }
    for (int i = 0; i < n; i++) {
        char p[128];
        snprintf(p, sizeof p, "%s/s%d.sock", argv[1], i);
        unlink(p);
    }
    printf("many: bound=%d ok=%d internal=%d\n", bound, ok, internal);
    return 0;
}
