/* A datagram AF_UNIX exchange between two processes that bound their own
 * pathnames (M49).
 *
 * A pathname is bound through the pinned directory, so what the kernel
 * stores — and what any reader gets back — is the monitor's own spelling of
 * the name. A server that answers a request at the source address its
 * recvfrom reported (wpa_supplicant to wpa_cli, a syslog daemon to a client
 * that bound its own socket) is a process the binder never forked and that
 * recorded nothing about the name: the readback has to resolve the spelling
 * on its own, and the reply it then sends has to reach the client.
 *
 *   uxreply server SRV        bind SRV, take one datagram, print its source,
 *                             answer "pong" to that source
 *   uxreply client SRV CLI    bind CLI, send "ping" to SRV, print the answer
 *                             and where it came from
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int bind_path(int s, const char *path) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof a.sun_path - 1);
    unlink(path);
    return bind(s, (struct sockaddr *)&a, sizeof a);
}

static void show_addr(const char *tag, const struct sockaddr_un *a,
                      socklen_t len) {
    size_t n = len > sizeof(sa_family_t) ? len - sizeof(sa_family_t) : 0;
    if (n > sizeof a->sun_path)
        n = sizeof a->sun_path;
    printf("%s=%.*s", tag, (int)n, a->sun_path);
}

int main(int argc, char **argv) {
    if (argc < 3)
        return 2;
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct timeval tv = {5, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_un from;
    socklen_t flen = sizeof from;
    char buf[64];
    if (strcmp(argv[1], "server") == 0) {
        if (bind_path(s, argv[2]) < 0) {
            perror("server bind");
            return 1;
        }
        ssize_t n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from,
                             &flen);
        if (n < 0) {
            perror("server recvfrom");
            return 1;
        }
        printf("server: got=%.*s ", (int)n, buf);
        show_addr("from", &from, flen);
        printf(" reply=%d\n",
               sendto(s, "pong", 4, 0, (struct sockaddr *)&from, flen) == 4);
        return 0;
    }
    if (argc < 4)
        return 2;
    if (bind_path(s, argv[3]) < 0) {
        perror("client bind");
        return 1;
    }
    struct sockaddr_un srv;
    memset(&srv, 0, sizeof srv);
    srv.sun_family = AF_UNIX;
    strncpy(srv.sun_path, argv[2], sizeof srv.sun_path - 1);
    if (sendto(s, "ping", 4, 0, (struct sockaddr *)&srv, sizeof srv) != 4) {
        perror("client sendto");
        return 1;
    }
    ssize_t n = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
    if (n < 0) {
        perror("client recvfrom");
        return 1;
    }
    printf("client: reply=%.*s ", (int)n, buf);
    show_addr("from", &from, flen);
    printf("\n");
    return 0;
}
