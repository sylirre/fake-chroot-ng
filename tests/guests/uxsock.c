/* AF_UNIX containment guest (M15).
 *
 * Binds a pathname socket at an absolute guest path, connects to it, and prints
 * what getsockname/getpeername report back. Under the emulation the inode must
 * land INSIDE the rootfs and the readback must be the guest path, never the host
 * one — handing back a host path both leaks where the rootfs lives and breaks
 * any program that compares the readback against what it bound.
 *
 *   argv[1]  socket path (or abstract name with argv[2])
 *   argv[2]  "abstract" to use an abstract name (leading NUL) instead, where
 *            there is no filesystem node to contain and the per-rootfs tag has
 *            to be invisible to the guest on readback.
 *   argv[3]  seconds to hold the bound socket before exiting, so another
 *            invocation can try the same name (abstract-namespace isolation) or
 *            the host can inspect it.
 *
 * Output is byte-comparable so the same binary can be diffed between a run under
 * chroot-ng and a run straight under qemu.
 */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Render sun_path the way ss/lsof do: a leading NUL becomes '@'. */
static void show(const char *tag, const struct sockaddr_un *a, socklen_t len) {
    char out[128];
    size_t n = (len > sizeof(sa_family_t)) ? len - sizeof(sa_family_t) : 0;
    if (n > sizeof a->sun_path)
        n = sizeof a->sun_path;
    size_t w = 0;
    for (size_t i = 0; i < n && w + 1 < sizeof out; i++) {
        char c = a->sun_path[i];
        if (i == 0 && c == '\0') {
            out[w++] = '@';
            continue;
        }
        if (c == '\0')
            break;
        out[w++] = c;
    }
    out[w] = '\0';
    printf("%s: %s\n", tag, out);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: uxsock PATH [abstract]\n");
        return 2;
    }
    const char *path = argv[1];
    int abstract = argc > 2 && argv[2][0] == 'a';

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    size_t off = abstract ? 1 : 0;
    size_t n = strlen(path);
    if (n > sizeof addr.sun_path - 1 - off)
        n = sizeof addr.sun_path - 1 - off;
    memcpy(addr.sun_path + off, path, n);
    socklen_t alen = (socklen_t)(sizeof(sa_family_t) + off + n + (abstract ? 0 : 1));

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    if (!abstract)
        unlink(path);
    if (bind(srv, (struct sockaddr *)&addr, alen) < 0) {
        perror("bind");
        return 1;
    }
    printf("bind: ok\n");
    if (listen(srv, 4) < 0) {
        perror("listen");
        return 1;
    }

    struct sockaddr_un got;
    socklen_t glen = sizeof got;
    memset(&got, 0, sizeof got);
    if (getsockname(srv, (struct sockaddr *)&got, &glen) < 0)
        perror("getsockname");
    else
        show("getsockname", &got, glen);

    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cli, (struct sockaddr *)&addr, alen) < 0) {
        perror("connect");
        return 1;
    }
    printf("connect: ok\n");

    socklen_t plen = sizeof got;
    memset(&got, 0, sizeof got);
    if (getpeername(cli, (struct sockaddr *)&got, &plen) < 0)
        perror("getpeername");
    else
        show("getpeername", &got, plen);

    if (argc > 3) {
        /* Hold the name so a second invocation can try to take it. */
        int secs = atoi(argv[3]);
        fflush(stdout);
        sleep(secs > 0 ? secs : 1);
    }
    close(cli);
    close(srv);
    if (!abstract)
        unlink(path);
    return 0;
}
