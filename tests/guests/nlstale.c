/* The emulated netlink socket's hidden descriptors and the guest's own (M16
 * regression).
 *
 * An emulated NETLINK_ROUTE socket is three descriptors in the guest's table:
 * the guest's end of a socketpair, the monitor's end, and an unbound relay
 * socket — and the guest knows only the first. A program that closes every
 * descriptor it did not open (a daemon's close-all loop, closefrom(3) before an
 * exec) closes the other two as well, and its next opens are handed the same
 * numbers back. The monitor used to reclaim the slot on the evidence of the
 * guest's fd alone and close the two hidden numbers with it — two descriptors
 * of whatever the program had opened there since.
 *
 * The relay socket is also close-on-exec, as every descriptor of the monitor's
 * is, while a netlink socket opened without SOCK_CLOEXEC survives an exec: the
 * new program inherits a working guest end whose relay the exec sweep closed.
 * The number is then free for the new program's own files, and a dump on the
 * inherited socket must neither be sent through them nor read from them — and
 * must still be relayed, since nothing the guest did took the relay away.
 *
 * Phase 1 ("closeall") opens a socket and dumps on it, closes everything from
 * 3 up, opens sixteen files onto the freed numbers, makes a trapped socket
 * call on the old netlink number to provoke the reclaim, and counts the files
 * still open. Then it opens a second socket without SOCK_CLOEXEC and execs
 * itself with its number; phase 2 ("exec") fills the low numbers with files
 * first, dumps on the inherited socket, and counts its files again. */
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NFILES 16

static int dump_ok(int fd) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0)
        return 0;
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.g);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 7;
    req.g.rtgen_family = AF_UNSPEC;
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0)
        return 0;
    char buf[16384];
    for (int rounds = 0; rounds < 64; rounds++) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0)
            return 0;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n))
            if (h->nlmsg_type == NLMSG_DONE)
                return 1;
    }
    return 0;
}

static int open_files(int *f) {
    int n = 0;
    for (int i = 0; i < NFILES; i++) {
        f[i] = open("/dev/null", O_RDONLY);
        n += f[i] >= 0;
    }
    return n;
}

static int files_kept(const int *f) {
    int n = 0;
    for (int i = 0; i < NFILES; i++)
        n += f[i] >= 0 && fcntl(f[i], F_GETFD) >= 0;
    return n;
}

/* Everything from 3 up, the way a daemon does it. */
static void close_from_3(void) {
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 4096)
        max = 4096;
    for (int i = 3; i < max; i++)
        close(i);
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "exec") == 0) {
        int nl = atoi(argv[2]);
        int f[NFILES];
        int opened = open_files(f); /* onto what the exec sweep closed */
        int dump = dump_ok(nl);
        printf("exec: inherited_open=%d dump=%d files=%d kept=%d\n",
               fcntl(nl, F_GETFD) >= 0, dump, opened, files_kept(f));
        return 0;
    }

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int dump1 = fd >= 0 && dump_ok(fd);
    close_from_3();
    int f[NFILES];
    int opened = open_files(f);
    /* A trapped socket call on the number the netlink socket had: the slot's
     * fd names a file of ours now, and the monitor gives the slot back. */
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    errno = 0;
    int gr = getsockname(fd, (struct sockaddr *)&ss, &sl);
    int gerr = errno;
    int kept = files_kept(f);
    /* ...and a socket opened after the reclaim still works. */
    for (int i = 0; i < NFILES; i++)
        close(f[i]);
    int fd2 = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int dump2 = fd2 >= 0 && dump_ok(fd2);
    printf("closeall: dump=%d files=%d reclaim=%d/%d kept=%d redump=%d\n", dump1,
           opened, gr, gerr, kept, dump2);
    fflush(stdout);

    char num[16];
    snprintf(num, sizeof num, "%d", fd2);
    execl(argv[0], argv[0], "exec", num, (char *)0);
    printf("exec: failed errno=%d\n", errno);
    return 1;
}
