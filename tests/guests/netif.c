/* NETLINK_ROUTE emulation guest (M16).
 *
 * Exercises the two things a guest actually does with rtnetlink:
 *   - getifaddrs(3), which glibc/musl implement over an unbound netlink dump and
 *     which apt, dnf, `ip addr`, and Java/Go runtimes all reach for;
 *   - a raw RTM_GETLINK dump, the shape iproute2 issues, plus the getsockname
 *     that iproute2 insists must return a 12-byte sockaddr_nl.
 *
 * Prints one line per interface name found, then the raw-dump message count, so
 * the output is byte-comparable between a run under the emulation and a run
 * straight under qemu (where the guest talks to the real kernel).
 */
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    /* --- getifaddrs ---------------------------------------------------- */
    struct ifaddrs *ifa = 0;
    if (getifaddrs(&ifa) != 0) {
        printf("getifaddrs: FAILED\n");
    } else {
        int n = 0;
        int saw_lo = 0;
        for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
            n++;
            if (p->ifa_name && !strcmp(p->ifa_name, "lo"))
                saw_lo = 1;
        }
        printf("getifaddrs: ok entries>0=%d lo=%d\n", n > 0, saw_lo);
        freeifaddrs(ifa);
    }

    /* --- raw RTM_GETLINK dump, iproute2 style --------------------------- */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        printf("socket: FAILED\n");
        return 1;
    }
    printf("socket: ok\n");

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0)
        printf("bind: FAILED\n");
    else
        printf("bind: ok\n");

    /* iproute2 rejects a getsockname answer that is not sockaddr_nl-sized. */
    struct sockaddr_nl got;
    socklen_t glen = sizeof got;
    memset(&got, 0, sizeof got);
    if (getsockname(fd, (struct sockaddr *)&got, &glen) < 0)
        printf("getsockname: FAILED\n");
    else
        printf("getsockname: len=%d family=%d\n", (int)glen,
               (int)got.nl_family);

    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 4242;
    req.g.rtgen_family = AF_UNSPEC;

    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("sendto: FAILED\n");
        close(fd);
        return 1;
    }
    printf("sendto: ok\n");

    char buf[8192];
    long n = recv(fd, buf, sizeof buf, 0);
    int msgs = 0, seq_ok = 1, newlink = 0;
    if (n > 0) {
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        size_t len = (size_t)n;
        for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            msgs++;
            if (h->nlmsg_seq != 4242)
                seq_ok = 0;
            if (h->nlmsg_type == RTM_NEWLINK)
                newlink++;
        }
    }
    /* The message *count* differs between host and guest views, so report only
     * the properties that must hold either way. */
    printf("dump: got>0=%d msgs>0=%d seq_ok=%d newlink>0=%d\n", n > 0, msgs > 0,
           seq_ok, newlink > 0);
    close(fd);
    return 0;
}
