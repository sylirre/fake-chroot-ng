/* iproute2's dump contract (M16 regression).
 *
 * This is the check that `ip addr` makes and that glibc's getifaddrs does not,
 * which is why a malformed terminator passed every local test and still broke
 * `ip addr` on a device with the message "DONE truncated / Dump terminated":
 *
 *   iproute2 lib/libnetlink.c, rtnl_dump_done():
 *       if (h->nlmsg_len < NLMSG_LENGTH(sizeof(int))) {
 *               fprintf(stderr, "DONE truncated\n");
 *               return -1;
 *       }
 *
 * So NLMSG_DONE must carry a 4-byte error int — nlmsg_len >= 20, not 16. It also
 * mirrors iproute2's message filter (source nl_pid == 0, nlmsg_pid == our own
 * port id from getsockname, nlmsg_seq == the request's), because a mismatch there
 * makes a client silently drop the whole dump, terminator included, and that is
 * indistinguishable from an empty interface list.
 *
 * `ip addr` collects the RTM_GETLINK dump into a list *before printing anything*,
 * so any of these failing yields no output at all — not a partial listing.
 */
#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        printf("socket: FAILED\n");
        return 1;
    }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("bind: FAILED\n");
        return 1;
    }
    /* iproute2 learns its own port id here and matches every reply against it. */
    struct sockaddr_nl local;
    socklen_t llen = sizeof local;
    memset(&local, 0, sizeof local);
    if (getsockname(fd, (struct sockaddr *)&local, &llen) < 0) {
        printf("getsockname: FAILED\n");
        return 1;
    }

    /* iproute2's link-dump request, byte for byte: a struct ifinfomsg *plus* an
     * IFLA_EXT_MASK attribute. The shape matters — Android refuses this rich form
     * while accepting the bare rtgenmsg one that getifaddrs sends, which is how
     * `ip addr` came back with an empty link list on-device while getifaddrs
     * worked. An earlier version of this test sent the bare form and so could
     * not see it. */
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        struct rtattr ext_req __attribute__((aligned(NLMSG_ALIGNTO)));
        __u32 ext_filter_mask;
    } req;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = sizeof req;
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1234;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ext_req.rta_type = IFLA_EXT_MASK;
    req.ext_req.rta_len = RTA_LENGTH(sizeof(__u32));
    req.ext_filter_mask = RTEXT_FILTER_VF;
    if (sendto(fd, &req, sizeof req, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("sendto: FAILED\n");
        return 1;
    }

    /* Drain the dump the way rtnl_dump_filter_l does. */
    int links = 0, saw_done = 0, done_len_ok = 0, skipped = 0, rounds = 0;
    char buf[16384];
    while (!saw_done && rounds++ < 256) {
        struct sockaddr_nl from;
        socklen_t flen = sizeof from;
        memset(&from, 0, sizeof from);
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from,
                            &flen);
        if (n <= 0)
            break;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        size_t len = (size_t)n;
        for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
            /* iproute2's filter, verbatim in spirit. */
            if (from.nl_pid != 0 || h->nlmsg_pid != local.nl_pid ||
                h->nlmsg_seq != 1234) {
                skipped++;
                continue;
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                saw_done = 1;
                done_len_ok = h->nlmsg_len >= NLMSG_LENGTH(sizeof(int));
                break;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                printf("dump: NLMSG_ERROR\n");
                close(fd);
                return 1;
            }
            if (h->nlmsg_type == RTM_NEWLINK)
                links++;
        }
    }
    printf("nldone: done=%d done_len_ok=%d links>0=%d skipped=%d\n", saw_done,
           done_len_ok, links > 0, skipped);
    close(fd);
    return 0;
}
