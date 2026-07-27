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
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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

    /* --- the SIOCGIF* family, the same questions over an AF_INET socket ---
     * `ifconfig` and getifaddrs's oldest fallback ask this way, and the answers
     * have to describe the same interfaces the dump above did — a guest told it
     * has only loopback must not be shown the host's whole interface list here.
     * Only properties that hold in both views are printed, so an emulated run
     * and a raw one are directly comparable. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        printf("ifconf: FAILED\n");
        return 0;
    }
    struct ifconf ifc;
    memset(&ifc, 0, sizeof ifc);
    int size_ok = (ioctl(s, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len > 0);
    char ibuf[8192];
    int nif = 0, saw_lo = 0, lo_addr = 0;
    ifc.ifc_len = (int)sizeof ibuf;
    ifc.ifc_buf = ibuf;
    if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
        nif = (int)(ifc.ifc_len / sizeof(struct ifreq));
        struct ifreq *r = (struct ifreq *)ibuf;
        for (int i = 0; i < nif; i++) {
            if (strcmp(r[i].ifr_name, "lo"))
                continue;
            saw_lo = 1;
            struct sockaddr_in *sin = (struct sockaddr_in *)&r[i].ifr_addr;
            lo_addr = (sin->sin_family == AF_INET &&
                       sin->sin_addr.s_addr == htonl(0x7f000001));
        }
    }
    printf("ifconf: size_ok=%d entries>0=%d lo=%d lo_addr=%d\n", size_ok,
           nif > 0, saw_lo, lo_addr);
    /* The exact count differs between the host's view and a synthesized one, so
     * it gets its own line: only the leg that pins the degraded (loopback-only)
     * view asserts it. */
    printf("ifcount: %d\n", nif);

    struct ifreq r;
    memset(&r, 0, sizeof r);
    strcpy(r.ifr_name, "lo");
    int idx = ioctl(s, SIOCGIFINDEX, &r) == 0 ? r.ifr_ifindex : -1;
    memset(&r.ifr_ifru, 0, sizeof r.ifr_ifru);
    strcpy(r.ifr_name, "lo");
    int flags = ioctl(s, SIOCGIFFLAGS, &r) == 0 ? r.ifr_flags : 0;
    memset(&r.ifr_ifru, 0, sizeof r.ifr_ifru);
    strcpy(r.ifr_name, "lo");
    int mtu = ioctl(s, SIOCGIFMTU, &r) == 0 ? r.ifr_mtu : -1;
    memset(&r.ifr_ifru, 0, sizeof r.ifr_ifru);
    strcpy(r.ifr_name, "lo");
    unsigned mask = 0;
    if (ioctl(s, SIOCGIFNETMASK, &r) == 0)
        mask = ((struct sockaddr_in *)&r.ifr_netmask)->sin_addr.s_addr;
    /* SIOCGIFNAME goes the other way: index in, name out. */
    memset(&r, 0, sizeof r);
    r.ifr_ifindex = idx;
    int byidx = (ioctl(s, SIOCGIFNAME, &r) == 0 && !strcmp(r.ifr_name, "lo"));
    printf("ifget: lo idx=%d up=%d loopback=%d mtu=%d mask8=%d byidx=%d\n", idx,
           (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) != 0, mtu,
           mask == htonl(0xff000000), byidx);

    memset(&r, 0, sizeof r);
    strcpy(r.ifr_name, "cngnope0");
    errno = 0;
    int nodev = (ioctl(s, SIOCGIFFLAGS, &r) < 0 && errno == ENODEV);
    printf("ifget: nodev=%d\n", nodev);
    close(s);
    return 0;
}
