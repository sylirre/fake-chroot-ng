/* The rest of a recvmsg header on an emulated netlink socket (M73).
 *
 * A recvmsg is more than its address: the kernel scatters the datagram over
 * every iovec, reports a cut one with MSG_TRUNC in msg_flags, writes back how
 * much control data it delivered in msg_controllen, consumes the datagram even
 * into no room at all, and refuses a header it cannot read. The emulation
 * received into the first iovec only and left msg_flags and msg_controllen as
 * the caller had them, and a datagram offered no room at all stayed queued
 * (the first iovec was the only one looked at, and an empty set none).
 *
 * msg_flags and msg_controllen start as garbage the kernel must overwrite.
 * Prints protocol only, byte-comparable against the same program on a kernel
 * whose rtnetlink works. Whether a datagram was consumed is asked of the
 * datagram after it, which is a different one wherever the dump is split.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int fd;
static char data[65536], peek1[65536], peek2[65536];

static void request(void) {
    struct {
        struct nlmsghdr h;
        struct rtgenmsg g;
    } r;
    memset(&r, 0, sizeof r);
    r.h.nlmsg_len = sizeof r;
    r.h.nlmsg_type = RTM_GETLINK;
    r.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    r.h.nlmsg_seq = 1;
    r.g.rtgen_family = AF_UNSPEC;
    struct sockaddr_nl k = {.nl_family = AF_NETLINK};
    sendto(fd, &r, sizeof r, 0, (struct sockaddr *)&k, sizeof k);
}

static void drain(void) {
    while (recv(fd, data, sizeof data, MSG_DONTWAIT) > 0)
        ;
}

static int err(long r) { return r < 0 ? errno : 0; }

/* A header with garbage where the kernel writes. */
static void garbage(struct msghdr *m, char *ctl, size_t cl) {
    memset(m, 0, sizeof *m);
    m->msg_control = ctl;
    m->msg_controllen = cl;
    m->msg_flags = 0x7777;
}

int main(void) {
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("netlink: unavailable\n");
        return 1;
    }
    struct msghdr m;
    char ctl[64];
    long r;

    /* Two 16-byte iovecs: filled both, and cut. */
    char a[16], b[16];
    memset(b, 0xAA, sizeof b);
    struct iovec two[2] = {{a, sizeof a}, {b, sizeof b}};
    request();
    garbage(&m, ctl, sizeof ctl);
    m.msg_iov = two;
    m.msg_iovlen = 2;
    r = recvmsg(fd, &m, 0);
    printf("scatter: r=%ld second=%d flags=%#x controllen=%zu\n", r,
           b[0] != (char)0xAA, m.msg_flags, (size_t)m.msg_controllen);
    drain();

    /* One iovec the whole datagram fits in: nothing cut. */
    struct iovec whole = {data, sizeof data};
    request();
    garbage(&m, ctl, sizeof ctl);
    m.msg_iov = &whole;
    m.msg_iovlen = 1;
    r = recvmsg(fd, &m, 0);
    printf("whole: got=%d flags=%#x controllen=%zu\n", r > 0, m.msg_flags,
           (size_t)m.msg_controllen);
    drain();

    /* No room at all: the datagram goes, cut to nothing. (One empty iovec
     * rather than none: qemu-user answers a recvmsg with no iovec 0 without
     * asking the kernel, which receives and cuts as it does here.) */
    struct iovec none = {data, 0};
    request();
    long n1 = recv(fd, peek1, sizeof peek1, MSG_PEEK);
    garbage(&m, ctl, sizeof ctl);
    m.msg_iov = &none;
    m.msg_iovlen = 1;
    r = recvmsg(fd, &m, 0);
    long n2 = recv(fd, peek2, sizeof peek2, MSG_PEEK | MSG_DONTWAIT);
    int consumed = n2 != n1 || memcmp(peek1, peek2, n1 > 0 ? n1 : 0) != 0;
    printf("empty: r=%ld flags=%#x controllen=%zu consumed=%d\n", r,
           m.msg_flags, (size_t)m.msg_controllen, consumed);
    drain();

    /* Headers the kernel refuses: none at all, too many iovecs, an iovec
     * array it cannot read. None of them takes the reply. */
    request();
    errno = 0;
    r = recvmsg(fd, NULL, MSG_DONTWAIT);
    printf("nullhdr: r=%ld e=%d\n", r, err(r));
    garbage(&m, ctl, sizeof ctl);
    m.msg_iov = &whole;
    m.msg_iovlen = 1025;
    errno = 0;
    r = recvmsg(fd, &m, MSG_DONTWAIT);
    printf("bigiov: r=%ld e=%d\n", r, err(r));
    garbage(&m, ctl, sizeof ctl);
    m.msg_iov = (struct iovec *)8;
    m.msg_iovlen = 1;
    errno = 0;
    r = recvmsg(fd, &m, MSG_DONTWAIT);
    printf("badiov: r=%ld e=%d", r, err(r));
    r = recv(fd, data, sizeof data, MSG_DONTWAIT);
    printf(" then=%d\n", r > 0);
    drain();

    /* recvmmsg: the same header, per message. */
    request();
    struct mmsghdr mm[1];
    memset(mm, 0, sizeof mm);
    memset(b, 0xAA, sizeof b);
    mm[0].msg_hdr.msg_iov = two;
    mm[0].msg_hdr.msg_iovlen = 2;
    mm[0].msg_hdr.msg_control = ctl;
    mm[0].msg_hdr.msg_controllen = sizeof ctl;
    mm[0].msg_hdr.msg_flags = 0x7777;
    r = recvmmsg(fd, mm, 1, 0, NULL);
    printf("recvmmsg: r=%ld len=%u second=%d flags=%#x controllen=%zu\n", r,
           mm[0].msg_len, b[0] != (char)0xAA, mm[0].msg_hdr.msg_flags,
           (size_t)mm[0].msg_hdr.msg_controllen);
    drain();
    return 0;
}
