/* The address an emulated netlink socket hands back (M72).
 *
 * getsockname, getpeername and the source address of recvfrom/recvmsg/recvmmsg
 * all go out by the kernel's rules for handing any address back
 * (move_addr_to_user): a negative length is EINVAL, a short buffer gets a
 * prefix, and the length written back is the address's own. recvmsg judges
 * msg_namelen before it receives anything: negative is EINVAL with the reply
 * still queued, while 0 is room for nothing and still gets the length back. A
 * receive that fails writes no address at all.
 *
 * Prints protocol only — lengths, errnos, and the bytes of an address that
 * carry no port id — so the output is byte-comparable against the same program
 * on a kernel whose rtnetlink works. Only bytes the kernel is asked to copy
 * are printed: qemu-user writes the whole address into a short recvmmsg name,
 * which a real kernel does not.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fd;

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
    static char b[65536];
    while (recv(fd, b, sizeof b, MSG_DONTWAIT) > 0)
        ;
}

/* The first n bytes of an address, as hex. */
static void bytes(const unsigned char *b, unsigned n) {
    printf(" b=");
    for (unsigned i = 0; i < n; i++)
        printf("%02x", b[i]);
    if (!n)
        printf("-");
}

static int err(long r) { return r < 0 ? errno : 0; }

int main(void) {
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("netlink: unavailable\n");
        return 1;
    }
    unsigned char b[64];
    socklen_t l;
    long r;

    /* getsockname: a prefix of 4 (family and pad, no port id), none at all,
     * a negative length, no buffer, no length. */
    memset(b, 0xAA, sizeof b);
    l = 4;
    r = getsockname(fd, (struct sockaddr *)b, &l);
    printf("getsockname 4: r=%ld l=%u", r, l);
    bytes(b, 5);
    printf("\n");
    memset(b, 0xAA, sizeof b);
    l = 0;
    r = getsockname(fd, (struct sockaddr *)b, &l);
    printf("getsockname 0: r=%ld l=%u", r, l);
    bytes(b, 1);
    printf("\n");
    l = (socklen_t)-1;
    errno = 0;
    r = getsockname(fd, (struct sockaddr *)b, &l);
    printf("getsockname -1: r=%ld e=%d l=%d\n", r, err(r), (int)l);
    l = sizeof sa;
    errno = 0;
    r = getsockname(fd, NULL, &l);
    printf("getsockname nobuf: r=%ld e=%d l=%u\n", r, err(r), l);
    l = 0;
    errno = 0;
    r = getsockname(fd, NULL, &l);
    printf("getsockname nobuf 0: r=%ld e=%d l=%u\n", r, err(r), l);
    errno = 0;
    r = getsockname(fd, (struct sockaddr *)b, NULL);
    printf("getsockname nolen: r=%ld e=%d\n", r, err(r));

    /* getpeername: the kernel, for a socket that never connected. */
    struct sockaddr_nl pn;
    memset(&pn, 0xAA, sizeof pn);
    l = sizeof pn;
    r = getpeername(fd, (struct sockaddr *)&pn, &l);
    printf("getpeername: r=%ld l=%u family=%u pid=%u groups=%u\n", r, l,
           pn.nl_family, pn.nl_pid, pn.nl_groups);

    /* recvfrom: a 6-byte prefix of the source, then a receive that fails. */
    static char data[65536];
    request();
    memset(b, 0xAA, sizeof b);
    l = 6;
    r = recvfrom(fd, data, sizeof data, 0, (struct sockaddr *)b, &l);
    printf("recvfrom 6: got=%d l=%u", r > 0, l);
    bytes(b, 7);
    printf("\n");
    drain();
    memset(b, 0xAA, sizeof b);
    l = sizeof sa;
    errno = 0;
    r = recvfrom(fd, data, sizeof data, MSG_DONTWAIT, (struct sockaddr *)b, &l);
    printf("recvfrom again: r=%ld e=%d l=%u", r, err(r), l);
    bytes(b, 1);
    printf("\n");

    /* recvmsg: a 5-byte name, a 0-byte one, and a negative one against a
     * fresh request — EINVAL, and the reply still there for the receive after
     * it (how many replies a dump is split into is not the same on both sides,
     * so the earlier ones are drained first). */
    struct iovec iov = {data, sizeof data};
    struct msghdr m;
    request();
    memset(&m, 0, sizeof m);
    memset(b, 0xAA, sizeof b);
    m.msg_name = b;
    m.msg_namelen = 5;
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    r = recvmsg(fd, &m, 0);
    printf("recvmsg 5: got=%d namelen=%u", r > 0, m.msg_namelen);
    bytes(b, 5);
    printf("\n");
    memset(&m, 0, sizeof m);
    memset(b, 0xAA, sizeof b);
    m.msg_name = b;
    m.msg_namelen = 0;
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    r = recvmsg(fd, &m, 0);
    printf("recvmsg 0: got=%d namelen=%u", r > 0, m.msg_namelen);
    bytes(b, 1);
    printf("\n");
    drain();
    request();
    memset(&m, 0, sizeof m);
    m.msg_name = b;
    m.msg_namelen = (socklen_t)-1;
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    errno = 0;
    r = recvmsg(fd, &m, MSG_DONTWAIT);
    printf("recvmsg -1: r=%ld e=%d", r, err(r));
    r = recv(fd, data, sizeof data, MSG_DONTWAIT);
    printf(" then=%d\n", r > 0);
    drain();

    /* recvmmsg: a full name and a 0-byte one. */
    request();
    struct mmsghdr mm[2];
    struct sockaddr_nl from;
    struct iovec iov2 = {data + 32768, 32768};
    memset(mm, 0, sizeof mm);
    memset(&from, 0xAA, sizeof from);
    memset(b, 0xAA, sizeof b);
    iov.iov_len = 32768;
    mm[0].msg_hdr.msg_name = &from;
    mm[0].msg_hdr.msg_namelen = sizeof from;
    mm[0].msg_hdr.msg_iov = &iov;
    mm[0].msg_hdr.msg_iovlen = 1;
    mm[1].msg_hdr.msg_name = b;
    mm[1].msg_hdr.msg_namelen = 0;
    mm[1].msg_hdr.msg_iov = &iov2;
    mm[1].msg_hdr.msg_iovlen = 1;
    r = recvmmsg(fd, mm, 2, MSG_WAITFORONE, NULL);
    printf("recvmmsg: r=%ld namelen=%u family=%u pid=%u", r,
           mm[0].msg_hdr.msg_namelen, from.nl_family, from.nl_pid);
    if (r == 2) {
        printf(" namelen0=%u", mm[1].msg_hdr.msg_namelen);
        bytes(b, 1);
    }
    printf("\n");
    drain();
    return 0;
}
