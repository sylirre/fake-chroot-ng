/* The ACK a netlink request asks for with NLM_F_ACK (M96).
 *
 * The kernel answers a non-dump get with the object — or the error refusing
 * it — and then, when the request carried NLM_F_ACK and was not refused, with
 * an ACK of its own: an NLMSG_ERROR of error 0, flagged NLM_F_CAPPED, echoing
 * the request's header. A dump is never acked, whatever it asked. The
 * emulation sent the object alone: a relayed get left the kernel's ACK unread
 * on the relay socket, and a synthesized one (the link Android refuses) never
 * had one, so a client waiting for the ACK — libnl's nl_wait_for_ack — waited
 * for good.
 *
 * Each request is sent, its first reply waited for, and then everything else
 * queued for it read without waiting: a missing ACK reads as ack=0, an extra
 * message as more>0. Prints protocol only, byte-comparable against the same
 * program on a kernel whose rtnetlink works.
 *
 * With the argument `unmodelled` it sends instead a request the emulation does
 * not model, bubblewrap's RTM_NEWADDR of 127.0.0.1/8 on loopback, which the
 * emulation acks as a success. That one is for the emulation alone: a kernel
 * answers an unprivileged caller EPERM (Android's policy refuses the send
 * itself, EACCES), and finds the address there for root.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif

static int fd;
static char buf[65536];

/* Every message answering `seq`, the first waited for and the rest taken as
 * they are queued; non-zero from a failed wait. */
struct seen {
    int objects, errors, acks, dones, more;
    int ack_error;
    unsigned ack_flags, ack_len;
    struct nlmsghdr echo;
};

static int collect(unsigned seq, int object_type, struct seen *s) {
    memset(s, 0, sizeof *s);
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 4000) != 1)
        return -1;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0)
            return errno == EAGAIN ? 0 : -1;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != seq)
                continue;
            if (h->nlmsg_type == object_type) {
                s->objects++;
            } else if (h->nlmsg_type == NLMSG_DONE) {
                s->dones++;
            } else if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                if (e->error) {
                    s->errors++;
                } else {
                    s->acks++;
                    s->ack_error = e->error;
                    s->ack_flags = h->nlmsg_flags;
                    s->ack_len = h->nlmsg_len;
                    s->echo = e->msg;
                }
            } else {
                s->more++;
            }
        }
    }
}

static void report(const char *name, const struct seen *s) {
    if (s->acks)
        printf("%s: objects=%d errors=%d acks=%d dones=%d more=%d ack=%d "
               "flags=%#x len=%u echo=%u/%u/%#x/%u\n",
               name, s->objects, s->errors, s->acks, s->dones, s->more,
               s->ack_error, s->ack_flags, s->ack_len, s->echo.nlmsg_type,
               s->echo.nlmsg_len, s->echo.nlmsg_flags, s->echo.nlmsg_seq);
    else
        printf("%s: objects=%d errors=%d acks=0 dones=%d more=%d\n", name,
               s->objects, s->errors, s->dones, s->more);
}

static void getlink(const char *name, unsigned seq, unsigned flags) {
    struct {
        struct nlmsghdr h;
        struct ifinfomsg i;
    } q;
    memset(&q, 0, sizeof q);
    q.h.nlmsg_len = sizeof q;
    q.h.nlmsg_type = RTM_GETLINK;
    q.h.nlmsg_flags = NLM_F_REQUEST | flags;
    q.h.nlmsg_seq = seq;
    q.i.ifi_family = AF_UNSPEC;
    q.i.ifi_index = 1;
    struct seen s;
    if (send(fd, &q, sizeof q, 0) != (ssize_t)sizeof q ||
        collect(seq, RTM_NEWLINK, &s) != 0) {
        printf("%s: no answer\n", name);
        return;
    }
    report(name, &s);
}

static void getroute(const char *name, unsigned seq, unsigned flags) {
    struct {
        struct nlmsghdr h;
        struct rtmsg r;
        struct rtattr a;
        unsigned char dst[4];
    } q;
    memset(&q, 0, sizeof q);
    q.h.nlmsg_len = sizeof q;
    q.h.nlmsg_type = RTM_GETROUTE;
    q.h.nlmsg_flags = NLM_F_REQUEST | flags;
    q.h.nlmsg_seq = seq;
    q.r.rtm_family = AF_INET;
    q.r.rtm_dst_len = 32;
    q.a.rta_len = sizeof q.a + sizeof q.dst;
    q.a.rta_type = RTA_DST;
    q.dst[0] = 127;
    q.dst[3] = 1;
    struct seen s;
    if (send(fd, &q, sizeof q, 0) != (ssize_t)sizeof q ||
        collect(seq, RTM_NEWROUTE, &s) != 0) {
        printf("%s: no answer\n", name);
        return;
    }
    report(name, &s);
}

/* A dump that asks for an ACK all the same: it ends in NLMSG_DONE and nothing
 * after it. Only the presence of objects is printed — how many is the host's. */
static void dump(const char *name, unsigned seq) {
    struct {
        struct nlmsghdr h;
        struct rtgenmsg g;
    } q;
    memset(&q, 0, sizeof q);
    q.h.nlmsg_len = sizeof q;
    q.h.nlmsg_type = RTM_GETLINK;
    q.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
    q.h.nlmsg_seq = seq;
    q.g.rtgen_family = AF_UNSPEC;
    struct seen s;
    if (send(fd, &q, sizeof q, 0) != (ssize_t)sizeof q) {
        printf("%s: no answer\n", name);
        return;
    }
    /* A dump spans several receives, so it is read until its terminator. */
    memset(&s, 0, sizeof s);
    for (int rounds = 0; rounds < 64 && !s.dones; rounds++) {
        struct seen part;
        if (collect(seq, RTM_NEWLINK, &part) != 0)
            break;
        s.objects += part.objects;
        s.errors += part.errors;
        s.acks += part.acks;
        s.dones += part.dones;
        s.more += part.more;
    }
    printf("%s: objects>0=%d errors=%d acks=%d dones=%d more=%d\n", name,
           s.objects > 0, s.errors, s.acks, s.dones, s.more);
}

/* bubblewrap's loopback_setup(), first request: 127.0.0.1/8 on loopback. */
static void newaddr(const char *name, unsigned seq) {
    struct {
        struct nlmsghdr h;
        struct ifaddrmsg i;
        struct rtattr a;
        unsigned char addr[4];
    } q;
    memset(&q, 0, sizeof q);
    q.h.nlmsg_len = sizeof q;
    q.h.nlmsg_type = RTM_NEWADDR;
    q.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    q.h.nlmsg_seq = seq;
    q.i.ifa_family = AF_INET;
    q.i.ifa_prefixlen = 8;
    q.i.ifa_flags = IFA_F_PERMANENT;
    q.i.ifa_scope = RT_SCOPE_HOST;
    q.i.ifa_index = 1;
    q.a.rta_len = sizeof q.a + sizeof q.addr;
    q.a.rta_type = IFA_LOCAL;
    q.addr[0] = 127;
    q.addr[3] = 1;
    struct seen s;
    if (send(fd, &q, sizeof q, 0) != (ssize_t)sizeof q ||
        collect(seq, RTM_NEWADDR, &s) != 0) {
        printf("%s: no answer\n", name);
        return;
    }
    report(name, &s);
}

int main(int argc, char **argv) {
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        printf("socket: errno=%d\n", errno);
        return 1;
    }
    if (argc > 1 && !strcmp(argv[1], "unmodelled")) {
        newaddr("newaddr ack", 6);
        return 0;
    }
    getlink("getlink ack", 1, NLM_F_ACK);
    getlink("getlink", 2, 0);
    getroute("getroute ack", 3, NLM_F_ACK);
    getroute("getroute", 4, 0);
    dump("dump ack", 5);
    return 0;
}
