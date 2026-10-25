/* A netlink request written with write(2), and its reply read with read(2)
 * (M95).
 *
 * Mozilla's `mtu` crate, which Firefox's HTTP/3 stack asks for the MTU of the
 * path to every server it opens a connection to, opens a NETLINK_ROUTE socket,
 * write()s an RTM_GETROUTE for the peer and read()s the RTM_NEWROUTE back, then
 * does the same for RTM_GETLINK on the interface that names. The seccomp tier
 * traps neither call, and the emulation served a request only at the next
 * trapped call on its socket: there was none, so the read slept for good, and
 * Firefox's socket thread with it. A poll(2) between the two slept the same way
 * under either tier, and a sendmmsg(2) that named the kernel as its
 * destination was refused by the stand-in outright.
 *
 * Each leg runs in a child of its own under alarm(), so a request nobody
 * answers is reported as a timeout instead of wedging the legs after it.
 * Prints protocol only, byte-comparable against the same program on a kernel
 * whose rtnetlink works.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef ARPHRD_NONE
#define ARPHRD_NONE 0xfffe
#endif

struct route_req {
    struct nlmsghdr h;
    struct rtmsg r;
    struct rtattr a;
    unsigned char dst[4];
};

struct link_req {
    struct nlmsghdr h;
    struct ifinfomsg i;
};

/* The two requests exactly as the mtu crate builds them: NLM_F_ACK on both. */
static void route_req(struct route_req *q, unsigned seq) {
    memset(q, 0, sizeof *q);
    q->h.nlmsg_len = sizeof *q;
    q->h.nlmsg_type = RTM_GETROUTE;
    q->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    q->h.nlmsg_seq = seq;
    q->r.rtm_family = AF_INET;
    q->r.rtm_dst_len = 32;
    q->r.rtm_table = RT_TABLE_MAIN;
    q->r.rtm_scope = RT_SCOPE_UNIVERSE;
    q->r.rtm_type = RTN_UNICAST;
    q->a.rta_len = sizeof q->a + sizeof q->dst;
    q->a.rta_type = RTA_DST;
    q->dst[0] = 127;
    q->dst[3] = 1;
}

static void link_req(struct link_req *q, unsigned seq, int index) {
    memset(q, 0, sizeof *q);
    q->h.nlmsg_len = sizeof *q;
    q->h.nlmsg_type = RTM_GETLINK;
    q->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    q->h.nlmsg_seq = seq;
    q->i.ifi_family = AF_UNSPEC;
    q->i.ifi_type = ARPHRD_NONE;
    q->i.ifi_index = index;
}

/* What a reply said: its type, and the attributes these legs print. */
struct reply {
    int type;
    int oif;
    unsigned mtu;
    char name[16];
};

/* Read until the message of `want` with sequence `seq` arrives, the way the
 * mtu crate does: other sequences and success acks are skipped, an error is
 * the answer. 1 with `out` filled, or the negative errno. */
static int await(int fd, unsigned seq, int want, struct reply *out) {
    static char buf[16384];
    for (int rounds = 0; rounds < 16; rounds++) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0)
            return -errno;
        if (n == 0)
            return -EPIPE;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != seq)
                continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                if (e->error)
                    return e->error;
                continue;
            }
            if (h->nlmsg_type != want)
                continue;
            memset(out, 0, sizeof *out);
            out->type = h->nlmsg_type;
            size_t hdr = want == RTM_NEWROUTE ? sizeof(struct rtmsg)
                                              : sizeof(struct ifinfomsg);
            struct rtattr *a = (struct rtattr *)((char *)NLMSG_DATA(h) +
                                                 NLMSG_ALIGN(hdr));
            int left = (int)h->nlmsg_len - (int)NLMSG_LENGTH(NLMSG_ALIGN(hdr));
            for (; RTA_OK(a, left); a = RTA_NEXT(a, left)) {
                if (want == RTM_NEWROUTE && a->rta_type == RTA_OIF)
                    memcpy(&out->oif, RTA_DATA(a), sizeof out->oif);
                if (want == RTM_NEWLINK && a->rta_type == IFLA_MTU)
                    memcpy(&out->mtu, RTA_DATA(a), sizeof out->mtu);
                if (want == RTM_NEWLINK && a->rta_type == IFLA_IFNAME)
                    snprintf(out->name, sizeof out->name, "%s",
                             (char *)RTA_DATA(a));
            }
            return 1;
        }
    }
    return -ENOMSG;
}

static int nlsocket(int flags) {
    return socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | flags, NETLINK_ROUTE);
}

/* write(2) the route request, read(2) the reply, then the same for the link
 * that route leaves by: the mtu crate's whole conversation. */
static void leg_write(void) {
    int fd = nlsocket(0);
    struct route_req rq;
    struct link_req lq;
    struct reply rr, lr;
    route_req(&rq, 1);
    int r = write(fd, &rq, sizeof rq) == (ssize_t)sizeof rq
                ? await(fd, 1, RTM_NEWROUTE, &rr)
                : -errno;
    if (r < 0) {
        printf("write: route err=%d\n", -r);
        return;
    }
    link_req(&lq, 2, rr.oif);
    int l = write(fd, &lq, sizeof lq) == (ssize_t)sizeof lq
                ? await(fd, 2, RTM_NEWLINK, &lr)
                : -errno;
    if (l < 0) {
        printf("write: route=%d oif=%d link err=%d\n", rr.type, rr.oif, -l);
        return;
    }
    printf("write: route=%d oif=%d link=%d name=%s mtu=%u\n", rr.type, rr.oif,
           lr.type, lr.name, lr.mtu);
}

/* A non-blocking socket asks poll(2) when the reply is in. */
static void leg_poll(void) {
    int fd = nlsocket(SOCK_NONBLOCK);
    struct route_req rq;
    struct reply rr;
    route_req(&rq, 3);
    if (write(fd, &rq, sizeof rq) != (ssize_t)sizeof rq) {
        printf("poll: write err=%d\n", errno);
        return;
    }
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int ready = poll(&p, 1, 4000);
    int r = ready > 0 ? await(fd, 3, RTM_NEWROUTE, &rr) : -EAGAIN;
    if (r < 0) {
        printf("poll: ready=%d err=%d\n", ready, -r);
        return;
    }
    printf("poll: ready=%d route=%d oif=%d\n", ready, rr.type, rr.oif);
}

/* The request in two pieces: one message all the same. */
static void leg_writev(void) {
    int fd = nlsocket(0);
    struct route_req rq;
    struct reply rr;
    route_req(&rq, 4);
    struct iovec v[2] = {{&rq, sizeof rq.h}, {(char *)&rq + sizeof rq.h,
                                              sizeof rq - sizeof rq.h}};
    int r = writev(fd, v, 2) == (ssize_t)sizeof rq
                ? await(fd, 4, RTM_NEWROUTE, &rr)
                : -errno;
    if (r < 0) {
        printf("writev: err=%d\n", -r);
        return;
    }
    printf("writev: route=%d oif=%d\n", rr.type, rr.oif);
}

/* sendmmsg naming the kernel as the destination, as a batching library does. */
static void leg_sendmmsg(void) {
    int fd = nlsocket(0);
    struct route_req rq;
    struct reply rr;
    route_req(&rq, 5);
    struct sockaddr_nl k = {.nl_family = AF_NETLINK};
    struct iovec v = {&rq, sizeof rq};
    struct mmsghdr m;
    memset(&m, 0, sizeof m);
    m.msg_hdr.msg_name = &k;
    m.msg_hdr.msg_namelen = sizeof k;
    m.msg_hdr.msg_iov = &v;
    m.msg_hdr.msg_iovlen = 1;
    int sent = sendmmsg(fd, &m, 1, 0);
    if (sent != 1) {
        printf("sendmmsg: sent=%d err=%d\n", sent, errno);
        return;
    }
    int r = await(fd, 5, RTM_NEWROUTE, &rr);
    if (r < 0) {
        printf("sendmmsg: sent=%d err=%d\n", sent, -r);
        return;
    }
    printf("sendmmsg: sent=%d route=%d oif=%d\n", sent, rr.type, rr.oif);
}

static void run(const char *name, void (*leg)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        alarm(8);
        leg();
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    if (p < 0 || waitpid(p, &st, 0) != p)
        printf("%s: no child\n", name);
    else if (WIFSIGNALED(st))
        printf("%s: %s\n", name,
               WTERMSIG(st) == SIGALRM ? "timeout" : "killed");
}

int main(void) {
    run("write", leg_write);
    run("poll", leg_poll);
    run("writev", leg_writev);
    run("sendmmsg", leg_sendmmsg);
    return 0;
}
