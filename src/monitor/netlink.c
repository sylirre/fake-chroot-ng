/* NETLINK_ROUTE emulation.
 *
 * Android denies app domains rtnetlink: `socket(AF_NETLINK, …)` may be refused
 * outright, and where it is allowed the `bind()` is refused under a separate
 * SELinux check. Everything that reaches for interface information goes through
 * it — glibc/musl `getifaddrs(3)`, iproute2 (`ip link/addr/route`), bubblewrap's
 * `loopback_setup()`, and glibc's netlink-based source-address selection — so
 * without a shim they all fail inside the guest. This is the largest pure
 * functionality gap against arm64chroot, and it is on chroot-ng's own target
 * platform.
 *
 * The trick that makes it small: **an unbound socket can still dump.** Android
 * denies the bind, not the query, so `RTM_GETLINK`, `RTM_GETADDR` and
 * `RTM_GETROUTE` can all be relayed through a host netlink socket we open,
 * send on, and read from without ever binding it. arm64chroot only relays
 * GETROUTE that way and rebuilds the other two out of `getifaddrs`; relaying all
 * three is both far less code and *more* faithful, since every reply is the
 * kernel's own rather than an approximation — and it matters here, because
 * chroot-ng is -nostdlib and has no `getifaddrs` to call in the first place.
 *
 * The guest's fd is a real AF_UNIX datagram socket (so poll/close/dup behave)
 * that we never actually transmit on: sends are answered into a per-fd reply
 * buffer that the matching recv drains.
 */
#include "cng/monitor.h"
#include "cng/netlink.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include "cng/broker.h" /* cng_broker_env: no getenv in a freestanding build */

#include <asm/unistd.h>

int cng_nl_force_block = 0;
int cng_nl_no_relay = 0;

#define AF_NETLINK_    16
#define NETLINK_ROUTE_ 0
#define SOCK_DGRAM_    2
#define SOCK_RAW_      3
#define SOCK_TYPE_MASK 0xf /* SOCK_CLOEXEC/NONBLOCK ride the upper bits */

#define NLMSG_ERROR_ 2
#define NLMSG_DONE_  3
#define NLM_F_MULTI_ 2
#define NLM_F_DUMP_  0x300
#define MSG_PEEK_    2
#define MSG_TRUNC_   0x20

#define RTM_GETLINK_  18
#define RTM_GETADDR_  22
#define RTM_GETROUTE_ 26

#define NL_SLOTS 4

struct nlmsghdr_ {
    unsigned len;
    unsigned short type, flags;
    unsigned seq, pid;
};

struct sockaddr_nl_ {
    unsigned short family, pad;
    unsigned pid, groups;
};

/* One emulated netlink socket.
 *
 * `fd` is the AF_UNIX stand-in the guest holds; `hostfd` is a real, deliberately
 * UNBOUND netlink socket we keep for its lifetime and stream replies from. `ino`
 * pins the identity of the guest fd: we cannot trap close(), so a slot is only
 * ours while the fd still names the same socket inode — the same staleness
 * discipline procfs.c uses for its synthesized fds. Without it, a guest that
 * closed this fd and opened something else on the same number would have its I/O
 * quietly diverted here.
 *
 * `ack` holds a locally-built reply for the requests we answer ourselves rather
 * than forward (see nl_send); dumps never land in it, so it stays small. */
struct nl_slot {
    int fd, hostfd;
    unsigned long long ino;
    unsigned char ack[64];
    long alen, apos;
    int streaming; /* the pending reply comes from hostfd, not from ack */
};

static struct nl_slot g_slots[NL_SLOTS];

static unsigned long long fd_ino(int fd) {
    char st[144];
    if (CNG_SYS(__NR_fstat, fd, (long)st, 0, 0, 0, 0) != 0)
        return 0;
    return *(unsigned long long *)(st + 8); /* st_ino */
}

static struct nl_slot *slot_of(int fd) {
    if (fd < 0)
        return 0;
    for (int i = 0; i < NL_SLOTS; i++) {
        if (g_slots[i].fd != fd)
            continue;
        unsigned long long ino = fd_ino(fd);
        if (!ino || ino != g_slots[i].ino) {
            g_slots[i].fd = -1; /* recycled behind our back: not ours */
            return 0;
        }
        return &g_slots[i];
    }
    return 0;
}

int cng_nl_is_fake(int fd) { return slot_of(fd) != 0; }

/* Does the host refuse us rtnetlink? Probed once. socket() *and* bind() are both
 * tried, because a host may permit the socket and reject the bind under a
 * separate check — probing socket() alone would call such a host "working" and
 * leave the guest with a socket it can never use. */
static int host_blocks(void) {
    static int cached = -1;
    if (cached >= 0)
        return cached;
    if (cng_nl_force_block) {
        cached = 1;
        return 1;
    }
    long fd = CNG_SYS(__NR_socket, AF_NETLINK_, SOCK_RAW_ | CNG_O_CLOEXEC,
                      NETLINK_ROUTE_, 0, 0, 0);
    if (fd < 0) {
        cached = 1;
        return 1;
    }
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    long r = CNG_SYS(__NR_bind, fd, (long)&sa, sizeof sa, 0, 0, 0);
    sys_close((int)fd);
    cached = (r < 0);
    return cached;
}

/* Build a well-formed NLMSG_DONE at `buf`. The kernel's own DONE carries a
 * 4-byte error int and NLM_F_MULTI, and iproute2 *enforces* it: rtnl_dump_done()
 * prints "DONE truncated" and abandons the dump when nlmsg_len is below
 * NLMSG_LENGTH(sizeof(int)) == 20. glibc's getifaddrs never looks, which is why
 * a 16-byte DONE passed every local test and still broke `ip addr` on a device.
 * Returns the bytes written. */
static long put_done(unsigned char *buf, unsigned seq, unsigned pid) {
    struct nlmsghdr_ *d = (struct nlmsghdr_ *)buf;
    d->len = (unsigned)(sizeof *d + 4);
    d->type = NLMSG_DONE_;
    d->flags = NLM_F_MULTI_;
    d->seq = seq;
    d->pid = pid;
    *(int *)(buf + sizeof *d) = 0; /* dump error: success */
    return (long)d->len;
}

/* Rewrite the port id of every complete message in a received buffer.
 *
 * Our host socket is unbound, so the kernel addresses its replies to port 0,
 * while the guest's client matches them against the port id getsockname reported
 * (cng_nl_getname: our pid). iproute2 and glibc both silently skip a mismatch,
 * which loses the whole dump including its terminator. The sequence number needs
 * no fixing: the guest's own request carried it and we forward that verbatim. */
static void fix_pid(unsigned char *buf, long len, unsigned pid) {
    for (long p = 0; p + (long)sizeof(struct nlmsghdr_) <= len;) {
        struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + p);
        if (h->len < sizeof *h || p + (long)h->len > len)
            break;
        h->pid = pid;
        p += (long)((h->len + 3) & ~3u);
    }
}

/* An unbound netlink socket for relaying. Unbound is the whole point: the
 * SELinux denial on Android is on bind(2), not on the query. */
static long open_hostfd(void) {
    if (cng_nl_no_relay)
        return -1; /* test aid: exercise the degradation path on a working host */
    long fd = CNG_SYS(__NR_socket, AF_NETLINK_, SOCK_RAW_ | CNG_O_CLOEXEC,
                      NETLINK_ROUTE_, 0, 0, 0);
    if (fd < 0)
        return -1;
    /* Never block the guest forever on a kernel that says nothing. */
    struct cng_timeval tv = {2, 0};
    CNG_SYS(__NR_setsockopt, fd, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO, (long)&tv,
            sizeof tv, 0);
    return fd;
}

/* Relay a dump as the MINIMAL request form: an nlmsghdr plus a one-byte
 * rtgenmsg family, which is what Bionic's getifaddrs(3) sends.
 *
 * Forwarding the guest's request verbatim looked obviously right and is not:
 * iproute2 asks for RTM_GETLINK with a struct ifinfomsg *and* an IFLA_EXT_MASK
 * attribute, and Android refuses that form — while the bare rtgenmsg form it
 * refuses nothing. That is exactly the split observed on-device, where
 * RTM_GETLINK came back refused and RTM_GETADDR (which iproute2 sends without
 * the extra attribute) went through, leaving `ip addr` with an empty link list
 * and so nothing at all to print. It is also why arm64chroot works there: it
 * builds its link replies from getifaddrs, i.e. from this same minimal form.
 *
 * Dropping the request's filter attributes means the kernel may return more than
 * the guest asked for, which is safe: netlink filtering is advisory and every
 * client filters the replies itself (iproute2 always has).
 *
 * The family byte sits at offset 16 in all three dump payloads we relay —
 * ifinfomsg.ifi_family, ifaddrmsg.ifa_family, rtmsg.rtm_family — so it is
 * carried across without knowing which one this is. */
static long relay_dump(int hostfd, const unsigned char *req, long rlen) {
    unsigned char out[20];
    memset(out, 0, sizeof out);
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)out;
    const struct nlmsghdr_ *rh = (const struct nlmsghdr_ *)req;
    h->len = (unsigned)sizeof out;
    h->type = rh->type;
    h->flags = rh->flags;
    h->seq = rh->seq;
    h->pid = 0; /* the kernel fills in the source port id */
    out[16] = (rlen > 16) ? req[16] : 0;
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    return CNG_SYS(__NR_sendto, hostfd, (long)out, sizeof out, 0, (long)&sa,
                   sizeof sa);
}

long cng_nl_socket(long domain, long type, long protocol) {
    if (domain != AF_NETLINK_ || protocol != NETLINK_ROUTE_)
        return -1; /* not ours: let the real syscall run */
    if (!host_blocks())
        return -1; /* rtnetlink works here; nothing to emulate */
    int free_slot = -1;
    for (int i = 0; i < NL_SLOTS; i++) {
        if (g_slots[i].fd < 0 || !fd_ino(g_slots[i].fd) ||
            fd_ino(g_slots[i].fd) != g_slots[i].ino) {
            free_slot = i;
            break;
        }
    }
    if (free_slot < 0)
        return -1; /* table full: hand back the host's own refusal */
    /* A real AF_UNIX datagram socket stands in, so close/dup/poll/fcntl all
     * behave; we simply never transmit on it. The guest's SOCK_CLOEXEC and
     * SOCK_NONBLOCK bits are preserved. */
    long fd = CNG_SYS(__NR_socket, CNG_AF_UNIX,
                      SOCK_DGRAM_ | (type & ~(long)SOCK_TYPE_MASK), 0, 0, 0, 0);
    if (fd < 0)
        return -1;
    g_slots[free_slot].fd = (int)fd;
    g_slots[free_slot].ino = fd_ino((int)fd);
    g_slots[free_slot].hostfd = (int)open_hostfd();
    g_slots[free_slot].alen = 0;
    g_slots[free_slot].apos = 0;
    g_slots[free_slot].streaming = 0;
    if (cng_g_debug)
        cng_dprintf(2,
                    "[cng] netlink: emulating fd %ld (host denies rtnetlink), "
                    "relay fd %d\n",
                    fd, g_slots[free_slot].hostfd);
    return fd;
}

int cng_nl_send(int fd, const void *buf, long len, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;
    *out = len; /* the guest's request is always "sent" in full */
    s->alen = s->apos = 0;
    s->streaming = 0;
    if (!buf || len < (long)sizeof(struct nlmsghdr_))
        return 1;
    const struct nlmsghdr_ *rh = (const struct nlmsghdr_ *)buf;
    unsigned short type = rh->type;
    unsigned seq = rh->seq;
    int is_dump = (rh->flags & NLM_F_DUMP_) == NLM_F_DUMP_;

    if (type == RTM_GETLINK_ || type == RTM_GETADDR_ || type == RTM_GETROUTE_) {
        /* Forward verbatim to the unbound host socket and let the guest read the
         * kernel's own answer straight out of it (see cng_nl_recv). Buffering the
         * dump here instead — which is what this used to do — capped it at our
         * own buffer size, and a host with more than a few interfaces overran
         * that: the guest silently lost entries and got our synthesized
         * terminator rather than the kernel's. */
        long sr = (s->hostfd >= 0)
                      ? relay_dump(s->hostfd, (const unsigned char *)buf, len)
                      : -1;
        if (sr >= 0) {
            s->streaming = 1;
            if (cng_g_debug)
                cng_dprintf(2, "[cng] nl send fd=%d type=%u -> relayed\n", fd,
                            type);
            return 1;
        }
        /* The host will not answer at all. Give a well-formed empty dump: the
         * guest then sees no interfaces rather than an error or a hang. */
        s->alen = put_done(s->ack, seq, (unsigned)sys_getpid());
        if (cng_g_debug)
            cng_dprintf(2,
                        "[cng] nl send fd=%d type=%u -> empty (relay fd=%d "
                        "sendto=%ld)\n",
                        fd, type, s->hostfd, sr);
        return 1;
    }

    if (is_dump) {
        s->alen = put_done(s->ack, seq, (unsigned)sys_getpid());
        return 1;
    }
    /* Anything else gets a success ack, which is what lets bubblewrap's
     * loopback_setup() (RTM_NEWADDR/RTM_NEWLINK) proceed instead of aborting. */
    struct nlmsghdr_ *o = (struct nlmsghdr_ *)s->ack;
    o->len = (unsigned)(sizeof *o + 4 + sizeof *o);
    o->type = NLMSG_ERROR_;
    o->flags = 0;
    o->seq = seq;
    o->pid = (unsigned)sys_getpid();
    *(int *)(s->ack + sizeof *o) = 0; /* error == 0 => ack */
    memcpy(s->ack + sizeof *o + 4, buf, sizeof *o);
    s->alen = (long)o->len;
    return 1;
}

int cng_nl_recv(int fd, void *buf, long len, long flags, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;

    if (s->streaming) {
        /* Read the kernel's reply straight into the guest's buffer, forwarding
         * the guest's own MSG_* flags so MSG_PEEK and MSG_TRUNC are handled by
         * the kernel exactly as they would be on a real netlink socket — which
         * is how glibc sizes a dump before reading it. No message ever has to be
         * split by us, so there is no boundary bookkeeping and no cap. */
        long n = CNG_SYS(__NR_recvfrom, s->hostfd, (long)buf, len, flags, 0, 0);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] nl recv fd=%d len=%ld flags=%lx -> %ld\n", fd,
                        len, flags, n);
        if (n < 0) {
            *out = 0; /* nothing more: reads as end-of-dump */
            return 1;
        }
        /* Applies to a peek too: the client inspects what it peeked, and the
         * real read that follows rewrites it again harmlessly. */
        if (buf && n > 0)
            fix_pid((unsigned char *)buf, n < len ? n : len,
                    (unsigned)sys_getpid());
        *out = n;
        return 1;
    }

    long avail = s->alen - s->apos;
    if (avail <= 0) {
        *out = 0;
        return 1;
    }
    long n = avail < len ? avail : len;
    if (buf && n > 0)
        memcpy(buf, s->ack + s->apos, (size_t)n);
    if (!(flags & MSG_PEEK_))
        s->apos += n;
    *out = (flags & MSG_TRUNC_) ? avail : n;
    return 1;
}

/* Write a sockaddr_nl into a guest buffer. `pid` distinguishes the two callers,
 * and getting it wrong is not cosmetic: a netlink client discards any reply whose
 * *source* address is not nl_pid == 0, because that is what "came from the
 * kernel" means. Filling the source with our own port id made glibc skip every
 * message and wait for an NLMSG_DONE it would never accept. getsockname, by
 * contrast, must report our own port id, which is what the client then matches
 * each reply's nlmsg_pid against (see fix_pid). */
static int write_nladdr(void *addr, unsigned *alen, unsigned pid) {
    if (!addr || !alen || *alen < sizeof(struct sockaddr_nl_))
        return 1;
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    sa.pid = pid;
    memcpy(addr, &sa, sizeof sa);
    *alen = (unsigned)sizeof sa;
    return 1;
}

int cng_nl_getname(int fd, void *addr, unsigned *alen) {
    /* The real AF_UNIX answer is an unnamed 2-byte sockaddr, and iproute2
     * rejects that with "Wrong address length 2". Report the sockaddr_nl it
     * expects, carrying our own port id. */
    if (!slot_of(fd))
        return 0;
    return write_nladdr(addr, alen, (unsigned)sys_getpid());
}

int cng_nl_srcaddr(int fd, void *addr, unsigned *alen) {
    if (!slot_of(fd))
        return 0;
    return write_nladdr(addr, alen, 0); /* 0 == from the kernel */
}

int cng_nl_bind(int fd) { return slot_of(fd) != 0; }

void cng_nl_init(void) {
    for (int i = 0; i < NL_SLOTS; i++)
        g_slots[i].fd = -1;
}
