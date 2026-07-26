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

/* Big enough for a real interface list in one dump; the oracle's 8192 truncates
 * on a host with many interfaces, and a truncated dump costs the guest entries. */
#define NL_REPLY_MAX 16384
#define NL_SLOTS     4

struct nlmsghdr_ {
    unsigned len;
    unsigned short type, flags;
    unsigned seq, pid;
};

struct sockaddr_nl_ {
    unsigned short family, pad;
    unsigned pid, groups;
};

/* One emulated netlink socket. `ino` pins the identity of the fd: we cannot trap
 * close(), so a slot is only ours while the fd still names the same socket
 * inode — the same staleness discipline procfs.c uses for its synthesized fds.
 * Without it, a guest that closed this fd and opened something else on the same
 * number would have its I/O quietly diverted here. */
struct nl_slot {
    int fd;
    unsigned long long ino;
    unsigned char reply[NL_REPLY_MAX];
    long rlen, rpos;
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

/* Relay a dump through an UNBOUND host netlink socket. This is the whole reason
 * the emulation can be this small: the denial is on bind, not on the query.
 * Returns the bytes placed in `out`, or 0 if the host would not answer. */
static long relay(const unsigned char *req, long rlen, unsigned char *out,
                  long cap, unsigned seq, unsigned pid) {
    long fd = CNG_SYS(__NR_socket, AF_NETLINK_, SOCK_RAW_ | CNG_O_CLOEXEC,
                      NETLINK_ROUTE_, 0, 0, 0);
    if (fd < 0)
        return 0;
    /* Don't block forever if the kernel says nothing. */
    struct cng_timeval tv = {1, 0};
    CNG_SYS(__NR_setsockopt, fd, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO, (long)&tv,
            sizeof tv, 0);
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    if (CNG_SYS(__NR_sendto, fd, (long)req, rlen, 0, (long)&sa, sizeof sa) < 0) {
        sys_close((int)fd);
        return 0;
    }
    long off = 0;
    for (int round = 0; round < 64; round++) {
        long n = CNG_SYS(__NR_recvfrom, fd, (long)(out + off), cap - off, 0, 0, 0);
        if (n <= 0)
            break;
        /* Rewrite the sequence and port id of every message so the guest's
         * netlink library accepts them as answers to *its* request (iproute2
         * checks both and silently drops a mismatch). Also spot the terminating
         * NLMSG_DONE while walking. */
        int done = 0;
        long p = off;
        while (p + (long)sizeof(struct nlmsghdr_) <= off + n) {
            struct nlmsghdr_ *h = (struct nlmsghdr_ *)(out + p);
            if (h->len < sizeof *h || p + (long)h->len > off + n)
                break;
            h->seq = seq;
            h->pid = pid;
            if (h->type == NLMSG_DONE_ || h->type == NLMSG_ERROR_)
                done = 1;
            if (!(h->flags & NLM_F_MULTI_))
                done = 1;
            p += (long)((h->len + 3) & ~3u);
        }
        off += n;
        if (done || off >= cap)
            break;
    }
    sys_close((int)fd);
    return off;
}

/* Make a relayed dump self-terminating, and return its final length.
 *
 * A reply cut off by our buffer (or the round cap) ends in a PARTIAL message.
 * A netlink client walks with NLMSG_OK and stops dead at that partial record, so
 * appending the terminator after it is useless — the client never gets there,
 * reads again, sees an empty datagram and reports it as an error (glibc:
 * "Unexpected netlink response of size 0"). The terminator has to *replace* the
 * partial tail: rewind to the end of the last complete message and put
 * NLMSG_DONE there. The guest then loses whatever the truncation dropped, but it
 * sees a well-formed, finite dump instead of hanging. */
static long nl_finish(unsigned char *buf, long len, unsigned seq, unsigned pid) {
    long end = 0;
    int done = 0;
    for (long p = 0; p + (long)sizeof(struct nlmsghdr_) <= len;) {
        struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + p);
        if (h->len < sizeof *h || p + (long)h->len > len)
            break; /* partial: everything from here is discarded */
        done = (h->type == NLMSG_DONE_);
        p += (long)((h->len + 3) & ~3u);
        end = p;
    }
    if (done)
        return end;
    struct nlmsghdr_ *d = (struct nlmsghdr_ *)(buf + end);
    d->len = sizeof *d;
    d->type = NLMSG_DONE_;
    d->flags = 0;
    d->seq = seq;
    d->pid = pid;
    return end + (long)sizeof *d;
}

/* Build the answer to one guest request into the slot's reply buffer. */
static void answer(struct nl_slot *s, const unsigned char *req, long rlen) {
    s->rlen = 0;
    s->rpos = 0;
    if (rlen < (long)sizeof(struct nlmsghdr_))
        return;
    const struct nlmsghdr_ *rh = (const struct nlmsghdr_ *)req;
    unsigned seq = rh->seq;
    /* The reply's nlmsg_pid is the *destination* port id — the requesting
     * socket's — not whatever the request happened to carry (usually 0, since
     * the kernel fills it in). glibc's __netlink_request drops any message whose
     * nlmsg_pid does not equal the port id it read from getsockname, so echoing
     * the request's value made it discard the entire dump, terminator included,
     * and then report the next empty read as an error. Must stay in step with
     * cng_nl_getname. */
    unsigned pid = (unsigned)sys_getpid();
    unsigned short type = rh->type;
    int is_dump = (rh->flags & NLM_F_DUMP_) == NLM_F_DUMP_;

    if (type == RTM_GETLINK_ || type == RTM_GETADDR_ || type == RTM_GETROUTE_) {
        /* Reserve room for a terminator: a dump the guest cannot see the end of
         * is worse than a short one. glibc and iproute2 both read until
         * NLMSG_DONE, so a reply truncated by our buffer (or by the round cap)
         * without one makes them wait forever. */
        long n = relay(req, rlen, s->reply, NL_REPLY_MAX - (long)sizeof *rh, seq,
                       pid);
        if (n > 0) {
            s->rlen = nl_finish(s->reply, n, seq, pid);
            return;
        }
        /* The host would not answer at all. An empty dump is the graceful
         * degradation: getifaddrs() then succeeds with no interfaces rather
         * than failing outright, and `ip addr` prints nothing instead of
         * "Cannot open netlink socket". */
    }

    struct nlmsghdr_ *o = (struct nlmsghdr_ *)s->reply;
    if (is_dump) {
        o->len = sizeof *o;
        o->type = NLMSG_DONE_;
        o->flags = 0;
        o->seq = seq;
        o->pid = pid;
        s->rlen = (long)sizeof *o;
        return;
    }
    /* Everything else gets a success ack. This is what makes bubblewrap's
     * loopback_setup() (RTM_NEWADDR/RTM_NEWLINK) proceed instead of aborting. */
    o->len = sizeof *o + 4 + (unsigned)sizeof *o;
    o->type = NLMSG_ERROR_;
    o->flags = 0;
    o->seq = seq;
    o->pid = pid;
    *(int *)(s->reply + sizeof *o) = 0; /* error == 0 => ack */
    memcpy(s->reply + sizeof *o + 4, req, sizeof *o);
    s->rlen = (long)o->len;
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
    g_slots[free_slot].rlen = 0;
    g_slots[free_slot].rpos = 0;
    if (cng_g_debug)
        cng_dprintf(2, "[cng] netlink: emulating fd %ld (host denies rtnetlink)\n",
                    fd);
    return fd;
}

int cng_nl_send(int fd, const void *buf, long len, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;
    if (buf && len > 0)
        answer(s, (const unsigned char *)buf, len);
    if (cng_g_debug) {
        unsigned t = (len >= 16) ? ((const struct nlmsghdr_ *)buf)->type : 0;
        cng_dprintf(2, "[cng] nl send fd=%d len=%ld type=%u -> reply %ld\n", fd,
                    len, t, s->rlen);
    }
    *out = len; /* the guest's request was "sent" in full */
    return 1;
}

int cng_nl_recv(int fd, void *buf, long len, long flags, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;
    long avail = s->rlen - s->rpos;
    if (avail <= 0) {
        *out = 0; /* drained: an empty datagram, which reads as end-of-dump */
        return 1;
    }
    /* Netlink is message-oriented: a reader walks the buffer with NLMSG_OK, so a
     * read must never end mid-record. A dump legitimately spans several reads
     * (the client loops until NLMSG_DONE), but handing back a truncated record
     * makes the next read start mid-header and the walk falls apart — which
     * presented as glibc reporting "Unexpected netlink response of size 0" two
     * reads later. So hand back as many WHOLE messages as fit. */
    long end = s->rpos;
    while (end < s->rlen) {
        const struct nlmsghdr_ *h = (const struct nlmsghdr_ *)(s->reply + end);
        if (end + (long)sizeof *h > s->rlen || h->len < sizeof *h)
            break;
        long adv = (long)((h->len + 3) & ~3u);
        if (end + adv > s->rlen || (end - s->rpos) + adv > len)
            break;
        end += adv;
    }
    long n = end - s->rpos;
    if (n == 0) /* a single message larger than the buffer: truncate, as the
                 * kernel does (and flag it via MSG_TRUNC below) */
        n = avail < len ? avail : len;
    if (cng_g_debug)
        cng_dprintf(2, "[cng] nl recv fd=%d len=%ld flags=%lx avail=%ld -> %ld\n",
                    fd, len, flags, avail, n);
    if (buf && n > 0)
        memcpy(buf, s->reply + s->rpos, (size_t)n);
    /* glibc's __netlink_request sizes the message first with
     * MSG_PEEK|MSG_TRUNC, grows its buffer to fit, and only then reads for
     * real. Honoring both flags is what makes getifaddrs(3) work: PEEK must not
     * consume, and TRUNC must report the *whole* pending length rather than the
     * bytes that fit, or the caller concludes the reply was empty. */
    if (!(flags & MSG_PEEK_))
        s->rpos += n;
    *out = (flags & MSG_TRUNC_) ? avail : n;
    return 1;
}

/* Write a sockaddr_nl into a guest buffer. `pid` distinguishes the two callers,
 * and getting it wrong is not cosmetic: glibc's __netlink_request discards any
 * reply whose *source* address is not nl_pid == 0, because that is what "came
 * from the kernel" means. Filling the source with our own port id made glibc
 * skip every message and wait for an NLMSG_DONE it would never accept —
 * getifaddrs(3) hung rather than failed. getsockname, by contrast, must report
 * our own port id, which is what the caller then matches replies against. */
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
