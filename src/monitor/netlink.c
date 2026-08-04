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
 * denies the bind, not the query, so dumps can be relayed through a host
 * netlink socket we open, send on, and read from without ever binding it. But
 * the policy also splits by message type: RTM_GETADDR and RTM_GETROUTE are
 * plain `nlmsg_read` and relay fine, while RTM_GETLINK needs `nlmsg_readpriv`
 * (link dumps expose MAC addresses) and app domains are refused it in *every*
 * request form — the sendto itself fails with EACCES. A dump the host refuses
 * to answer is therefore synthesized instead, the way arm64chroot builds its
 * link replies (sys_netlink.c build_host_links): interfaces enumerated from
 * the one dump Android leaves open (RTM_GETADDR — the same enumeration
 * Bionic's getifaddrs falls back to under this policy), fleshed out with
 * SIOCGIF* ioctls. chroot-ng is -nostdlib, so this is that Bionic fallback
 * rebuilt from raw syscalls.
 *
 * The guest's fd is one end of a real AF_UNIX datagram SOCKETPAIR; the monitor
 * holds the other end. Replies are pushed into the pair as datagrams, so the
 * guest's recv — trapped or not — reads real datagrams from a real socket, and
 * the kernel provides MSG_PEEK/MSG_TRUNC/blocking/poll semantics unaided.
 * Requests the guest submits with plain write(2)/send(2) — syscalls we leave
 * untrapped for speed — queue on our end and are drained at the next trapped
 * netlink call (busybox ip writes its request with write() and then calls
 * recvmsg(), which traps and finds the request waiting).
 *
 * The same socket(2) trap carries the other netlink protocol Android takes
 * away, NETLINK_AUDIT — not emulated but *rephrased*, since the whole of what
 * libaudit's callers need is a refusal they recognise. See cng_nl_audit_refusal.
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
int cng_nl_deny_getlink = 0;
int cng_nl_deny_audit = 0;

#define AF_NETLINK_    16
#define AF_INET_       2
#define AF_INET6_      10
#define NETLINK_ROUTE_ 0
#define NETLINK_AUDIT_ 9
#define SOCK_DGRAM_    2
#define SOCK_RAW_      3
#define SOCK_TYPE_MASK 0xf /* SOCK_CLOEXEC/NONBLOCK ride the upper bits */

#define NLMSG_ERROR_   2
#define NLMSG_DONE_    3
#define NLM_F_REQUEST_ 1
#define NLM_F_MULTI_   2
#define NLM_F_DUMP_    0x300
#define MSG_PEEK_      2
#define MSG_TRUNC_     0x20
#define MSG_DONTWAIT_  0x40

#define RTM_NEWLINK_  16
#define RTM_GETLINK_  18
#define RTM_NEWADDR_  20
#define RTM_GETADDR_  22
#define RTM_GETROUTE_ 26

/* For the synthesized RTM_NEWLINK/RTM_NEWADDR messages (values are ABI). */
#define IFLA_ADDRESS_    1
#define IFLA_BROADCAST_  2
#define IFLA_IFNAME_     3
#define IFLA_MTU_        4
#define IFLA_TXQLEN_     13
#define IFLA_OPERSTATE_  16
#define IF_OPER_DOWN_    2
#define IF_OPER_UP_      6
#define IFA_ADDRESS_     1
#define IFA_LOCAL_       2
#define IFA_LABEL_       3
#define IFA_F_PERMANENT_ 0x80
#define RT_SCOPE_HOST_   254
#define IFF_UP_          0x1
#define IFF_LOOPBACK_    0x8
#define IFF_RUNNING_     0x40
#define IFF_LOWER_UP_    0x10000
#define ARPHRD_ETHER_    1
#define ARPHRD_LOOPBACK_ 772
#define IFNAMSIZ_        16

#define SIOCGIFNAME_    0x8910
#define SIOCGIFCONF_    0x8912
#define SIOCGIFFLAGS_   0x8913
#define SIOCGIFADDR_    0x8915
#define SIOCGIFDSTADDR_ 0x8917
#define SIOCGIFBRDADDR_ 0x8919
#define SIOCGIFNETMASK_ 0x891b
#define SIOCGIFMETRIC_  0x891d
#define SIOCGIFMTU_     0x8921
#define SIOCGIFHWADDR_  0x8927
#define SIOCGIFINDEX_   0x8933
#define SIOCGIFTXQLEN_  0x8942
#define SIOCGIFMAP_     0x8970

#define NL_SLOTS 4
/* Per-slot reply capacity, matching the oracle's NL_REPLY_MAX. A synthesized
 * link dump is ~100 bytes per interface, so this holds dozens with room for
 * the terminator. */
#define NL_REPLY_MAX 8192

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
 * `fd` is the guest's end of the stand-in socketpair and `monfd` is ours:
 * replies are sent into `monfd` and appear as datagrams on `fd`, and requests
 * the guest wrote with untrapped write(2)/send(2) queue on `monfd` until a
 * trapped call drains them. `hostfd` is a real, deliberately UNBOUND netlink
 * socket kept for the slot's lifetime and used to relay dumps. `ino` pins the
 * identity of the guest fd: we cannot trap close(), so a slot is only ours
 * while the fd still names the same socket inode — the same staleness
 * discipline procfs.c uses for its synthesized fds. Without it, a guest that
 * closed this fd and opened something else on the same number would have its
 * I/O quietly diverted here.
 *
 * `scratch` is assembly space for relayed and synthesized reply datagrams. */
struct nl_slot {
    int fd, monfd, hostfd;
    unsigned long long ino;
    unsigned char scratch[NL_REPLY_MAX];
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
 * no fixing: the guest's own request carried it and we forward that verbatim.
 * Returns 1 when the buffer contained the NLMSG_DONE terminator. */
static int fix_pid(unsigned char *buf, long len, unsigned pid) {
    int done = 0;
    for (long p = 0; p + (long)sizeof(struct nlmsghdr_) <= len;) {
        struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + p);
        if (h->len < sizeof *h || p + (long)h->len > len)
            break;
        h->pid = pid;
        if (h->type == NLMSG_DONE_)
            done = 1;
        p += (long)((h->len + 3) & ~3u);
    }
    return done;
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
/* The most a non-dump get needs bounced: `ip route get ADDR` is 36 bytes,
 * `ip link show dev NAME` about 42. */
#define NL_RELAY_MAX 256

static long relay_request(int hostfd, const unsigned char *req, long rlen,
                          int is_dump) {
    unsigned char out[NL_RELAY_MAX];
    long n;
    const struct nlmsghdr_ *rh = (const struct nlmsghdr_ *)req;
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)out;
    if (is_dump) {
        /* A dump goes in the minimal form — header plus a one-byte family,
         * with the request's filter attributes dropped. That is what gets past
         * Android's refusal of the attribute-bearing form, and it is safe
         * because netlink filtering is advisory: the kernel may return more
         * than the guest asked for, and every client filters the replies
         * itself. */
        n = 20;
        memset(out, 0, (size_t)n);
        h->len = (unsigned)n;
        h->type = rh->type;
        h->flags = rh->flags;
        h->seq = rh->seq;
        out[16] = (rlen > 16) ? req[16] : 0;
    } else {
        /* A non-dump get cannot be expressed that way: its payload *is* the
         * request, and the kernel validates that payload's length before the
         * handler ever sees it. rtnl_getlink() parses with hdrlen
         * sizeof(struct ifinfomsg) == 16 and rtnl_getroute() with
         * sizeof(struct rtmsg) == 12, while the minimal form's nlmsg_len() is
         * 4 — so nlmsg_parse refuses it and `ip route get 8.8.8.8` was told
         * "Invalid argument" for a request the host would have answered.
         * Forward it as it stands instead. */
        if (rlen < (long)sizeof *rh || rlen > (long)sizeof out)
            return -EINVAL; /* too big to bounce: fall back to synthesis */
        memcpy(out, req, (size_t)rlen);
        n = rlen;
        h->len = (unsigned)n; /* consistent with what we actually send */
    }
    h->pid = 0; /* the kernel fills in the source port id */
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    return CNG_SYS(__NR_sendto, hostfd, (long)out, n, 0, (long)&sa, sizeof sa);
}

/* ------------------------------------------------------------------------- */
/* Synthesized replies, for the queries the host refuses to answer at all.
 * Android forbids app domains RTM_GETLINK in every form (nlmsg_readpriv), so
 * the link dump is rebuilt the way the oracle rebuilds it: enumerate from the
 * address dump, flesh out with SIOCGIF* ioctls, hardcode what an app cannot
 * know (txqlen), and fall back to a bare loopback when even that is denied.   */

/* Append one rtattr; drop it (return `off` unchanged) if it would not fit. */
static long put_attr(unsigned char *buf, long off, long max, unsigned short type,
                     const void *data, unsigned short dlen) {
    long space = (long)((4u + dlen + 3u) & ~3u);
    if (off + space > max)
        return off;
    unsigned short *rta = (unsigned short *)(buf + off);
    rta[0] = (unsigned short)(4 + dlen);
    rta[1] = type;
    if (dlen)
        memcpy(buf + off + 4, data, dlen);
    if (space > 4 + dlen)
        memset(buf + off + 4 + dlen, 0, (size_t)(space - 4 - dlen));
    return off + space;
}

/* Facts for one synthesized RTM_NEWLINK. */
struct ifinfo {
    int index;
    unsigned flags, mtu;
    unsigned short hwtype;
    unsigned char hwaddr[8], hwlen;
    char name[IFNAMSIZ_];
};

/* Append an RTM_NEWLINK describing one interface. Attribute set and the values
 * an app cannot query (txqlen 1000, operstate from IFF_UP, IFF_LOWER_UP from
 * IFF_RUNNING) mirror the oracle's nl_build_link, which is what the on-device
 * `ip addr` output has always shown under arm64chroot. */
static long put_link(unsigned char *buf, long off, long max, unsigned seq,
                     unsigned pid, unsigned short nlflags,
                     const struct ifinfo *fi) {
    long start = off;
    if (start + 32 > max)
        return start;
    unsigned char *ifi = buf + start + 16; /* struct ifinfomsg */
    memset(ifi, 0, 16);
    *(unsigned short *)(ifi + 2) = fi->hwtype;
    *(int *)(ifi + 4) = fi->index;
    *(unsigned *)(ifi + 8) =
        fi->flags | ((fi->flags & IFF_RUNNING_) ? IFF_LOWER_UP_ : 0);
    off = start + 32;
    off = put_attr(buf, off, max, IFLA_IFNAME_, fi->name,
                   (unsigned short)(strlen(fi->name) + 1));
    unsigned mtu = fi->mtu, txqlen = 1000;
    unsigned char oper = (fi->flags & IFF_UP_) ? IF_OPER_UP_ : IF_OPER_DOWN_;
    off = put_attr(buf, off, max, IFLA_MTU_, &mtu, 4);
    off = put_attr(buf, off, max, IFLA_TXQLEN_, &txqlen, 4);
    off = put_attr(buf, off, max, IFLA_OPERSTATE_, &oper, 1);
    if (fi->hwlen) {
        unsigned char brd[8];
        memset(brd, fi->hwtype == ARPHRD_LOOPBACK_ ? 0x00 : 0xff, sizeof brd);
        off = put_attr(buf, off, max, IFLA_ADDRESS_, fi->hwaddr, fi->hwlen);
        off = put_attr(buf, off, max, IFLA_BROADCAST_, brd, fi->hwlen);
    }
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + start);
    h->len = (unsigned)(off - start);
    h->type = RTM_NEWLINK_;
    h->flags = nlflags;
    h->seq = seq;
    h->pid = pid;
    return off; /* header + 4-aligned attrs: already NLMSG_ALIGNed */
}

/* Append an RTM_NEWADDR for loopback (127.0.0.1/8 or ::1/128, scope host). */
static long put_lo_addr(unsigned char *buf, long off, long max, unsigned seq,
                        unsigned pid, int v6, unsigned short nlflags) {
    long start = off;
    if (start + 24 > max)
        return start;
    unsigned char *ifa = buf + start + 16; /* struct ifaddrmsg */
    memset(ifa, 0, 8);
    ifa[0] = (unsigned char)(v6 ? AF_INET6_ : AF_INET_);
    ifa[1] = (unsigned char)(v6 ? 128 : 8); /* prefixlen */
    ifa[2] = IFA_F_PERMANENT_;
    ifa[3] = RT_SCOPE_HOST_;
    *(unsigned *)(ifa + 4) = 1; /* loopback is index 1 on every kernel */
    off = start + 24;
    unsigned char a[16];
    memset(a, 0, sizeof a);
    unsigned short alen;
    if (v6) {
        a[15] = 1;
        alen = 16;
    } else {
        a[0] = 127;
        a[3] = 1;
        alen = 4;
    }
    off = put_attr(buf, off, max, IFA_ADDRESS_, a, alen);
    off = put_attr(buf, off, max, IFA_LOCAL_, a, alen);
    if (!v6)
        off = put_attr(buf, off, max, IFA_LABEL_, "lo", 3);
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + start);
    h->len = (unsigned)(off - start);
    h->type = RTM_NEWADDR_;
    h->flags = nlflags;
    h->seq = seq;
    h->pid = pid;
    return off;
}

/* Append an NLMSG_ERROR carrying `error`. The embedded original header is
 * zeroed, as the oracle's nl_build_error leaves it: clients match on the outer
 * header's seq, not the copy. */
static long put_error(unsigned char *buf, long off, long max, unsigned seq,
                      unsigned pid, int error) {
    long need = 16 + 4 + 16;
    if (off + need > max)
        return off;
    memset(buf + off, 0, (size_t)need);
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + off);
    h->len = (unsigned)need;
    h->type = NLMSG_ERROR_;
    h->seq = seq;
    h->pid = pid;
    *(int *)(buf + off + 16) = error;
    return off + need;
}

/* Enumerate interface indices from our own RTM_GETADDR dump on a throwaway
 * unbound socket — the one enumeration Android's policy leaves open, and the
 * same one Bionic's getifaddrs falls back to when RTM_GETLINK is refused. So
 * the guest sees the interface set arm64chroot shows there: everything that
 * carries at least one address; an interface with none stays invisible,
 * because an app has no way to learn of it. `scratch` is borrowed for the
 * receive buffer (the caller's reply buffer, not yet written). */
static int addr_dump_indices(int *idx, unsigned *v4, unsigned char *plen,
                             int cap, unsigned char *scratch,
                             long scratch_len) {
    long fd = open_hostfd();
    int n = 0;
    if (fd < 0)
        return 0;
    unsigned char req[20];
    memset(req, 0, sizeof req);
    struct nlmsghdr_ *h = (struct nlmsghdr_ *)req;
    h->len = (unsigned)sizeof req;
    h->type = RTM_GETADDR_;
    h->flags = NLM_F_REQUEST_ | NLM_F_DUMP_;
    h->seq = 1;
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    if (CNG_SYS(__NR_sendto, fd, (long)req, sizeof req, 0, (long)&sa,
                sizeof sa) < 0)
        goto out;
    for (int rounds = 0, done = 0; !done && rounds < 64; rounds++) {
        long r = CNG_SYS(__NR_recvfrom, fd, (long)scratch, scratch_len, 0, 0, 0);
        if (r <= 0)
            break;
        for (long p = 0; p + (long)sizeof(struct nlmsghdr_) <= r;) {
            struct nlmsghdr_ *m = (struct nlmsghdr_ *)(scratch + p);
            /* Read the length once and bound everything below by the copy. The
             * walk stores through idx/v4/plen, which the compiler must assume
             * may alias this buffer, so re-reading m->len would let a value
             * written after the check decide how far the attribute loop goes —
             * and this buffer is the caller's, not ours. */
            long mlen = (long)m->len;
            if (mlen < (long)sizeof *m || p + mlen > r)
                break;
            if (m->type == NLMSG_DONE_ || m->type == NLMSG_ERROR_) {
                done = 1;
                break;
            }
            /* ifaddrmsg: family, prefixlen, flags, scope, then u32 index. */
            if (m->type == RTM_NEWADDR_ && mlen >= (long)sizeof *m + 8) {
                unsigned char *ifa = (unsigned char *)m + sizeof *m;
                int ifi = *(int *)(ifa + 4);
                int slot = -1;
                for (int i = 0; i < n; i++)
                    if (idx[i] == ifi)
                        slot = i;
                if (slot < 0 && n < cap) {
                    slot = n++;
                    idx[slot] = ifi;
                    if (v4)
                        v4[slot] = 0;
                    if (plen)
                        plen[slot] = 0;
                }
                /* The first IPv4 address of each interface, for the SIOCGIF*
                 * family — which has no way to express anything else, and which
                 * must describe the same interfaces this dump defines. */
                if (slot >= 0 && v4 && !v4[slot] && ifa[0] == AF_INET_) {
                    for (long q = (long)sizeof *m + 8; q + 4 <= mlen;) {
                        unsigned short al = *(unsigned short *)((char *)m + q);
                        unsigned short at = *(unsigned short *)((char *)m + q + 2);
                        if (al < 4 || q + al > mlen)
                            break;
                        if ((at == IFA_LOCAL_ || at == IFA_ADDRESS_) &&
                            al >= 8 && !v4[slot]) {
                            memcpy(&v4[slot], (char *)m + q + 4, 4);
                            if (plen)
                                plen[slot] = ifa[1];
                        }
                        q += (al + 3) & ~3u;
                    }
                }
            }
            p += (mlen + 3) & ~3L;
        }
    }
out:
    sys_close((int)fd);
    return n;
}

/* The kernel's struct ifreq: 16 bytes of name, 24 of union. */
struct ifreq_ {
    char name[IFNAMSIZ_];
    unsigned char u[24];
};

/* Fill `fi` for the interface with `index` via SIOCGIF* on an AF_INET dgram
 * socket (the ioctls Bionic's fallback leans on; app domains keep them). */
static int gather_ifinfo(long ioctlfd, int index, struct ifinfo *fi) {
    struct ifreq_ ifr;
    if (ioctlfd < 0)
        return 0;
    memset(&ifr, 0, sizeof ifr);
    *(int *)ifr.u = index; /* SIOCGIFNAME: ifr_ifindex in, ifr_name out */
    if (CNG_SYS(__NR_ioctl, ioctlfd, SIOCGIFNAME_, (long)&ifr, 0, 0, 0) < 0)
        return 0;
    memset(fi, 0, sizeof *fi);
    fi->index = index;
    memcpy(fi->name, ifr.name, IFNAMSIZ_);
    fi->name[IFNAMSIZ_ - 1] = 0;

    memset(ifr.u, 0, sizeof ifr.u);
    if (CNG_SYS(__NR_ioctl, ioctlfd, SIOCGIFFLAGS_, (long)&ifr, 0, 0, 0) == 0)
        fi->flags = *(unsigned short *)ifr.u;
    /* Defaults the remaining ioctls refine — the oracle's assumptions. */
    fi->hwtype = (fi->flags & IFF_LOOPBACK_) ? ARPHRD_LOOPBACK_ : ARPHRD_ETHER_;
    fi->mtu = (fi->flags & IFF_LOOPBACK_) ? 65536 : 1500;
    memset(ifr.u, 0, sizeof ifr.u);
    if (CNG_SYS(__NR_ioctl, ioctlfd, SIOCGIFMTU_, (long)&ifr, 0, 0, 0) == 0)
        fi->mtu = (unsigned)*(int *)ifr.u;
    memset(ifr.u, 0, sizeof ifr.u);
    if (CNG_SYS(__NR_ioctl, ioctlfd, SIOCGIFHWADDR_, (long)&ifr, 0, 0, 0) == 0) {
        /* A sockaddr whose sa_family is the ARPHRD_* type. Android refuses
         * this to apps; then the attribute is simply absent, which is the
         * blank `link/ether ` arm64chroot prints on-device. */
        fi->hwtype = *(unsigned short *)ifr.u;
        memcpy(fi->hwaddr, ifr.u + 2, 6);
        fi->hwlen = 6;
    }
    return 1;
}

/* The target of a single (non-dump) RTM_GETLINK: ifi_index, and the
 * IFLA_IFNAME string when one was given (empty otherwise). */
static int link_target(const unsigned char *req, long rlen,
                       char name[IFNAMSIZ_]) {
    name[0] = 0;
    if (rlen < 32)
        return 0;
    int index = *(const int *)(req + 20); /* ifinfomsg.ifi_index */
    for (long p = 32; p + 4 <= rlen;) {
        unsigned short alen = *(const unsigned short *)(req + p);
        unsigned short atype = *(const unsigned short *)(req + p + 2);
        if (alen < 4 || p + (long)alen > rlen)
            break;
        if (atype == IFLA_IFNAME_) {
            long d = alen - 4;
            if (d > IFNAMSIZ_ - 1)
                d = IFNAMSIZ_ - 1;
            memcpy(name, req + p + 4, (size_t)d);
            name[d] = 0;
        }
        p += (long)((alen + 3) & ~3u);
    }
    return index;
}

/* Build the RTM_GETLINK reply the host refused to give us. Mirrors the
 * oracle's RTM_GETLINK case: enumerate, filter for a non-dump get, and when
 * enumeration comes up empty present loopback alone — or ENODEV for a
 * non-dump get of anything else. */
static long synth_links(unsigned char *out, long max, const unsigned char *req,
                        long rlen, unsigned seq, unsigned pid, int dump) {
    char want[IFNAMSIZ_];
    int want_index = 0;
    want[0] = 0;
    if (!dump)
        want_index = link_target(req, rlen, want);

    int idx[32];
    int nidx = addr_dump_indices(idx, 0, 0, 32, out, max);
    long ioctlfd = CNG_SYS(__NR_socket, AF_INET_, SOCK_DGRAM_ | CNG_O_CLOEXEC,
                           0, 0, 0, 0);
    long off = 0;
    int built = 0;
    for (int i = 0; i < nidx; i++) {
        struct ifinfo fi;
        if (!gather_ifinfo(ioctlfd, idx[i], &fi))
            continue;
        if (!dump) {
            if (want[0]) {
                if (strcmp(want, fi.name) != 0)
                    continue;
            } else if (want_index > 0 && fi.index != want_index)
                continue;
        }
        off = put_link(out, off, max, seq, pid, dump ? NLM_F_MULTI_ : 0, &fi);
        built++;
        if (!dump)
            break;
    }
    if (ioctlfd >= 0)
        sys_close((int)ioctlfd);

    if (!built) {
        /* Enumeration unavailable (or no match): loopback is still real. */
        struct ifinfo lo;
        memset(&lo, 0, sizeof lo);
        lo.index = 1;
        lo.flags = IFF_UP_ | IFF_LOOPBACK_ | IFF_RUNNING_;
        lo.mtu = 65536;
        lo.hwtype = ARPHRD_LOOPBACK_;
        lo.hwlen = 6; /* all-zero hwaddr, as the kernel reports for lo */
        lo.name[0] = 'l';
        lo.name[1] = 'o';
        lo.name[2] = 0;
        off = 0;
        if (dump)
            off = put_link(out, 0, max, seq, pid, NLM_F_MULTI_, &lo);
        else if (want[0] ? strcmp(want, "lo") == 0
                         : (want_index == 0 || want_index == 1))
            off = put_link(out, 0, max, seq, pid, 0, &lo);
        else
            off = put_error(out, 0, max, seq, pid, -ENODEV);
    }
    return off;
}

/* Build the RTM_GETADDR reply when even the address dump is refused: loopback
 * and nothing else, filtered by the request's rtgenmsg family byte. */
static long synth_addrs(unsigned char *out, long max, const unsigned char *req,
                        long rlen, unsigned seq, unsigned pid, int dump) {
    unsigned char family = (rlen > 16) ? req[16] : 0;
    unsigned short fl = dump ? NLM_F_MULTI_ : 0;
    long off = 0;
    if (family == 0 || family == AF_INET_)
        off = put_lo_addr(out, off, max, seq, pid, 0, fl);
    if (family == 0 || family == AF_INET6_)
        off = put_lo_addr(out, off, max, seq, pid, 1, fl);
    return off;
}

/* ------------------------------------------------------------------------- */
/* Delivery through the pair.                                                 */

/* Send one reply datagram into the guest's receive queue. DONTWAIT: if the
 * guest let its queue fill (~200 KB of unread replies) the tail is dropped
 * rather than deadlocking the monitor against a guest that is not reading. */
static void push(struct nl_slot *s, const void *b, long len) {
    if (s->monfd < 0 || len <= 0)
        return;
    long r = CNG_SYS(__NR_sendto, s->monfd, (long)b, len, MSG_DONTWAIT_, 0, 0);
    if (r < 0 && cng_g_debug)
        cng_dprintf(2, "[cng] nl push %ld bytes -> %ld (reply dropped)\n", len,
                    r);
}

/* Push a buffer of built messages as one datagram apiece. Per-message
 * datagrams keep every recv smaller than any client's buffer, so nothing is
 * ever truncated; a client loops until NLMSG_DONE regardless (a real kernel
 * also splits a dump across recvs whenever it overflows one skb). */
static void push_msgs(struct nl_slot *s, const unsigned char *b, long len) {
    for (long p = 0; p + (long)sizeof(struct nlmsghdr_) <= len;) {
        const struct nlmsghdr_ *h = (const struct nlmsghdr_ *)(b + p);
        long step = (long)((h->len + 3) & ~3u);
        if (step < (long)sizeof *h || p + step > len)
            break;
        push(s, b + p, (long)h->len);
        p += step;
    }
}

/* Relay the host kernel's answer into the pair, datagram for datagram. A dump
 * runs until its NLMSG_DONE; a single get expects exactly one reply. If the
 * host goes quiet (SO_RCVTIMEO) the guest still gets a terminator — a dump
 * that simply stops mid-stream would hang every netlink client ever written. */
static void pump(struct nl_slot *s, unsigned seq, unsigned pid, int is_dump) {
    int done = 0;
    for (int rounds = 0; !done && rounds < 256; rounds++) {
        long r = CNG_SYS(__NR_recvfrom, s->hostfd, (long)s->scratch,
                         NL_REPLY_MAX, 0, 0, 0);
        if (r <= 0)
            break;
        done = fix_pid(s->scratch, r, pid);
        push(s, s->scratch, r);
        if (!is_dump)
            return;
    }
    if (!done) {
        long n = is_dump ? put_done(s->scratch, seq, pid)
                         : put_error(s->scratch, 0, NL_REPLY_MAX, seq, pid, 0);
        push(s, s->scratch, n);
    }
}

/* Serve one guest request: relay it when the host will answer, synthesize when
 * it will not, ack everything else. Replies land in the pair as datagrams. */
static void process_request(struct nl_slot *s, const unsigned char *req,
                            long rlen) {
    if (!req || rlen < (long)sizeof(struct nlmsghdr_))
        return;
    const struct nlmsghdr_ *rh = (const struct nlmsghdr_ *)req;
    unsigned short type = rh->type;
    unsigned seq = rh->seq;
    unsigned pid = (unsigned)sys_getpid();
    int is_dump = (rh->flags & NLM_F_DUMP_) == NLM_F_DUMP_;
    long rl = (long)rh->len < rlen ? (long)rh->len : rlen;

    if (type == RTM_GETLINK_ || type == RTM_GETADDR_ || type == RTM_GETROUTE_) {
        long sr = -1;
        if (s->hostfd >= 0)
            sr = (cng_nl_deny_getlink && type == RTM_GETLINK_)
                     ? -EACCES /* test aid: Android's nlmsg_readpriv refusal */
                     : relay_request(s->hostfd, req, rl, is_dump);
        if (sr >= 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] nl send fd=%d type=%u -> relayed\n",
                            s->fd, type);
            pump(s, seq, pid, is_dump);
            return;
        }
        /* The host refuses to answer this query — on Android RTM_GETLINK is
         * denied outright (nlmsg_readpriv), in any request form, while the
         * other dumps relay fine. Synthesize what the oracle synthesizes
         * instead of handing back an empty dump that `ip addr` renders as
         * total silence. */
        long off = 0;
        if (type == RTM_GETLINK_)
            off = synth_links(s->scratch, NL_REPLY_MAX - 24, req, rl, seq, pid,
                              is_dump);
        else if (type == RTM_GETADDR_)
            off = synth_addrs(s->scratch, NL_REPLY_MAX - 24, req, rl, seq, pid,
                              is_dump);
        /* RTM_GETROUTE with no relay: an empty dump, as the oracle serves. */
        if (is_dump)
            off += put_done(s->scratch + off, seq, pid);
        if (off > 0) {
            if (cng_g_debug)
                cng_dprintf(2,
                            "[cng] nl send fd=%d type=%u -> synthesized %ld "
                            "bytes (relay fd=%d sendto=%ld)\n",
                            s->fd, type, off, s->hostfd, sr);
            push_msgs(s, s->scratch, off);
            return;
        }
        /* Non-dump GETROUTE (or an unparseable request): ack it below, which
         * is the oracle's answer too. */
    }

    if (is_dump) {
        push(s, s->scratch, put_done(s->scratch, seq, pid));
        return;
    }
    /* Anything else gets a success ack, which is what lets bubblewrap's
     * loopback_setup() (RTM_NEWADDR/RTM_NEWLINK) proceed instead of aborting. */
    struct nlmsghdr_ *o = (struct nlmsghdr_ *)s->scratch;
    o->len = (unsigned)(sizeof *o + 4 + sizeof *o);
    o->type = NLMSG_ERROR_;
    o->flags = 0;
    o->seq = seq;
    o->pid = pid;
    *(int *)(s->scratch + sizeof *o) = 0; /* error == 0 => ack */
    memcpy(s->scratch + sizeof *o + 4, req, sizeof *o);
    push(s, s->scratch, (long)o->len);
}

/* Requests the guest wrote with plain write(2)/send(2) — syscalls left
 * untrapped for speed — queue on our end of the pair. Every trapped netlink
 * call drains them first, so a write()-then-recvmsg() client (busybox ip)
 * works: the request is processed when its recv traps, and the reply is
 * waiting in the pair before the real recv runs. The 256-byte cap is the
 * oracle's own request cap; a GET request is routed on its header and family
 * byte, both well inside it. */
static void drain_requests(struct nl_slot *s) {
    unsigned char req[256];
    for (int i = 0; i < 32; i++) {
        long r = CNG_SYS(__NR_recvfrom, s->monfd, (long)req, sizeof req,
                         MSG_DONTWAIT_, 0, 0);
        if (r <= 0)
            break;
        process_request(s, req, r);
    }
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
    struct nl_slot *s = &g_slots[free_slot];
    /* Claiming a stale slot: its pair peer and relay socket are still ours. */
    if (s->fd >= 0 && s->monfd >= 0)
        sys_close(s->monfd);
    if (s->fd >= 0 && s->hostfd >= 0)
        sys_close(s->hostfd);
    /* A connected AF_UNIX datagram socketpair stands in: the guest gets one
     * end (so close/dup/poll/fcntl all behave), we keep the other to deliver
     * replies and to catch requests written with untrapped write(2). The
     * guest's SOCK_CLOEXEC and SOCK_NONBLOCK bits are preserved. */
    int sv[2] = {-1, -1};
    if (CNG_SYS(__NR_socketpair, CNG_AF_UNIX,
                SOCK_DGRAM_ | (type & ~(long)SOCK_TYPE_MASK), 0, (long)sv, 0,
                0) < 0)
        return -1;
    s->fd = sv[0];
    s->monfd = sv[1];
    s->ino = fd_ino(sv[0]);
    s->hostfd = (int)open_hostfd();
    if (cng_g_debug)
        cng_dprintf(2,
                    "[cng] netlink: emulating fd %d (host denies rtnetlink), "
                    "pair peer %d, relay fd %d\n",
                    s->fd, s->monfd, s->hostfd);
    return sv[0];
}

/* ---- the audit interface --------------------------------------------------
 *
 * NETLINK_AUDIT is the other netlink protocol Android's policy takes away, and
 * unlike rtnetlink there is nothing to emulate: the guest cannot have a view of
 * the host's audit log, and does not want one. What it needs is the *right
 * refusal*, because libaudit's callers branch on which one they get.
 *
 * `audit_open()` is a bare socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT), and
 * shadow-utils wraps it in audit_help_open(), which treats EINVAL /
 * EPROTONOSUPPORT / EAFNOSUPPORT as "this kernel was built without audit" and
 * carries on — and treats anything else as fatal:
 *
 *     useradd: Cannot open audit interface - aborting.
 *
 * That is what a Debian/Ubuntu rootfs prints on a device for `useradd`,
 * `usermod`, `passwd`, `chage`, `groupadd` and shadow's `su`: the socket is
 * refused by SELinux (EACCES on the app domain's netlink_audit_socket, no
 * capability involved), which is not one of the three the tool survives. The
 * kernel's own way of saying "no audit here" is EPROTONOSUPPORT — netlink_create
 * returns exactly that for a protocol nobody registered — so that is what the
 * guest is told, and every one of those tools proceeds.
 *
 * Deviation from the oracle, deliberate: arm64chroot gates this on
 * `fake_id && euid == 0`, framing it as part of the pretend-to-be-root story.
 * Here it is gated on the host's refusal alone, for two reasons. The refusal is
 * the SELinux policy's and does not depend on the guest's credentials — real or
 * synthetic — so "this container has no audit subsystem" is equally true for
 * every guest in it; and the rest of this file already answers the same policy's
 * rtnetlink denial without asking who the guest claims to be. Gating on fake
 * root would leave `useradd` aborting in a rootfs whose files the invoking user
 * already owns, which is the one case where it would otherwise have worked.
 *
 * Called with the result of the real socket(2); returns what the guest sees. */
long cng_nl_audit_refusal(long domain, long protocol, long r) {
    if (domain != AF_NETLINK_ || protocol != NETLINK_AUDIT_)
        return r;
    if (cng_nl_deny_audit && r >= 0) {
        sys_close((int)r); /* test aid: Android's SELinux refusal, on a host
                            * that grants the socket */
        r = -EACCES;
    }
    if (r != -EPERM && r != -EACCES)
        return r; /* the host answered: its answer is the guest's */
    if (cng_g_debug)
        cng_dprintf(2,
                    "[cng] netlink: audit socket refused (%ld) -> "
                    "EPROTONOSUPPORT (no audit in this kernel)\n",
                    r);
    return -EPROTONOSUPPORT;
}

int cng_nl_send(int fd, const void *buf, long len, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;
    /* The request is the guest's own buffer, and this is the one send path that
     * never reaches the kernel — nothing else was going to check the pointer.
     * Reading it where it lies made `sendto(nlfd, garbage, n, ...)` a SIGSEGV
     * inside the SIGSYS handler, where every signal but SIGSYS is masked, so it
     * is unblockable and kills the guest outright: a real kernel answers
     * -EFAULT. Take a copy on the same terms the write(2)-submitted path has
     * always had (drain_requests reads into 256 bytes), which also bounds what
     * a hostile length can cost us in probe syscalls. */
    unsigned char req[256];
    long n = len < 0 ? 0 : (len > (long)sizeof req ? (long)sizeof req : len);
    if (n && !cng_user_readable(buf, (unsigned long)n)) {
        *out = -EFAULT;
        return 1;
    }
    if (n)
        memcpy(req, buf, (size_t)n);
    *out = len; /* the guest's request is always "sent" in full */
    drain_requests(s); /* older write()-submitted requests keep their order */
    process_request(s, req, n);
    return 1;
}

int cng_nl_recv(int fd, void *buf, long len, long flags, long *out) {
    struct nl_slot *s = slot_of(fd);
    if (!s)
        return 0;
    /* A request submitted with an untrapped write(2) is processed here, so its
     * reply datagrams are in the pair before the real receive below runs. */
    drain_requests(s);
    /* The real receive, against the guest's own end of the pair, with the
     * guest's own flags: MSG_PEEK, MSG_TRUNC, O_NONBLOCK and blocking are all
     * the kernel's genuine article — which is how glibc sizes a dump before
     * reading it, and why no message ever needs splitting by us. */
    long n = CNG_SYS(__NR_recvfrom, fd, (long)buf, len, flags, 0, 0);
    if (cng_g_debug)
        cng_dprintf(2, "[cng] nl recv fd=%d len=%ld flags=%lx -> %ld\n", fd,
                    len, flags, n);
    *out = n;
    return 1;
}

/* Write a sockaddr_nl into a guest buffer. `pid` distinguishes the two callers,
 * and getting it wrong is not cosmetic: a netlink client discards any reply whose
 * *source* address is not nl_pid == 0, because that is what "came from the
 * kernel" means. Filling the source with our own port id made glibc skip every
 * message and wait for an NLMSG_DONE it would never accept. getsockname, by
 * contrast, must report our own port id, which is what the client then matches
 * each reply's nlmsg_pid against (see fix_pid). */
/* Both pointers are the guest's, and this address is synthesized rather than
 * fetched — so the kernel never validates either, and a bad one has to answer
 * -EFAULT instead of faulting inside the handler, where SIGSEGV is masked and
 * fatal. The caller's length is read out before anything is probed for
 * writing, since the write probe validates a range by zeroing it. */
static long write_nladdr(void *addr, unsigned *alen, unsigned pid) {
    if (!addr || !alen)
        return 0;
    if (!cng_user_readable(alen, sizeof *alen))
        return -EFAULT;
    if (*alen < sizeof(struct sockaddr_nl_))
        return 0;
    if (!cng_user_writable(addr, sizeof(struct sockaddr_nl_)) ||
        !cng_user_writable(alen, sizeof *alen))
        return -EFAULT;
    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.family = AF_NETLINK_;
    sa.pid = pid;
    memcpy(addr, &sa, sizeof sa);
    *alen = (unsigned)sizeof sa;
    return 0;
}

long cng_nl_getname(int fd, void *addr, unsigned *alen) {
    /* The real AF_UNIX answer is an unnamed 2-byte sockaddr, and iproute2
     * rejects that with "Wrong address length 2". Report the sockaddr_nl it
     * expects, carrying our own port id. */
    return write_nladdr(addr, alen, (unsigned)sys_getpid());
}

long cng_nl_srcaddr(int fd, void *addr, unsigned *alen) {
    return write_nladdr(addr, alen, 0); /* 0 == from the kernel */
}

int cng_nl_bind(int fd) { return slot_of(fd) != 0; }

void cng_nl_poke(int fd) {
    struct nl_slot *s = slot_of(fd);
    if (s)
        drain_requests(s);
}

/* ---- the SIOCGIF* family -------------------------------------------------
 *
 * These arrive on an ordinary AF_INET socket, not on a netlink one, and they
 * answer the same questions the dumps do: `ifconfig` and `getifaddrs`'s oldest
 * fallback are built on them. Where the netlink emulation is engaged they have
 * to agree with it — otherwise a guest told by `ip addr` that it has only
 * loopback is shown the host's entire interface list by `ifconfig`, which is
 * both a contradiction and a description of a network the guest cannot reach.
 * So both views come from one enumeration.
 *
 * Where the host's own rtnetlink works nothing is emulated, here or there, and
 * these pass straight through: the kernel's answer is the truth and the dumps
 * are the same kernel's. Only the getters are modelled; SIOCSIF* changes the
 * host's network configuration and stays unemulated (and unprivileged, so the
 * host refuses it anyway). */

/* One interface as the guest sees it: the link facts, plus the first IPv4
 * address of the interface — all this family can express. */
struct ifview {
    struct ifinfo fi;
    unsigned addr; /* network byte order; 0 = the interface has none */
    unsigned char plen;
};

static int enum_ifviews(struct ifview *out, int cap) {
    /* Not static: cng_nl_ioctl reaches this from the SIGSYS handler, on any
     * thread, with no lock anywhere on the path. A process-wide parse buffer
     * would have two threads' recvfrom writing into it while the other walks
     * it — two guest threads in getifaddrs(3) is all that takes — and the
     * damage is not confined to a wrong answer: addr_dump_indices derives every
     * bound from a length it reads back out of this buffer, so a value landing
     * there mid-walk sends the attribute loop past the end of it, and a fault
     * in the handler is unblockable. 8 KiB on the 256 KiB scratch stack. Every
     * other receive area in this file is already per-slot or automatic. */
    unsigned char scratch[NL_REPLY_MAX];
    int idx[32];
    unsigned v4[32];
    unsigned char pl[32];
    int nidx = addr_dump_indices(idx, v4, pl, 32, scratch, sizeof scratch);
    long ioctlfd = CNG_SYS(__NR_socket, AF_INET_, SOCK_DGRAM_ | CNG_O_CLOEXEC,
                           0, 0, 0, 0);
    int n = 0;
    for (int i = 0; i < nidx && n < cap; i++) {
        if (!gather_ifinfo(ioctlfd, idx[i], &out[n].fi))
            continue;
        out[n].addr = v4[i];
        out[n].plen = pl[i];
        n++;
    }
    if (ioctlfd >= 0)
        sys_close((int)ioctlfd);
    if (!n && cap > 0) {
        /* Enumeration unavailable: loopback is still real, and it is exactly
         * what the link dump falls back to (synth_links). */
        memset(&out[0], 0, sizeof out[0]);
        out[0].fi.index = 1;
        out[0].fi.flags = IFF_UP_ | IFF_LOOPBACK_ | IFF_RUNNING_;
        out[0].fi.mtu = 65536;
        out[0].fi.hwtype = ARPHRD_LOOPBACK_;
        out[0].fi.hwlen = 6;
        out[0].fi.name[0] = 'l';
        out[0].fi.name[1] = 'o';
        out[0].addr = 0x0100007f; /* 127.0.0.1, network order */
        out[0].plen = 8;
        n = 1;
    }
    return n;
}

/* A sockaddr_in carrying `a` into the 24-byte ifreq union. */
static void put_sin(unsigned char *u, unsigned a) {
    memset(u, 0, 24);
    *(unsigned short *)u = AF_INET_;
    memcpy(u + 4, &a, 4);
}

static unsigned mask_of(unsigned char plen) {
    if (plen == 0)
        return 0;
    if (plen > 32)
        plen = 32;
    unsigned m = 0xffffffffu << (32 - plen); /* host order */
    return __builtin_bswap32(m);             /* the ifreq wants network order */
}

int cng_nl_ioctl(int fd, unsigned long req, void *arg, long *out) {
    (void)fd;
    if (!host_blocks())
        return 0; /* the host's own answers and its dumps agree already */

    struct ifview v[32];
    int n = enum_ifviews(v, 32);

    if (req == SIOCGIFCONF_) {
        /* struct ifconf { int ifc_len; char *ifc_buf; } — 16 bytes on LP64.
         * A NULL buffer asks for the size only, which is how every caller
         * sizes its allocation. */
        if (!cng_user_readable(arg, 16)) {
            *out = -EFAULT;
            return 1;
        }
        int len = *(int *)arg;
        char *buf = *(char **)((char *)arg + 8);
        /* SIOCGIFCONF is an IPv4 interface list: the kernel reports only
         * interfaces that carry an AF_INET address, and an interface with none
         * simply is not in it (it is still nameable by every getter below). */
        int nv4 = 0;
        for (int i = 0; i < n; i++)
            if (v[i].addr)
                nv4++;
        int need = nv4 * (int)sizeof(struct ifreq_);
        /* Only ifc_len is written back — the kernel leaves ifc_buf alone, and
         * the write probe would zero whatever it validates. */
        if (!cng_user_writable(arg, sizeof(int))) {
            *out = -EFAULT;
            return 1;
        }
        if (!buf) {
            *(int *)arg = need;
            *out = 0;
            return 1;
        }
        if (len > need)
            len = need;
        if (len < 0 || !cng_user_writable(buf, (unsigned long)len)) {
            *out = -EFAULT;
            return 1;
        }
        int w = 0;
        for (int i = 0; i < n && w + (int)sizeof(struct ifreq_) <= len; i++) {
            if (!v[i].addr)
                continue;
            struct ifreq_ r;
            memset(&r, 0, sizeof r);
            cng_strlcpy(r.name, v[i].fi.name, IFNAMSIZ_);
            put_sin(r.u, v[i].addr);
            memcpy(buf + w, &r, sizeof r);
            w += (int)sizeof r;
        }
        *(int *)arg = w;
        *out = 0;
        return 1;
    }

    /* Read before probing for write: every request here names its target in the
     * same buffer it answers into, and the write probe zeroes what it
     * validates (see uaccess.c). */
    if (!cng_user_readable(arg, sizeof(struct ifreq_))) {
        *out = -EFAULT;
        return 1;
    }
    struct ifreq_ ifr;
    memcpy(&ifr, arg, sizeof ifr);
    ifr.name[IFNAMSIZ_ - 1] = '\0';

    /* SIOCGIFNAME is the one that names its target by index; every other form
     * names it by ifr_name.
     *
     * An interface we did not enumerate is left to the host rather than refused.
     * Refusing it would be the tidier story — "what the dump did not show does
     * not exist" — but a guest can learn a name from /proc/net/dev, which is a
     * host passthrough, and busybox `ifconfig` does exactly that: an ENODEV
     * there stops it on its first interface. This emulation exists to answer
     * where the host will not, so it never takes away an answer the host is
     * willing to give. */
    const struct ifview *f = 0;
    for (int i = 0; i < n && !f; i++) {
        if (req == SIOCGIFNAME_) {
            if (v[i].fi.index == *(int *)ifr.u)
                f = &v[i];
        } else if (!strcmp(v[i].fi.name, ifr.name)) {
            f = &v[i];
        }
    }
    if (!f)
        return 0;

    memset(ifr.u, 0, sizeof ifr.u);
    switch (req) {
    case SIOCGIFNAME_:
        cng_strlcpy(ifr.name, f->fi.name, IFNAMSIZ_);
        break;
    case SIOCGIFINDEX_:
        *(int *)ifr.u = f->fi.index;
        break;
    case SIOCGIFFLAGS_:
        *(unsigned short *)ifr.u = (unsigned short)f->fi.flags;
        break;
    case SIOCGIFMTU_:
        *(int *)ifr.u = (int)f->fi.mtu;
        break;
    case SIOCGIFTXQLEN_:
        *(int *)ifr.u = 1000; /* what the link dump reports for every device */
        break;
    case SIOCGIFMETRIC_:
        *(int *)ifr.u = 0; /* the kernel has always answered 0 here */
        break;
    case SIOCGIFMAP_:
        break; /* no memory/irq/dma to report: all zeros, as for any modern nic */
    case SIOCGIFHWADDR_:
        *(unsigned short *)ifr.u = f->fi.hwtype;
        if (f->fi.hwlen)
            memcpy(ifr.u + 2, f->fi.hwaddr, f->fi.hwlen);
        break;
    case SIOCGIFADDR_:
    case SIOCGIFDSTADDR_:
        if (!f->addr) {
            *out = -EADDRNOTAVAIL; /* the interface has no IPv4 address */
            return 1;
        }
        put_sin(ifr.u, f->addr);
        break;
    case SIOCGIFNETMASK_:
        if (!f->addr) {
            *out = -EADDRNOTAVAIL;
            return 1;
        }
        put_sin(ifr.u, mask_of(f->plen));
        break;
    case SIOCGIFBRDADDR_:
        if (!f->addr) {
            *out = -EADDRNOTAVAIL;
            return 1;
        }
        put_sin(ifr.u, (f->addr & mask_of(f->plen)) | ~mask_of(f->plen));
        break;
    default:
        return 0; /* not one of ours: let the host answer */
    }
    if (!cng_user_writable(arg, sizeof ifr)) {
        *out = -EFAULT;
        return 1;
    }
    memcpy(arg, &ifr, sizeof ifr);
    *out = 0;
    return 1;
}

void cng_nl_init(void) {
    for (int i = 0; i < NL_SLOTS; i++) {
        g_slots[i].fd = -1;
        g_slots[i].monfd = -1;
        g_slots[i].hostfd = -1;
    }
}
