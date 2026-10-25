/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* NETLINK_ROUTE emulation for hosts that deny app domains rtnetlink (Android).
 * A guest netlink socket is stood in for by one end of an AF_UNIX
 * SOCK_SEQPACKET socketpair whose other end the namespace's broker daemon
 * holds: the daemon serves each request the moment it arrives, by whatever
 * route it came, and pushes the replies into the pair, so untrapped
 * read()/write()/poll() behave like the real fd they are. Dumps are relayed
 * through an UNBOUND host netlink socket, which works because the SELinux
 * denial is on bind(2), not on the query — except RTM_GETLINK, which Android
 * refuses outright (nlmsg_readpriv) and which is synthesized from the address
 * dump plus SIOCGIF* ioctls instead. See src/monitor/netlink.c.
 */
#ifndef CNG_NETLINK_H
#define CNG_NETLINK_H

struct cng_bresp;
struct cng_pollfd;

/* CNG_NETLINK_FORCE_BLOCK=1: pretend the host denies rtnetlink, so the
 * emulation can be exercised on a host where it actually works (mirrors
 * CNG_SHM_FORCE_FILE). */
extern int cng_nl_force_block;

/* CNG_NETLINK_NO_RELAY=1: additionally pretend the host refuses us a netlink
 * socket for relaying, so the degradation path (a loopback-only dump, as the
 * oracle presents when getifaddrs fails) can be exercised on a host where the
 * relay actually works. */
extern int cng_nl_no_relay;

/* CNG_NETLINK_DENY_GETLINK=1: pretend the host refuses RTM_GETLINK sends on
 * the relay socket — Android's nlmsg_readpriv restriction, which denies app
 * domains the link dump in every request form while the address dump relays
 * fine — so the synthesized link dump can be exercised on a host whose relay
 * works. Implies CNG_NETLINK_FORCE_BLOCK. */
extern int cng_nl_deny_getlink;

/* CNG_NETLINK_DENY_AUDIT=1: pretend the host refuses a NETLINK_AUDIT socket the
 * way Android's SELinux policy does (EACCES), so the answer that refusal is
 * turned into can be exercised on a host that grants the socket. Independent of
 * the rtnetlink knobs above — it does not imply CNG_NETLINK_FORCE_BLOCK. */
extern int cng_nl_deny_audit;

/* 1 if `fd` is one of our emulated netlink sockets. */
int cng_nl_is_fake(int fd);

/* socket(2) hook. Returns the new guest fd; the negative errno the emulated
 * interface answers a request no kernel would grant (a socket type netlink does
 * not take); or -1 when this is not an emulated case (wrong family/protocol,
 * host rtnetlink works, no memory for the record, or no broker daemon would
 * take the socket) and the real syscall should run.
 *
 * -1 is the sentinel and never an answer: EPERM is not something this interface
 * says, and the refusals it does give have to reach the guest rather than fall
 * through to a real syscall that, on the hosts this exists for, would answer
 * about the policy instead of about the request. */
long cng_nl_socket(long domain, long type, long protocol);

/* NETLINK_AUDIT is refused, not emulated — but with the errno libaudit's callers
 * recognise. shadow-utils (`useradd`, `usermod`, `passwd`, `chage`, `su`) treats
 * EINVAL/EPROTONOSUPPORT/EAFNOSUPPORT as "this kernel has no audit" and carries
 * on, and anything else — such as the EACCES Android's policy returns — as fatal
 * ("Cannot open audit interface - aborting"). Pass the result of the real
 * socket(2); returns what the guest should see, unchanged unless this was an
 * audit socket the host refused on permission grounds. */
long cng_nl_audit_refusal(long domain, long protocol, long r);

/* After a send on `fd` went into the pair, or where a receive on it found
 * nothing yet: if `fd` is an emulated socket, wait until the daemon has served
 * every request sent on it so far, so their replies are queued — the kernel
 * answers inside the sendmsg itself. Returns 1 when `fd` is ours, 0 when it is
 * not (nothing was asked). */
int cng_nl_sync(int fd);

/* recv hooks. Return 1 when the call was handled (result in *out), 0 when `fd`
 * is not ours and the real syscall should run. `flags` must carry the caller's
 * MSG_* bits: MSG_PEEK must not consume and MSG_TRUNC must report the whole
 * pending length, which is how glibc's getifaddrs(3) sizes its buffer before
 * reading. */
int cng_nl_recv(int fd, void *buf, long len, long flags, long *out);
/* The same for recvmsg: `msg` is a struct cng_msghdr of the caller's, handed
 * to the kernel's recvmsg on the stand-in whole — its iovecs are received
 * into, and its msg_flags and msg_controllen written, by the kernel. */
int cng_nl_recvmsg(int fd, void *msg, long flags, long *out);

/* getsockname (`peer` 0) / getpeername (`peer` 1): report a sockaddr_nl — our
 * own port id, or the kernel's (0) for the peer — since the real AF_UNIX answer
 * is 2 bytes and iproute2 rejects that. Call only for a stand-in fd
 * (cng_nl_is_fake). The address goes out by the kernel's rules for a short or
 * absent buffer (move_addr_to_user): 0, -EINVAL for a negative length, or
 * -EFAULT for a guest buffer we cannot read or write — this address is
 * synthesized, so the kernel never checks it. */
long cng_nl_getname(int fd, void *addr, unsigned *alen, int peer);

/* The *source* address of a received reply, which must be nl_pid == 0: that is
 * how a netlink client knows a message came from the kernel, and glibc discards
 * anything else. For a successful receive only, and nothing for a NULL `addr`.
 * Same contract as cng_nl_getname otherwise. */
long cng_nl_srcaddr(int fd, void *addr, unsigned *alen);

/* bind(2) on an emulated socket is a silent success. Returns 1 if handled. */
int cng_nl_bind(int fd);

/* The SIOCGIF* interface-query ioctls, which arrive on an ordinary AF_INET
 * socket and answer the same questions the dumps do (`ifconfig`, and
 * getifaddrs's oldest fallback). Answered from the same enumeration, so the two
 * views cannot contradict each other. Returns 1 when handled (result in *out),
 * 0 when the host's own rtnetlink works — then nothing here is emulated and the
 * real ioctl is the right answer. */
int cng_nl_ioctl(int fd, unsigned long req, void *arg, long *out);

/* ---- the broker daemon's side (broker.c) ---------------------------------
 * The daemon owns the other end of every emulated socket in its namespace and
 * is where requests are answered. These run in the daemon only. */

/* Emulated sockets one namespace's daemon holds at once. A registration past
 * it is refused, and the guest's socket(2) gets the host's own answer. */
#define CNG_NL_SOCK_MAX 1024

/* CNG_REQ_NLSOCK's cng_breq.arg: the test aids the registering process runs
 * with, which are its own and not the daemon's (one --shared-proc daemon may
 * serve invocations started with different ones). */
#define CNG_NL_F_NO_RELAY     1 /* CNG_NETLINK_NO_RELAY */
#define CNG_NL_F_DENY_GETLINK 2 /* CNG_NETLINK_DENY_GETLINK */

/* CNG_REQ_NLSOCK: take `fd`, the daemon's end of a new pair, for a socket
 * whose replies carry `port`. Returns its id (> 0), or a negative errno with
 * `fd` closed. */
long cng_nl_serve_register(int fd, unsigned port, int flags);
/* CNG_REQ_NLSYNC: serve everything queued on socket `id`, then report what
 * was served on it since the last sync — the count is the return value, and
 * r->size / r->nattch carry how many of those were relayed / synthesized.
 * -ENOENT for an id the daemon does not hold. */
long cng_nl_serve_sync(unsigned id, struct cng_bresp *r);
/* The daemon's ends, appended to its poll set from index `n` (up to `cap`);
 * returns the new count. cng_nl_poll_ready then serves what the poll found in
 * [from, n): requests on a readable end, and the end given up once the guest
 * has closed its own. */
int cng_nl_poll_add(struct cng_pollfd *pf, int n, int cap);
void cng_nl_poll_ready(struct cng_pollfd *pf, int from, int n);
/* Does any guest still hold an emulated socket? Anchors the namespace. */
int cng_nl_any_live(void);
/* Close every end the daemon holds, on its way out. */
void cng_nl_free_all(void);

#endif /* CNG_NETLINK_H */
