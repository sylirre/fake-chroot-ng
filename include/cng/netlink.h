/* NETLINK_ROUTE emulation for hosts that deny app domains rtnetlink (Android).
 * A guest netlink socket is stood in for by one end of an AF_UNIX datagram
 * socketpair whose peer the monitor holds: replies are pushed into the pair,
 * so untrapped read()/write()/poll() behave like the real fd they are. Dumps
 * are relayed through an UNBOUND host netlink socket, which works because the
 * SELinux denial is on bind(2), not on the query — except RTM_GETLINK, which
 * Android refuses outright (nlmsg_readpriv) and which is synthesized from the
 * address dump plus SIOCGIF* ioctls instead. See src/monitor/netlink.c.
 */
#ifndef CNG_NETLINK_H
#define CNG_NETLINK_H

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

void cng_nl_init(void);

/* 1 if `fd` is one of our emulated netlink sockets. */
int cng_nl_is_fake(int fd);

/* socket(2) hook. Returns the new guest fd, or -1 when this is not an emulated
 * case (wrong family/protocol, host rtnetlink works, or the table is full) and
 * the real syscall should run. */
long cng_nl_socket(long domain, long type, long protocol);

/* send/recv hooks. Return 1 when the call was handled (result in *out), 0 when
 * `fd` is not ours and the real syscall should run. A send builds the reply; the
 * matching recv drains it. */
int cng_nl_send(int fd, const void *buf, long len, long *out);
/* `flags` must carry the caller's MSG_* bits: MSG_PEEK must not consume and
 * MSG_TRUNC must report the whole pending length, which is how glibc's
 * getifaddrs(3) sizes its buffer before reading. */
int cng_nl_recv(int fd, void *buf, long len, long flags, long *out);

/* getsockname/getpeername: report a sockaddr_nl carrying our own port id, since
 * the real AF_UNIX answer is 2 bytes and iproute2 rejects that. Returns 1 if
 * handled. */
int cng_nl_getname(int fd, void *addr, unsigned *alen);

/* The *source* address of a received reply, which must be nl_pid == 0: that is
 * how a netlink client knows a message came from the kernel, and glibc discards
 * anything else. Returns 1 if handled. */
int cng_nl_srcaddr(int fd, void *addr, unsigned *alen);

/* bind(2) on an emulated socket is a silent success. Returns 1 if handled. */
int cng_nl_bind(int fd);

/* Serve any requests the guest submitted with untrapped write(2)/send(2), so
 * their replies are in the pair before a passthrough read runs. No-op unless
 * `fd` is an emulated netlink socket. */
void cng_nl_poke(int fd);

#endif /* CNG_NETLINK_H */
