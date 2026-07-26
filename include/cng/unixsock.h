/* AF_UNIX address containment: a pathname socket carries a filesystem path in
 * sun_path, so it needs the same rootfs/bind translation as any other path
 * argument. Abstract names have no filesystem node and are isolated per rootfs
 * by a spliced tag instead. See src/monitor/unixsock.c.
 */
#ifndef CNG_UNIXSOCK_H
#define CNG_UNIXSOCK_H

#include <stddef.h>

/* --share-abstract-sockets: do not tag abstract names, so the guest shares the
 * host's global abstract namespace (the default is to isolate per rootfs, as
 * pathname sockets are isolated by the rootfs prefix). */
extern int cng_g_share_abstract;

/* A translated sockaddr, held across the re-issue. `buf` is a sockaddr_un with
 * room for the tag growth; `dirfd` is the parent directory opened for the
 * over-long-path fallback and must be closed with cng_sun_done() *after* the
 * syscall has run, since the kernel resolves /proc/self/fd/<n> through it. */
struct cng_sun_xlate {
    char buf[2 + 108 + 16];
    long len;
    int dirfd;
    int applied; /* 0: pass the guest's own address through unchanged */
};

/* Translate an outbound guest sockaddr (bind/connect/sendto/sendmsg). `follow`
 * dereferences a final symlink — bind keeps the last component literal, since it
 * is the name being created. Returns 1 when x->buf/x->len should be used, 0 to
 * pass the guest's address through untouched. Always pair with cng_sun_done(). */
int cng_sun_in(struct cng_sun_xlate *x, const void *addr, long alen, int follow);

/* Release anything cng_sun_in() held (the fallback dirfd). */
void cng_sun_done(struct cng_sun_xlate *x);

/* Map a sockaddr the kernel just wrote back into guest terms, in place
 * (getsockname/getpeername/accept/accept4/recvfrom/recvmsg): strip the rootfs
 * prefix from a pathname, strip our tag from an abstract name. `*alen` is the
 * kernel's returned length and is updated. */
void cng_sun_out(void *addr, long *alen);

#endif /* CNG_UNIXSOCK_H */
