/* AF_UNIX address containment.
 *
 * A pathname socket carries a filesystem path in sun_path, so it needs exactly
 * the same containment as any other path argument — and it was getting none,
 * because no socket syscall was trapped. A guest bind("/run/foo.sock") created
 * the inode on the HOST, and connect("/run/dbus/system_bus_socket") reached the
 * HOST daemon with the guest's real credentials. Readback (getsockname, accept,
 * recvfrom, ...) handed the guest raw host paths, which both leaks where the
 * rootfs lives and breaks any program that compares the readback against what it
 * bound.
 *
 * Two directions, therefore:
 *   in  — bind/connect/sendto/sendmsg: guest path -> host path;
 *   out — getsockname/getpeername/accept/accept4/recvfrom/recvmsg: host -> guest.
 *
 * The array forms (sendmmsg/recvmmsg) carry one address per message and get the
 * same two directions applied per element; the loop is in dispatch.c, which is
 * also where the decision to take a batch apart at all is made.
 *
 * Abstract names (a leading NUL) have no filesystem node, so the rootfs prefix
 * cannot scope them, and an unprivileged process cannot be handed its own
 * network namespace. They are isolated by splicing a short per-rootfs tag after
 * the leading NUL instead, and stripping it back off on readback — the same
 * trick broker.c already uses to keep its own rendezvous per-rootfs. Without it
 * two invocations over different rootfs collide on the same abstract name (two
 * guest X or D-Bus daemons fighting over @/tmp/.X11-unix/X0) and a guest can
 * reach host abstract services.
 */
#include "cng/l2s.h"
#include "cng/broker.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/unixsock.h"

#include <asm/unistd.h>

int cng_g_share_abstract = 0;

#define SUN_PATH_MAX 108
#define SUN_HDR      2 /* sizeof(sun_family) */

/* The per-rootfs abstract tag: NUL is already there, then 0x01 (so a collision
 * with a real host name is effectively impossible — host software does not put
 * a control byte first) then "cng" and 8 hex digits of the rootfs hash. */
#define ABS_TAG_LEN 12

static int abs_tag(char *out) {
    static const char hex[] = "0123456789abcdef";
    u32 h = cng_broker_key_hash(cng_g_fs && cng_g_fs->rootfs[0]
                                    ? cng_g_fs->rootfs
                                    : "/");
    out[0] = 0x01;
    out[1] = 'c';
    out[2] = 'n';
    out[3] = 'g';
    for (int i = 0; i < 8; i++)
        out[4 + i] = hex[(h >> ((7 - i) * 4)) & 0xf];
    return ABS_TAG_LEN;
}

/* "/proc/self/fd/<n>/" into out. Returns the length written. */
static size_t fd_dir_prefix(int fd, char *out, size_t sz) {
    size_t p = cng_strlcpy(out, "/proc/self/fd/", sz);
    char num[16];
    int ni = 0;
    unsigned v = (unsigned)fd;
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0 && ni < 15);
    while (ni > 0 && p + 1 < sz)
        out[p++] = num[--ni];
    if (p + 1 < sz)
        out[p++] = '/';
    out[p] = '\0';
    return p;
}

void cng_sun_done(struct cng_sun_xlate *x) {
    if (x->dirfd >= 0) {
        sys_close(x->dirfd);
        x->dirfd = -1;
    }
}

/* Is this an address cng_sun_in() would rewrite? Asked per message by the mmsg
 * array forms, where the answer decides between re-issuing the batch whole and
 * taking it apart — so it reads the two family bytes and nothing more. */
int cng_sun_needed(const void *addr, long alen) {
    struct cng_sun_xlate probe;
    if (!addr || alen < SUN_HDR + 1 || alen > (long)sizeof probe.buf)
        return 0;
    unsigned short fam;
    if (!cng_user_readable(addr, sizeof fam))
        return 0;
    memcpy(&fam, addr, sizeof fam);
    return fam == CNG_AF_UNIX;
}

int cng_sun_in(struct cng_sun_xlate *x, const void *addr, long alen,
               int follow) {
    x->applied = 0;
    x->dirfd = -1;
    x->len = alen;
    if (!addr || alen < SUN_HDR + 1 || alen > (long)sizeof x->buf)
        return 0;
    /* The address is read here, ahead of the kernel call that would have
     * validated it, and a fault inside the handler is unblockable. An
     * unreadable one is passed through untouched so the kernel answers the
     * guest's own pointer with -EFAULT, which is what it would have done. */
    if (!cng_user_readable(addr, (unsigned long)alen))
        return 0;
    unsigned short fam;
    memcpy(&fam, addr, sizeof fam);
    if (fam != CNG_AF_UNIX)
        return 0;

    const char *gp = (const char *)addr + SUN_HDR;
    long plen = alen - SUN_HDR;

    /* Abstract namespace: no filesystem node, so tag rather than translate. A
     * name that will not fit the tag under 108 bytes passes through untagged
     * (as does an unnamed/autobind address, which has no name at all). */
    if (gp[0] == '\0') {
        /* plen is at least 1 here (the leading NUL), and 1 exactly is the
         * zero-length abstract name — a real name two processes can meet on, so
         * it is tagged like any other rather than passed through. An address
         * with no name at all (autobind) never reaches this far: its addrlen
         * stops at sun_family and the caller returned above. */
        if (cng_g_share_abstract)
            return 0;
        if (plen + ABS_TAG_LEN > SUN_PATH_MAX)
            return 0;
        char *out = x->buf;
        memcpy(out, &fam, sizeof fam);
        out[SUN_HDR] = '\0';
        abs_tag(out + SUN_HDR + 1);
        memcpy(out + SUN_HDR + 1 + ABS_TAG_LEN, gp + 1, (size_t)plen - 1);
        x->len = alen + ABS_TAG_LEN;
        x->applied = 1;
        return 1;
    }

    /* Pathname socket. sun_path need not be NUL-terminated when the caller
     * passes an exact addrlen, so copy out at most the bytes it gave us. */
    char guest[SUN_PATH_MAX + 1];
    long n = plen;
    if (n > SUN_PATH_MAX)
        n = SUN_PATH_MAX;
    memcpy(guest, gp, (size_t)n);
    guest[n] = '\0';
    for (long i = 0; i < n; i++)
        if (guest[i] == '\0') { /* honor an embedded terminator */
            guest[i] = '\0';
            break;
        }

    char host[CNG_PATH_MAX];
    if (cng_resolve(guest, follow, host, sizeof host) != 0 &&
        cng_fs_translate(cng_g_fs, guest, host, sizeof host) != 0)
        return 0; /* unresolvable: let the kernel answer on the raw name */

    size_t hl = strlen(host);
    char *out = x->buf;
    memcpy(out, &fam, sizeof fam);
    if (hl + 1 <= SUN_PATH_MAX) {
        memcpy(out + SUN_HDR, host, hl + 1);
        x->len = (long)(SUN_HDR + hl + 1);
        x->applied = 1;
        return 1;
    }

    /* The rootfs prefix pushed the translated name past sun_path. Open the
     * parent directory and name the socket relative to that fd, so only the
     * basename has to fit: /proc/self/fd/<n>/<basename>. The fd is closed by
     * cng_sun_done once the syscall has run. */
    size_t cut = hl;
    while (cut > 0 && host[cut - 1] != '/')
        cut--;
    if (cut == 0)
        return 0;
    char parent[CNG_PATH_MAX];
    memcpy(parent, host, cut - 1); /* drop the '/' itself */
    parent[cut - 1] = '\0';
    const char *base = host + cut;
    long fd = sys_openat(CNG_AT_FDCWD, parent[0] ? parent : "/",
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    char pfx[64];
    size_t pl = fd_dir_prefix((int)fd, pfx, sizeof pfx);
    size_t bl = strlen(base);
    if (pl + bl + 1 > SUN_PATH_MAX) {
        sys_close((int)fd);
        return 0;
    }
    memcpy(out + SUN_HDR, pfx, pl);
    memcpy(out + SUN_HDR + pl, base, bl + 1);
    x->len = (long)(SUN_HDR + pl + bl + 1);
    x->dirfd = (int)fd;
    x->applied = 1;
    return 1;
}

void cng_sun_out(void *addr, long *alen) {
    if (!addr || !alen || *alen < SUN_HDR + 1)
        return;
    unsigned short fam;
    memcpy(&fam, addr, sizeof fam);
    if (fam != CNG_AF_UNIX)
        return;
    char *p = (char *)addr + SUN_HDR;
    long plen = *alen - SUN_HDR;

    /* Abstract: strip our tag if this name carries it. A foreign name (untagged,
     * or another rootfs's tag) is left exactly as the kernel wrote it. */
    if (p[0] == '\0') {
        if (cng_g_share_abstract || plen < 1 + ABS_TAG_LEN)
            return;
        char tag[ABS_TAG_LEN];
        abs_tag(tag);
        if (memcmp(p + 1, tag, ABS_TAG_LEN) != 0)
            return;
        long rest = plen - 1 - ABS_TAG_LEN;
        memmove(p + 1, p + 1 + ABS_TAG_LEN, (size_t)rest);
        *alen -= ABS_TAG_LEN;
        return;
    }

    /* Pathname: map the host path back to the guest one. */
    char hostp[SUN_PATH_MAX + 1], guest[CNG_PATH_MAX];
    long n = plen;
    if (n > SUN_PATH_MAX)
        n = SUN_PATH_MAX;
    memcpy(hostp, p, (size_t)n);
    hostp[n] = '\0';
    if (cng_fs_untranslate(cng_g_fs, hostp, guest, sizeof guest) != 0)
        return; /* outside the guest view: leave it alone */
    size_t gl = strlen(guest);
    if (gl + 1 > SUN_PATH_MAX)
        return;
    memcpy(p, guest, gl + 1);
    *alen = (long)(SUN_HDR + gl + 1);
}
