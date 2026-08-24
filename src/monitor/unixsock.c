/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
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
 * a control byte first) then "cn", a byte saying which of the two forms below
 * this is, and 8 hex digits of the rootfs hash.
 *
 *   'g'  the name follows the tag, unchanged. What almost every abstract name
 *        gets, and what makes the readback a plain matter of taking 12 bytes
 *        back off the front.
 *   'H'  the tag is followed by 16 hex digits of a hash of the name, and the
 *        name itself is not on the wire at all. For a name with no room left
 *        under 108 bytes to carry the tag as well.
 *
 * Two spellings so the readback can tell them apart: a tagged name is otherwise
 * free to begin with 16 hex digits of its own. */
#define ABS_TAG_LEN 12
#define ABS_DIG_LEN (ABS_TAG_LEN + 16)

static int abs_tag_kind(char *out, char kind) {
    static const char hex[] = "0123456789abcdef";
    u32 h = cng_broker_key_hash(cng_g_fs && cng_g_fs->rootfs[0]
                                    ? cng_g_fs->rootfs
                                    : "/");
    out[0] = 0x01;
    out[1] = 'c';
    out[2] = 'n';
    out[3] = kind;
    for (int i = 0; i < 8; i++)
        out[4 + i] = hex[(h >> ((7 - i) * 4)) & 0xf];
    return ABS_TAG_LEN;
}

static int abs_tag(char *out) {
    return abs_tag_kind(out, 'g');
}

/* FNV-1a over the name's bytes — a name may carry NULs, so it is taken by
 * length rather than as a C string. */
static u64 abs_hash(const char *p, unsigned long n) {
    u64 h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* The 'H' form: the rootfs tag, then the name reduced to 16 hex digits. Both
 * halves are deterministic, so a bind and a connect on the same name from the
 * same rootfs still meet — which is what makes this a containment and not a
 * refusal. Writes ABS_DIG_LEN bytes. */
static void abs_digest(char *out, const char *name, unsigned long n) {
    static const char hex[] = "0123456789abcdef";
    abs_tag_kind(out, 'H');
    u64 h = abs_hash(name, n);
    for (int i = 0; i < 16; i++)
        out[ABS_TAG_LEN + i] = hex[(h >> ((15 - i) * 4)) & 0xf];
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
    if (cng_user_copyin(&fam, addr, sizeof fam) < 0)
        return 0;
    return fam == CNG_AF_UNIX;
}

/* What a socket bound through one of the two irreversible fallbacks reads back
 * as — the over-long pathname, which is bound through /proc/self/fd, and the
 * over-long abstract name, which is bound through its digest.
 *
 * The kernel stores sun_path exactly as it was handed in — measured: bind
 * through "/proc/self/fd/3/s.sock" and getsockname returns that same string,
 * before and after fd 3 is closed. So a socket bound either way reads back as
 * our own internal spelling: not the name the guest asked for, naming nothing by
 * the time the guest can look (cng_sun_done closed the fd), and the one thing in
 * this module that cng_fs_untranslate cannot map, since it matches neither a
 * bind's host prefix nor the rootfs. That breaks what this module is for and
 * what README.md promises of it — "a program comparing the readback against what
 * it bound still agrees".
 *
 * The guest's own name always fits in sun_path, having arrived in one, so the
 * answer is simply to remember it. Recorded as the fallback is applied, and
 * consulted on the way back out.
 *
 * Keyed on the stored spelling, which is all the readback carries, and by
 * length rather than as a C string: an abstract name begins with a NUL and may
 * carry more. Two pathname sockets bound through the fallback with the same
 * basename, in different directories, landing on the same fd number would
 * collide — and the fd is closed right after the bind, so consecutive fallbacks
 * do tend to reuse the number, which leaves the basename doing the work. The
 * answer is then one plausible guest path instead of another, where before it
 * was our /proc/self/fd spelling either way. Two abstract names cannot collide
 * unless their 64-bit hashes do.
 *
 * `slen` is the entry's validity flag and is written last: a reader either sees
 * an entry whose guest name is already there, or does not match it at all. */
#define SUN_FB_MAX 8
static struct {
    char stored[SUN_PATH_MAX];
    char guest[SUN_PATH_MAX];
    unsigned glen;
    unsigned slen; /* 0 while the entry is unused or half-written */
} g_sun_fb[SUN_FB_MAX];
static unsigned g_sun_fb_next;

static void sun_fb_note(const void *stored, unsigned slen, const void *guest,
                        unsigned glen) {
    if (!slen || slen > SUN_PATH_MAX || glen > SUN_PATH_MAX)
        return;
    unsigned i = __atomic_fetch_add(&g_sun_fb_next, 1, __ATOMIC_RELAXED) %
                 SUN_FB_MAX;
    __atomic_store_n(&g_sun_fb[i].slen, 0u, __ATOMIC_RELEASE);
    memcpy(g_sun_fb[i].guest, guest, glen);
    g_sun_fb[i].glen = glen;
    memcpy(g_sun_fb[i].stored, stored, slen);
    __atomic_store_n(&g_sun_fb[i].slen, slen, __ATOMIC_RELEASE);
}

/* The guest name for a stored spelling, into `out` (SUN_PATH_MAX bytes), or -1
 * when this is not one of ours. */
static int sun_fb_lookup(const void *stored, unsigned slen, void *out) {
    for (int i = 0; i < SUN_FB_MAX; i++) {
        if (__atomic_load_n(&g_sun_fb[i].slen, __ATOMIC_ACQUIRE) != slen)
            continue;
        if (memcmp(g_sun_fb[i].stored, stored, slen) != 0)
            continue;
        unsigned n = g_sun_fb[i].glen;
        memcpy(out, g_sun_fb[i].guest, n);
        return (int)n;
    }
    return -1;
}

int cng_sun_in(struct cng_sun_xlate *x, const void *addr, long alen,
               int follow) {
    x->applied = 0;
    x->dirfd = -1;
    x->len = alen;
    /* unix_validate_addr()'s own bounds: past sun_family and no longer than a
     * whole sockaddr_un. Anything else is -EINVAL and is passed through for the
     * kernel to say so — which matters here and not only for tidiness, since
     * the abstract branch below would otherwise take an over-long address and
     * hand the kernel a short one it accepts. */
    if (!addr || alen < SUN_HDR + 1 || alen > SUN_HDR + SUN_PATH_MAX)
        return 0;
    /* The address is read here, ahead of the kernel call that would have
     * validated it, and a fault inside the handler is unblockable. An
     * unreadable one is passed through untouched so the kernel answers the
     * guest's own pointer with -EFAULT, which is what it would have done.
     *
     * Taken as a copy, once: the name decides which of two very different
     * things happens to it (a rootfs translation, or the abstract tag), and
     * reading it again afterwards would let a guest thread pick one path and
     * hand over the name for the other. */
    char in[sizeof x->buf];
    if (cng_user_copyin(in, addr, (unsigned long)alen) < 0)
        return 0;
    unsigned short fam;
    memcpy(&fam, in, sizeof fam);
    if (fam != CNG_AF_UNIX)
        return 0;

    const char *gp = in + SUN_HDR;
    long plen = alen - SUN_HDR;

    /* Abstract namespace: no filesystem node, so tag rather than translate. */
    if (gp[0] == '\0') {
        /* plen is at least 1 here (the leading NUL), and 1 exactly is the
         * zero-length abstract name — a real name two processes can meet on, so
         * it is tagged like any other rather than passed through. An address
         * with no name at all (autobind) never reaches this far: its addrlen
         * stops at sun_family and the caller returned above. */
        if (cng_g_share_abstract)
            return 0;
        char *out = x->buf;
        memcpy(out, &fam, sizeof fam);
        out[SUN_HDR] = '\0';
        if (plen + ABS_TAG_LEN <= SUN_PATH_MAX) {
            abs_tag(out + SUN_HDR + 1);
            memcpy(out + SUN_HDR + 1 + ABS_TAG_LEN, gp + 1, (size_t)plen - 1);
            x->len = alen + ABS_TAG_LEN;
            x->applied = 1;
            return 1;
        }
        /* No room left under 108 bytes to carry the tag as well. This used to
         * pass through untagged, which put the guest's own name straight into
         * the HOST's global abstract namespace — the one escape the tag exists
         * to close, available to any guest willing to spell its name with 96
         * bytes or more: two rootfs collide on it, and a host service listening
         * on such a name is reachable. It was not even a visible limitation,
         * since a name that long simply worked.
         *
         * Contained by standing in for the name rather than refusing it. The
         * digest is a function of the name and the rootfs alone, so a bind and
         * a connect on the same name from the same rootfs still meet and two
         * rootfs still cannot; what is lost is the readback, which is what the
         * fallback table below is for. Refusing instead would have been the
         * simpler containment and a worse one: a long abstract name is a legal
         * address that every kernel accepts. */
        abs_digest(out + SUN_HDR + 1, gp + 1, (unsigned long)plen - 1);
        x->len = SUN_HDR + 1 + ABS_DIG_LEN;
        x->applied = 1;
        /* Only where the name is being created (bind), as for the pathname
         * fallback: a connect names something someone else bound. */
        if (!follow)
            sun_fb_note(out + SUN_HDR, (unsigned)(x->len - SUN_HDR), gp,
                        (unsigned)plen);
        return 1;
    }

    /* Pathname socket. sun_path need not be NUL-terminated when the caller
     * passes an exact addrlen, so copy out at most the bytes it gave us. */
    char guest[SUN_PATH_MAX + 1];
    long n = plen;
    /* (the fallback below records the pair for the readback; see sun_fb_note) */
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
        return -ENAMETOOLONG; /* the contained name cannot be spelled */

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
     * cng_sun_done once the syscall has run.
     *
     * Every way out of here below is an error, never a 0. A 0 means "nothing to
     * translate" and sends the caller's own address to the kernel — which for a
     * pathname socket is the guest's untranslated name, resolved against the
     * host filesystem. That is the containment gone: a bind creates the inode
     * outside the rootfs and a connect reaches a host daemon, in exactly the
     * case the rootfs prefix is longest. */
    size_t cut = hl;
    while (cut > 0 && host[cut - 1] != '/')
        cut--;
    if (cut == 0)
        return -ENAMETOOLONG;
    char parent[CNG_PATH_MAX];
    memcpy(parent, host, cut - 1); /* drop the '/' itself */
    parent[cut - 1] = '\0';
    const char *base = host + cut;
    long fd = sys_openat(CNG_AT_FDCWD, parent[0] ? parent : "/",
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return (int)fd; /* the parent's own errno: ENOENT, EACCES, ... */
    char pfx[64];
    size_t pl = fd_dir_prefix((int)fd, pfx, sizeof pfx);
    size_t bl = strlen(base);
    if (pl + bl + 1 > SUN_PATH_MAX) {
        sys_close((int)fd);
        return -ENAMETOOLONG;
    }
    memcpy(out + SUN_HDR, pfx, pl);
    memcpy(out + SUN_HDR + pl, base, bl + 1);
    x->len = (long)(SUN_HDR + pl + bl + 1);
    x->dirfd = (int)fd;
    x->applied = 1;
    /* Only where the name is being created — !follow is exactly bind, the one
     * call that establishes what a later getsockname has to report. A connect
     * or a sendto names something someone else bound, and its readback is that
     * binding's to answer. */
    if (!follow)
        sun_fb_note(out + SUN_HDR, (unsigned)(pl + bl), guest,
                    (unsigned)strlen(guest));
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
        if (memcmp(p + 1, tag, ABS_TAG_LEN) == 0) {
            long rest = plen - 1 - ABS_TAG_LEN;
            memmove(p + 1, p + 1 + ABS_TAG_LEN, (size_t)rest);
            *alen -= ABS_TAG_LEN;
            return;
        }
        /* The digest form carries no name to strip, so the only way back is the
         * one this process recorded when it bound it. A digest someone else
         * bound is left as it stands: our own spelling, which is not the guest's
         * name — but it is at least not another rootfs's, and there is nothing
         * here that could reconstruct it. */
        abs_tag_kind(tag, 'H');
        if (plen == 1 + ABS_DIG_LEN && memcmp(p + 1, tag, ABS_TAG_LEN) == 0) {
            char g[SUN_PATH_MAX];
            int n = sun_fb_lookup(p, (unsigned)plen, g);
            if (n > 0) {
                memcpy(p, g, (size_t)n);
                *alen = SUN_HDR + n;
            }
        }
        return;
    }

    /* Pathname: map the host path back to the guest one. */
    char hostp[SUN_PATH_MAX + 1], guest[CNG_PATH_MAX];
    long n = plen;
    if (n > SUN_PATH_MAX)
        n = SUN_PATH_MAX;
    memcpy(hostp, p, (size_t)n);
    hostp[n] = '\0';
    if (cng_fs_untranslate(cng_g_fs, hostp, guest, sizeof guest) != 0) {
        /* ...unless it is one of our own fallback spellings, which no prefix
         * matches and which the guest must never be shown (see sun_fb_note). */
        char fb[SUN_PATH_MAX];
        int gl = sun_fb_lookup(hostp, (unsigned)strlen(hostp), fb);
        if (gl < 0)
            return; /* outside the guest view: leave it alone */
        memcpy(guest, fb, (size_t)gl);
        guest[gl] = '\0';
    }
    size_t gl = strlen(guest);
    if (gl + 1 > SUN_PATH_MAX)
        return;
    memcpy(p, guest, gl + 1);
    *alen = (long)(SUN_HDR + gl + 1);
}
