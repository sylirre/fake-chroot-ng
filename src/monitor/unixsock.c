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
#include "cng/tab.h"
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

/* What a socket bound through one of the irreversible fallbacks reads back as.
 *
 * The kernel stores sun_path exactly as it was handed in — measured: bind
 * through "/proc/self/fd/3/s.sock" and getsockname returns that same string,
 * before and after fd 3 is closed. So a socket bound through a fallback reads
 * back as our own internal spelling: not the name the guest asked for, naming
 * nothing by the time the guest can look (cng_sun_done closed the fd), and the
 * one thing in this module that cng_fs_untranslate cannot map, since it matches
 * neither a bind's host prefix nor the rootfs. That breaks what this module is
 * for and what README.md promises of it — "a program comparing the readback
 * against what it bound still agrees".
 *
 * Three answers, in the order they are tried on the way back out:
 *
 *  - a pathname under the rootfs is spelled so that the spelling carries the
 *    guest name itself: "/proc/self/fd/<root>/./<guest path>", the rootfs
 *    directory as the fd and the guest's own path beneath it (sun_spell_root).
 *    The kernel resolves the "." and the guest path as host components — they
 *    are the same components — and ANY process that reads the address back,
 *    the binder, a peer, a process that inherited or was handed the socket,
 *    takes the guest name straight off the string with nothing to look up;
 *  - what fits nowhere — a pathname under a bind, a guest path too long to
 *    ride with the prefix, an over-long abstract name reduced to its digest —
 *    is remembered here as it is bound, keyed by the socket's own identity
 *    (its inode in sockfs) for the getsockname of the socket itself, the one
 *    call whose answer is by definition its own address: dup'd, inherited,
 *    it is the same socket and the same inode. That answer cannot collide;
 *  - by the stored spelling, for a reader without the socket — getpeername,
 *    accept, recvfrom — which is all the readback carries. Two pathname
 *    sockets bound through the bind fallback with the same basename, in
 *    different directories, on the same fd number could collide there, and
 *    the answer is then one plausible guest path instead of another, where
 *    before it was our /proc/self/fd spelling either way. Two abstract names
 *    cannot collide unless their 64-bit hashes do.
 *
 * The table grows (cng_tab); it was eight entries in a ring, so the ninth
 * fallback bind of a process overwrote the first's answer. Entries are taken
 * by a CAS on `state`, and `slen` is written last: a reader either sees an
 * entry whose guest name is already there, or does not match it at all. The
 * name is kept by length rather than as a C string: an abstract name begins
 * with a NUL and may carry more. */
struct sun_fb {
    int state; /* 0 free, 1 being written, 2 published */
    unsigned glen;
    unsigned slen;
    unsigned long long ino; /* the bound socket's sockfs inode, 0 if unknown */
    char stored[SUN_PATH_MAX];
    char guest[SUN_PATH_MAX];
};

static struct cng_tab g_sun_fb = CNG_TAB_INIT(struct sun_fb);

static unsigned long long sock_ino(int fd) {
    char st[144];
    if (fd < 0 || CNG_SYS(__NR_fstat, fd, (long)st, 0, 0, 0, 0) != 0)
        return 0;
    return *(unsigned long long *)(st + 8); /* st_ino */
}

static void sun_fb_note(int fd, const void *stored, unsigned slen,
                        const void *guest, unsigned glen) {
    if (!slen || slen > SUN_PATH_MAX || glen > SUN_PATH_MAX)
        return;
    unsigned long long ino = sock_ino(fd);
    for (unsigned long i = 0;; i++) {
        struct sun_fb *e = cng_tab_at(&g_sun_fb, i);
        if (!e)
            return; /* no page for the record: the readback stays ours */
        int st = __atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
        if (st != 0 ||
            !__atomic_compare_exchange_n(&e->state, &st, 1, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&e->slen, 0u, __ATOMIC_RELEASE);
        memcpy(e->guest, guest, glen);
        e->glen = glen;
        memcpy(e->stored, stored, slen);
        e->ino = ino;
        __atomic_store_n(&e->slen, slen, __ATOMIC_RELEASE);
        __atomic_store_n(&e->state, 2, __ATOMIC_RELEASE);
        return;
    }
}

/* The guest name for a stored spelling, into `out` (SUN_PATH_MAX bytes), or -1
 * when this is not one of ours. `ino` (0: unknown) is the socket the answer is
 * the own address of, and an entry recorded for it wins over one that merely
 * carries the same spelling. */
static int sun_fb_lookup(unsigned long long ino, const void *stored,
                         unsigned slen, void *out) {
    struct sun_fb *by_str = 0;
    struct cng_tab_iter it;
    for (struct sun_fb *e = cng_tab_first(&g_sun_fb, &it); e;
         e = cng_tab_next(&g_sun_fb, &it)) {
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != 2 ||
            __atomic_load_n(&e->slen, __ATOMIC_ACQUIRE) != slen ||
            memcmp(e->stored, stored, slen) != 0)
            continue;
        if (ino && e->ino == ino) {
            by_str = e;
            break;
        }
        if (!by_str)
            by_str = e;
    }
    if (!by_str)
        return -1;
    unsigned n = by_str->glen;
    memcpy(out, by_str->guest, n);
    return (int)n;
}

/* The self-describing spelling for a pathname under the rootfs (see the
 * readback note above): "/proc/self/fd/<root>/./<guest path>", with the
 * rootfs directory held open as <root> for the syscall and the guest's own
 * canonical path — symlink-free, since `host` was resolved — beneath it. The
 * "." is the mark the readback recognizes the form by; the kernel resolves it
 * to nothing. 1 with x filled, 0 when this name is not one it can carry (under
 * a bind, or too long even so: the caller's fallback takes it), or -errno. */
static int sun_spell_root(struct cng_sun_xlate *x, const char *host) {
    char canon[CNG_PATH_MAX], again[CNG_PATH_MAX];
    int mnt = CNG_MOUNT_ROOTFS;
    if (!cng_g_fs || cng_fs_untranslate(cng_g_fs, host, canon, sizeof canon) != 0 ||
        cng_fs_translate_mnt(cng_g_fs, canon, again, sizeof again, &mnt) != 0 ||
        mnt != CNG_MOUNT_ROOTFS || canon[0] != '/' || canon[1] == '\0' ||
        strcmp(again, host) != 0)
        return 0;
    const char *root = cng_g_fs->rootfs[0] ? cng_g_fs->rootfs : "/";
    long rfd = sys_openat(CNG_AT_FDCWD, root,
                          CNG_O_PATH | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (rfd < 0)
        return 0;
    char pfx[64];
    size_t pl = fd_dir_prefix((int)rfd, pfx, sizeof pfx);
    size_t gl = strlen(canon + 1);
    if (pl + 2 + gl + 1 > SUN_PATH_MAX) {
        sys_close((int)rfd);
        return 0;
    }
    char *out = x->buf;
    memcpy(out + SUN_HDR, pfx, pl);
    memcpy(out + SUN_HDR + pl, "./", 2);
    memcpy(out + SUN_HDR + pl + 2, canon + 1, gl + 1);
    x->len = (long)(SUN_HDR + pl + 2 + gl + 1);
    x->dirfd = (int)rfd;
    x->applied = 1;
    return 1;
}

int cng_sun_in(struct cng_sun_xlate *x, int fd, const void *addr, long alen,
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
            sun_fb_note(fd, out + SUN_HDR, (unsigned)(x->len - SUN_HDR), gp,
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

    /* The rootfs prefix pushed the translated name past sun_path.
     *
     * Every way out of here below is an error, never a 0. A 0 means "nothing to
     * translate" and sends the caller's own address to the kernel — which for a
     * pathname socket is the guest's untranslated name, resolved against the
     * host filesystem. That is the containment gone: a bind creates the inode
     * outside the rootfs and a connect reaches a host daemon, in exactly the
     * case the rootfs prefix is longest. */
    int sr = sun_spell_root(x, host);
    if (sr)
        return sr;

    /* Open the parent directory and name the socket relative to that fd, so
     * only the basename has to fit: /proc/self/fd/<n>/<basename>. The fd is
     * closed by cng_sun_done once the syscall has run. */
    size_t cut = hl;
    while (cut > 0 && host[cut - 1] != '/')
        cut--;
    if (cut == 0)
        return -ENAMETOOLONG;
    char parent[CNG_PATH_MAX];
    memcpy(parent, host, cut - 1); /* drop the '/' itself */
    parent[cut - 1] = '\0';
    const char *base = host + cut;
    long dfd = sys_openat(CNG_AT_FDCWD, parent[0] ? parent : "/",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return (int)dfd; /* the parent's own errno: ENOENT, EACCES, ... */
    char pfx[64];
    size_t pl = fd_dir_prefix((int)dfd, pfx, sizeof pfx);
    size_t bl = strlen(base);
    if (pl + bl + 1 > SUN_PATH_MAX) {
        sys_close((int)dfd);
        return -ENAMETOOLONG;
    }
    memcpy(out + SUN_HDR, pfx, pl);
    memcpy(out + SUN_HDR + pl, base, bl + 1);
    x->len = (long)(SUN_HDR + pl + bl + 1);
    x->dirfd = (int)dfd;
    x->applied = 1;
    /* Only where the name is being created — !follow is exactly bind, the one
     * call that establishes what a later getsockname has to report. A connect
     * or a sendto names something someone else bound, and its readback is that
     * binding's to answer. */
    if (!follow)
        sun_fb_note(fd, out + SUN_HDR, (unsigned)(pl + bl), guest,
                    (unsigned)strlen(guest));
    return 1;
}

/* Is `p` (NUL-terminated) the self-describing spelling? Then the guest path
 * begins at the byte after "./", and this returns its offset; else 0. */
static long sun_root_form(const char *p) {
    if (strncmp(p, "/proc/self/fd/", 14) != 0)
        return 0;
    long i = 14;
    if (p[i] < '0' || p[i] > '9')
        return 0;
    while (p[i] >= '0' && p[i] <= '9')
        i++;
    if (p[i] != '/' || p[i + 1] != '.' || p[i + 2] != '/')
        return 0;
    return i + 3;
}

void cng_sun_out(int fd, void *addr, long *alen) {
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
            int n = sun_fb_lookup(sock_ino(fd), p, (unsigned)plen, g);
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
    long rf = sun_root_form(hostp);
    if (rf) {
        /* The self-describing spelling: the guest name is on the string. */
        guest[0] = '/';
        cng_strlcpy(guest + 1, hostp + rf, sizeof guest - 1);
    } else if (cng_fs_untranslate(cng_g_fs, hostp, guest, sizeof guest) != 0) {
        /* ...unless it is one of our own fallback spellings, which no prefix
         * matches and which the guest must never be shown (see sun_fb_note). */
        char fb[SUN_PATH_MAX];
        int gl = sun_fb_lookup(sock_ino(fd), hostp, (unsigned)strlen(hostp), fb);
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
