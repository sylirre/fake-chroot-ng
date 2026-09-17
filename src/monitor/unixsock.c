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
#include "cng/pin.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/tab.h"
#include "cng/uapi.h"
#include "cng/unixsock.h"

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
    char root[CNG_PATH_MAX];
    if (!cng_g_fs || !cng_fs_rootfs(root, sizeof root))
        cng_strlcpy(root, "/", sizeof root);
    u32 h = cng_broker_key_hash(root);
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

/* What a bound pathname socket reads back as.
 *
 * The kernel stores sun_path exactly as it was handed in — measured: bind
 * through "/proc/self/fd/3/s.sock" and getsockname returns that same string,
 * before and after fd 3 is closed. A pathname is bound through the pinned
 * directory (cng/pin.h), so what every reader gets back is the monitor's own
 * spelling, "/proc/<pid>/fd/<n>/<name>": not the name the guest asked for,
 * and the one thing in this module cng_fs_untranslate cannot map. That
 * breaks what this module is for and what README.md promises of it — "a
 * program comparing the readback against what it bound still agrees" — and
 * not only for the binder: a datagram service replies to the source address
 * its recvfrom reports, and wpa_cli, a syslog client, anything that binds a
 * pathname of its own and waits for the answer, is a process the binder never
 * forked.
 *
 * So the spelling is made resolvable by anyone: the pid is the binder's own,
 * and the directory descriptor is kept open in it for as long as the socket
 * is, which makes "/proc/<pid>/fd/<n>" a link any process of the same user
 * can read back to the host directory (`sun_fb_pin`). Three answers, in the
 * order they are tried on the way out:
 *
 *  - the record this process made as it bound, keyed by the socket's own
 *    identity (its inode in sockfs) for the getsockname of the socket
 *    itself, the one call whose answer is by definition its own address:
 *    dup'd, inherited, it is the same socket and the same inode. That answer
 *    cannot collide;
 *  - the same record by the stored spelling, for a reader without the socket
 *    in a process that has the record — the binder and everything forked
 *    from it. Two live bindings with the same basename could only collide
 *    here on the same descriptor number, which two open descriptors never
 *    share;
 *  - the spelling resolved, for a reader with no record at all: the link is
 *    read back to the host directory and the directory to its guest name,
 *    while the binder lives and holds the descriptor. A stale spelling — a
 *    binder gone, its descriptor closed — is left as it stands, which is not
 *    the guest's name but is at least nobody's host path.
 *
 * The over-long abstract name reduced to its digest is recorded the same
 * way, with no descriptor to keep. The table grows (cng_tab). Entries are
 * taken by a CAS on `state`, and `slen` is written last: a reader either
 * sees an entry whose guest name is already there, or does not match it at
 * all. The name is kept by length rather than as a C string: an abstract name
 * begins with a NUL and may carry more. A kept descriptor is given back when
 * the socket it was kept for is no longer open in this process, which is
 * looked for on every bind (sun_fb_sweep): close(2) is not trapped, so that
 * is the earliest anything here can learn of it. */
struct sun_fb {
    int state; /* 0 free, 1 being written, 2 published */
    int pfd;   /* the pinned directory, held for the binding; -1 for none */
    struct cng_fdid pid; /* ...and what it was: the number is in the guest's
                          * table, and is closed only while it is still ours */
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

/* Give back the kept descriptors of bindings whose socket this process no
 * longer holds. The open sockets are read off /proc/self/fd once (a socket
 * is S_IFSOCK by fstat) into a bounded set; a process with more sockets open
 * than the set holds keeps everything this time, and asks again on its next
 * bind. Only run when there is a descriptor to give back. */
#define SUN_SWEEP_MAX 256
static void sun_fb_sweep(void) {
    int kept = 0;
    struct cng_tab_iter it;
    for (struct sun_fb *e = cng_tab_first(&g_sun_fb, &it); e;
         e = cng_tab_next(&g_sun_fb, &it))
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == 2 && e->pfd >= 0)
            kept++;
    if (!kept)
        return;
    unsigned long long live[SUN_SWEEP_MAX];
    int n = 0, overflow = 0;
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc/self/fd",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return;
    char buf[4096];
    for (;;) {
        long r = CNG_SYS(__NR_getdents64, (int)dfd, buf, sizeof buf, 0, 0, 0);
        if (r <= 0)
            break;
        for (long o = 0; o + 19 <= r;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > r)
                break;
            const char *nm = buf + o + 19;
            o += reclen;
            int fd = 0, ok = (nm[0] >= '0' && nm[0] <= '9');
            for (const char *c = nm; *c && ok; c++) {
                ok = *c >= '0' && *c <= '9';
                fd = fd * 10 + (*c - '0');
            }
            if (!ok || fd == (int)dfd)
                continue;
            char st[144];
            if (CNG_SYS(__NR_fstat, fd, (long)st, 0, 0, 0, 0) != 0 ||
                (*(unsigned *)(st + 16) & 0170000) != 0140000)
                continue;
            if (n == SUN_SWEEP_MAX) {
                overflow = 1;
                break;
            }
            live[n++] = *(unsigned long long *)(st + 8);
        }
        if (overflow)
            break;
    }
    sys_close((int)dfd);
    if (overflow)
        return;
    for (struct sun_fb *e = cng_tab_first(&g_sun_fb, &it); e;
         e = cng_tab_next(&g_sun_fb, &it)) {
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != 2 || e->pfd < 0)
            continue;
        int open = 0;
        for (int i = 0; i < n && !open; i++)
            open = live[i] == e->ino;
        if (open)
            continue;
        int st = 2;
        if (!__atomic_compare_exchange_n(&e->state, &st, 1, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        if (cng_fd_is(e->pfd, &e->pid))
            sys_close(e->pfd);
        e->pfd = -1;
        __atomic_store_n(&e->slen, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&e->state, 0, __ATOMIC_RELEASE);
    }
}

/* Record what `fd` was bound as: `stored` is what the kernel keeps, `guest`
 * what it stands for, `pfd` the pinned directory to hold for the binding (or
 * -1). The descriptor is the table's to close from here on. */
static void sun_fb_note(int fd, const void *stored, unsigned slen,
                        const void *guest, unsigned glen, int pfd) {
    if (!slen || slen > SUN_PATH_MAX || glen > SUN_PATH_MAX) {
        if (pfd >= 0)
            sys_close(pfd);
        return;
    }
    sun_fb_sweep();
    unsigned long long ino = sock_ino(fd);
    for (unsigned long i = 0;; i++) {
        struct sun_fb *e = cng_tab_at(&g_sun_fb, i);
        if (!e) {
            /* No page for the record: the readback stays ours, and the
             * directory has nobody to hold it. */
            if (pfd >= 0)
                sys_close(pfd);
            return;
        }
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
        e->pfd = pfd;
        if (pfd >= 0 && cng_fdid_of(pfd, &e->pid) != 0) {
            sys_close(pfd);
            e->pfd = -1;
        }
        __atomic_store_n(&e->slen, slen, __ATOMIC_RELEASE);
        __atomic_store_n(&e->state, 2, __ATOMIC_RELEASE);
        return;
    }
}

/* The guest name for a stored spelling, into `out` (SUN_PATH_MAX bytes), or -1
 * when this is not one of ours. `ino` (0: unknown) is the socket the answer is
 * the own address of, and an entry recorded for it wins over one that merely
 * carries the same spelling; of those, the latest. */
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
        by_str = e;
    }
    if (!by_str)
        return -1;
    unsigned n = by_str->glen;
    memcpy(out, by_str->guest, n);
    return (int)n;
}

/* Is `p` the pinned spelling, "/proc/<pid>/fd/<n>/<name>"? Then `*link` is
 * the length of its "/proc/<pid>/fd/<n>" head and the name follows the slash
 * after it. A name with a slash of its own is not one (nothing here makes
 * those), and neither is the digit run that is not a number. */
static int sun_pin_form(const char *p, size_t *link) {
    if (strncmp(p, "/proc/", 6) != 0)
        return 0;
    size_t i = 6;
    if (p[i] < '0' || p[i] > '9')
        return 0;
    while (p[i] >= '0' && p[i] <= '9')
        i++;
    if (strncmp(p + i, "/fd/", 4) != 0)
        return 0;
    i += 4;
    if (p[i] < '0' || p[i] > '9')
        return 0;
    while (p[i] >= '0' && p[i] <= '9')
        i++;
    if (p[i] != '/' || !p[i + 1] || strchr(p + i + 1, '/'))
        return 0;
    *link = i;
    return 1;
}

int cng_sun_in(struct cng_sun_xlate *x, int fd, const void *addr, long alen,
               int follow) {
    x->applied = 0;
    x->dirfd = -1;
    x->bind_fd = -1;
    x->glen = 0;
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
                        (unsigned)plen, -1);
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
    long rr = cng_resolve(guest, follow, host, sizeof host);
    if (rr == -EACCES)
        return -EACCES; /* through a directory the guest has no name for */
    if (rr != 0 && cng_fs_translate(cng_g_fs, guest, host, sizeof host) != 0)
        return -ENAMETOOLONG; /* the contained name cannot be spelled */

    /* Every way out of here below is an error, never a 0. A 0 means "nothing
     * to translate" and sends the caller's own address to the kernel — which
     * for a pathname socket is the guest's untranslated name, resolved against
     * the host filesystem. That is the containment gone: a bind creates the
     * inode outside the rootfs and a connect reaches a host daemon. */
    char *out = x->buf;
    memcpy(out, &fam, sizeof fam);

    /* Pinned (cng/pin.h), like every other host path: the kernel is not
     * handed the string to resolve again. The name being created (bind) goes
     * in as a name against the pinned directory's link; a name being reached
     * (connect, sendto, sendmsg) goes in as the socket file's own link, which
     * resolves to that inode and nothing further. */
    struct cng_pin pin;
    long e = cng_pin_at(CNG_AT_FDCWD, host, &pin);
    if (e) {
        cng_unpin(&pin);
        return (int)e; /* the directory's own answer: ENOENT, ENOTDIR, ... */
    }
    if (!pin.pinned) {
        /* The host path as it stands: a /proc name, or a /dev node. */
        cng_unpin(&pin);
        size_t hl = strlen(host);
        if (hl + 1 > SUN_PATH_MAX)
            return -ENAMETOOLONG;
        memcpy(out + SUN_HDR, host, hl + 1);
        x->len = (long)(SUN_HDR + hl + 1);
        x->applied = 1;
        return 1;
    }
    if (!follow) {
        /* bind: "/proc/<pid>/fd/<n>/<name>", the pid being ours so that any
         * process can read the directory back (see the readback note). The
         * descriptor goes to the record if the bind succeeds (cng_sun_done),
         * and is held there for the binding. */
        size_t n = cng_snprintf(out + SUN_HDR, SUN_PATH_MAX, "/proc/%d/fd/%d/%s",
                                (int)sys_getpid(), pin.dfd, pin.name);
        if (n >= SUN_PATH_MAX) {
            cng_unpin(&pin);
            return -ENAMETOOLONG;
        }
        x->len = (long)(SUN_HDR + n + 1);
        x->dirfd = pin.dfd;
        pin.own = 0; /* ours now */
        cng_unpin(&pin);
        x->bind_fd = fd;
        x->glen = (unsigned)strlen(guest);
        memcpy(x->guest, guest, x->glen);
        x->applied = 1;
        return 1;
    }
    e = cng_pin_leaf(&pin, 0);
    if (e) {
        cng_unpin(&pin);
        return (int)e; /* ENOENT for a name that is not there, as connect says */
    }
    size_t ll = strlen(pin.link);
    memcpy(out + SUN_HDR, pin.link, ll + 1);
    x->len = (long)(SUN_HDR + ll + 1);
    x->dirfd = pin.leaf;
    pin.leaf = -1; /* ours now, until the kernel has resolved it */
    cng_unpin(&pin);
    x->applied = 1;
    return 1;
}

void cng_sun_done(struct cng_sun_xlate *x, long r) {
    if (x->dirfd < 0)
        return;
    if (x->bind_fd >= 0 && r == 0) {
        /* Bound: the record takes the directory, and closes it in time. */
        sun_fb_note(x->bind_fd, x->buf + SUN_HDR,
                    (unsigned)(x->len - SUN_HDR - 1), x->guest, x->glen,
                    x->dirfd);
        x->dirfd = -1;
        return;
    }
    sys_close(x->dirfd);
    x->dirfd = -1;
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
    size_t link;
    if (sun_pin_form(hostp, &link)) {
        /* Our own spelling (see the readback note): the record first, then
         * the spelling resolved through the binder's descriptor. */
        char fb[SUN_PATH_MAX], hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX];
        int gl = sun_fb_lookup(sock_ino(fd), hostp, (unsigned)strlen(hostp), fb);
        if (gl >= 0) {
            memcpy(guest, fb, (size_t)gl);
            guest[gl] = '\0';
        } else {
            char lk[SUN_PATH_MAX + 1];
            memcpy(lk, hostp, link);
            lk[link] = '\0';
            long hn = sys_readlinkat(CNG_AT_FDCWD, lk, hdir, sizeof hdir - 1);
            if (hn <= 0)
                return; /* the binder is gone: nobody's host path, left alone */
            hdir[hn] = '\0';
            if (hdir[0] != '/' || cng_host_dir_guest(hdir, gdir, sizeof gdir) != 0)
                return;
            size_t dl = strlen(gdir);
            if (dl == 1 && gdir[0] == '/')
                dl = 0;
            if (dl + 1 + strlen(hostp + link + 1) + 1 > sizeof guest)
                return;
            memcpy(guest, gdir, dl);
            guest[dl] = '/';
            cng_strlcpy(guest + dl + 1, hostp + link + 1, sizeof guest - dl - 1);
        }
    } else if (cng_fs_untranslate(cng_g_fs, hostp, guest, sizeof guest) != 0) {
        return; /* outside the guest view: leave it alone */
    }
    size_t gl = strlen(guest);
    if (gl + 1 > SUN_PATH_MAX)
        return;
    memcpy(p, guest, gl + 1);
    *alen = (long)(SUN_HDR + gl + 1);
}
