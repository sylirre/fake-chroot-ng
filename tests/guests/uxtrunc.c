/* AF_UNIX readback truncation guest (M21).
 *
 * Every readback call reports the address's UNtruncated length while copying
 * only as much as the caller's buffer holds ("fromlen shall refer to the value
 * before truncation", 1003.1g). Under chroot-ng the kernel's answer is a HOST
 * address, so a short buffer left the emulation a truncated host path plus a
 * length describing bytes that were never written — and translating that in the
 * guest's own buffer both read past it and wrote the shortened guest path back
 * past its end.
 *
 * This pins all three consequences at once:
 *   - the address buffer sits at the very end of a page whose successor is
 *     PROT_NONE, so a read past it faults (inside the SIGSYS handler, where
 *     SIGSEGV is masked, that is a force-kill — the process simply vanishes);
 *   - the bytes after the buffer are poisoned, so a write past it is visible;
 *   - the reported length must be the GUEST view's, never the host's.
 *
 * With an abstract name the guest-visible address is the same string with and
 * without a rootfs under it, so this is also a byte-for-byte differential: the
 * same binary run straight under qemu must print the same lines.
 *
 *   argv[1]  socket name: "@name" for the abstract namespace, else a path
 *
 * A pre-fix binary fails this three ways over: the run dies on the guard page,
 * or the poison is gone, or the length is the host's (for an abstract name, the
 * four bytes printed are the per-rootfs tag itself).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SHORT_LEN 6 /* sun_family + four bytes of sun_path */
#define POISON    0xAA

static char *g_guard;   /* the short buffer, last SHORT_LEN bytes of a page */
static char *g_poison;  /* SHORT_LEN bytes before it, to catch an overwrite */

/* A buffer that ends exactly at a PROT_NONE page, with a poisoned run in front
 * of it. Reading past the end faults; writing past the requested length lands
 * in neither, so it is caught by the poison check on the bytes before it. */
static int guard_setup(void) {
    long ps = sysconf(_SC_PAGESIZE);
    char *p = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return -1;
    if (mprotect(p + ps, (size_t)ps, PROT_NONE) != 0)
        return -1;
    g_guard = p + ps - SHORT_LEN;
    g_poison = g_guard - SHORT_LEN;
    return 0;
}

static void guard_arm(void) {
    memset(g_poison, POISON, SHORT_LEN);
    memset(g_guard, 0, SHORT_LEN);
}

static int poison_intact(void) {
    for (int i = 0; i < SHORT_LEN; i++)
        if ((unsigned char)g_poison[i] != POISON)
            return 0;
    return 1;
}

/* The four sun_path bytes a SHORT_LEN buffer has room for, in hex. An abstract
 * name starts with a NUL, so "00" is expected there and the per-rootfs tag —
 * were it ever to reach the guest — would show up as 01636e67 ("\x01cng"). */
static void show4(const char *tag, int rc, socklen_t len) {
    char hex[16];
    for (int i = 0; i < 4; i++) {
        static const char d[] = "0123456789abcdef";
        unsigned char c = (unsigned char)g_guard[2 + i];
        hex[i * 2] = d[c >> 4];
        hex[i * 2 + 1] = d[c & 15];
    }
    hex[8] = '\0';
    printf("%s: rc=%d len=%u bytes=%s poison=%d\n", tag, rc, (unsigned)len, hex,
           poison_intact());
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: uxtrunc NAME|@ABSTRACT\n");
        return 2;
    }
    if (guard_setup() != 0) {
        printf("guard: mmap failed\n");
        return 2;
    }
    int abstract = argv[1][0] == '@';
    const char *name = argv[1] + (abstract ? 1 : 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    size_t off = abstract ? 1 : 0;
    strncpy(addr.sun_path + off, name, sizeof addr.sun_path - off - 1);
    socklen_t alen =
        (socklen_t)(sizeof(sa_family_t) + off + strlen(name) + (abstract ? 0 : 1));

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        printf("socket: %s\n", strerror(errno));
        return 1;
    }
    if (!abstract)
        unlink(name);
    if (bind(srv, (struct sockaddr *)&addr, alen) != 0) {
        printf("bind: %s\n", strerror(errno));
        return 1;
    }
    printf("bind: ok\n");
    listen(srv, 4);

    /* getsockname into a buffer far too small for the address. */
    guard_arm();
    socklen_t l = SHORT_LEN;
    int rc = getsockname(srv, (struct sockaddr *)g_guard, &l);
    show4("short getsockname", rc, l);

    /* ...and into no buffer at all: nothing may be written, but the length is
     * still reported. This is the case a guard page cannot catch, since zero
     * bytes of the guest's buffer were ever validated. */
    guard_arm();
    l = 0;
    rc = getsockname(srv, (struct sockaddr *)g_guard, &l);
    printf("zero getsockname: rc=%d len=%u poison=%d\n", rc, (unsigned)l,
           poison_intact());

    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cli, (struct sockaddr *)&addr, alen) != 0) {
        printf("connect: %s\n", strerror(errno));
        return 1;
    }
    guard_arm();
    l = SHORT_LEN;
    rc = getpeername(cli, (struct sockaddr *)g_guard, &l);
    show4("short getpeername", rc, l);

    /* accept: the peer of a stream connection is unnamed, so this checks that a
     * two-byte address survives the same path unmangled. */
    guard_arm();
    l = SHORT_LEN;
    int acc = accept(srv, (struct sockaddr *)g_guard, &l);
    printf("accept: rc=%d len=%u poison=%d\n", acc >= 0 ? 0 : -1, (unsigned)l,
           poison_intact());

    /* recvmsg with a short msg_name, which is the same rule inside a header —
     * and where msg_controllen/msg_flags must still come back, since they are
     * written into the header the kernel was given and not the guest's own. */
    if (acc >= 0) {
        if (write(cli, "hi", 2) != 2)
            printf("write: %s\n", strerror(errno));
        guard_arm();
        char data[8], ctl[64];
        struct iovec iov = {data, sizeof data};
        struct msghdr mh;
        memset(&mh, 0, sizeof mh);
        mh.msg_name = g_guard;
        mh.msg_namelen = SHORT_LEN;
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = ctl;
        mh.msg_controllen = sizeof ctl;
        ssize_t n = recvmsg(acc, &mh, 0);
        printf("recvmsg: n=%zd namelen=%u controllen=%zu flags=%d poison=%d\n",
               n, (unsigned)mh.msg_namelen, (size_t)mh.msg_controllen,
               mh.msg_flags, poison_intact());
        close(acc);
    }

    close(cli);
    close(srv);
    if (!abstract)
        unlink(name);
    printf("done\n");
    return 0;
}
