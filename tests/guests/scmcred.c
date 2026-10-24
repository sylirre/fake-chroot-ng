/* SCM_CREDENTIALS under a fake identity (M7).
 *
 * The kernel holds a sender to the ids its credentials record claims
 * (scm_check_creds) and names the sender by its real ids to a receiver. Under
 * --fake-id the claim is the fake ids — GLib sends getpid(), geteuid(),
 * getegid() before every D-Bus authentication — so the emulation judges it
 * against the fake set by the kernel's rule and spells it in the host's ids,
 * and remaps a received record as SO_PEERCRED's answer is remapped.
 *
 * Every row sends one datagram over a socketpair whose receiving end has
 * SO_PASSCRED set, and prints what the send answered and, when it went out,
 * the ids the receiver was handed beside its own. Nothing waits: a receive
 * finds the datagram queued or reports that it did not.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int sv[2];

/* One credentials record claiming pid/uid/gid with a cmsg_len of `clen`,
 * optionally behind an SCM_RIGHTS record carrying `fd`. */
static unsigned long build(char *buf, unsigned pid, unsigned uid, unsigned gid,
                           unsigned long clen, int fd) {
    unsigned long off = 0;
    struct cmsghdr *c;
    if (fd >= 0) {
        c = (struct cmsghdr *)buf;
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof fd);
        memcpy(CMSG_DATA(c), &fd, sizeof fd);
        off = CMSG_SPACE(sizeof fd);
    }
    c = (struct cmsghdr *)(buf + off);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_CREDENTIALS;
    c->cmsg_len = clen;
    unsigned v[3] = {pid, uid, gid};
    memcpy(CMSG_DATA(c), v, sizeof v);
    return off + CMSG_SPACE(sizeof(struct ucred));
}

static int sendone(unsigned pid, unsigned uid, unsigned gid, unsigned long clen,
                   int fd) {
    char b = 'x';
    struct iovec io = {&b, 1};
    char buf[64] __attribute__((aligned(8)));
    memset(buf, 0, sizeof buf);
    struct msghdr mh = {0};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = buf;
    mh.msg_controllen = build(buf, pid, uid, gid, clen, fd);
    return sendmsg(sv[0], &mh, 0) == 1 ? 0 : errno;
}

/* Receive one datagram into a control buffer of `cl` bytes and print the
 * credentials record (as much of it as arrived) and any descriptor. */
static void recvone(const char *tag, unsigned long cl) {
    char b;
    struct iovec io = {&b, 1};
    char buf[128] __attribute__((aligned(8)));
    memset(buf, 0xff, sizeof buf);
    struct msghdr mh = {0};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = buf;
    mh.msg_controllen = cl;
    if (recvmsg(sv[1], &mh, MSG_DONTWAIT) != 1) {
        printf("%s recv errno=%d\n", tag, errno);
        return;
    }
    printf("%s", tag);
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level != SOL_SOCKET)
            continue;
        if (c->cmsg_type == SCM_CREDENTIALS) {
            unsigned v[3];
            unsigned long n = c->cmsg_len - CMSG_LEN(0);
            memcpy(v, CMSG_DATA(c), n < sizeof v ? n : sizeof v);
            printf(" pid_ok=%d", n >= 4 ? v[0] == (unsigned)getpid() : -1);
            if (n >= 8)
                printf(" uid=%u", v[1]);
            if (n >= 12)
                printf(" gid=%u", v[2]);
        } else if (c->cmsg_type == SCM_RIGHTS) {
            int fd;
            struct stat st;
            memcpy(&fd, CMSG_DATA(c), sizeof fd);
            printf(" fifo=%d", fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode));
            close(fd);
        }
    }
    printf("%s self=%u:%u\n", mh.msg_flags & MSG_CTRUNC ? " ctrunc" : "",
           (unsigned)geteuid(), (unsigned)getegid());
}

/* Send one claim (beside `fd` when it is one) and receive it into `cl`
 * bytes of control buffer, if it went out. */
static void row_into(const char *tag, unsigned pid, unsigned uid, unsigned gid,
                     unsigned long clen, int fd, unsigned long cl) {
    int e = sendone(pid, uid, gid, clen, fd);
    printf("%s send=%d\n", tag, e);
    if (!e)
        recvone(tag, cl);
}

static void row(const char *tag, unsigned pid, unsigned uid, unsigned gid,
                unsigned long clen) {
    row_into(tag, pid, uid, gid, clen, -1, 128);
}

int main(void) {
    int on = 1;
    setvbuf(stdout, NULL, _IOLBF, 0); /* what was printed survives a kill */
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) ||
        setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) {
        printf("setup errno=%d\n", errno);
        return 1;
    }
    unsigned me = (unsigned)getpid(), u = geteuid(), g = getegid();
    unsigned long cl = CMSG_LEN(sizeof(struct ucred));

    /* What GLib sends: the caller's own pid and effective ids. */
    row("own", me, u, g, cl);
    /* The real uid and gid are as much the caller's to claim. */
    row("real", me, getuid(), getgid(), cl);
    /* Nothing claimed: SO_PASSCRED attaches the sender's ids itself. */
    char b = 'x';
    printf("implicit send=%d\n", send(sv[0], &b, 1, 0) == 1 ? 0 : errno);
    recvone("implicit", 128);
    /* An id that is none of the caller's: refused unless privileged. */
    row("other-uid", me, u + 1, g, cl);
    row("other-gid", me, u, g + 1, cl);
    /* A pid not the caller's. */
    row("other-pid", me + 100000, u, g, cl);
    /* -1 maps to nothing, and a record of the wrong length is malformed:
     * both the kernel's EINVAL, ahead of any EPERM. */
    row("uid-1", me + 100000, ~0u, g, cl);
    row("badlen", me, u, g, cl - 1);
    /* A receive buffer cut inside the record: what arrived is still
     * remapped. */
    row_into("short", me, u, g, cl, -1, CMSG_LEN(8));
    /* A descriptor beside the claim. */
    int p[2];
    if (pipe(p) == 0) {
        row_into("rights", me, u, g, cl, p[0], 128);
        close(p[0]);
        close(p[1]);
    }
    /* The array forms: two claims in one sendmmsg, received by one
     * recvmmsg. */
    struct mmsghdr mm[2];
    struct iovec io[2];
    char xb[2] = {'a', 'b'};
    char ctl[2][64] __attribute__((aligned(8)));
    memset(mm, 0, sizeof mm);
    for (int i = 0; i < 2; i++) {
        io[i].iov_base = &xb[i];
        io[i].iov_len = 1;
        mm[i].msg_hdr.msg_iov = &io[i];
        mm[i].msg_hdr.msg_iovlen = 1;
        mm[i].msg_hdr.msg_control = ctl[i];
        mm[i].msg_hdr.msg_controllen = build(ctl[i], me, u, g, cl, -1);
    }
    int n = sendmmsg(sv[0], mm, 2, 0);
    printf("mmsg sent=%d errno=%d\n", n, n < 0 ? errno : 0);
    char rb[2];
    for (int i = 0; i < 2; i++) {
        io[i].iov_base = &rb[i];
        mm[i].msg_hdr.msg_controllen = sizeof ctl[i];
    }
    n = recvmmsg(sv[1], mm, 2, MSG_DONTWAIT, NULL);
    printf("mmsg got=%d", n);
    for (int i = 0; i < n; i++) {
        struct cmsghdr *c = CMSG_FIRSTHDR(&mm[i].msg_hdr);
        unsigned v[3] = {0, 0, 0};
        if (c && c->cmsg_type == SCM_CREDENTIALS)
            memcpy(v, CMSG_DATA(c), sizeof v);
        printf(" uid=%u gid=%u", v[1], v[2]);
    }
    printf(" self=%u:%u\n", u, g);
    /* Root dropping its real and effective ids but keeping 0 as the saved
     * ones: those are still its to claim, an id it never had is not. */
    if (geteuid() == 0 && setresgid(1234, 1234, 0) == 0 &&
        setresuid(1234, 1234, 0) == 0) {
        row("saved", me, 0, 0, cl);
        row("dropped-other", me, 5678, 1234, cl);
    }
    return 0;
}
