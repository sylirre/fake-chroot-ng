/* Descriptors arriving over a socket (M25).
 *
 * A descriptor received with SCM_RIGHTS is the third way one can enter the
 * guest's table from outside the view (cng_fd_admit): a file is let in for
 * the I/O it carries, a directory the guest has no name for is closed on
 * arrival — its number stays in the record, and the guest finds it not open.
 * The numbers are judged out of the control data as the kernel wrote it into
 * a buffer of the monitor's, not out of the guest's buffer a syscall later.
 *
 * Binds a pathname socket at argv[1] (a guest path), accepts one connection,
 * and receives three messages carrying descriptors: the first with recvmsg,
 * the second with recvmmsg, the third with recvmsg into a control buffer far
 * longer than any AF_UNIX message can fill (16 KiB, past the monitor's own
 * bound, so the socket's family decides how it is received); one byte of
 * data each so a stream read stops at each message's descriptors. Each
 * descriptor received is reported as what it turned out to be — dir, file,
 * or closed (fstat says EBADF) — along with whether the control data was
 * truncated. The sender is a host program (the test script), the only kind
 * of process that can hold a directory outside the view to send.
 *
 * Then, on a UDP socket to itself with the same long control buffer, a
 * message whose control data is IP_PKTINFO: a family that cannot carry
 * descriptors keeps the guest's own buffer, and the record has to arrive. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define LONG_CTL 16384

static const char *kind(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return errno == EBADF ? "closed" : "error";
    return S_ISDIR(st.st_mode) ? "dir" : "file";
}

static void report(int round, long n, struct msghdr *mh) {
    printf("round=%d n=%ld ctrunc=%d", round, n,
           (mh->msg_flags & MSG_CTRUNC) ? 1 : 0);
    for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
            continue;
        size_t nfd = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < nfd; i++) {
            int fd;
            memcpy(&fd, CMSG_DATA(c) + i * sizeof fd, sizeof fd);
            printf(" %s", kind(fd));
        }
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: fdimport SOCKET-PATH\n");
        return 2;
    }
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", argv[1]);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 ||
        listen(s, 1) != 0) {
        printf("fdimport: bind %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    int c = accept(s, 0, 0);
    if (c < 0) {
        printf("fdimport: accept: %s\n", strerror(errno));
        return 1;
    }
    static union {
        char buf[LONG_CTL];
        struct cmsghdr align;
    } u;
    for (int round = 0; round < 3; round++) {
        char data;
        struct iovec io = {&data, 1};
        memset(&u, 0, sizeof u);
        struct mmsghdr mm;
        memset(&mm, 0, sizeof mm);
        struct msghdr *mh = &mm.msg_hdr;
        mh->msg_iov = &io;
        mh->msg_iovlen = 1;
        mh->msg_control = u.buf;
        mh->msg_controllen =
            round == 2 ? sizeof u.buf : CMSG_SPACE(8 * sizeof(int));
        long n = round == 1 ? recvmmsg(c, &mm, 1, 0, 0) : recvmsg(c, mh, 0);
        if (n < 0) {
            printf("round=%d %s: %s\n", round,
                   round == 1 ? "recvmmsg" : "recvmsg", strerror(errno));
            return 1;
        }
        report(round, round == 1 ? (long)mm.msg_len : n, mh);
    }

    /* A family that cannot carry descriptors, with the same long buffer. */
    int d = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in in;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t il = sizeof in;
    int one = 1;
    if (d < 0 || bind(d, (struct sockaddr *)&in, sizeof in) != 0 ||
        getsockname(d, (struct sockaddr *)&in, &il) != 0 ||
        setsockopt(d, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) != 0 ||
        sendto(d, "p", 1, 0, (struct sockaddr *)&in, sizeof in) != 1) {
        printf("inet: setup: %s\n", strerror(errno));
        return 0; /* no loopback here: the unix legs stand on their own */
    }
    char data;
    struct iovec io = {&data, 1};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    memset(&u, 0, sizeof u);
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = u.buf;
    mh.msg_controllen = sizeof u.buf;
    long n = recvmsg(d, &mh, 0);
    int pktinfo = 0;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm))
        if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO)
            pktinfo = 1;
    printf("inet: n=%ld ctrunc=%d pktinfo=%d controllen=%zu\n", n,
           (mh.msg_flags & MSG_CTRUNC) ? 1 : 0, pktinfo,
           (size_t)mh.msg_controllen);
    return 0;
}
