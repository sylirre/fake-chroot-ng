/* Socket peers that have changed their ids (M7).
 *
 * Under --fake-id every guest process has the host's ids, so those are what
 * the kernel names a peer by (SO_PEERCRED, SCM_CREDENTIALS), whatever ids the
 * peer has taken since the run began; the emulation names it by the fake set
 * the peer publishes. After `su - user`, a session bus running as the user
 * was told each of its clients was root, the identity the run began as, and
 * closed the connection (XFCE's "Unable to contact settings server: The
 * connection is closed").
 *
 * Usage: peerid SID CID. A server process takes SID as its every id and
 * listens; a client process takes CID and connects. The server prints the
 * client as SO_PEERCRED names it and as two credentials records do, one the
 * client claims its own effective ids in and one SO_PASSCRED attaches by
 * itself; the client prints the server as SO_PEERCRED names it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void become(const char *who, unsigned id) {
    if (setgroups(0, NULL) || setresgid(id, id, id) || setresuid(id, id, id)) {
        printf("%s become %u errno=%d\n", who, id, errno);
        exit(1);
    }
}

static void peer(const char *who, int fd, pid_t want) {
    struct ucred uc;
    socklen_t l = sizeof uc;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0) {
        printf("%s peercred errno=%d\n", who, errno);
        return;
    }
    printf("%s peer pid_ok=%d uid=%u gid=%u self=%u:%u\n", who, uc.pid == want,
           uc.uid, uc.gid, (unsigned)geteuid(), (unsigned)getegid());
}

/* One byte, and the credentials record that came with it. */
static void record(const char *tag, int fd, pid_t want) {
    char b;
    struct iovec io = {&b, 1};
    char ctl[CMSG_SPACE(sizeof(struct ucred))] __attribute__((aligned(8)));
    struct msghdr mh = {0};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = ctl;
    mh.msg_controllen = sizeof ctl;
    if (recvmsg(fd, &mh, 0) != 1) {
        printf("%s recv errno=%d\n", tag, errno);
        return;
    }
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS) {
        printf("%s no record\n", tag);
        return;
    }
    struct ucred uc;
    memcpy(&uc, CMSG_DATA(c), sizeof uc);
    printf("%s pid_ok=%d uid=%u gid=%u\n", tag, uc.pid == want, uc.uid, uc.gid);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0); /* the children's lines, in order */
    if (argc < 3)
        return 2;
    alarm(30); /* inherited: a side left waiting on a failed one dies */
    unsigned sid = (unsigned)strtoul(argv[1], 0, 10);
    unsigned cid = (unsigned)strtoul(argv[2], 0, 10);
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "/tmp/peerid.%d", (int)getpid());
    int go[2];
    if (pipe(go) != 0)
        return 1;

    /* The client waits for the server to listen, which sends its pid. */
    pid_t cli = fork();
    if (cli == 0) {
        close(go[1]);
        pid_t srv;
        if (read(go[0], &srv, sizeof srv) != sizeof srv)
            return 1;
        become("client", cid);
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        int on = 1;
        /* A sender with SO_PASSCRED set has the kernel attach its ids to
         * every message, whether or not the server's end has the option
         * yet. */
        if (s < 0 || setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof on) ||
            connect(s, (struct sockaddr *)&a, sizeof a)) {
            printf("client connect errno=%d\n", errno);
            return 1;
        }
        peer("client", s, srv);
        /* What GLib sends before it authenticates: the caller's own pid and
         * effective ids. */
        char b = 'c';
        struct iovec io = {&b, 1};
        char ctl[CMSG_SPACE(sizeof(struct ucred))] __attribute__((aligned(8)));
        memset(ctl, 0, sizeof ctl);
        struct msghdr mh = {0};
        mh.msg_iov = &io;
        mh.msg_iovlen = 1;
        mh.msg_control = ctl;
        mh.msg_controllen = sizeof ctl;
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_CREDENTIALS;
        c->cmsg_len = CMSG_LEN(sizeof(struct ucred));
        struct ucred uc = {getpid(), geteuid(), getegid()};
        memcpy(CMSG_DATA(c), &uc, sizeof uc);
        if (sendmsg(s, &mh, 0) != 1)
            printf("client claim errno=%d\n", errno);
        b = 'i';
        if (send(s, &b, 1, 0) != 1)
            printf("client implicit errno=%d\n", errno);
        /* Hold the connection until the server is done with it. */
        if (read(s, &b, 1) < 0)
            return 1;
        return 0;
    }
    pid_t srv = fork();
    if (srv == 0) {
        close(go[0]);
        become("server", sid);
        /* Connecting needs write permission on the socket file, which a root
         * server's would not give a client of another uid on a real kernel. */
        umask(0);
        int l = socket(AF_UNIX, SOCK_STREAM, 0);
        if (l < 0 || bind(l, (struct sockaddr *)&a, sizeof a) || listen(l, 1)) {
            printf("server listen errno=%d\n", errno);
            return 1;
        }
        pid_t me = getpid();
        if (write(go[1], &me, sizeof me) != sizeof me)
            return 1;
        int c = accept(l, 0, 0);
        int on = 1;
        if (c < 0 || setsockopt(c, SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) {
            printf("server accept errno=%d\n", errno);
            return 1;
        }
        peer("server", c, cli);
        record("claim", c, cli);
        record("implicit", c, cli);
        unlink(a.sun_path);
        return 0;
    }
    close(go[0]);
    close(go[1]);
    int st;
    waitpid(srv, &st, 0);
    waitpid(cli, &st, 0);
    return 0;
}
