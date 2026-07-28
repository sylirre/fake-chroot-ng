/* AF_UNIX containment for the array forms (M15, sendmmsg/recvmmsg).
 *
 * The single-message calls were contained by M15; sendmmsg/recvmmsg carry one
 * address per message and were left native, so a pathname sun_path handed to
 * sendmmsg reached the HOST untranslated and a source address returned by
 * recvmmsg came back as a raw host path. This makes the same proof uxsock makes,
 * one loop further in: bind a datagram socket at a guest path, send a batch to
 * it from a second socket with sendmmsg, then read the batch back with recvmmsg
 * and print what each message says its source was. Every message is checked, not
 * just the first, because the translation is per element.
 *
 *   argv[1]  server socket path (guest spelling)
 *   argv[2]  client socket path, whose spelling is what comes back as the source
 *            address; a leading '@' makes it an abstract name, where the
 *            per-rootfs tag has to be invisible on readback here too.
 *
 * Output is byte-comparable, so the same binary can be diffed between a run
 * under chroot-ng and a run straight under qemu.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define NMSG 3

/* Fill a sockaddr_un; a leading '@' selects the abstract namespace, rendered
 * the way ss/lsof render it. Returns the addrlen to pass. */
static socklen_t mkaddr(struct sockaddr_un *a, const char *name) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    int abstract = name[0] == '@';
    const char *p = name + (abstract ? 1 : 0);
    size_t n = strlen(p);
    if (n > sizeof a->sun_path - 2)
        n = sizeof a->sun_path - 2;
    memcpy(a->sun_path + (abstract ? 1 : 0), p, n);
    return (socklen_t)(sizeof(sa_family_t) + (abstract ? 1 : 0) + n +
                       (abstract ? 0 : 1));
}

/* Render sun_path the way uxsock does: a leading NUL becomes '@'. */
static void show(char *out, size_t sz, const struct sockaddr_un *a,
                 socklen_t len) {
    size_t n = (len > sizeof(sa_family_t)) ? len - sizeof(sa_family_t) : 0;
    if (n > sizeof a->sun_path)
        n = sizeof a->sun_path;
    size_t w = 0;
    for (size_t i = 0; i < n && w + 1 < sz; i++) {
        char c = a->sun_path[i];
        if (i == 0 && c == '\0') {
            out[w++] = '@';
            continue;
        }
        if (c == '\0')
            break;
        out[w++] = c;
    }
    out[w] = '\0';
}

/* A loopback UDP batch — the use sendmmsg was added for, and the one the
 * containment must not touch: the socket is not AF_UNIX, so no message can be
 * carrying a sun_path. Prints "udp: skip" where the host has no loopback UDP to
 * offer (a sandbox, a device without the permission), since that says nothing
 * about the emulation either way. */
static void udp_batch(void) {
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    socklen_t slen = sizeof sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srv < 0 || cli < 0 || bind(srv, (struct sockaddr *)&sa, sizeof sa) < 0 ||
        getsockname(srv, (struct sockaddr *)&sa, &slen) < 0) {
        printf("udp: skip\n");
        goto out;
    }

    char body[NMSG][16];
    struct iovec iov[NMSG];
    struct mmsghdr sv[NMSG];
    memset(sv, 0, sizeof sv);
    for (int i = 0; i < NMSG; i++) {
        snprintf(body[i], sizeof body[i], "udp-%d", i);
        iov[i].iov_base = body[i];
        iov[i].iov_len = strlen(body[i]);
        sv[i].msg_hdr.msg_name = &sa;
        sv[i].msg_hdr.msg_namelen = sizeof sa;
        sv[i].msg_hdr.msg_iov = &iov[i];
        sv[i].msg_hdr.msg_iovlen = 1;
    }
    int sent = sendmmsg(cli, sv, NMSG, 0);

    char buf[NMSG][32];
    struct iovec riov[NMSG];
    struct mmsghdr rv[NMSG];
    memset(rv, 0, sizeof rv);
    for (int i = 0; i < NMSG; i++) {
        riov[i].iov_base = buf[i];
        riov[i].iov_len = sizeof buf[i] - 1;
        rv[i].msg_hdr.msg_iov = &riov[i];
        rv[i].msg_hdr.msg_iovlen = 1;
    }
    struct timeval tv = {2, 0};
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int got = recvmmsg(srv, rv, NMSG, MSG_WAITFORONE, NULL);
    int ok = got == NMSG;
    for (int i = 0; i < got && i < NMSG; i++) {
        buf[i][rv[i].msg_len < sizeof buf[i] ? rv[i].msg_len
                                             : sizeof buf[i] - 1] = '\0';
        if (strcmp(buf[i], body[i]) != 0)
            ok = 0;
    }
    printf("udp: sent=%d got=%d ok=%d\n", sent, got, ok);
out:
    if (srv >= 0)
        close(srv);
    if (cli >= 0)
        close(cli);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: uxmmsg SERVER-PATH CLIENT-PATH\n");
        return 2;
    }
    struct sockaddr_un sa, ca;
    socklen_t salen = mkaddr(&sa, argv[1]);
    socklen_t calen = mkaddr(&ca, argv[2]);

    int srv = socket(AF_UNIX, SOCK_DGRAM, 0);
    int cli = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (srv < 0 || cli < 0) {
        perror("socket");
        return 1;
    }
    if (argv[1][0] != '@')
        unlink(argv[1]);
    if (argv[2][0] != '@')
        unlink(argv[2]);
    if (bind(srv, (struct sockaddr *)&sa, salen) < 0) {
        perror("bind server");
        return 1;
    }
    if (bind(cli, (struct sockaddr *)&ca, calen) < 0) {
        perror("bind client");
        return 1;
    }
    printf("bind: ok\n");

    /* The batch. Each message names the server itself, so all NMSG addresses go
     * through the translation — an implementation that only looked at the first
     * would send the rest to the host's own /run. */
    char body[NMSG][16];
    struct iovec siov[NMSG];
    struct mmsghdr svec[NMSG];
    memset(svec, 0, sizeof svec);
    for (int i = 0; i < NMSG; i++) {
        snprintf(body[i], sizeof body[i], "hello-%d", i);
        siov[i].iov_base = body[i];
        siov[i].iov_len = strlen(body[i]);
        svec[i].msg_hdr.msg_name = &sa;
        svec[i].msg_hdr.msg_namelen = salen;
        svec[i].msg_hdr.msg_iov = &siov[i];
        svec[i].msg_hdr.msg_iovlen = 1;
    }
    int sent = sendmmsg(cli, svec, NMSG, 0);
    if (sent < 0) {
        perror("sendmmsg");
        return 1;
    }
    printf("sendmmsg: %d\n", sent);
    for (int i = 0; i < sent; i++)
        printf("sent[%d]: %u\n", i, svec[i].msg_len);

    /* The readback. Each message gets its own source-address buffer, and every
     * one of them must come back in guest spelling. */
    char buf[NMSG][32];
    struct sockaddr_un from[NMSG];
    struct iovec riov[NMSG];
    struct mmsghdr rvec[NMSG];
    memset(rvec, 0, sizeof rvec);
    memset(from, 0, sizeof from);
    for (int i = 0; i < NMSG; i++) {
        riov[i].iov_base = buf[i];
        riov[i].iov_len = sizeof buf[i] - 1;
        rvec[i].msg_hdr.msg_name = &from[i];
        rvec[i].msg_hdr.msg_namelen = sizeof from[i];
        rvec[i].msg_hdr.msg_iov = &riov[i];
        rvec[i].msg_hdr.msg_iovlen = 1;
    }
    int got = recvmmsg(srv, rvec, NMSG, MSG_WAITFORONE, NULL);
    if (got < 0) {
        perror("recvmmsg");
        return 1;
    }
    printf("recvmmsg: %d\n", got);
    for (int i = 0; i < got; i++) {
        char src[128];
        buf[i][rvec[i].msg_len < sizeof buf[i] ? rvec[i].msg_len
                                               : sizeof buf[i] - 1] = '\0';
        show(src, sizeof src, &from[i], rvec[i].msg_hdr.msg_namelen);
        printf("msg[%d]: %s from %s\n", i, buf[i], src);
    }

    close(cli);
    close(srv);
    if (argv[1][0] != '@')
        unlink(argv[1]);
    if (argv[2][0] != '@')
        unlink(argv[2]);

    /* --- the batches that carry no address at all ------------------------
     * A socketpair has nowhere to put one and a UDP batch is what sendmmsg
     * exists for; neither has anything to translate, so both must reach the
     * kernel as one call and come back exactly as they would unemulated. These
     * are the legs that catch a containment loop that took a batch apart, or
     * mangled it, when it had no reason to touch it at all. */
    int sp[2];
    int psent = -1, pgot = -1, pok = 0;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0) {
        struct mmsghdr pv[NMSG];
        struct iovec piov[NMSG];
        memset(pv, 0, sizeof pv);
        for (int i = 0; i < NMSG; i++) {
            piov[i].iov_base = body[i];
            piov[i].iov_len = strlen(body[i]);
            pv[i].msg_hdr.msg_iov = &piov[i];
            pv[i].msg_hdr.msg_iovlen = 1;
        }
        psent = sendmmsg(sp[0], pv, NMSG, 0);
        char pbuf[NMSG][32];
        struct iovec riov2[NMSG];
        struct mmsghdr rv[NMSG];
        memset(rv, 0, sizeof rv);
        for (int i = 0; i < NMSG; i++) {
            riov2[i].iov_base = pbuf[i];
            riov2[i].iov_len = sizeof pbuf[i] - 1;
            rv[i].msg_hdr.msg_iov = &riov2[i];
            rv[i].msg_hdr.msg_iovlen = 1;
        }
        pgot = recvmmsg(sp[1], rv, NMSG, MSG_WAITFORONE, NULL);
        pok = pgot == NMSG;
        for (int i = 0; i < pgot && i < NMSG; i++) {
            pbuf[i][rv[i].msg_len < sizeof pbuf[i] ? rv[i].msg_len
                                                   : sizeof pbuf[i] - 1] = '\0';
            if (strcmp(pbuf[i], body[i]) != 0)
                pok = 0;
        }
        close(sp[0]);
        close(sp[1]);
    }
    printf("pair: sent=%d got=%d ok=%d\n", psent, pgot, pok);

    udp_batch();
    return 0;
}
