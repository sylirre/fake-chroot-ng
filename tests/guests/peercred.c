/* SO_PEERCRED under a fake identity (M7).
 *
 * The kernel reports the real invoking uid/gid of a peer; under --fake-id the
 * emulation remaps the pair to the fake identity, the way stat's ownership is
 * remapped, and a guest daemon comparing the peer against its own getuid()
 * has to find them equal. The answer is delivered out of a buffer of the
 * monitor's now, so the length rules of sock_getsockopt() are applied there:
 * a length longer than the struct is cut to it and reported cut, a shorter
 * one gets that many bytes, zero gets nothing, and a negative one is EINVAL.
 *
 * Both ends of a socketpair are this process, so the pid reported is our own.
 * Prints one line per length asked: what came back and the ids it carried.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void ask(int fd, int len) {
    unsigned char raw[64];
    memset(raw, 0xff, sizeof raw);
    socklen_t l = (socklen_t)len;
    int rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, raw, &l);
    if (rc != 0) {
        printf("len=%d -> errno=%d\n", len, errno);
        return;
    }
    struct ucred uc;
    memcpy(&uc, raw, sizeof uc);
    /* Only the bytes the kernel reports written are named here: the tail of
     * a short read is whatever it was, and stays out of the comparison. */
    printf("len=%d -> got=%u pid_ok=%d", len, (unsigned)l,
           (unsigned)l >= 4 ? uc.pid == getpid() : -1);
    if (l >= 8)
        printf(" uid=%u", uc.uid);
    if (l >= 12)
        printf(" gid=%u", uc.gid);
    printf(" self=%u:%u\n", (unsigned)getuid(), (unsigned)getgid());
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("socketpair: errno=%d\n", errno);
        return 1;
    }
    ask(sv[0], 12);
    ask(sv[0], 64);
    ask(sv[0], 8);
    ask(sv[0], 0);
    ask(sv[0], -1);
    return 0;
}
