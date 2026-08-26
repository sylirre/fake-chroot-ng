/* recvmmsg's timeout argument, on the AF_UNIX path the monitor decomposes.
 *
 * An AF_UNIX batch cannot be re-issued whole (a source address has to be mapped
 * back out of a bounce buffer), so the monitor takes it apart into per-message
 * recvmsg calls — and a loop of recvmsg calls has no timeout to hand the
 * kernel. That makes the timeout the emulation's own to apply, and the kernel's
 * rule for it is peculiar enough that guessing gets it wrong: it is NOT a bound
 * on the wait. do_recvmmsg() turns the argument into an absolute deadline and
 * consults it only *between* datagrams, so each receive blocks with no deadline
 * of its own, the remaining time is written back to the caller's own timespec
 * when at least one datagram arrived, and a zero timeout stops the batch after
 * exactly one message rather than draining what is queued.
 *
 * Every leg here is on a socketpair — no filesystem, no addresses, nothing that
 * differs between a host build and a guest one — so the output is
 * byte-comparable against the same program built for the host and run with no
 * emulation under it. errno is printed as a number for the same reason.
 *
 * The legs that block forever on a real kernel (a vlen larger than the batch
 * that will ever arrive, timeout or not — recvmmsg(2) documents that under
 * BUGS) are deliberately not here: the fidelity they would prove is that the
 * test hangs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NV 4

static int sv[2];
static struct mmsghdr v[NV];
static struct iovec io[NV];
static char buf[NV][64];

static void prep(void) {
    memset(v, 0, sizeof v);
    for (int i = 0; i < NV; i++) {
        io[i].iov_base = buf[i];
        io[i].iov_len = sizeof buf[i];
        v[i].msg_hdr.msg_iov = &io[i];
        v[i].msg_hdr.msg_iovlen = 1;
    }
}

static void queue(int n) {
    for (int i = 0; i < n; i++)
        send(sv[1], "x", 1, 0);
}

static void drain(void) {
    char b[64];
    while (recv(sv[0], b, sizeof b, MSG_DONTWAIT) > 0)
        ;
}

static void nap(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, 0);
}

/* r, plus errno only when it failed: an errno left over from a success is not
 * something either side promises. */
static void say(const char *tag, int r) {
    if (r < 0)
        printf("%s: r=-1 e=%d\n", tag, errno);
    else
        printf("%s: r=%d\n", tag, r);
}

int main(void) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("socketpair: e=%d\n", errno);
        return 1;
    }
    prep();
    struct timespec t;

    /* A zero timeout is a deadline already in the past: one message, not the
     * three that are sitting there. */
    queue(3);
    t.tv_sec = 0;
    t.tv_nsec = 0;
    say("zero-to", recvmmsg(sv[0], v, NV, 0, &t));
    printf("zero-to-left: %ld.%09ld\n", (long)t.tv_sec, (long)t.tv_nsec);
    drain();

    /* MSG_WAITFORONE is the flag that really does bound the wait, so the whole
     * queue comes back — and the time left over is written back, which means
     * strictly less than was asked for and more than none. */
    queue(3);
    t.tv_sec = 5;
    t.tv_nsec = 0;
    say("wfo-to", recvmmsg(sv[0], v, NV, MSG_WAITFORONE, &t));
    printf("wfo-to-left: shorter=%d positive=%d\n", t.tv_sec < 5,
           t.tv_sec > 0 || t.tv_nsec > 0);
    drain();

    /* The timeout is read (and validated) before the socket is so much as
     * looked at, so these three are answered with nothing received. */
    queue(1);
    say("badptr", recvmmsg(sv[0], v, NV, 0, (struct timespec *)(void *)0x1));
    drain();

    queue(1);
    t.tv_sec = 0;
    t.tv_nsec = 1000000000L;
    say("badnsec", recvmmsg(sv[0], v, NV, 0, &t));
    drain();

    queue(1);
    t.tv_sec = -1;
    t.tv_nsec = 0;
    say("negsec", recvmmsg(sv[0], v, NV, 0, &t));
    drain();

    queue(1);
    t.tv_sec = 0;
    t.tv_nsec = -1;
    say("negnsec", recvmmsg(sv[0], v, NV, 0, &t));
    drain();

    /* The leg the "a timeout means first-only" shortcut got wrong: with time
     * left on the deadline the batch keeps asking, and blocks for each of the
     * three the feeder is still spacing out. vlen is exactly the number that
     * will arrive, so the loop ends by filling the array rather than by the
     * deadline — the one way this can be asked without asking it to hang. */
    {
        pid_t p = fork();
        if (p == 0) {
            for (int i = 0; i < 3; i++) {
                nap(120);
                send(sv[1], "y", 1, 0);
            }
            _exit(0);
        }
        t.tv_sec = 20;
        t.tv_nsec = 0;
        say("slowfeed", recvmmsg(sv[0], v, 3, 0, &t));
        int st;
        if (p > 0)
            waitpid(p, &st, 0);
        drain();
    }

    /* A zero timeout still wins over MSG_WAITFORONE: both stop after one. */
    queue(3);
    t.tv_sec = 0;
    t.tv_nsec = 0;
    say("zero-wfo", recvmmsg(sv[0], v, NV, MSG_WAITFORONE, &t));
    drain();

    /* No timeout at all: the batch is bounded only by MSG_WAITFORONE. */
    queue(3);
    say("noto-wfo", recvmmsg(sv[0], v, NV, MSG_WAITFORONE, NULL));
    drain();

    /* (An empty batch is re-issued whole rather than decomposed, so what it
     * answers is whatever is underneath us — the kernel on hardware, qemu-user
     * on a cross host, which ignores the timeout argument outright. Nothing of
     * ours to compare, so it is not asked.) */

    close(sv[0]);
    close(sv[1]);
    return 0;
}
