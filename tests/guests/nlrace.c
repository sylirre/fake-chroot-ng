/* Concurrent relays on one emulated rtnetlink socket (M16 regression).
 *
 * A relayed dump went through a host netlink socket the emulated socket kept
 * for its life, re-opened whenever the number stopped naming it (the exec
 * sweep closes it; so does a guest's close-all loop). Two threads finding it
 * gone at once each opened one and recorded its identity in the slot before
 * the compare-and-swap that published it, so the loser could overwrite the
 * winner's record: the published socket then failed its own identity check,
 * was taken for stale by the next call, and was replaced without a close —
 * a descriptor lost per race, in the guest's own table.
 *
 * Each round closes every host netlink socket the guest did not open (what a
 * close-all loop would do to the relay), then eight threads make a trapped
 * call on the same emulated socket at the same moment, each with a dump
 * request queued, and the host netlink sockets left over are counted once
 * they are done. A relay socket belongs to its request now, so there must be
 * none; the old scheme leaves its one relay, and more whenever the race
 * struck ("leaked" counts those). Emulated by force (CNG_NETLINK_FORCE_BLOCK),
 * so the guest's own socket is an AF_UNIX stand-in and every AF_NETLINK
 * socket in the table is the monitor's. */
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define THREADS 8
#define ROUNDS  60

static int g_fd;
static pthread_barrier_t g_bar;

static void send_dump(void) {
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.g);
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 9;
    req.g.rtgen_family = AF_UNSPEC;
    send(g_fd, &req, req.nlh.nlmsg_len, 0);
}

static void *worker(void *arg) {
    (void)arg;
    char buf[64];
    pthread_barrier_wait(&g_bar);
    /* The request queues; the trapped receive that follows serves it. */
    send_dump();
    recv(g_fd, buf, sizeof buf, MSG_DONTWAIT | MSG_PEEK);
    return 0;
}

/* Host netlink sockets in the table other than the guest's own. */
static int count_nl(int close_them) {
    int n = 0;
    for (int fd = 0; fd < 1024; fd++) {
        int dom = 0;
        socklen_t l = sizeof dom;
        if (fd == g_fd ||
            getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &l) != 0 ||
            dom != AF_NETLINK)
            continue;
        n++;
        if (close_them)
            close(fd);
    }
    return n;
}

static void drain(void) {
    char buf[16384];
    while (recv(g_fd, buf, sizeof buf, MSG_DONTWAIT) > 0)
        ;
}

int main(void) {
    g_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (g_fd < 0 || bind(g_fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("nlrace: no socket errno=%d\n", errno);
        return 1;
    }
    int leaked = 0, left = 0;
    for (int r = 0; r < ROUNDS; r++) {
        count_nl(1);
        pthread_barrier_init(&g_bar, 0, THREADS);
        pthread_t t[THREADS];
        for (int i = 0; i < THREADS; i++)
            pthread_create(&t[i], 0, worker, 0);
        for (int i = 0; i < THREADS; i++)
            pthread_join(t[i], 0);
        pthread_barrier_destroy(&g_bar);
        drain();
        left = count_nl(0);
        if (left > 1)
            leaked += left - 1;
    }
    printf("nlrace: rounds=%d left=%d leaked=%d\n", ROUNDS, left, leaked);
    return 0;
}
