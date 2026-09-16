/* Many emulated rtnetlink sockets at once (M16 regression).
 *
 * The emulation kept four slots, and a fifth concurrent NETLINK_ROUTE socket
 * fell through to the host's own refusal — on a device, where the whole shim
 * exists because the host refuses. A resolver with a socket per thread reaches
 * that. Twelve sockets are held open together and each is made to answer a
 * link dump; then all are closed and twelve opened again (slots are reclaimed
 * by the socket's identity, not by close, which is not trapped); then four
 * threads open three each at the same moment, which is the claim race.
 *
 * On a host that grants rtnetlink the fifth socket would have been a real one
 * and worked, so the harness counts the emulator's own "emulating fd" log
 * lines rather than trusting these numbers alone. */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define N 12

static int dump_ok(int fd) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0)
        return 0;
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    memset(&req, 0, sizeof req);
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.g);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 7;
    req.g.rtgen_family = AF_UNSPEC;
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0)
        return 0;
    char buf[16384];
    for (int rounds = 0; rounds < 64; rounds++) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0)
            return 0;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n))
            if (h->nlmsg_type == NLMSG_DONE)
                return 1;
    }
    return 0;
}

static int open_all(int *fd, int n) {
    int opened = 0;
    for (int i = 0; i < n; i++) {
        fd[i] = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        opened += fd[i] >= 0;
    }
    return opened;
}

static int dump_all(const int *fd, int n) {
    int ok = 0;
    for (int i = 0; i < n; i++)
        ok += fd[i] >= 0 && dump_ok(fd[i]);
    return ok;
}

static void close_all(const int *fd, int n) {
    for (int i = 0; i < n; i++)
        if (fd[i] >= 0)
            close(fd[i]);
}

static pthread_barrier_t bar;
static int thr_ok[4];

static void *thr(void *arg) {
    int k = (int)(long)arg, fd[3];
    pthread_barrier_wait(&bar);
    int opened = open_all(fd, 3);
    thr_ok[k] = opened == 3 && dump_all(fd, 3) == 3;
    close_all(fd, 3);
    return 0;
}

int main(void) {
    int fd[N];
    int opened = open_all(fd, N);
    int dumps = dump_all(fd, N);
    close_all(fd, N);
    int reopened = open_all(fd, N);
    int redumps = dump_all(fd, N);
    close_all(fd, N);

    pthread_t t[4];
    pthread_barrier_init(&bar, 0, 4);
    for (long k = 0; k < 4; k++)
        pthread_create(&t[k], 0, thr, (void *)k);
    int threaded = 1;
    for (int k = 0; k < 4; k++) {
        pthread_join(t[k], 0);
        threaded &= thr_ok[k];
    }
    printf("many: opened=%d dumps=%d reopened=%d redumps=%d threaded=%d\n",
           opened, dumps, reopened, redumps, threaded);
    return 0;
}
