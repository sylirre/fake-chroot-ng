/* Emulated rtnetlink sockets opened and closed by many threads at once (M16
 * regression).
 *
 * Close is not trapped, so the table of emulated sockets retires an entry
 * lazily: whoever next finds one whose descriptor no longer names its socket
 * gives it back and may take it. Found, judged and claimed as three separate
 * steps, an entry could be judged from one occupant and claimed from the
 * next: another thread had retired it and put a new socket there in between,
 * and the claim — the same "live" state it had read — went through and
 * released that new, live socket, closing its pair peer. The socket's next
 * call then reached the host as an AF_UNIX one: bind() EINVAL. A lookup that
 * retired a stale entry with the number it was asked about also stopped
 * there, and a live socket that had been handed that number was taken for a
 * socket that was not emulated at all.
 *
 * Eight threads each open, bind, name and close sockets in a loop; every
 * bind must succeed and every name must be a netlink one ("bad" counts the
 * ones that were not). Emulated by force (CNG_NETLINK_FORCE_BLOCK). */
#include <linux/netlink.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define THREADS 8
#define ITERS   150

static pthread_barrier_t g_bar;
static int g_bad[THREADS];

static void *churn(void *arg) {
    int k = (int)(long)arg;
    pthread_barrier_wait(&g_bar);
    for (int i = 0; i < ITERS; i++) {
        int fd[3];
        for (int j = 0; j < 3; j++)
            fd[j] = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        for (int j = 0; j < 3; j++) {
            struct sockaddr_nl sa;
            memset(&sa, 0, sizeof sa);
            sa.nl_family = AF_NETLINK;
            socklen_t sl = sizeof sa;
            if (fd[j] < 0 || bind(fd[j], (struct sockaddr *)&sa, sizeof sa) != 0 ||
                getsockname(fd[j], (struct sockaddr *)&sa, &sl) != 0 ||
                sa.nl_family != AF_NETLINK)
                g_bad[k]++;
        }
        for (int j = 0; j < 3; j++)
            if (fd[j] >= 0)
                close(fd[j]);
    }
    return 0;
}

int main(void) {
    pthread_t t[THREADS];
    pthread_barrier_init(&g_bar, 0, THREADS);
    for (long k = 0; k < THREADS; k++)
        pthread_create(&t[k], 0, churn, (void *)k);
    int bad = 0;
    for (int k = 0; k < THREADS; k++) {
        pthread_join(t[k], 0);
        bad += g_bad[k];
    }
    printf("nlchurn: sockets=%d bad=%d\n", THREADS * ITERS * 3, bad);
    return 0;
}
