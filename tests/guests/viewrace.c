/* Process-wide emulated state read while another thread changes it (M17).
 *
 * The kernel replaces a task's cwd, root and credentials as one object, so a
 * concurrent reader sees the old or the new. The emulation kept each as a
 * struct edited in place: a getcwd racing a chdir could copy out half of one
 * directory name and half of another, an open of a relative name resolve
 * against that, a getgroups read the new count with the old list. This guest
 * runs each pair for a while and counts every answer that was neither the old
 * state nor the new one.
 *
 *   viewrace cwd    two directories of very different name lengths, one
 *                   thread chdir'ing between them, one reading getcwd and
 *                   opening a relative name that exists in both
 *   viewrace groups (needs a fake identity) one thread alternating two group
 *                   lists of different lengths, one reading them back; and
 *                   setresuid/getresuid alternating two identities
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ROUNDS 20000

static const char *d_short = "/a";
static char d_long[128];
static volatile int stop;

static void *cwd_writer(void *arg) {
    (void)arg;
    void *res = 0;
    for (int i = 0; i < ROUNDS && !res; i++) {
        if (chdir(d_short) != 0 || chdir(d_long) != 0)
            res = (void *)1;
    }
    stop = 1;
    return res;
}

static int cwd_reader(void) {
    int bad = 0;
    char buf[4096];
    while (!stop) {
        if (!getcwd(buf, sizeof buf)) {
            bad++;
            continue;
        }
        if (strcmp(buf, d_short) != 0 && strcmp(buf, d_long) != 0)
            bad++;
        int fd = open("marker", O_RDONLY);
        if (fd < 0)
            bad++;
        else
            close(fd);
    }
    return bad;
}

static gid_t list_a[8] = {11, 12, 13, 14, 15, 16, 17, 18};
static gid_t list_b[3] = {21, 22, 23};

/* The identities alternate between (0,0,0) and (1000,1000,0): the saved
 * uid stays 0 so the unprivileged half can come back. */
static void *grp_writer(void *arg) {
    (void)arg;
    void *res = 0;
    for (int i = 0; i < ROUNDS && !res; i++) {
        if (setgroups(8, list_a) != 0 || setresuid(1000, 1000, 0) != 0 ||
            setresuid(0, 0, 0) != 0 || setgroups(3, list_b) != 0)
            res = (void *)1;
    }
    stop = 1;
    return res;
}

static int grp_reader(void) {
    int bad = 0;
    gid_t got[64];
    while (!stop) {
        int n = getgroups(64, got);
        if (n == 8) {
            if (memcmp(got, list_a, sizeof list_a) != 0)
                bad++;
        } else if (n == 3) {
            if (memcmp(got, list_b, sizeof list_b) != 0)
                bad++;
        } else {
            bad++;
        }
        uid_t r, e, s;
        if (getresuid(&r, &e, &s) != 0 || s != 0 || r != e ||
            (r != 0 && r != 1000))
            bad++;
    }
    return bad;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: viewrace cwd|groups\n");
        return 2;
    }
    pthread_t t;
    int bad;
    void *wres = 0;
    if (argv[1][0] == 'c') {
        memset(d_long, 'b', 100);
        d_long[0] = '/';
        d_long[100] = 0;
        mkdir(d_short, 0755);
        mkdir(d_long, 0755);
        char m[160];
        snprintf(m, sizeof m, "%s/marker", d_short);
        close(open(m, O_WRONLY | O_CREAT, 0644));
        snprintf(m, sizeof m, "%s/marker", d_long);
        close(open(m, O_WRONLY | O_CREAT, 0644));
        if (chdir(d_short) != 0) {
            printf("viewrace: setup failed\n");
            return 1;
        }
        pthread_create(&t, 0, cwd_writer, 0);
        bad = cwd_reader();
    } else {
        if (setgroups(3, list_b) != 0) {
            printf("viewrace: no fake identity\n");
            return 1;
        }
        pthread_create(&t, 0, grp_writer, 0);
        bad = grp_reader();
    }
    pthread_join(t, &wres);
    printf("viewrace %s: writer=%s torn=%d\n", argv[1], wres ? "failed" : "ok",
           bad);
    return 0;
}
