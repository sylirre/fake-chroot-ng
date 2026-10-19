/* The uid and gid setters without --fake-id (M84).
 *
 * The ids are then the host's, and so are the answers a kernel gives a process
 * with no capabilities whose real, effective and saved ids are all one: 0 for a
 * call that changes nothing, EPERM for one that would, EINVAL for an id of -1,
 * the current id from setfsuid and setfsgid, and EPERM from setgroups whatever
 * it is handed. That is an Android app's process, whose filter refuses every
 * setter but setresuid — they were all answered ENOSYS there, and under -R on
 * any host. A process the description does not fit says SKIP, since what a
 * kernel answers it differs.
 *
 * The last call is made with a second thread running, which libc turns into
 * the same call on every thread (the setxid broadcast); it fails as a whole if
 * any thread's does. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <unistd.h>

static void show(const char *name, long r) {
    if (r < 0)
        printf("%s=%ld errno=%d\n", name, r, errno);
    else
        printf("%s=%ld\n", name, r);
}

static void *idle(void *a) {
    pause();
    return a;
}

int main(void) {
    uid_t r, e, s;
    gid_t rg, eg, sg;
    unsigned cap[2] = {0x20080522u, 0}, data[6] = {0};
    if (getresuid(&r, &e, &s) || getresgid(&rg, &eg, &sg) ||
        syscall(SYS_capget, cap, data) != 0) {
        printf("SKIP: the ids cannot be read\n");
        return 0;
    }
    /* CAP_SETGID is bit 6, CAP_SETUID bit 7. */
    if ((data[0] & 0xc0) || r != e || e != s || rg != eg || eg != sg) {
        printf("SKIP: privileged, or ids that differ\n");
        return 0;
    }
    uid_t u = r, uo = r + 1;
    gid_t g = rg, go = rg + 1;
    show("setuid_self", setuid(u));
    show("setgid_self", setgid(g));
    show("setuid_other", setuid(uo));
    show("setgid_other", setgid(go));
    show("setuid_invalid", setuid((uid_t)-1));
    show("setgid_invalid", setgid((gid_t)-1));
    show("setreuid_keep", setreuid((uid_t)-1, (uid_t)-1));
    show("setreuid_self", setreuid(u, u));
    show("setregid_other", setregid(go, (gid_t)-1));
    show("setresuid_self", setresuid(u, -1, u));
    show("setresuid_other", setresuid(-1, -1, uo));
    show("setresgid_keep", setresgid(-1, -1, -1));
    show("setresgid_other", setresgid(g, go, g));
    printf("setfsuid_self=%d\n", setfsuid(u) == (int)u);
    printf("setfsuid_other=%d\n",
           setfsuid(uo) == (int)u && setfsuid((uid_t)-1) == (int)u);
    printf("setfsgid_other=%d\n",
           setfsgid(go) == (int)g && setfsgid((gid_t)-1) == (int)g);
    show("setgroups_none", setgroups(0, 0));
    uid_t r2, e2, s2;
    gid_t rg2, eg2, sg2;
    getresuid(&r2, &e2, &s2);
    getresgid(&rg2, &eg2, &sg2);
    printf("ids_kept=%d\n", r2 == r && e2 == e && s2 == s && rg2 == rg &&
                                eg2 == eg && sg2 == sg);
    pthread_t t;
    if (pthread_create(&t, 0, idle, 0) != 0) {
        printf("SKIP: no thread\n");
        return 0;
    }
    show("threads_setgid", setgid(g));
    show("threads_setuid", setuid(u));
    printf("done\n");
    return 0;
}
