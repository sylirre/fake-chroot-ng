/* TIOCGSID 0x5429 (tcgetsid(3)): the session a terminal belongs to,
 * self-checking.
 *
 * tcgetsid is what login, script and agetty ask. Android's SELinux policy
 * whitelists the ioctls an app may issue on its pty and this one is not on the
 * list: the host answers EACCES on a pty slave and on a pipe (the ptmx master
 * it lets through), where a kernel answers the session -- or ENOTTY, for a
 * slave the caller does not control, a master whose slave has no session, and
 * a descriptor that is no terminal. The monitor serves it from the commands the
 * policy allows (src/monitor/tty.c); the answers must be the kernel's whichever
 * way they were reached, so this runs over the host as it is and over
 * CNG_TIOCGSID_DENY=1, which refuses it before the host is asked.
 *
 * What is asked, over a real pty: before anything controls it, the slave and
 * the master are ENOTTY (no session); a child that setsid()s and takes the pty
 * as its controlling terminal reads the slave's session and the master's, both
 * its own pid, and a null buffer is EFAULT; the parent reads the master's
 * session too (the child's pid -- a master answers whoever asks) and still gets
 * ENOTTY of the slave it does not control; once the session leader has exited,
 * which takes the terminal from the session, the master is ENOTTY again; and a
 * pipe, /dev/null and a directory are ENOTTY and a closed descriptor EBADF.
 * The pipe and the directory are where a host that refuses the ioctl differs
 * from a kernel (EACCES against ENOTTY; Android 15's refuses even TCGETS on
 * the directory), so a native run on such a host is no oracle for them; the
 * expected text is a kernel's.
 *
 * One more case, on a pty of its own: the foreground group's leader has gone
 * (reaped) and the group lives on in a member, so the master's answer cannot
 * come from getsid of the group and has to be found among the members.
 *
 * A host that refuses to hand a pty to a new session steps aside with a lone
 * SKIP line.
 *
 * `tiocgsid probe` asks the host's own TIOCGSID and nothing else, to be run
 * outside the monitor, and prints one word: "works" (the session, the right
 * one), "refused" (an error -- EACCES under Android's policy), "broken"
 * (success, and no session written: qemu-user's ioctl table lists the request
 * as input only) or "nopty". The harness reads it to know whether the host
 * can be the oracle for the unforced rows.
 */
#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define T_SCTTY 0x540eUL
#define T_GSID  0x5429UL

/* What the child saw, sent to the parent over a pipe. */
struct kid {
    int ctty, ctty_errno;               /* TIOCSCTTY on the slave */
    int slave, slave_own;               /* TIOCGSID(slave), == its pid */
    int slave_fault, slave_fault_errno; /* ... into a null buffer */
    int master, master_own;             /* TIOCGSID(master), == its pid */
};

static int gsid(int fd, int *sid) {
    errno = 0;
    int r = ioctl(fd, T_GSID, sid);
    return r < 0 ? -errno : 0;
}

static void row(const char *name, int fd) {
    int sid = -77;
    int e = gsid(fd, &sid);
    printf("%s=%d errno=%d\n", name, e ? -1 : 0, -e);
}

/* A pty: no grantpt, as devpts hands the slave to the opener and a libc that
 * does more (glibc looks up the "tty" group) asks a rootfs for files it need
 * not have. */
static int open_pty(int *m, int *s) {
    *m = posix_openpt(O_RDWR | O_NOCTTY);
    if (*m < 0 || unlockpt(*m) != 0)
        return -1;
    char *sn = ptsname(*m);
    *s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    return *s < 0 ? -1 : 0;
}

/* The host's own answer, from a session leader that controls the pty. */
static int probe(void) {
    int m, s, st = 0;
    if (open_pty(&m, &s)) {
        puts("nopty");
        return 0;
    }
    pid_t kid = fork();
    if (kid < 0)
        return 1;
    if (kid == 0) {
        int sid = -1;
        setsid();
        if (ioctl(s, T_SCTTY, 0) != 0)
            _exit(4);
        int r = ioctl(s, T_GSID, &sid);
        _exit(r < 0 ? 2 : sid == getpid() ? 0 : 3);
    }
    waitpid(kid, &st, 0);
    int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    puts(code == 0 ? "works" : code == 2 ? "refused" : code == 3 ? "broken" : "nopty");
    return 0;
}

#define T_SPGRP 0x5410UL

/* The session of a foreground group whose leader is gone. K is the session
 * leader and controls the pty; C starts a group, leaves D in it and exits, K
 * reaps C and makes the group the pty's foreground one. The master is then
 * asked by the parent and must say K. */
static void orphan_group(void) {
    int m, s, up[2], hold[2];
    if (open_pty(&m, &s) || pipe(up) || pipe(hold)) {
        puts("master_orphan=-1 sess=0");
        return;
    }
    fflush(stdout);
    pid_t k = fork();
    if (k < 0)
        return;
    if (k == 0) {
        char b;
        setsid();
        if (ioctl(s, T_SCTTY, 0) != 0)
            _exit(1);
        pid_t c = fork();
        if (c == 0) {
            setpgid(0, 0);
            if (fork() == 0) { /* D: stays in C's group until released */
                (void)!read(hold[0], &b, 1);
                _exit(0);
            }
            _exit(0);
        }
        waitpid(c, NULL, 0);
        int pg = (int)c;
        int r = ioctl(s, T_SPGRP, &pg);
        (void)!write(up[1], r == 0 ? "y" : "n", 1);
        (void)!read(hold[0], &b, 1);
        _exit(0);
    }
    char ok = 0;
    int sid = -1;
    int got = read(up[0], &ok, 1) == 1 && ok == 'y';
    int e = got ? gsid(m, &sid) : -1;
    printf("master_orphan=%d sess=%d\n", e ? -1 : 0, e == 0 && sid == (int)k);
    (void)!write(hold[1], "xx", 2);
    waitpid(k, NULL, 0);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "probe"))
        return probe();
    int m, s;
    if (open_pty(&m, &s)) {
        puts("SKIP: no pty");
        return 0;
    }
    int p[2], up[2], down[2];
    if (pipe(p) || pipe(up) || pipe(down))
        return 1;
    int nul = open("/dev/null", O_RDWR);
    int dir = open("/", O_RDONLY);
    int closed = dup(p[0]);
    close(closed);

    /* No session yet: nobody controls the slave, and the master has none to
     * answer for. */
    row("slave_nosess", s);
    row("master_nosess", m);
    fflush(stdout); /* the child must not inherit it */

    pid_t kid = fork();
    if (kid < 0)
        return 1;
    if (kid == 0) {
        struct kid k;
        int sid = -1;
        memset(&k, 0, sizeof k);
        setsid();
        errno = 0;
        k.ctty = ioctl(s, T_SCTTY, 0);
        k.ctty_errno = k.ctty < 0 ? errno : 0;
        if (k.ctty == 0) {
            k.slave = gsid(s, &sid) == 0;
            k.slave_own = sid == getpid();
            k.slave_fault_errno = -gsid(s, (int *)0);
            k.slave_fault = k.slave_fault_errno ? -1 : 0;
            sid = -1;
            k.master = gsid(m, &sid) == 0;
            k.master_own = sid == getpid();
        }
        if (write(up[1], &k, sizeof k) != sizeof k)
            _exit(1);
        char go;
        if (read(down[0], &go, 1) != 1)
            _exit(1);
        _exit(0); /* the session leader's exit */
    }

    struct kid k;
    memset(&k, 0, sizeof k);
    int got = read(up[0], &k, sizeof k) == sizeof k;
    int skip = !got || k.ctty != 0;
    int sid = -1;
    if (skip) {
        if (got && k.ctty_errno != 0)
            printf("SKIP: the host refuses TIOCSCTTY on a pty (errno %d)\n",
                   k.ctty_errno);
        else
            puts("SKIP: the child did not report");
        (void)!write(down[1], "x", 1);
        waitpid(kid, NULL, 0);
        return 0;
    }

    /* The terminal is the child's now: the rows that need none, then the rows
     * about the child's own session, then the leader's exit. */
    row("slave_foreign", s);
    printf("slave_ctl=%d own=%d\n", k.slave ? 0 : -1, k.slave_own);
    printf("slave_fault=%d errno=%d\n", k.slave_fault, k.slave_fault_errno);
    printf("master_ctl=%d own=%d\n", k.master ? 0 : -1, k.master_own);
    int e = gsid(m, &sid);
    printf("master_parent=%d kid=%d\n", e ? -1 : 0, e == 0 && sid == (int)kid);
    (void)!write(down[1], "x", 1);
    waitpid(kid, NULL, 0);
    row("master_gone", m);
    row("pipe", p[0]);
    row("null", nul);
    row("dir", dir);
    row("closed", closed);
    orphan_group();
    puts("done");
    return 0;
}
