/* TCSETSF 0x5404 -- tcsetattr(TCSAFLUSH) -- self-checking.
 *
 * The setter every password prompt makes: the change, after the input already
 * typed is thrown away. Android 8's SELinux policy lets an app issue TCSETS,
 * TCSETSW and TCFLSH on its pty and refuses this one with EACCES, so a guest's
 * getpass met the refusal, and so did the TCSETSF2 that the monitor serves
 * from it where termios2 is refused too (src/monitor/tty.c). The monitor
 * serves it from TCFLSH and TCSETSW when the host will not, and the answers
 * must be a kernel's either way: this runs over the host as it is and over
 * CNG_TCSETSF_DENY=1, which refuses it before the host is asked.
 *
 * What is asked, over a real pty: a line waiting on the slave is gone after a
 * TCSETSF and the change has been made (VMIN/VTIME read back), the same line
 * survives a TCSETSW (so the first answer is the flush, not the line never
 * having arrived), an unmapped termios is EFAULT, and a pipe and a directory
 * are ENOTTY. Android 15's policy refuses TCSETSF and the pair alike on both
 * (EACCES) and TCGETS too on the directory, so those two are where a native
 * run there is no oracle.
 *
 * The termios is the kernel's 36-byte one, set by the raw command, so no libc
 * gets to choose the command for it. The expected output is what this program
 * prints run natively on a real kernel. A host that cannot give it a pty steps
 * aside with a lone SKIP line.
 */
#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define T_GETS  0x5401UL
#define T_SETSW 0x5403UL
#define T_SETSF 0x5404UL

struct kt { /* kernel struct termios */
    unsigned c_iflag, c_oflag, c_cflag, c_lflag;
    unsigned char c_line, c_cc[19];
};

/* Type a line into the slave through the master and wait until the slave has
 * it: the pty hands input over from a work queue, so a flush made straight
 * after the write could run ahead of it and prove nothing. */
static int typed(int m, int s) {
    if (write(m, "typed\n", 6) != 6)
        return 0;
    struct pollfd p = {s, POLLIN, 0};
    return poll(&p, 1, 5000) == 1;
}

/* What is left to read on the slave: the byte count, or -errno. */
static int pending(int s) {
    char buf[64];
    int fl = fcntl(s, F_GETFL);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
    errno = 0;
    int n = (int)read(s, buf, sizeof buf);
    int e = errno;
    fcntl(s, F_SETFL, fl);
    return n >= 0 ? n : -e;
}

int main(void) {
    /* No grantpt, as in termios2.c: devpts hands the slave to the opener. */
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || unlockpt(m) != 0) {
        puts("SKIP: no pty");
        return 0;
    }
    char *sn = ptsname(m);
    int s = sn ? open(sn, O_RDWR | O_NOCTTY) : -1;
    if (s < 0) {
        puts("SKIP: no pty");
        return 0;
    }

    struct kt t;
    memset(&t, 0, sizeof t);
    if (ioctl(s, T_GETS, &t) != 0) {
        puts("SKIP: no TCGETS");
        return 0;
    }
    /* Canonical, so a whole line is what becomes readable; no echo, so the
     * master's side stays empty. */
    t.c_lflag = (t.c_lflag | 0000002 /*ICANON*/) & ~0000010u /*ECHO*/;
    ioctl(s, T_SETSW, &t);

    int in = typed(m, s);
    t.c_cc[6] = 3; /* VMIN */
    t.c_cc[5] = 7; /* VTIME */
    errno = 0;
    int r = ioctl(s, T_SETSF, &t);
    int e = r < 0 ? errno : 0;
    struct kt b;
    memset(&b, 0, sizeof b);
    int back = ioctl(s, T_GETS, &b) == 0 && b.c_cc[6] == 3 && b.c_cc[5] == 7;
    printf("setsf=%d errno=%d readback=%d typed=%d left=%d\n", r, e, back, in,
           pending(s));

    in = typed(m, s);
    r = ioctl(s, T_SETSW, &t);
    printf("setsw=%d typed=%d left=%d\n", r, in, pending(s));

    errno = 0;
    r = ioctl(s, T_SETSF, (void *)0);
    printf("setsf_fault=%d errno=%d\n", r, r < 0 ? errno : 0);

    int p[2];
    if (pipe(p))
        return 1;
    errno = 0;
    r = ioctl(p[0], T_SETSF, &t);
    printf("pipe=%d errno=%d\n", r, r < 0 ? errno : 0);

    int d = open("/", O_RDONLY);
    errno = 0;
    r = ioctl(d, T_SETSF, &t);
    printf("dir=%d errno=%d\n", r, r < 0 ? errno : 0);

    puts("done");
    return 0;
}
