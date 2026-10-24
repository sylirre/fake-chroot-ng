/* The termios2 ioctls -- TCGETS2 0x802c542a, TCSETS2 0x402c542b, TCSETSW2
 * 0x402c542c, TCSETSF2 0x402c542d (src/monitor/tty.c), self-checking.
 *
 * They carry a 44-byte struct termios2: the 36-byte termios plus c_ispeed and
 * c_ospeed, the way a terminal is given a rate no Bnnn constant names. A glibc
 * since 2.42 builds tcgetattr -- and so isatty -- on them, which is how its
 * guest learns it has a terminal at all. Android's SELinux policy whitelists
 * the ioctls an app may issue on its pty and these are not on the list: the
 * host answers EACCES, on a terminal and on a pipe alike, so such a guest took
 * its terminal for none (bash printed no prompt). The monitor serves them from
 * TCGETS/TCSETS when the host will not, and the answers must be a kernel's
 * whichever way they were reached: this runs over the host as it is and over
 * CNG_TERMIOS2_DENY=1, which refuses them before the host is asked.
 *
 * What is asked, over a real pty: the whole struct comes back and not a byte
 * past it (a canary after it), the first 36 bytes of it are what TCGETS
 * reports, each of the three setters carries all 44 bytes in (c_ospeed
 * included, a different rate each: a copy that stopped at 36 would leave it 0)
 * and the next TCGETS2 returns the rate and the VMIN/VTIME it was given, an
 * unmapped buffer is EFAULT both ways, and a descriptor that is no tty is
 * ENOTTY: a pipe, to a getter and to a setter, and a directory. Android 15's
 * policy refuses the classic setters on a pipe and TCGETS too on a directory,
 * so the answer has to come from somewhere else there.
 *
 * The master's termios is the slave's, so a rate set through one end is read
 * back through the other and through the same end (a BOTHER rate that a host
 * cannot hold is kept per terminal by the monitor, which has to know the two
 * ends for one).
 *
 * The rates are arbitrary numbers (BOTHER) where the host's classic termios
 * can hold the marker in c_cflag, which a kernel does and qemu-user does not:
 * its translation table has no entry for it and answers B0. There the rows
 * are made with the Bnnn constants instead, and print the same.
 *
 * The expected output is what this program prints built for a native host and
 * run on a real kernel. A host that cannot give it a pty steps aside with a
 * lone SKIP line.
 */
#define _XOPEN_SOURCE 600
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define T_GETS   0x5401UL
#define T_SETS   0x5402UL
#define T_GETS2  0x802c542aUL
#define T_SETS2  0x402c542bUL
#define T_SETSW2 0x402c542cUL
#define T_SETSF2 0x402c542dUL
#define T_CBAUD  0x100fU /* the rate field of c_cflag */
#define T_BOTHER 0x1000U /* ... holding "the rate is in c_ospeed" */

struct t2 { /* kernel struct termios2 */
    unsigned c_iflag, c_oflag, c_cflag, c_lflag;
    unsigned char c_line, c_cc[19];
    unsigned c_ispeed, c_ospeed;
};

/* A termios2 with 8 bytes after it that nothing may write. */
struct guarded {
    struct t2 t;
    unsigned char tail[8];
};

static void poison(struct guarded *g) {
    memset(&g->t, 0xa5, sizeof g->t);
    memset(g->tail, 0x5a, sizeof g->tail);
}

static int tail_ok(const struct guarded *g) {
    for (unsigned i = 0; i < sizeof g->tail; i++)
        if (g->tail[i] != 0x5a)
            return 0;
    return 1;
}

/* Does the host's classic termios hold the BOTHER marker? */
static int holds_bother(int s) {
    struct t2 t;
    memset(&t, 0, sizeof t);
    if (ioctl(s, T_GETS, &t) != 0)
        return 0;
    t.c_cflag = (t.c_cflag & ~T_CBAUD) | T_BOTHER;
    if (ioctl(s, T_SETS, &t) != 0)
        return 0;
    memset(&t, 0, sizeof t);
    return ioctl(s, T_GETS, &t) == 0 && (t.c_cflag & T_CBAUD) == T_BOTHER;
}

static int bother; /* rates are arbitrary numbers, not Bnnn constants */

/* The nth row's rate: BOTHER with a number of its own, or a constant. */
static void pick(unsigned n, unsigned *cbaud, unsigned *speed) {
    static const unsigned num[] = {123456, 230400, 345678, 56789};
    static const unsigned cb[] = {0x1002 /*B115200*/, 0x1003 /*B230400*/,
                                  0x1004 /*B460800*/, 0x1001 /*B57600*/};
    static const unsigned val[] = {115200, 230400, 460800, 57600};
    *cbaud = bother ? T_BOTHER : cb[n];
    *speed = bother ? num[n] : val[n];
}

/* One setter on `s`, then the read-back, through `rd`, that must be what it was given. */
static void set_and_check(const char *name, unsigned long cmd, int s, int rd,
                          struct guarded *g, unsigned n, unsigned vmin,
                          unsigned vtime) {
    unsigned cbaud, speed;
    pick(n, &cbaud, &speed);
    g->t.c_cflag = (g->t.c_cflag & ~T_CBAUD) | cbaud;
    g->t.c_ispeed = speed; /* the kernel makes the input rate follow */
    g->t.c_ospeed = speed; /* the output one unless CIBAUD says else */
    g->t.c_cc[6] = (unsigned char)vmin;  /* VMIN */
    g->t.c_cc[5] = (unsigned char)vtime; /* VTIME */
    errno = 0;
    int r = ioctl(s, cmd, &g->t);
    int e = r < 0 ? errno : 0;
    struct guarded b;
    poison(&b);
    int r2 = ioctl(rd, T_GETS2, &b.t);
    int same = r2 == 0 && tail_ok(&b) && b.t.c_ospeed == speed &&
               b.t.c_cc[6] == vmin && b.t.c_cc[5] == vtime &&
               (b.t.c_cflag & T_CBAUD) == cbaud;
    printf("%s=%d errno=%d readback=%d\n", name, r, e, same);
}

int main(void) {
    /* No grantpt: devpts hands the slave to the opener, and a libc that does
     * more (glibc looks up the "tty" group) asks a rootfs for files it need
     * not have. */
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

    bother = holds_bother(s);

    struct guarded g;
    poison(&g);
    errno = 0;
    int r = ioctl(s, T_GETS2, &g.t);
    int e = r < 0 ? errno : 0;
    /* Every byte of the struct is written, the speeds (offsets 36..43) too. */
    int whole = r == 0 && g.t.c_ispeed != 0xa5a5a5a5u &&
                g.t.c_ospeed != 0xa5a5a5a5u && g.t.c_line != 0xa5;

    unsigned char old[36 + 8];
    memset(old, 0x5a, sizeof old);
    int r1 = ioctl(s, T_GETS, old);
    int prefix = r == 0 && r1 == 0 && memcmp(old, &g.t, 36) == 0;
    printf("get2=%d errno=%d whole=%d tail=%d prefix=%d\n", r, e, whole,
           tail_ok(&g), prefix);
    if (r < 0)
        return 0;

    set_and_check("set2", T_SETS2, s, s, &g, 0, 7, 3);
    set_and_check("setsw2", T_SETSW2, s, s, &g, 1, 5, 2);
    set_and_check("setsf2", T_SETSF2, s, s, &g, 2, 9, 4);

    /* A pty's master and slave are one termios: set through the master, read
     * through the slave and through the master itself. */
    set_and_check("master_set2", T_SETS2, m, s, &g, 3, 6, 1);
    struct guarded mb;
    poison(&mb);
    r = ioctl(m, T_GETS2, &mb.t);
    unsigned mcb, mspeed;
    pick(3, &mcb, &mspeed);
    printf("master_get2=%d speed=%d\n", r,
           r == 0 && mb.t.c_ospeed == mspeed && tail_ok(&mb));

    errno = 0;
    r = ioctl(s, T_GETS2, (void *)0);
    printf("get2_fault=%d errno=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = ioctl(s, T_SETS2, (void *)0);
    printf("set2_fault=%d errno=%d\n", r, r < 0 ? errno : 0);

    int p[2];
    if (pipe(p))
        return 1;
    errno = 0;
    r = ioctl(p[0], T_GETS2, &g.t);
    printf("pipe=%d errno=%d\n", r, r < 0 ? errno : 0);
    errno = 0;
    r = ioctl(p[0], T_SETS2, &g.t);
    printf("pipe_set2=%d errno=%d\n", r, r < 0 ? errno : 0);

    int d = open("/", O_RDONLY);
    errno = 0;
    r = ioctl(d, T_GETS2, &g.t);
    printf("dir=%d errno=%d\n", r, r < 0 ? errno : 0);

    puts("done");
    return 0;
}
