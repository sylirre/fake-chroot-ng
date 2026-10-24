/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Terminal ioctls an Android app is refused, served from the ones it is not
 * (see include/cng/tty.h). Freestanding: raw syscalls and the runtime helpers
 * only, as it runs inside the SIGSYS handler -- and on the guest's own stack
 * with every signal masked, so every guest address goes through
 * cng_user_copyin/copyout rather than being touched.
 *
 * ---- termios2: TCGETS2 / TCSETS2 / TCSETSW2 / TCSETSF2 ----
 *
 * 44 bytes: the 36-byte termios plus c_ispeed and c_ospeed (2 u32). A glibc
 * since 2.42 implements tcgetattr/tcsetattr -- and so isatty -- on these,
 * which is how a guest learns whether it has a terminal.
 *
 * Android's SELinux policy whitelists the ioctls an app may issue on its pty
 * and TCGETS2 is not among them: the host answers EACCES, on a terminal and
 * on a pipe alike. isatty(0) was then false for the guest, so bash (Ubuntu
 * 26.04, glibc 2.43) ran non-interactively on a terminal and printed no
 * prompt, and readline's tcsetattr would have been refused the same way. A
 * host kernel that predates the commands (ENOTTY on a tty) is in the same
 * position.
 *
 * Both are served from the classic commands, which every host answers: the
 * termios is the first 36 bytes either way, and what the classic struct
 * leaves out are the rates, which c_cflag already holds -- as a Bnnn constant
 * in CBAUD (output) and CIBAUD (input; 0 = "as the output"), or BOTHER, "the
 * number is in c_ospeed / c_ispeed". A Bnnn is read back from the constant;
 * a BOTHER number cannot be held by a termios that has no field for it, so
 * the last one set is kept per terminal (tc_shadow below) while c_cflag keeps
 * the BOTHER marker in the host's own termios, where every reader sees it.
 * The kernel's own termios2 reads the speeds back from the tty the same way
 * for a tty that is not a serial port: they are only ever what was last set.
 *
 * Tried on the host first, so a host that does implement termios2 serves them
 * itself; the first refusal that the classic command then proves to be about
 * termios2 (it worked on the same descriptor) is remembered, and the
 * remaining calls go straight to the fallback instead of being denied -- and
 * logged by the policy -- every time. CNG_TERMIOS2_DENY=1 forces the tier on
 * any host.
 *
 * ---- TCSETSF: tcsetattr(TCSAFLUSH) ----
 *
 * The one classic setter an older policy leaves off the list: Android 8's
 * lets TCSETS, TCSETSW and TCFLSH through on a pty and refuses TCSETSF
 * (measured on a 3.18 device), which every password prompt asks for -- and
 * which TCSETSF2 above falls back to. The kernel's TCSETSF is TCSETSW's wait
 * for the output to drain, then an input flush, then the change; on a pty
 * slave, the only terminal such a policy is about, there is no output queue
 * to wait for, and it is served as TCFLSH(TCIFLUSH) and then TCSETSW, on a
 * descriptor that TCGETS has shown to be a terminal (see the end). The host
 * is asked first, and the refusal remembered once the pair has proved it is
 * about TCSETSF; CNG_TCSETSF_DENY=1 forces the tier on any host.
 *
 * ---- TIOCGSID: the session a terminal belongs to ----
 *
 * tcgetsid(3), which login, script and agetty ask. Android's SELinux policy
 * whitelists a pty's ioctls and TIOCGSID is not on the list for a slave or a
 * pipe (the ptmx master it lets through): EACCES, where a kernel answers the
 * session, or ENOTTY for a descriptor that is no terminal of the caller's.
 * The host is asked first; on that refusal it is served from the commands
 * that are allowed -- TCGETS to know a terminal from a pipe (ENOTTY, as a
 * kernel says; see the end), TIOCGPGRP for the kernel's own reach check (a
 * slave answers only the process whose controlling terminal it is, a master
 * always: ENOTTY otherwise) -- and the session is then worked out the way the
 * kernel holds it:
 *   - a slave the caller controls belongs to the caller's session: getsid(0).
 *     A terminal is a session's only while it is that session's controlling
 *     terminal, and a process controls it only from inside that session;
 *   - a master answers for its slave, the session of its foreground group (a
 *     slave nobody controls has no group, and no session: ENOTTY).
 * The ids are the host's, as getsid(2) and TIOCGPGRP report them -- there is
 * no pid namespace here. As with termios2 above, the first refusal that the
 * allowed commands prove to be about TIOCGSID is remembered, and
 * CNG_TIOCGSID_DENY=1 forces the tier on any host.
 *
 * ---- A descriptor that is no terminal ----
 *
 * A kernel answers each of these ENOTTY on a descriptor that is no terminal,
 * before it looks at the pointer, and every fallback above asks TCGETS first
 * to tell (tc_probe): the command that serves the refused one may be refused
 * there as well, by the same policy. Android 15's lets TCGETS alone through on
 * a pipe or a socket (ENOTTY), where it refuses TCSETS, TCSETSW, TCSETSF and
 * TCFLSH, and refuses every terminal command on a directory, a named FIFO or a
 * /proc file, TCGETS included (all measured). Only a character device can be
 * a terminal, so a refused TCGETS on anything else is a kernel's ENOTTY too; a
 * character device the policy will not ask keeps the refusal.
 */
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/tty.h"
#include "cng/uapi.h"

#include <asm-generic/errno.h>

int cng_g_termios2_deny = 0;
int cng_g_tiocgsid_deny = 0;
int cng_g_tcsetsf_deny = 0;

#define TC_GETS    0x5401u
#define TC_SETS    0x5402u
#define TC_SETSW   0x5403u
#define TC_SETSF   0x5404u
#define TC_FLSH    0x540bu
#define TC_IFLUSH  0      /* TCFLSH's TCIFLUSH */
#define TC_GETS2   0x802c542au
#define TC_SETS2   0x402c542bu
#define TC_SETSW2  0x402c542cu
#define TC_SETSF2  0x402c542du
#define TC_CBAUD   0x100fu /* c_cflag's output-rate field */
#define TC_BOTHER  0x1000u /* ... holding "the rate is in c_ospeed" */
#define TC_IBSHIFT 16      /* the input-rate field is CBAUD << this */
#define TC_GPGRP   0x540fu
#define TC_GSID    0x5429u
#define TC_TIOCGPTN 0x80045430u
#define TC_TERMIOS_SZ  36  /* kernel struct termios: 4 u32 + c_line + c_cc[19] */
#define TC_TERMIOS2_SZ 44  /* kernel struct termios2: termios + c_ispeed + c_ospeed */
#define TC_CFLAG_OFF   8

const unsigned cng_ioctl_tty[] = {
    TC_GETS2,
    TC_SETS2,
    TC_SETSW2,
    TC_SETSF2,
    TC_GSID,
    TC_SETSF,
};
const int cng_ioctl_tty_n =
    (int)(sizeof cng_ioctl_tty / sizeof cng_ioctl_tty[0]);

int cng_tty_request(unsigned req) {
    for (int i = 0; i < cng_ioctl_tty_n; i++)
        if (req == cng_ioctl_tty[i])
            return 1;
    return 0;
}

/* The rate each Bnnn names: B0..B38400 are 0..15, B57600..B4000000 0x1001..0x100f. */
static const u32 tc_rate_lo[16] = {0,    50,   75,   110,  134,  150,
                                   200,  300,  600,  1200, 1800, 2400,
                                   4800, 9600, 19200, 38400};
static const u32 tc_rate_hi[15] = {57600,   115200,  230400,  460800,  500000,
                                   576000,  921600,  1000000, 1152000, 1500000,
                                   2000000, 2500000, 3000000, 3500000, 4000000};

/* A rate field's number; `held` is the one kept for BOTHER. */
static u32 tc_rate(u32 field, u32 held) {
    if (field == TC_BOTHER)
        return held;
    return (field & TC_BOTHER) ? tc_rate_hi[(field & 0xf) - 1]
                               : tc_rate_lo[field];
}

/* The BOTHER numbers last set, per terminal: a few slots, replaced round
 * robin. Lock-free on purpose (a lock held across fork() would be inherited
 * held by the child, and the handler may be re-entered by a guest signal):
 * `speeds` is written before `key`, and a reader that lands between two
 * writers of the same terminal gets one of the two pairs. Per host process --
 * an emulated execve keeps it, a fork's child starts with a copy -- so a
 * BOTHER set by some other process is not known here and reads as 38400. */
typedef struct {
    u64 key, speeds;
} TcShadow;
static TcShadow tc_shadow[8];
static unsigned tc_shadow_next;

/* What an AArch64 struct stat holds (see dispatch.c): st_mode at 16, st_rdev
 * at 32, the kernel's 32-bit device encoding. */
#define ST_MODE_OFF 16
#define ST_RDEV_OFF 32

static unsigned tc_major(u64 rd) { return (unsigned)((rd >> 8) & 0xfff); }
static unsigned tc_minor(u64 rd) {
    return (unsigned)((rd & 0xff) | ((rd >> 12) & 0xfff00));
}

/* /dev/ptmx, whichever devpts mounts it: a pty's master end. */
static int tc_is_ptmx(u64 rd) { return tc_major(rd) == 5 && tc_minor(rd) == 2; }

/* Which terminal a descriptor is: the slave's device number, which the master
 * ptmx's termios is too (it talks to its slave's). Bit 63 keeps it nonzero. */
static u64 tc_key(int fd) {
    char st[144];
    if (sys_fstat(fd, st) != 0 ||
        (*(unsigned *)(st + ST_MODE_OFF) & 0170000) != 0020000)
        return 1;
    u64 rd = *(u64 *)(st + ST_RDEV_OFF);
    int n;
    if (tc_is_ptmx(rd) && sys_ioctl(fd, TC_TIOCGPTN, &n) == 0 && n >= 0) {
        unsigned maj = 136 + (unsigned)n / 256, min = (unsigned)n % 256;
        rd = (min & 0xff) | ((u64)maj << 8); /* UNIX98_PTY_SLAVE_MAJOR */
    }
    return rd | (1ull << 63);
}

/* TCGETS into t: whether fd is a terminal at all, the policy's refusal of
 * TCGETS on what cannot be one taken for the kernel's ENOTTY (see the top). */
static long tc_probe(int fd, void *t) {
    long r = sys_ioctl(fd, TC_GETS, t);
    char st[144];
    if (r == -EACCES && sys_fstat(fd, st) == 0 &&
        (*(unsigned *)(st + ST_MODE_OFF) & 0170000) != 0020000)
        return -ENOTTY;
    return r;
}

static int tc_shadow_get(u64 key, u32 *ispeed, u32 *ospeed) {
    for (unsigned i = 0; i < sizeof tc_shadow / sizeof tc_shadow[0]; i++) {
        if (__atomic_load_n(&tc_shadow[i].key, __ATOMIC_ACQUIRE) != key)
            continue;
        u64 v = __atomic_load_n(&tc_shadow[i].speeds, __ATOMIC_RELAXED);
        *ispeed = (u32)(v >> 32);
        *ospeed = (u32)v;
        return 1;
    }
    return 0;
}

static void tc_shadow_put(u64 key, u32 ispeed, u32 ospeed) {
    unsigned n = sizeof tc_shadow / sizeof tc_shadow[0], slot = n;
    for (unsigned i = 0; i < n; i++)
        if (__atomic_load_n(&tc_shadow[i].key, __ATOMIC_RELAXED) == key) {
            slot = i;
            break;
        }
    if (slot == n)
        slot = __atomic_fetch_add(&tc_shadow_next, 1, __ATOMIC_RELAXED) % n;
    __atomic_store_n(&tc_shadow[slot].speeds, (u64)ispeed << 32 | ospeed,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&tc_shadow[slot].key, key, __ATOMIC_RELEASE);
}

/* Set once the host refused TCSETSF where the pair answering for it was not
 * refused: the host is not asked again. */
static int tcsf_host_lacks;

static int tcsf_refused(void) {
    return cng_g_tcsetsf_deny ||
           __atomic_load_n(&tcsf_host_lacks, __ATOMIC_RELAXED);
}

/* TCSETSF without TCSETSF, from a termios in our own memory, on a terminal. */
static long tc_flush_set(int fd, void *t) {
    long r = sys_ioctl(fd, TC_FLSH, (void *)TC_IFLUSH);
    if (r == 0)
        r = sys_ioctl(fd, TC_SETSW, t);
    if (r == 0)
        __atomic_store_n(&tcsf_host_lacks, 1, __ATOMIC_RELAXED);
    return r;
}

/* TCSETSF from our own memory: the host's, or the pair where it refuses. */
static long tc_setsf(int fd, void *t) {
    long r = tcsf_refused() ? -EACCES : sys_ioctl(fd, TC_SETSF, t);
    return r == -EACCES ? tc_flush_set(fd, t) : r;
}

/* The guest's own TCSETSF: the host handed the guest's pointer, as termios2's
 * are, so an unmapped one is the kernel's EFAULT; on the refusal, a terminal's
 * termios is copied in and set by the pair. */
static long tty_setsf(long fd, long argp) {
    long r = tcsf_refused() ? -EACCES
                            : CNG_SYS(__NR_ioctl, fd, TC_SETSF, argp, 0, 0, 0);
    if (r != -EACCES)
        return r;
    u8 buf[TC_TERMIOS_SZ];
    r = tc_probe((int)fd, buf);
    if (r < 0)
        return r;
    if (cng_user_copyin(buf, (const void *)argp, sizeof buf) < 0)
        return -EFAULT;
    return tc_flush_set((int)fd, buf);
}

/* Set once the host refused a termios2 command that the classic one answering
 * for it was not refused (so the refusal was about termios2): the host is not
 * asked again. */
static int tc2_host_lacks;

static long tty_termios2(long fd, unsigned req, long argp) {
    /* The host's own answer, handed the guest's pointer as it stands -- the
     * kernel does the copy, and says EFAULT itself -- or the refusal when the
     * tier is forced or already proven. */
    long r = cng_g_termios2_deny ||
                     __atomic_load_n(&tc2_host_lacks, __ATOMIC_RELAXED)
                 ? -EACCES
                 : CNG_SYS(__NR_ioctl, fd, req, argp, 0, 0, 0);
    if (r != -EACCES && r != -ENOTTY)
        return r;

    /* Not served by the host: the classic command answers for it, on a
     * terminal -- TCGETS first, which a getter's answer is, and a setter's
     * ENOTTY before its pointer is looked at. Zeroed first: only what is
     * written is copied out. */
    u8 buf[TC_TERMIOS2_SZ];
    memset(buf, 0, sizeof buf);
    r = tc_probe((int)fd, buf);
    if (r < 0)
        return r;
    int set = req != TC_GETS2;
    if (set && cng_user_copyin(buf, (const void *)argp, sizeof buf) < 0)
        return -EFAULT;
    u32 cflag, ispeed = 0, ospeed = 0;
    u64 key = 0;
    if (!set) {
        memcpy(&cflag, buf + TC_CFLAG_OFF, 4);
        u32 ib = (cflag >> TC_IBSHIFT) & TC_CBAUD, ob = cflag & TC_CBAUD;
        u32 hi = 38400, ho = 38400; /* a BOTHER nobody told us the number of */
        if ((ob == TC_BOTHER || ib == TC_BOTHER) && (key = tc_key((int)fd)))
            tc_shadow_get(key, &hi, &ho);
        ospeed = tc_rate(ob, ho);
        ispeed = ib ? tc_rate(ib, hi) : ospeed;
        memcpy(buf + TC_TERMIOS_SZ, &ispeed, 4);
        memcpy(buf + TC_TERMIOS_SZ + 4, &ospeed, 4);
    } else {
        memcpy(&cflag, buf + TC_CFLAG_OFF, 4);
        memcpy(&ispeed, buf + TC_TERMIOS_SZ, 4);
        memcpy(&ospeed, buf + TC_TERMIOS_SZ + 4, 4);
        unsigned hcmd = TC_SETS + (req - TC_SETS2); /* TCSETS, TCSETSW, TCSETSF */
        r = hcmd == TC_SETSF ? tc_setsf((int)fd, buf)
                             : sys_ioctl((int)fd, hcmd, buf);
        if (r < 0)
            return r;
        if (((cflag & TC_CBAUD) == TC_BOTHER ||
             ((cflag >> TC_IBSHIFT) & TC_CBAUD) == TC_BOTHER) &&
            (key = tc_key((int)fd)))
            tc_shadow_put(key, ispeed, ospeed);
    }
    __atomic_store_n(&tc2_host_lacks, 1, __ATOMIC_RELAXED);
    if (!set && cng_user_copyout((void *)argp, buf, sizeof buf) < 0)
        return -EFAULT;
    return 0;
}

/* Fields of /proc/<pid>/stat after the command name, as proc(5) numbers
 * them from 3: state, ppid, pgrp, session. */
static int stat_ids(long dfd, int pid, char *state, int *pgrp, int *sess) {
    char path[32], b[512];
    cng_snprintf(path, sizeof path, "%d/stat", pid);
    long fd = sys_openat((int)dfd, path, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    long r = sys_read((int)fd, b, sizeof b - 1);
    sys_close((int)fd);
    if (r <= 0)
        return 0;
    b[r] = '\0';
    char *p = strrchr(b, ')');
    if (!p)
        return 0;
    p++;
    while (*p == ' ')
        p++;
    *state = *p++;
    long v[3];
    for (int i = 0; i < 3; i++) {
        while (*p == ' ')
            p++;
        int neg = *p == '-', nd = 0;
        long x = 0;
        p += neg;
        for (; *p >= '0' && *p <= '9'; p++, nd++)
            x = x * 10 + (*p - '0');
        if (!nd)
            return 0;
        v[i] = neg ? -x : x;
    }
    *pgrp = (int)v[1];
    *sess = (int)v[2];
    return 1;
}

/* The session of process group `pg`, or -1 if no process of it can be found.
 * getsid(pg) answers while the group's leader is there -- as a zombie too --
 * but a group outlives its leader, and then one of its members' /proc stat
 * says (a member the host's /proc will not show cannot be found). The members
 * are read relative to a directory descriptor on /proc: under qemu-user an
 * absolute spelling of the caller's own stat is a synthesized copy, and the
 * relative form is never intercepted (see procreg.c). */
static int pgrp_session(int pg) {
    if (pg <= 0)
        return -1;
    long s = CNG_SYS(__NR_getsid, pg, 0, 0, 0, 0, 0);
    if (s >= 0)
        return (int)s;
    if (s != -ESRCH)
        return -1;
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return -1;
    int found = -1;
    char buf[1024];
    for (long n; found < 0 &&
                 (n = CNG_SYS(__NR_getdents64, dfd, buf, sizeof buf, 0, 0, 0)) > 0;) {
        /* linux_dirent64: d_ino(8) d_off(8) d_reclen(2 @16) d_type(1) name(@19) */
        for (long o = 0; found < 0 && o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen < 20 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            o += reclen;
            int pid = 0, nd = 0;
            for (; *nm >= '0' && *nm <= '9' && nd < 9; nm++, nd++)
                pid = pid * 10 + (*nm - '0');
            if (!nd || *nm)
                continue;
            char st;
            int pgr, se;
            if (stat_ids(dfd, pid, &st, &pgr, &se) && pgr == pg && st != 'X')
                found = se;
        }
    }
    sys_close((int)dfd);
    return found;
}

/* Set once the host refused TIOCGSID where the allowed commands answered. */
static int tsid_host_lacks;

static long tty_tiocgsid(long fd, long argp) {
    long r = cng_g_tiocgsid_deny ||
                     __atomic_load_n(&tsid_host_lacks, __ATOMIC_RELAXED)
                 ? -EACCES
                 : CNG_SYS(__NR_ioctl, fd, TC_GSID, argp, 0, 0, 0);
    if (r != -EACCES)
        return r;

    u8 probe[TC_TERMIOS_SZ];
    char st[144];
    s32 pg = 0, sid;
    r = tc_probe((int)fd, probe); /* no terminal */
    if (r < 0)
        return r;
    r = sys_ioctl((int)fd, TC_GPGRP, &pg); /* not the caller's */
    if (r < 0)
        return r;
    if (sys_fstat((int)fd, st) == 0 &&
        (*(unsigned *)(st + ST_MODE_OFF) & 0170000) == 0020000 &&
        tc_is_ptmx(*(u64 *)(st + ST_RDEV_OFF))) {
        if (pg <= 0 || (sid = pgrp_session(pg)) < 0)
            return -ENOTTY;
    } else {
        r = CNG_SYS(__NR_getsid, 0, 0, 0, 0, 0, 0);
        if (r < 0)
            return r;
        sid = (s32)r;
    }
    __atomic_store_n(&tsid_host_lacks, 1, __ATOMIC_RELAXED);
    if (cng_user_copyout((void *)argp, &sid, sizeof sid) < 0)
        return -EFAULT;
    return 0;
}

long cng_tty_ioctl(long fd, unsigned req, long argp) {
    if (req == TC_GSID)
        return tty_tiocgsid(fd, argp);
    if (req == TC_SETSF)
        return tty_setsf(fd, argp);
    return tty_termios2(fd, req, argp);
}
