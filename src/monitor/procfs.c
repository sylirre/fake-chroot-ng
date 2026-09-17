/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Synthesized /proc files (see include/cng/procfs.h). Freestanding: raw
 * syscalls, cng_dprintf for formatting, no allocator. Every entry point runs
 * inside the SIGSYS handler, so nothing here may block on a lock. */
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/procfs.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

/* aarch64 struct stat / statfs field offsets (stable syscall ABI). */
#define STAT_DEV_OFF   0
#define STAT_INO_OFF   8
#define STATFS_TYPE_OFF 0

/* Which file a synthesized fd holds. */
enum {
    PF_CMDLINE = 1, PF_ENVIRON, PF_AUXV, PF_MAPS,
    PF_MOUNTS, PF_MOUNTINFO, PF_MOUNTSTATS,
    PF_LOADAVG, PF_UPTIME, PF_STAT, PF_STATUS, PF_VERSION,
};

/* put_mounts rendering. */
enum { MNT_MOUNTS = 0, MNT_MOUNTINFO = 1, MNT_MOUNTSTATS = 2 };

int cng_g_synth_fd_base = 0;

/* ---- small freestanding helpers ---------------------------------------- */

static unsigned long dev_major(unsigned long dev) {
    return ((dev >> 8) & 0xfffu) | ((dev >> 32) & ~0xfffuL);
}
static unsigned long dev_minor(unsigned long dev) {
    return (dev & 0xffu) | ((dev >> 12) & ~0xffuL);
}

/* Parse a decimal run at *p, advancing it. */
static unsigned long parse_ul(const char **p) {
    unsigned long v = 0;
    while (**p >= '0' && **p <= '9') {
        v = v * 10 + (unsigned long)(**p - '0');
        (*p)++;
    }
    return v;
}
static void skip_ws(const char **p) {
    while (**p == ' ' || **p == '\t')
        (*p)++;
}

/* Buffered line reader over a host file: enough to walk status/maps without an
 * allocator. Returns a NUL-terminated line (newline stripped) or NULL at EOF.
 * A line longer than the buffer is still delivered in pieces — the line buffer
 * holds the longest maps line the kernel can produce for a path we could
 * render, so that is unreachable in practice — and lrd_whole() tells a caller
 * that re-parses what it reads whether it is looking at one. */
struct lrd {
    int fd;
    unsigned pos, len;
    int eof;
    int cut;  /* the chunk just returned was ended by the buffer, not a newline */
    int cont; /* ...and this one continues it */
    char buf[4096];
    char line[CNG_PATH_MAX + 256]; /* pathname column plus the five fixed ones */
};

static void lrd_init(struct lrd *r, int fd) {
    r->fd = fd;
    r->pos = r->len = 0;
    r->eof = 0;
    r->cut = r->cont = 0;
}

static const char *lrd_next(struct lrd *r) {
    unsigned n = 0;
    r->cont = r->cut;
    r->cut = 0;
    for (;;) {
        if (r->pos == r->len) {
            if (r->eof)
                break;
            long got = sys_read(r->fd, r->buf, sizeof r->buf);
            if (got <= 0) {
                r->eof = 1;
                break;
            }
            r->pos = 0;
            r->len = (unsigned)got;
        }
        char c = r->buf[r->pos++];
        if (c == '\n')
            break;
        if (n < sizeof r->line - 1)
            r->line[n++] = c;
        if (n == sizeof r->line - 1) {
            r->cut = 1;
            break; /* over-long line: hand back what we have */
        }
    }
    if (!n && r->eof && r->pos == r->len)
        return 0;
    r->line[n] = '\0';
    return r->line;
}

/* Whether the chunk just returned is a line in its own right, rather than one
 * piece of an over-long one. */
static int lrd_whole(const struct lrd *r) {
    return !r->cut && !r->cont;
}

/* The host path behind a canonical guest /proc path (identity under the
 * passthrough, the bind target when the user redirected /proc). */
static int host_of(const char *canon, char *out, size_t sz) {
    return cng_fs_translate(cng_g_fs, canon, out, sz) == 0 ? 0 : -1;
}

static long open_host_ro(const char *host) {
    return sys_openat(CNG_AT_FDCWD, host, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
}

/* ---- mounts / mountinfo / mountstats ------------------------------------ */

/* Guest fstype of the rootfs: host statfs magic -> name, "ext4" fallback. */
static const char *rootfs_fstype(const char *root) {
    static const struct {
        unsigned long magic;
        const char *name;
    } tab[] = {
        {0xEF53, "ext4"},       {0x9123683E, "btrfs"}, {0x58465342, "xfs"},
        {0xF2F52010, "f2fs"},   {0x01021994, "tmpfs"}, {0x794C7630, "overlay"},
        {0x65735546, "fuse"},   {0x4D44, "vfat"},
    };
    char sf[128];
    if (sys_statfs(root, sf) == 0) {
        unsigned long ty = *(unsigned long *)(sf + STATFS_TYPE_OFF);
        for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
            if (ty == tab[i].magic)
                return tab[i].name;
    }
    return "ext4";
}

/* The one device name the guest is ever shown. A real mount table names a
 * *device* (or a pseudo-filesystem) as the source of every row — /proc/mounts
 * has nothing else, and mountinfo puts the source filesystem in field 10 and the
 * subtree it was bound from in field 4 — so this is both the faithful rendering
 * and the one that says nothing about the host. A bind's rows used to carry
 * cng_g_fs->binds[i].host there: the directory on the device the rootfs was
 * assembled from, spelled out in a file that `df`, `mount`, findmnt and every
 * container runtime read, in a namespace whose whole purpose is that the guest
 * cannot name a host path. The rootfs row has always been "/dev/root"; the binds
 * are rows of the same invented device now, which is a shape real tables have
 * (several mounts off one device name) and no shape a tool can trip over. The
 * per-bind major:minor is still the real one, so anything cross-referencing
 * stat().st_dev — which is what actually identifies a filesystem — still finds
 * its row. */
#define MNT_DEV "/dev/root"

/* A mount table escapes the four characters that would otherwise make its
 * whitespace-separated fields ambiguous — space, tab, newline, and the
 * backslash that spells them — as octal, which is what fs/proc_namespace.c does
 * for every path and every device name it prints (mangle(), and seq_path with
 * " \t\n\\"). Every other field in these tables is a constant of ours; a bind's
 * guest mount point is the one a caller chooses, and `-b /data/rootfs:/mnt/my
 * disk` put a raw space in the middle of the row. Everything that reads these
 * files splits on whitespace — libmount, busybox df and mount, findmnt,
 * /proc/mounts parsers of every kind — so the row named a mount point nobody
 * asked for and gave the next field, the filesystem type, to whatever followed
 * the space. Returns `out`, and stops rather than truncating a multi-byte
 * escape. */
static const char *mnt_esc(const char *p, char *out, size_t sz) {
    size_t o = 0;
    for (; *p; p++) {
        const char *e = 0;
        switch (*p) {
        case ' ':
            e = "\\040";
            break;
        case '\t':
            e = "\\011";
            break;
        case '\n':
            e = "\\012";
            break;
        case '\\':
            e = "\\134";
            break;
        }
        size_t k = e ? 4 : 1;
        if (o + k >= sz)
            break;
        if (e)
            memcpy(out + o, e, 4);
        else
            out[o] = *p;
        o += k;
    }
    out[o] = '\0';
    return out;
}

/* The guest mount table: the rootfs, the /proc and /dev passthrough zones, and
 * one row per -b bind. Mount IDs are handed out by a running counter because the
 * zone rows are conditional (--no-proc / --no-dev), so a bind's id depends on
 * what precedes it. The root's major:minor is real, so tools cross-referencing
 * stat().st_dev find it. */
static void put_mounts(int fd, int fmt) {
    /* A snapshot of the view: the table is emitted to the file as it is
     * walked, and a chroot on another thread replaces the view whole while a
     * reader may still be looking at the old one — a snapshot taken under the
     * view's protocol is emitted from start to end as one thing. */
    static struct cng_bind binds[CNG_MAX_BINDS];
    static long snap_owner;
    char rootbuf[CNG_PATH_MAX];
    int nb;
    /* The snapshot is static (50 KiB, more than a stack here should carry)
     * and so is taken one reader at a time. */
    long me = sys_gettid();
    for (int spin = 0;; spin++) {
        long none = 0;
        if (__atomic_compare_exchange_n(&snap_owner, &none, me, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            break;
        /* A holder that is gone (killed by an exec's de_thread mid-snapshot,
         * or the thread a fork child inherited it from) is taken over. */
        if (spin > 100 && none &&
            CNG_SYS(__NR_tgkill, sys_getpid(), none, 0, 0, 0, 0) == -ESRCH)
            __atomic_compare_exchange_n(&snap_owner, &none, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
        CNG_SYS(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    const struct cng_fs *v;
    do {
        unsigned seq = cng_fs_read_begin(&v);
        cng_strlcpy(rootbuf, v->rootfs, sizeof rootbuf);
        nb = v->nbinds;
        for (int i = 0; i < nb; i++)
            binds[i] = v->binds[i];
        if (!cng_fs_read_retry(seq))
            break;
    } while (1);
    const char *root = rootbuf[0] ? rootbuf : "/";
    const char *fstype = rootfs_fstype(root);
    unsigned long maj = 0, min = 0;
    char st[128];
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, root, st, 0, 0, 0) == 0) {
        unsigned long dev = *(unsigned long *)(st + STAT_DEV_OFF);
        maj = dev_major(dev);
        min = dev_minor(dev);
    }
    /* Room for the worst case: a guest path of nothing but characters that
     * escape to four bytes each. */
    char esc[4 * CNG_PATH_MAX];
    int proc_row = !cng_g_no_proc;
    int dev_row = !cng_g_no_dev;
    /* ...and the tmpfs at /dev/shm only where the guest actually has one. The
     * row was unconditional, so on Android — which has no /dev/shm at all and
     * where the stand-in under $TMPDIR may not have been available either — the
     * mount table announced a filesystem that every open under it then answered
     * ENOENT for. A mount table is something programs test before they act. */
    int shm_row = dev_row && cng_dev_shm_ok();
    int id = 2; /* 1 is the root */

    if (fmt == MNT_MOUNTINFO) {
        cng_dprintf(fd, "1 1 %lu:%lu / / rw,relatime - %s " MNT_DEV " rw\n",
                    maj, min, fstype);
        if (proc_row)
            cng_dprintf(fd, "%d 1 0:5 / /proc rw,nosuid,nodev,noexec,relatime - "
                            "proc proc rw\n", id++);
        if (dev_row) {
            cng_dprintf(fd, "%d 1 0:6 / /dev rw,nosuid,relatime - devtmpfs "
                            "devtmpfs rw\n", id++);
            cng_dprintf(fd, "%d 1 0:7 / /dev/pts rw,nosuid,noexec,relatime - "
                            "devpts devpts rw\n", id++);
            if (shm_row)
                cng_dprintf(fd, "%d 1 0:8 / /dev/shm rw,nosuid,nodev,relatime - "
                                "tmpfs tmpfs rw\n", id++);
        }
        for (int i = 0; i < nb; i++) {
            unsigned long bmaj = maj, bmin = min;
            char bst[128];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, binds[i].host,
                        bst, 0, 0, 0) == 0) {
                unsigned long d = *(unsigned long *)(bst + STAT_DEV_OFF);
                bmaj = dev_major(d);
                bmin = dev_minor(d);
            }
            const char *rw = binds[i].ro ? "ro" : "rw";
            cng_dprintf(fd, "%d 1 %lu:%lu / %s %s,relatime - %s " MNT_DEV " %s\n",
                        id++, bmaj, bmin,
                        mnt_esc(binds[i].guest, esc, sizeof esc), rw,
                        fstype, rw);
        }
    } else if (fmt == MNT_MOUNTSTATS) {
        /* No NFS per-op stats: every mount here is a local filesystem. */
        cng_dprintf(fd, "device " MNT_DEV " mounted on / with fstype %s\n",
                    fstype);
        if (proc_row)
            cng_dprintf(fd, "device proc mounted on /proc with fstype proc\n");
        if (dev_row) {
            cng_dprintf(fd,
                        "device devtmpfs mounted on /dev with fstype devtmpfs\n");
            cng_dprintf(
                fd, "device devpts mounted on /dev/pts with fstype devpts\n");
            if (shm_row)
                cng_dprintf(
                    fd, "device tmpfs mounted on /dev/shm with fstype tmpfs\n");
        }
        for (int i = 0; i < nb; i++)
            cng_dprintf(fd, "device " MNT_DEV " mounted on %s with fstype %s\n",
                        mnt_esc(binds[i].guest, esc, sizeof esc),
                        fstype);
    } else {
        cng_dprintf(fd, MNT_DEV " / %s rw,relatime 0 0\n", fstype);
        if (proc_row)
            cng_dprintf(fd,
                        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        if (dev_row) {
            cng_dprintf(fd, "devtmpfs /dev devtmpfs rw,nosuid,relatime 0 0\n");
            cng_dprintf(
                fd, "devpts /dev/pts devpts rw,nosuid,noexec,relatime 0 0\n");
            if (shm_row)
                cng_dprintf(fd,
                            "tmpfs /dev/shm tmpfs rw,nosuid,nodev,relatime 0 0\n");
        }
        for (int i = 0; i < nb; i++)
            cng_dprintf(fd, MNT_DEV " %s %s %s,relatime 0 0\n",
                        mnt_esc(binds[i].guest, esc, sizeof esc),
                        fstype, binds[i].ro ? "ro" : "rw");
    }
    __atomic_store_n(&snap_owner, 0, __ATOMIC_RELEASE);
}

/* ---- loadavg / uptime / stat -------------------------------------------- */

/* Try-host-first gate for /proc/stat: 1 when the host denies the file (Android
 * SELinux) or CNG_PROCSTAT_SYNTH forces the fallback in tests. Probed once. */
int cng_g_procstat_synth = 0;
static int stat_blocked(void) {
    static int blocked = -1;
    if (blocked < 0) {
        if (cng_g_procstat_synth) {
            blocked = 1;
        } else {
            long fd = open_host_ro("/proc/stat");
            blocked = fd < 0;
            if (fd >= 0)
                sys_close((int)fd);
        }
    }
    return blocked;
}

static unsigned long stat_ncpu(void) {
    unsigned long mask[16];
    long r = CNG_SYS(__NR_sched_getaffinity, 0, sizeof mask, mask, 0, 0, 0);
    if (r <= 0)
        return 1;
    unsigned long n = 0;
    for (unsigned long i = 0; i < (unsigned long)r / sizeof mask[0]; i++) {
        /* Kernighan's, not __builtin_popcountl: the builtin compiles either to
         * `cnt v0.8b` — a vector register the guest still owns on the -R tier,
         * see -mgeneral-regs-only in the Makefile — or to a libgcc helper a
         * -nostdlib link cannot resolve. One iteration per set bit, and the bits
         * here are CPUs. */
        for (unsigned long m = mask[i]; m; m &= m - 1)
            n++;
    }
    return n ? n : 1;
}

static void put_loadavg(int fd) {
    struct cng_sysinfo si;
    unsigned long l[3] = {0, 0, 0};
    unsigned nproc = 1;
    if (sys_sysinfo(&si) == 0) {
        for (int i = 0; i < 3; i++)
            l[i] = si.loads[i];
        nproc = si.procs ? si.procs : 1;
    }
    /* loads are fixed-point, scaled by 1 << SI_LOAD_SHIFT. nr_running and the
     * last-allocated pid are unknowable without /proc/stat (which Android
     * denies too): claim 1 running (the reader is) and our own pid — put_stat's
     * procs_running/processes fabrications agree with these. */
    cng_dprintf(fd, "%lu.%02lu %lu.%02lu %lu.%02lu 1/%u %d\n",
                l[0] >> CNG_SI_LOAD_SHIFT, (l[0] & 0xFFFF) * 100 / 65536,
                l[1] >> CNG_SI_LOAD_SHIFT, (l[1] & 0xFFFF) * 100 / 65536,
                l[2] >> CNG_SI_LOAD_SHIFT, (l[2] & 0xFFFF) * 100 / 65536, nproc,
                (int)sys_getpid());
}

/* CPU-time estimate for the synthesized /proc/stat, in USER_HZ = 100 jiffies:
 * the real split is unknowable without the host file, so busy time is the
 * integral of the sysinfo() load average over wall time (seeded from the
 * 15-minute average, advanced by the 1-minute average, capped at ncpu) and idle
 * is the remainder. Increments are >= 0, so the counters stay monotonic — what
 * delta-computing readers (top, vmstat) require. */
static unsigned long g_stat_busy;
static unsigned long g_stat_last_ns;

static void stat_estimate(unsigned long ncpu, unsigned long *busy_j,
                          unsigned long *idle_j) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_BOOTTIME, &ts);
    unsigned long now = (unsigned long)ts.tv_sec * 1000000000uL +
                        (unsigned long)ts.tv_nsec;
    unsigned long up_j =
        (unsigned long)ts.tv_sec * 100 + (unsigned long)ts.tv_nsec / 10000000;
    unsigned long l1 = 0, l15 = 0; /* << 16 fixed point */
    struct cng_sysinfo si;
    if (sys_sysinfo(&si) == 0) {
        l1 = si.loads[0];
        l15 = si.loads[2];
    }
    unsigned long cap = ncpu << CNG_SI_LOAD_SHIFT;
    if (l1 > cap)
        l1 = cap;
    if (l15 > cap)
        l15 = cap;
    if (!g_stat_last_ns)
        g_stat_busy = up_j * l15 >> CNG_SI_LOAD_SHIFT;
    else if (now > g_stat_last_ns)
        g_stat_busy += (now - g_stat_last_ns) / 10000000 * l1 >> CNG_SI_LOAD_SHIFT;
    g_stat_last_ns = now;
    unsigned long busy = g_stat_busy;
    unsigned long total = up_j * ncpu;
    if (busy > total)
        busy = total;
    *busy_j = busy;
    *idle_j = total - busy;
}

/* Idle jiffies summed across CPUs (field 4 of the host /proc/stat aggregate
 * line); 0 when the file is unreadable, so uptime and the synthesized stat
 * report the same idle time. */
static int host_stat_idle(unsigned long *idle_j) {
    if (stat_blocked())
        return 0;
    long fd = open_host_ro("/proc/stat");
    if (fd < 0)
        return 0;
    char buf[256];
    long n = sys_read((int)fd, buf, sizeof buf - 1);
    sys_close((int)fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    if (strncmp(buf, "cpu ", 4) != 0)
        return 0;
    const char *p = buf + 4;
    for (int i = 0; i < 3; i++) { /* user, nice, system */
        skip_ws(&p);
        parse_ul(&p);
    }
    skip_ws(&p);
    if (*p < '0' || *p > '9')
        return 0;
    *idle_j = parse_ul(&p);
    return 1;
}

/* Uptime from CLOCK_BOOTTIME (counts suspend, like the real file). */
static void put_uptime(int fd) {
    struct cng_timespec ts = {0, 0};
    if (sys_clock_gettime(CNG_CLOCK_BOOTTIME, &ts) != 0) {
        struct cng_sysinfo si;
        if (sys_sysinfo(&si) == 0)
            ts.tv_sec = si.uptime;
    }
    unsigned long busy_j, idle_j = 0;
    if (!host_stat_idle(&idle_j))
        stat_estimate(stat_ncpu(), &busy_j, &idle_j);
    cng_dprintf(fd, "%lu.%02lu %lu.%02lu\n", (unsigned long)ts.tv_sec,
                (unsigned long)ts.tv_nsec / 10000000, idle_j / 100,
                idle_j % 100);
}

/* /proc/version, in the kernel's own format. It exists only to agree with what
 * uname(2) reports (dispatch.c): faking the syscall and letting the host file
 * through would leave the two contradicting each other, and distro install
 * scripts read whichever one they were written against. */
static void put_version(int fd) {
    cng_dprintf(fd, "Linux version %s (chroot-ng@localhost) (chroot-ng) %s\n",
                CNG_KREL, CNG_KVER);
}

/* The guest /proc/stat where the host's is unreadable (see stat_blocked). CPU
 * time comes from stat_estimate, all attributed to user; intr and ctxt are
 * honest zeros; btime is exact; processes/procs_running match put_loadavg. */
static void put_stat(int fd) {
    unsigned long ncpu = stat_ncpu(), busy_j, idle_j;
    stat_estimate(ncpu, &busy_j, &idle_j);
    cng_dprintf(fd, "cpu  %lu 0 0 %lu 0 0 0 0 0 0\n", busy_j, idle_j);
    for (unsigned long i = 0; i < ncpu; i++)
        cng_dprintf(fd, "cpu%lu %lu 0 0 %lu 0 0 0 0 0 0\n", i, busy_j / ncpu,
                    idle_j / ncpu);
    struct cng_timespec up = {0, 0}, now = {0, 0};
    sys_clock_gettime(CNG_CLOCK_BOOTTIME, &up);
    sys_clock_gettime(CNG_CLOCK_REALTIME, &now);
    cng_dprintf(fd,
                "intr 0\nctxt 0\nbtime %ld\nprocesses %d\n"
                "procs_running 1\nprocs_blocked 0\n"
                "softirq 0 0 0 0 0 0 0 0 0 0 0\n",
                now.tv_sec - up.tv_sec, (int)sys_getpid());
}

/* ---- status (fake-id remap) --------------------------------------------- */

/* Copy the host status through, rewriting the Uid:/Gid:/Groups: lines to the
 * identity the guest has, so ps/top resolve the fake identity's user (they read
 * the Uid: line, which otherwise carries our real host uid). Returns 0, or -1 if
 * the host file cannot be read (caller falls back to passthrough).
 *
 * `self` picks where that identity comes from. For this process it is the live
 * set in cng_g_cred — the one every credential syscall reads and writes, and the
 * one getresuid/getresgid/getgroups answer from. Remapping the host's numbers
 * instead described the identity the process STARTED with: a guest that dropped
 * privilege was still Uid: 0 here while `id` said otherwise, and its Groups:
 * line was the invoking user's supplementary groups, which getgroups() has never
 * reported (the synthetic set starts empty). One process cannot have two
 * answers; the kernel reads both out of the same struct cred.
 *
 * Another guest process is a different matter: its set is its own copy, forked
 * for real and changed since, and nothing publishes it. There the host line
 * remapped is the closest thing available — that process's startup identity,
 * which is right until it changes its own credentials. */
static int put_status(int fd, const char *host, int self) {
    long hf = open_host_ro(host);
    if (hf < 0)
        return -1;
    struct lrd r; /* 8.5 KiB — the dispatcher runs on its own 256 KiB stack */
    lrd_init(&r, (int)hf);
    const char *line;
    while ((line = lrd_next(&r)) != 0) {
        int is_uid = !strncmp(line, "Uid:", 4);
        if (is_uid || !strncmp(line, "Gid:", 4)) {
            if (self) {
                const struct cng_cred *c;
                unsigned id[4];
                do {
                    unsigned s = cng_cred_read_begin(&c);
                    id[0] = is_uid ? c->ruid : c->rgid;
                    id[1] = is_uid ? c->euid : c->egid;
                    id[2] = is_uid ? c->suid : c->sgid;
                    id[3] = is_uid ? c->fsuid : c->fsgid;
                    if (!cng_cred_read_retry(s))
                        break;
                } while (1);
                cng_dprintf(fd, "%s\t%u\t%u\t%u\t%u\n", is_uid ? "Uid:" : "Gid:",
                            id[0], id[1], id[2], id[3]);
                continue;
            }
            const char *p = line + 4;
            unsigned id[4];
            int got = 0;
            while (got < 4) {
                skip_ws(&p);
                if (*p < '0' || *p > '9')
                    break;
                id[got++] = (unsigned)parse_ul(&p);
            }
            if (got == 4) {
                for (int i = 0; i < 4; i++)
                    id[i] = is_uid ? cng_remap_uid(id[i]) : cng_remap_gid(id[i]);
                cng_dprintf(fd, "%s\t%u\t%u\t%u\t%u\n", is_uid ? "Uid:" : "Gid:",
                            id[0], id[1], id[2], id[3]);
                continue;
            }
        } else if (!strncmp(line, "Groups:", 7)) {
            /* The kernel's own spelling: a tab after the keyword, single spaces
             * between the ids, and a trailing space after the last one — see the
             * "Trailing space shouldn't have been added in the first place"
             * comment in fs/proc/array.c, which is why it is still there. This
             * used to print a leading space and no tab, so the line did not read
             * like the one every other status file has. Measured on the host. */
            cng_dprintf(fd, "Groups:\t");
            if (self) {
                /* The count and the list as one thing: a setgroups on another
                 * thread publishes a whole new set, never edits this one. */
                unsigned got[CNG_NGROUPS_MAX];
                int n;
                const struct cng_cred *c;
                do {
                    unsigned s = cng_cred_read_begin(&c);
                    n = c->ngroups;
                    for (int i = 0; i < n; i++)
                        got[i] = c->groups[i];
                    if (!cng_cred_read_retry(s))
                        break;
                } while (1);
                for (int i = 0; i < n; i++)
                    cng_dprintf(fd, "%u ", got[i]);
            } else {
                const char *p = line + 7;
                for (;;) {
                    skip_ws(&p);
                    if (*p < '0' || *p > '9')
                        break;
                    cng_dprintf(fd, "%u ", cng_remap_gid((unsigned)parse_ul(&p)));
                }
            }
            cng_dprintf(fd, "\n");
            continue;
        }
        cng_dprintf(fd, "%s\n", line);
    }
    sys_close((int)hf);
    return 0;
}

/* ---- maps ---------------------------------------------------------------- */

/* The guest's mappings ARE this process's mappings — addresses, protections,
 * device and inode are all true — so unlike the emulator this is a rewrite, not
 * a fabrication: a file-backed line naming a path inside the guest view has
 * that path translated back to its guest spelling, a line naming a host path
 * outside the view (chroot-ng's own text and data, our memfds) is dropped
 * because it is not part of the guest's image, and anonymous lines — including
 * every segment our loader mapped, plus [heap]/[stack]/[vdso] — pass through
 * unchanged. Returns 0, or -1 if the host file cannot be read. */
static int put_maps(int fd, const char *host) {
    long hf = open_host_ro(host);
    if (hf < 0)
        return -1;
    struct lrd r;
    lrd_init(&r, (int)hf);
    const char *line;
    while ((line = lrd_next(&r)) != 0) {
        /* Every other caller of lrd only matches a leading keyword or copies
         * the line through; this one re-parses it, so a piece of an over-long
         * line must not reach the scan below. Only the first piece carries the
         * five fixed fields, so the rest is bare path characters: the scan runs
         * to the terminator, comes up short of five fields, and the "no
         * pathname column" branch prints the raw host path — the one thing this
         * function exists to prevent. There is nothing faithful to emit for a
         * line we could not read whole, so drop it, as an untranslatable path
         * is dropped below. */
        if (!lrd_whole(&r))
            continue;
        /* The pathname column starts at the first '/' or '[' after the five
         * fixed fields; everything before it is copied verbatim. */
        const char *p = line;
        int field = 0;
        while (*p && field < 5) {
            while (*p && *p != ' ')
                p++;
            while (*p == ' ')
                p++;
            field++;
        }
        if (!*p) { /* anonymous mapping: no pathname column */
            cng_dprintf(fd, "%s\n", line);
            continue;
        }
        if (*p != '/') { /* [heap], [stack], [vdso], anon shmem, ... */
            cng_dprintf(fd, "%s\n", line);
            continue;
        }
        char guest[CNG_PATH_MAX];
        if (cng_fs_untranslate(cng_g_fs, p, guest, sizeof guest) != 0)
            continue; /* outside the guest view: not the guest's mapping */
        size_t head = (size_t)(p - line);
        char prefix[256];
        if (head >= sizeof prefix)
            continue;
        memcpy(prefix, line, head);
        prefix[head] = '\0';
        cng_dprintf(fd, "%s%s\n", prefix, guest);
    }
    sys_close((int)hf);
    return 0;
}

/* ---- synthesized fd bookkeeping ----------------------------------------- */

/* Time-varying files are regenerated when a read starts at offset 0. The
 * memfd's identity is recorded so a stale entry (an fd number reused after a
 * close we never saw — we do not trap close) is detected and dropped rather
 * than clobbering an innocent file. The identity is the (device, inode) pair
 * (cng_fdid): the inode number alone was what this kept, and an inode number
 * is per filesystem — a guest file with the memfd's number, moved onto the
 * memfd's old descriptor number, passed as the memfd and was truncated and
 * rewritten with /proc/stat, through a description of our own opened for
 * writing on a file the guest may only have been able to read. */
static struct {
    int fd1; /* fd + 1, so a zeroed table means "all free"; claimed by CAS */
    int kind;
    struct cng_fdid id;
} g_pf[CNG_SYNTH_FD_SLOTS];

static void pf_track(int fd, int kind) {
    struct cng_fdid id;
    if (cng_fdid_of(fd, &id) != 0)
        return;
    for (int i = 0; i < CNG_SYNTH_FD_SLOTS; i++) {
        int expect = 0; /* free */
        if (__atomic_compare_exchange_n(&g_pf[i].fd1, &expect, fd + 1, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_pf[i].kind = kind;
            g_pf[i].id = id;
            return;
        }
        /* Reclaim a slot whose fd is gone or now names a different file (we do
         * not trap close, so entries are only ever retired lazily). */
        if (expect > 0 && !cng_fd_is(expect - 1, &g_pf[i].id) &&
            __atomic_compare_exchange_n(&g_pf[i].fd1, &expect, fd + 1, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_pf[i].kind = kind;
            g_pf[i].id = id;
            return;
        }
    }
    /* Table full: the fd simply keeps its open-time snapshot. */
}

/* A second description of the memfd behind `fd`, opened with `oflags` through
 * the fd's own magic link. The memfd is ours (0777, no seals), so the mode can
 * be anything: this is how the guest's read-only description is made from the
 * writable one memfd_create hands out, and how a writer is had again for a
 * refresh. -errno where the host will not (a /proc a policy keeps us out of,
 * an fd table that is full). */
static long synth_reopen(int fd, long oflags) {
    char link[40];
    cng_snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    return sys_openat(CNG_AT_FDCWD, link, oflags | CNG_O_CLOEXEC, 0);
}

static void regen(int fd, int kind, const struct cng_fdid *id) {
    /* The guest holds a read-only description, so the rewrite goes through a
     * writable one taken for the call. Where that cannot be had, the fd itself
     * is tried: it is writable exactly when the seal below could not be
     * applied, and the rewrite moves its offset, which the caller puts back.
     *
     * The reopen goes through the fd's magic link, which names whatever the
     * number is at that moment — the caller checked it a syscall ago, and the
     * number is in the guest's table. So what came back is checked against
     * the memfd's identity before a byte of it is truncated: a description
     * of something else is closed and left as it was. */
    long w = synth_reopen(fd, CNG_O_RDWR);
    if (w >= 0 && !cng_fd_is((int)w, id)) {
        sys_close((int)w);
        return;
    }
    int wfd = w >= 0 ? (int)w : fd;
    if ((w >= 0 || cng_fd_is(fd, id)) && sys_ftruncate(wfd, 0) == 0) {
        sys_lseek(wfd, 0, CNG_SEEK_SET);
        switch (kind) {
        case PF_LOADAVG:
            put_loadavg(wfd);
            break;
        case PF_UPTIME:
            put_uptime(wfd);
            break;
        case PF_STAT:
            put_stat(wfd);
            break;
        }
    }
    if (w >= 0)
        sys_close((int)w);
    else
        sys_lseek(fd, 0, CNG_SEEK_SET);
}

void cng_procfs_pre_read(int fd, long off) {
    if (fd < 0)
        return;
    for (int i = 0; i < CNG_SYNTH_FD_SLOTS; i++) {
        if (__atomic_load_n(&g_pf[i].fd1, __ATOMIC_ACQUIRE) != fd + 1)
            continue;
        if (!cng_fd_is(fd, &g_pf[i].id)) { /* stale: the fd was reused */
            __atomic_store_n(&g_pf[i].fd1, 0, __ATOMIC_RELEASE);
            return;
        }
        long cur = sys_lseek(fd, 0, CNG_SEEK_CUR);
        if (off < 0)
            off = cur;
        if (off != 0)
            return; /* mid-file: keep the current snapshot */
        regen(fd, g_pf[i].kind, &g_pf[i].id);
        /* pread(2) is defined never to move the file offset. The rewrite goes
         * through a description of its own and leaves the guest's where it
         * was — unless it had to write through the guest's own, which it then
         * rewinds — so put the position back either way: reached only for the
         * p-variants, since read()/readv() arrive here with an offset that
         * already is 0. Without this a sequential reader that pread's its own
         * held fd at offset 0 — one refresh idiom among several — silently
         * starts over from the top on its next read. (Measured: the kernel
         * leaves /proc/uptime's offset at 8 across a pread of the whole file.) */
        if (cur > 0)
            sys_lseek(fd, cur, CNG_SEEK_SET);
        return;
    }
}

/* Anonymous backing for a synthesized view, moved into the reserved high fd
 * range when the file needs refresh-on-rewind (that range is what the seccomp
 * filter traps the read family on). Returns the fd, or -1. Writable at this
 * point — the content still has to go in; synth_seal() makes it the guest's.
 *
 * The memfd is named after the file it stands in for — "cng-proc:/proc/<pid>/
 * cmdline", the spelling the kernel's own fd link would carry — because the
 * name is the one thing about a memfd that survives everything an fd goes
 * through: dup, inheritance across fork, a reopen through /proc/self/fd/N,
 * and another process's look at our fd links all reach the same inode, and
 * /proc/self/fd/N reads "/memfd:cng-proc:/proc/<pid>/cmdline (deleted)" for
 * every one of them. That is how the fstat family and the fd links find their
 * way back to the real file (synth_name_of). */
#define SYNTH_TAG     "cng-proc:"
#define SYNTH_TAG_LEN 9
#define SYNTH_LINK_HEAD "/memfd:" SYNTH_TAG
#define SYNTH_LINK_HEAD_LEN (7 + SYNTH_TAG_LEN)
#define SYNTH_LINK_TAIL " (deleted)"
#define SYNTH_LINK_TAIL_LEN 10
static long synth_memfd(int refreshable, const char *name) {
    char tag[SYNTH_TAG_LEN + CNG_PATH_MAX];
    cng_snprintf(tag, sizeof tag, SYNTH_TAG "%s", name);
    long fd = sys_memfd_create(tag, CNG_MFD_CLOEXEC);
    if (fd < 0)
        return -1;
    if (refreshable && cng_g_synth_fd_base > 0) {
        long hi = sys_fcntl((int)fd, CNG_F_DUPFD_CLOEXEC, cng_g_synth_fd_base);
        if (hi >= 0) {
            sys_close((int)fd);
            fd = hi;
        }
        /* On failure the low fd stands: correct content, no refresh. */
    }
    return fd;
}

/* The open(2) status flags the guest may ask for and get back from F_GETFL on
 * a /proc file: recorded on the description, no effect on what a read returns.
 * The rest of the word is either decided above (access mode, O_TRUNC, O_PATH,
 * ...), consumed at open time (O_CREAT, O_EXCL, O_NOFOLLOW, O_CLOEXEC — the
 * last put on the fd separately), or a hint. */
#define SYNTH_STATUS_FLAGS                                                     \
    (CNG_O_APPEND | CNG_O_NONBLOCK | CNG_O_DSYNC | CNG___O_SYNC |              \
     CNG_O_NOATIME | CNG_O_NOCTTY | CNG_O_LARGEFILE)

/* Turn the writable memfd holding a finished view into what the guest opened:
 * a read-only description, with the status flags it asked for. The memfd is
 * reopened through its own /proc link with O_RDONLY and the new description is
 * dup3'd over the same fd number, so the number the guest gets is still the
 * lowest that was free (or the reserved slot) and the inode the refresh
 * bookkeeping recorded is unchanged.
 *
 * memfd_create only ever hands out O_RDWR, and that was what the guest got: a
 * /proc file it could write(), ftruncate(), mmap(MAP_SHARED|PROT_WRITE) and
 * see O_RDWR from F_GETFL on — every one of which the kernel refuses on the
 * real file (EBADF, EINVAL, EACCES, O_RDONLY; measured). Where the reopen is
 * refused the writable fd stands, as before: the content is right and only the
 * description's mode is wrong. */
static void synth_seal(int fd, long gflags) {
    long ro = synth_reopen(fd, CNG_O_RDONLY | (gflags & SYNTH_STATUS_FLAGS));
    if (ro < 0) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] procfs fd %d stays writable: reopen errno=%ld\n",
                        fd, -ro);
        return;
    }
    if (CNG_SYS(__NR_dup3, ro, fd, CNG_O_CLOEXEC, 0, 0, 0) < 0 && cng_g_debug)
        cng_dprintf(2, "[cng] procfs fd %d stays writable: dup3 failed\n", fd);
    sys_close((int)ro);
}

/* Is the host file behind a synthesized name ours to open with O_NOATIME? The
 * kernel grants the flag to the file's owner (or CAP_FOWNER), which for the
 * global files is root and for a process's own entries is that process — a
 * question the fake identity has no say in, since it is asked of the real
 * inode. Answered from a stat of the host name so a non-dumpable process's
 * root-owned entries are judged right too. */
static int noatime_allowed(const char *host) {
    unsigned euid = (unsigned)sys_geteuid();
    if (euid == 0)
        return 1;
    char st[128];
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, host, st, 0, 0, 0) != 0)
        return 1; /* cannot tell: let the open stand rather than invent EPERM */
    return *(unsigned *)(st + 24) == euid; /* st_uid */
}

/* ---- path classification ------------------------------------------------ */

/* "/proc/<self|thread-self|N>/<leaf>" -> *pid and the leaf; 0 otherwise. */
static const char *pid_tail(const char *canon, int *pid) {
    if (strncmp(canon, "/proc/", 6) != 0)
        return 0;
    const char *q = canon + 6;
    if (!strncmp(q, "self/", 5)) {
        *pid = (int)sys_getpid();
        return q + 5;
    }
    if (!strncmp(q, "thread-self/", 12)) {
        *pid = (int)sys_getpid();
        return q + 12;
    }
    if (*q < '0' || *q > '9')
        return 0;
    long n = 0;
    for (; *q >= '0' && *q <= '9'; q++) {
        n = n * 10 + (*q - '0');
        if (n > 0x7fffffff)
            return 0;
    }
    if (*q != '/')
        return 0;
    *pid = (int)n;
    return q + 1;
}

static int per_pid_kind(const char *leaf) {
    if (!strcmp(leaf, "cmdline"))
        return PF_CMDLINE;
    if (!strcmp(leaf, "environ"))
        return PF_ENVIRON;
    if (!strcmp(leaf, "auxv"))
        return PF_AUXV;
    if (!strcmp(leaf, "maps"))
        return PF_MAPS;
    if (!strcmp(leaf, "mounts"))
        return PF_MOUNTS;
    if (!strcmp(leaf, "mountinfo"))
        return PF_MOUNTINFO;
    if (!strcmp(leaf, "mountstats"))
        return PF_MOUNTSTATS;
    if (!strcmp(leaf, "status"))
        return PF_STATUS;
    return 0;
}

/* The guest stack of the program running here, kept so our own cmdline/environ/
 * auxv can be answered from live state when the registry cannot answer (see
 * self_snapshot). Re-recorded at every emulated execve, which is where a real
 * kernel moves its own arg_start/env_start too. */
static unsigned long g_self_sp;

/* Flatten a NUL-terminated vector into NUL-joined bytes, the way the kernel
 * stores cmdline and environ. Nothing here is dereferenced unchecked: this reads
 * the guest's own stack long after it was built, and a program that has since
 * rewritten its argv (setproctitle) or unmapped it must not be able to fault us
 * — the fault would land in the SIGSYS handler, where it is unblockable. Both
 * the slot and the string it names are taken with the copy-in pair, so the
 * bytes that are measured are the bytes that are stored; a strlen followed by a
 * memcpy reads the same string twice, and between the two reads it can change.
 * Whatever will not come across ends the vector where it stands, which is also
 * what the kernel shows for a process rewriting its own argv. */
static unsigned flatten_vec(char *dst, unsigned cap, char **v) {
    unsigned n = 0;
    long cnt = cng_user_veclen(v, 4096);
    for (long i = 0; i < cnt; i++) {
        char *s;
        if (cng_user_copyin(&s, &v[i], sizeof s) < 0)
            break;
        long len = cng_user_strcopyin(dst + n, s, cap - n);
        if (len < 0)
            break; /* -EFAULT, or no terminator in the room that is left */
        n += (unsigned)len + 1;
    }
    return n;
}

/* Our own identity from the live stack rather than the registry.
 *
 * The registry can miss — it was never mapped, or its table is full — and the
 * fallback then was the *host* file, which for a guest process describes the
 * chroot-ng invocation that started it: `/proc/self/cmdline` read back
 * "chroot-ng -u /rootfs /bin/sh". Anything that identifies itself by its own
 * cmdline (busybox multi-call applets, `ps` on itself, a daemon writing a pid
 * file) was told the wrong program was running. We are the process being asked
 * about, so no shared table is needed to answer. */
static int self_snapshot(struct cng_procsnap *out) {
    if (!g_self_sp)
        return 0;
    /* The stack this walks is the guest's, not ours: we built it, but the
     * program living on it owns every byte since. It can rewrite argc, run its
     * environment off the end of the mapping, or unmap the whole region — and
     * this used to be a raw dereference, an unbounded `while (*p) p++` over the
     * environment and another over the auxv pairs, all inside the SIGSYS handler
     * where a SIGSEGV cannot be blocked and kills the process. A /proc file the
     * guest opens on itself is not a place to die: every step goes through the
     * probes now, and what will not come across shortens the answer instead of
     * ending the process. */
    memset(out, 0, sizeof *out);
    long argc;
    if (cng_user_copyin(&argc, (void *)g_self_sp, sizeof argc) < 0)
        return 0;
    if (argc < 0 || argc > 4096)
        return 0;
    /* Past this point a stack that does not read is answered with what it does
     * hold, not declined: declining hands the question back to the host file,
     * and for a guest process that file is the chroot-ng invocation — the one
     * answer that is certainly wrong, and the reason any of this exists. So a
     * cmdline the guest has scribbled over comes back short or empty rather
     * than coming back as ours. Only the word `argc` itself is fatal, because
     * without it nothing below can even be located. */
    char **argv = (char **)(g_self_sp + 8);
    char **envp = argv + argc + 1;
    out->cmd_len = flatten_vec(out->cmd, CNG_PROCREG_CMDLINE, argv);
    out->env_len = flatten_vec(out->env, CNG_PROCREG_ENVIRON, envp);
    /* The auxv lies behind the environment's terminator, so it can be found at
     * all only where the environment can be counted — the same 4096-entry bound
     * flatten_vec holds it to, well past what an entry could store anyway. It is
     * pairs to an AT_NULL one, copied as it is walked, and one that runs past
     * what the entry holds is dropped whole rather than truncated: half a vector
     * is not one, and its readers (`cat /proc/self/auxv`, a libc re-reading
     * AT_HWCAP) parse to the terminator. */
    long envc = cng_user_veclen(envp, 4096);
    if (envc >= 0) {
        const char *pairs = (const char *)(envp + envc + 1);
        unsigned alen = 0;
        for (;;) {
            if (alen + 16 > CNG_PROCREG_AUXV ||
                cng_user_copyin(out->auxv + alen, pairs + alen, 16) < 0) {
                alen = 0;
                break;
            }
            unsigned long tag;
            memcpy(&tag, out->auxv + alen, sizeof tag);
            alen += 16;
            if (!tag)
                break;
        }
        out->auxv_len = alen;
    }
    return 1;
}

/* ---- the open hook ------------------------------------------------------- */

int cng_procfs_open(const char *canon, long gflags, long *ret) {
    if (cng_g_no_proc || !cng_g_fs)
        return 0;

    /* Only names that reach the host /proc are ours to answer. A path the map
     * redirects — an explicit `-b /proc:DIR`, or the rootfs prefix a hidden pid
     * falls back to — is the user's mapping (or the hidden view) speaking, and
     * it outranks synthesis. */
    char host[CNG_PATH_MAX];
    if (host_of(canon, host, sizeof host) != 0 || strcmp(host, canon) != 0)
        return 0;

    int kind = 0, pid = 0;
    const char *leaf = pid_tail(canon, &pid);
    if (leaf) {
        kind = per_pid_kind(leaf);
        /* status only diverges under a fake identity; everything else about a
         * guest process's status is already true. */
        if (kind == PF_STATUS && !cng_g_fake_id)
            return 0;
        /* Another process is describable only if it is a guest process; a host
         * one is already hidden by the path layer. */
        if (kind && !cng_procreg_has(pid))
            return 0;
    } else if (!strcmp(canon, "/proc/mounts")) {
        kind = PF_MOUNTS; /* where the /etc/mtab symlink usually lands */
    } else if (!strcmp(canon, "/proc/loadavg")) {
        kind = PF_LOADAVG;
    } else if (!strcmp(canon, "/proc/uptime")) {
        kind = PF_UPTIME;
    } else if (!strcmp(canon, "/proc/version")) {
        kind = PF_VERSION;
    } else if (!strcmp(canon, "/proc/stat")) {
        if (!stat_blocked())
            return 0; /* a readable host file is strictly richer */
        kind = PF_STAT;
    }
    if (!kind)
        return 0;

    /* The registry-backed files need a live entry; without one (registry
     * unavailable, or the table was full) the host file is the better answer. */
    struct cng_procsnap snap;
    if (kind == PF_CMDLINE || kind == PF_ENVIRON || kind == PF_AUXV) {
        /* For ourselves the registry is a convenience, not the source: we ARE
         * the process being described, and the host file — chroot-ng's own
         * argv and exec-time environment — is the one answer that is certainly
         * wrong. Only another process's identity truly needs the table. */
        if (!cng_procreg_get(pid, &snap) &&
            !(pid == (int)sys_getpid() && self_snapshot(&snap)))
            return 0;
    }

    /* The flags, judged the way build_open_flags() and do_open() judge them
     * and in that order (every answer below was measured on the host against
     * the real file). Three of them are not ours to answer at all, and return 0
     * so the real open does: O_PATH, which the kernel takes as "open the name,
     * ignore every other flag" — the guest gets an fd on the real inode that
     * cannot be read from anyway, and the content a memfd would hold never
     * comes into it (the old code built one and handed over a *readable* fd);
     * O_DIRECTORY and __O_TMPFILE, which fail on a regular file (ENOTDIR, or
     * EINVAL for the combinations build_open_flags refuses first, and the
     * running kernel is the one that knows which — O_CREAT|O_DIRECTORY became
     * EINVAL in 6.3); and O_CREAT|O_EXCL, which is EEXIST on a name that is
     * there. Each of those used to open the memfd as if nothing had been
     * asked. Then the ones we do answer: write intent (a non-read access mode,
     * or O_TRUNC, which build_open_flags folds into MAY_WRITE) is EACCES on a
     * 0444 file, O_NOATIME is the owner's, and O_DIRECT is EINVAL on an inode
     * with no direct_IO — which a memfd does have on a current kernel, so it
     * cannot be left to the reopen to refuse. */
    if (gflags & CNG_O_PATH)
        return 0;
    if (gflags & (CNG_O_DIRECTORY | CNG___O_TMPFILE))
        return 0;
    if ((gflags & (CNG_O_CREAT | CNG_O_EXCL)) == (CNG_O_CREAT | CNG_O_EXCL))
        return 0;
    /* /proc/mounts itself is a symlink (to self/mounts): O_NOFOLLOW on that
     * spelling is ELOOP, which only the real open can say. */
    if (!leaf && kind == PF_MOUNTS && (gflags & CNG_O_NOFOLLOW))
        return 0;
    if ((gflags & CNG_O_ACCMODE) != CNG_O_RDONLY || (gflags & CNG_O_TRUNC)) {
        *ret = -EACCES;
        return 1;
    }
    if ((gflags & CNG_O_NOATIME) && !noatime_allowed(host)) {
        *ret = -EPERM;
        return 1;
    }
    if (gflags & CNG_O_DIRECT) {
        *ret = -EINVAL;
        return 1;
    }

    int refreshable =
        (kind == PF_LOADAVG || kind == PF_UPTIME || kind == PF_STAT);
    /* The name the kernel's fd link would show: a process's entries by number
     * (self resolved, thread-self as the task entry), /proc/mounts as the
     * self/mounts it links to, the global files as themselves. */
    char link[CNG_PATH_MAX];
    if (leaf) {
        if (!strncmp(canon + 6, "thread-self/", 12))
            cng_snprintf(link, sizeof link, "/proc/%d/task/%ld/%s", pid,
                         sys_gettid(), leaf);
        else
            cng_snprintf(link, sizeof link, "/proc/%d/%s", pid, leaf);
    } else if (kind == PF_MOUNTS) {
        cng_snprintf(link, sizeof link, "/proc/%d/mounts", (int)sys_getpid());
    } else {
        cng_strlcpy(link, canon, sizeof link);
    }
    long fd = synth_memfd(refreshable, link);
    if (fd < 0)
        return 0; /* no memfd: degrade to host passthrough */

    int rc = 0;
    switch (kind) {
    case PF_CMDLINE:
        cng_write_all((int)fd, snap.cmd, snap.cmd_len);
        break;
    case PF_ENVIRON:
        cng_write_all((int)fd, snap.env, snap.env_len);
        break;
    case PF_AUXV:
        cng_write_all((int)fd, snap.auxv, snap.auxv_len);
        break;
    case PF_MOUNTS:
        put_mounts((int)fd, MNT_MOUNTS);
        break;
    case PF_MOUNTINFO:
        put_mounts((int)fd, MNT_MOUNTINFO);
        break;
    case PF_MOUNTSTATS:
        put_mounts((int)fd, MNT_MOUNTSTATS);
        break;
    case PF_LOADAVG:
        put_loadavg((int)fd);
        break;
    case PF_UPTIME:
        put_uptime((int)fd);
        break;
    case PF_VERSION:
        put_version((int)fd);
        break;
    case PF_STAT:
        put_stat((int)fd);
        break;
    case PF_STATUS:
        rc = put_status((int)fd, host, pid == (int)sys_getpid());
        break;
    case PF_MAPS:
        rc = put_maps((int)fd, host);
        break;
    }
    if (rc < 0) { /* host file unreadable: let the real open answer */
        sys_close((int)fd);
        return 0;
    }

    synth_seal((int)fd, gflags); /* read-only from here, like the real file */
    sys_lseek((int)fd, 0, CNG_SEEK_SET);
    if (!(gflags & CNG_O_CLOEXEC))
        sys_fcntl((int)fd, CNG_F_SETFD, 0); /* the guest did not ask for it */
    /* Track only an fd that actually landed in the trapped range; one that
     * didn't (F_DUPFD failed) keeps its open-time snapshot, and tracking it
     * would waste a slot on reads that never reach us. */
    if (refreshable && cng_g_synth_fd_base > 0 && fd >= cng_g_synth_fd_base)
        pf_track((int)fd, kind);
    if (cng_g_debug)
        cng_dprintf(2, "[cng] procfs %s -> fd %ld (kind %d)\n", canon, fd, kind);
    *ret = fd;
    return 1;
}

/* ---- the fd's own account of itself --------------------------------------- */

/* The device memfds live on: the kernel's internal tmpfs, one for the whole
 * system, so a stat that lands on it is a memfd's and nothing else's. Learned
 * from a probe once; 0 where memfd_create is refused, when no synthesized fd
 * can exist either. */
static unsigned long g_memfd_dev;
static int g_memfd_dev_known;
static unsigned long memfd_dev(void) {
    if (!__atomic_load_n(&g_memfd_dev_known, __ATOMIC_ACQUIRE)) {
        unsigned long dev = 0;
        long fd = sys_memfd_create("cng-probe", CNG_MFD_CLOEXEC);
        if (fd >= 0) {
            char st[128];
            if (sys_fstat((int)fd, st) == 0)
                dev = *(unsigned long *)(st + STAT_DEV_OFF);
            sys_close((int)fd);
        }
        g_memfd_dev = dev;
        __atomic_store_n(&g_memfd_dev_known, 1, __ATOMIC_RELEASE);
    }
    return g_memfd_dev;
}

int cng_procfs_link_name(const char *tgt, char *out, size_t sz) {
    if (strncmp(tgt, SYNTH_LINK_HEAD, SYNTH_LINK_HEAD_LEN))
        return 0;
    size_t n = strlen(tgt);
    if (n < SYNTH_LINK_HEAD_LEN + 1 + SYNTH_LINK_TAIL_LEN ||
        strcmp(tgt + n - SYNTH_LINK_TAIL_LEN, SYNTH_LINK_TAIL))
        return 0;
    size_t pl = n - SYNTH_LINK_HEAD_LEN - SYNTH_LINK_TAIL_LEN;
    if (pl >= sz)
        return 0;
    memcpy(out, tgt + SYNTH_LINK_HEAD_LEN, pl);
    out[pl] = '\0';
    return 1;
}

/* The /proc file behind the link at (dirfd, path) — /proc/self/fd/N for an fd
 * of ours, or wherever a guest's stat landed on a memfd — or 0. */
static int synth_name_at(long dirfd, const char *path, char *out, size_t sz) {
    char tgt[CNG_PATH_MAX];
    long n = sys_readlinkat((int)dirfd, path, tgt, sizeof tgt - 1);
    if (n <= 0)
        return 0;
    tgt[n] = '\0';
    return cng_procfs_link_name(tgt, out, sz);
}

static int synth_name_of(int fd, char *out, size_t sz) {
    char link[40];
    cng_snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    return synth_name_at(CNG_AT_FDCWD, link, out, sz);
}

/* What every regular file under /proc has in common, put on a stat that could
 * not be taken from the file itself: the kernel keeps a held inode answering
 * after its process is gone, and there is no path left to ask for one of
 * those. So the procfs mount's own identity carries 0444 (0400 for environ and
 * auxv, which are the owner's alone), one link, size 0, 1 KiB blocks, and the
 * memfd's inode number in place of one nobody can look up any more. A
 * process's entries are its owner's, and every guest process runs as us. */
#define ST_U32(b, o) (*(unsigned *)((b) + (o)))
#define ST_S64(b, o) (*(long long *)((b) + (o)))
static unsigned proc_mode_of(const char *name) {
    const char *b = strrchr(name, '/');
    b = b ? b + 1 : name;
    return 0100000u | (!strcmp(b, "environ") || !strcmp(b, "auxv") ? 0400u
                                                                     : 0444u);
}
static int proc_owned(const char *name) {
    return name[6] >= '0' && name[6] <= '9'; /* "/proc/<pid>/..." */
}
static int synth_stat_gone(const char *name, unsigned long memfd_ino, char *st) {
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, "/proc", st, 0, 0, 0) != 0)
        return 0;
    ST_U32(st, 16) = proc_mode_of(name);
    ST_U32(st, 20) = 1;
    ST_U32(st, 24) = proc_owned(name) ? (unsigned)sys_getuid() : 0;
    ST_U32(st, 28) = proc_owned(name) ? (unsigned)sys_getgid() : 0;
    *(unsigned long *)(st + STAT_INO_OFF) = memfd_ino;
    ST_S64(st, 48) = 0;
    *(int *)(st + 56) = 1024;
    ST_S64(st, 64) = 0;
    return 1;
}
static int synth_statx_gone(const char *name, unsigned long long memfd_ino,
                            unsigned flags, unsigned mask, char *sx) {
    if (CNG_SYS(__NR_statx, CNG_AT_FDCWD, "/proc", flags, mask, sx, 0) != 0)
        return 0;
    ST_U32(sx, 4) = 1024;
    ST_U32(sx, 16) = 1;
    ST_U32(sx, 20) = proc_owned(name) ? (unsigned)sys_getuid() : 0;
    ST_U32(sx, 24) = proc_owned(name) ? (unsigned)sys_getgid() : 0;
    *(unsigned short *)(sx + 28) = (unsigned short)proc_mode_of(name);
    *(unsigned long long *)(sx + 32) = memfd_ino;
    ST_S64(sx, 40) = 0;
    ST_S64(sx, 48) = 0;
    return 1;
}

int cng_procfs_fix_fd(int fd, void *stat) {
    char *st = (char *)stat;
    if (fd < 0 || *(unsigned long *)(st + STAT_DEV_OFF) != memfd_dev() ||
        !memfd_dev())
        return 0;
    char name[CNG_PATH_MAX];
    if (!synth_name_of(fd, name, sizeof name))
        return 0; /* a memfd, but not one of ours */
    unsigned long ino = *(unsigned long *)(st + STAT_INO_OFF);
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, name, st, 0, 0, 0) == 0)
        return 1;
    return synth_stat_gone(name, ino, st);
}

int cng_procfs_fix_path(long dirfd, const char *path, void *stat) {
    char *st = (char *)stat;
    if (*(unsigned long *)(st + STAT_DEV_OFF) != memfd_dev() || !memfd_dev())
        return 0;
    char name[CNG_PATH_MAX];
    if (!synth_name_at(dirfd, path, name, sizeof name))
        return 0;
    unsigned long ino = *(unsigned long *)(st + STAT_INO_OFF);
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, name, st, 0, 0, 0) == 0)
        return 1;
    return synth_stat_gone(name, ino, st);
}

/* statx's dev is major/minor; stat's encoding has major in bits 8..19 and
 * 32 up, minor in 0..7 and 20..31. */
static unsigned long statx_dev(const char *sx) {
    unsigned long maj = ST_U32(sx, 136), min = ST_U32(sx, 140);
    return (min & 0xff) | ((maj & 0xfff) << 8) | ((min & ~0xffUL) << 12) |
           ((maj & ~0xfffUL) << 32);
}

static int fix_statx(long dirfd, const char *path, int fd, unsigned flags,
                     unsigned mask, char *sx) {
    if (statx_dev(sx) != memfd_dev() || !memfd_dev())
        return 0;
    char name[CNG_PATH_MAX];
    int ours = fd >= 0 ? synth_name_of(fd, name, sizeof name)
                       : synth_name_at(dirfd, path, name, sizeof name);
    if (!ours)
        return 0;
    unsigned long long ino = *(unsigned long long *)(sx + 32);
    /* The guest's own flags, less the lookup ones: the name is followed to the
     * file whatever the guest said about symlinks or empty paths, and the sync
     * flags (AT_STATX_*) are what remains. */
    flags &= ~(unsigned)(CNG_AT_SYMLINK_NOFOLLOW | CNG_AT_EMPTY_PATH |
                         CNG_AT_NO_AUTOMOUNT);
    if (CNG_SYS(__NR_statx, CNG_AT_FDCWD, name, flags, mask, sx, 0) == 0)
        return 1;
    return synth_statx_gone(name, ino, flags, mask, sx);
}

int cng_procfs_fix_fd_statx(int fd, unsigned flags, unsigned mask,
                            void *statx) {
    return fd < 0 ? 0 : fix_statx(CNG_AT_FDCWD, 0, fd, flags, mask, statx);
}

int cng_procfs_fix_path_statx(long dirfd, const char *path, unsigned flags,
                              unsigned mask, void *statx) {
    return fix_statx(dirfd, path, -1, flags, mask, statx);
}

int cng_procfs_fstatfs(int fd, void *buf) {
    char st[128];
    if (fd < 0 || sys_fstat(fd, st) != 0 ||
        *(unsigned long *)(st + STAT_DEV_OFF) != memfd_dev() || !memfd_dev())
        return 0;
    char name[CNG_PATH_MAX];
    if (!synth_name_of(fd, name, sizeof name))
        return 0;
    /* One procfs; the mount the file is on is the one /proc is. */
    long r = CNG_SYS(__NR_statfs, "/proc", buf, 0, 0, 0, 0);
    return r == 0 ? 1 : (int)r;
}

#define TMPFS_MAGIC 0x01021994L
int cng_procfs_fix_path_statfs(long dirfd, const char *path, void *buf) {
    /* statfs names no inode, so the filesystem type is the first cut: only a
     * name that landed on a tmpfs can have landed on a memfd. */
    if (*(long *)((char *)buf + STATFS_TYPE_OFF) != TMPFS_MAGIC)
        return 0;
    char name[CNG_PATH_MAX];
    if (!synth_name_at(dirfd, path, name, sizeof name))
        return 0;
    long r = CNG_SYS(__NR_statfs, "/proc", buf, 0, 0, 0, 0);
    return r == 0 ? 1 : (int)r;
}

/* ---- setup --------------------------------------------------------------- */

/* Reserve the high fd range the refreshable files live in: the top
 * CNG_SYNTH_FD_SLOTS descriptors below the process's fd limit, so the seccomp
 * filter can trap read/pread64/lseek on "fd >= base" alone. Disabled when the
 * limit is too small to give the guest room (then those files keep their
 * open-time snapshot). */
static void fd_base_init(void) {
    struct cng_rlimit rl;
    if (sys_prlimit64(0, CNG_RLIMIT_NOFILE, 0, &rl) != 0)
        return;
    unsigned long soft = rl.cur;
    if (soft > 65536) /* an "unlimited" limit would size the fd table absurdly */
        soft = 65536;
    if (soft < 128)
        return; /* no room: refresh stays off */
    cng_g_synth_fd_base = (int)(soft - CNG_SYNTH_FD_SLOTS);
}

void cng_procfs_init(void) {
    /* --shared-proc keys the registry by the rootfs, so independent
     * invocations over the same tree share one process view. */
    cng_procreg_init(cng_g_shared_proc && cng_g_fs ? cng_g_fs->rootfs : 0);
    fd_base_init();
}

/* comm: the kernel takes it from the exec'd file's basename (15 chars max), and
 * ps/top and /proc/<pid>/{stat,status} report it. We never execve, so without
 * this every guest process would be named "chroot-ng". This one is not
 * synthesis — PR_SET_NAME makes the kernel's own record correct. */
static void set_comm(const char *exe_guest) {
    if (!exe_guest)
        return;
    const char *base = strrchr(exe_guest, '/');
    base = base ? base + 1 : exe_guest;
    if (!*base)
        return;
    char nm[16];
    cng_strlcpy(nm, base, sizeof nm);
    sys_prctl(CNG_PR_SET_NAME, (unsigned long)nm, 0, 0, 0);
}

void cng_procfs_publish_stack(unsigned long guest_sp) {
    if (!guest_sp)
        return;
    g_self_sp = guest_sp;
    long argc = *(long *)guest_sp;
    if (argc < 0 || argc > 4096)
        return;
    char **argv = (char **)(guest_sp + 8);
    char **envp = argv + argc + 1;
    char **p = envp;
    while (*p)
        p++;
    unsigned long *auxv = (unsigned long *)(p + 1);
    unsigned long *end = auxv;
    while (end[0]) /* walk to AT_NULL, then past its value */
        end += 2;
    end += 2;
    unsigned alen = (unsigned)((char *)end - (char *)auxv);
    if (alen > CNG_PROCREG_AUXV)
        alen = 0; /* an over-long block is better omitted than truncated */

    char cwd[CNG_PATH_MAX];
    if (cng_g_fs)
        cng_fs_cwd(cwd, sizeof cwd);
    else
        cng_strlcpy(cwd, "/", sizeof cwd);
    cng_procreg_publish(argv, envp, auxv, alen, cng_g_exe_guest, cwd);
    set_comm(cng_g_exe_guest);
}
