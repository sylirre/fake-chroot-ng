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
    PF_LOADAVG, PF_UPTIME, PF_STAT, PF_STATUS,
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
 * A line longer than the buffer is delivered in pieces, which is fine for both
 * callers (they only match on a line's leading keyword or copy it through). */
struct lrd {
    int fd;
    unsigned pos, len;
    int eof;
    char buf[4096];
    char line[2048];
};

static void lrd_init(struct lrd *r, int fd) {
    r->fd = fd;
    r->pos = r->len = 0;
    r->eof = 0;
}

static const char *lrd_next(struct lrd *r) {
    unsigned n = 0;
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
        if (n == sizeof r->line - 1)
            break; /* over-long line: hand back what we have */
    }
    if (!n && r->eof && r->pos == r->len)
        return 0;
    r->line[n] = '\0';
    return r->line;
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

/* The guest mount table: the rootfs, the /proc passthrough, and one row per
 * -b bind. Fixed mount IDs; the root's major:minor is real, so tools
 * cross-referencing stat().st_dev find it. */
static void put_mounts(int fd, int fmt) {
    const char *root = cng_g_fs->rootfs[0] ? cng_g_fs->rootfs : "/";
    const char *fstype = rootfs_fstype(root);
    unsigned long maj = 0, min = 0;
    char st[128];
    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, root, st, 0, 0, 0) == 0) {
        unsigned long dev = *(unsigned long *)(st + STAT_DEV_OFF);
        maj = dev_major(dev);
        min = dev_minor(dev);
    }
    int nb = cng_g_fs->nbinds;
    int proc_row = !cng_g_no_proc;

    if (fmt == MNT_MOUNTINFO) {
        cng_dprintf(fd, "1 1 %lu:%lu / / rw,relatime - %s /dev/root rw\n", maj,
                    min, fstype);
        if (proc_row)
            cng_dprintf(fd, "2 1 0:5 / /proc rw,nosuid,nodev,noexec,relatime - "
                            "proc proc rw\n");
        for (int i = 0; i < nb; i++) {
            unsigned long bmaj = maj, bmin = min;
            char bst[128];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, cng_g_fs->binds[i].host,
                        bst, 0, 0, 0) == 0) {
                unsigned long d = *(unsigned long *)(bst + STAT_DEV_OFF);
                bmaj = dev_major(d);
                bmin = dev_minor(d);
            }
            cng_dprintf(fd, "%d 1 %lu:%lu / %s rw,relatime - %s %s rw\n",
                        i + 3, bmaj, bmin, cng_g_fs->binds[i].guest, fstype,
                        cng_g_fs->binds[i].host);
        }
    } else if (fmt == MNT_MOUNTSTATS) {
        /* No NFS per-op stats: every mount here is a local filesystem. */
        cng_dprintf(fd, "device /dev/root mounted on / with fstype %s\n",
                    fstype);
        if (proc_row)
            cng_dprintf(fd, "device proc mounted on /proc with fstype proc\n");
        for (int i = 0; i < nb; i++)
            cng_dprintf(fd, "device %s mounted on %s with fstype %s\n",
                        cng_g_fs->binds[i].host, cng_g_fs->binds[i].guest,
                        fstype);
    } else {
        cng_dprintf(fd, "/dev/root / %s rw,relatime 0 0\n", fstype);
        if (proc_row)
            cng_dprintf(fd,
                        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
        for (int i = 0; i < nb; i++)
            cng_dprintf(fd, "%s %s %s rw,relatime 0 0\n",
                        cng_g_fs->binds[i].host, cng_g_fs->binds[i].guest,
                        fstype);
    }
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
    for (unsigned long i = 0; i < (unsigned long)r / sizeof mask[0]; i++)
        n += (unsigned long)__builtin_popcountl(mask[i]);
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

/* Copy the host status through, rewriting only the Uid:/Gid:/Groups: numeric
 * fields via the fake-id remap so ps/top resolve the fake identity's user (they
 * read the Uid: line, which otherwise carries our real host uid). Returns 0, or
 * -1 if the host file cannot be read (caller falls back to passthrough). */
static int put_status(int fd, const char *host) {
    long hf = open_host_ro(host);
    if (hf < 0)
        return -1;
    struct lrd r; /* 6 KiB — the dispatcher runs on its own 256 KiB stack */
    lrd_init(&r, (int)hf);
    const char *line;
    while ((line = lrd_next(&r)) != 0) {
        int is_uid = !strncmp(line, "Uid:", 4);
        if (is_uid || !strncmp(line, "Gid:", 4)) {
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
            cng_dprintf(fd, "Groups:");
            const char *p = line + 7;
            for (;;) {
                skip_ws(&p);
                if (*p < '0' || *p > '9')
                    break;
                cng_dprintf(fd, " %u", cng_remap_gid((unsigned)parse_ul(&p)));
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

/* Time-varying files are regenerated when a read starts at offset 0. The memfd
 * inode is recorded so a stale entry (an fd number reused after a close we
 * never saw — we do not trap close) is detected and dropped rather than
 * clobbering an innocent file. */
static struct {
    int fd1; /* fd + 1, so a zeroed table means "all free"; claimed by CAS */
    int kind;
    unsigned long ino;
} g_pf[CNG_SYNTH_FD_SLOTS];

static unsigned long fd_ino(int fd) {
    char st[128];
    if (sys_fstat(fd, st) != 0)
        return 0;
    return *(unsigned long *)(st + STAT_INO_OFF);
}

static void pf_track(int fd, int kind) {
    unsigned long ino = fd_ino(fd);
    if (!ino)
        return;
    for (int i = 0; i < CNG_SYNTH_FD_SLOTS; i++) {
        int expect = 0; /* free */
        if (__atomic_compare_exchange_n(&g_pf[i].fd1, &expect, fd + 1, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_pf[i].kind = kind;
            g_pf[i].ino = ino;
            return;
        }
        /* Reclaim a slot whose fd is gone or now names a different file (we do
         * not trap close, so entries are only ever retired lazily). */
        if (expect > 0 && fd_ino(expect - 1) != g_pf[i].ino &&
            __atomic_compare_exchange_n(&g_pf[i].fd1, &expect, fd + 1, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            g_pf[i].kind = kind;
            g_pf[i].ino = ino;
            return;
        }
    }
    /* Table full: the fd simply keeps its open-time snapshot. */
}

static void regen(int fd, int kind) {
    if (sys_ftruncate(fd, 0) != 0)
        return; /* memfd: cannot fail in practice */
    sys_lseek(fd, 0, CNG_SEEK_SET);
    switch (kind) {
    case PF_LOADAVG:
        put_loadavg(fd);
        break;
    case PF_UPTIME:
        put_uptime(fd);
        break;
    case PF_STAT:
        put_stat(fd);
        break;
    }
    sys_lseek(fd, 0, CNG_SEEK_SET);
}

void cng_procfs_pre_read(int fd, long off) {
    if (fd < 0)
        return;
    for (int i = 0; i < CNG_SYNTH_FD_SLOTS; i++) {
        if (__atomic_load_n(&g_pf[i].fd1, __ATOMIC_ACQUIRE) != fd + 1)
            continue;
        if (fd_ino(fd) != g_pf[i].ino) { /* stale: the fd was reused */
            __atomic_store_n(&g_pf[i].fd1, 0, __ATOMIC_RELEASE);
            return;
        }
        if (off < 0)
            off = sys_lseek(fd, 0, CNG_SEEK_CUR);
        if (off != 0)
            return; /* mid-file: keep the current snapshot */
        regen(fd, g_pf[i].kind);
        return;
    }
}

/* Anonymous backing for a synthesized view, moved into the reserved high fd
 * range when the file needs refresh-on-rewind (that range is what the seccomp
 * filter traps the read family on). Returns the fd, or -1. */
static long synth_memfd(int refreshable) {
    long fd = sys_memfd_create("cng-proc", CNG_MFD_CLOEXEC);
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
        if (!cng_procreg_get(pid, &snap))
            return 0;
    }

    if ((gflags & 3) != CNG_O_RDONLY) {
        *ret = -EACCES;
        return 1;
    }
    if (gflags & CNG_O_DIRECTORY) {
        *ret = -ENOTDIR;
        return 1;
    }

    int refreshable =
        (kind == PF_LOADAVG || kind == PF_UPTIME || kind == PF_STAT);
    long fd = synth_memfd(refreshable);
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
    case PF_STAT:
        put_stat((int)fd);
        break;
    case PF_STATUS:
        rc = put_status((int)fd, host);
        break;
    case PF_MAPS:
        rc = put_maps((int)fd, host);
        break;
    }
    if (rc < 0) { /* host file unreadable: let the real open answer */
        sys_close((int)fd);
        return 0;
    }

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

    cng_procreg_publish(argv, envp, auxv, alen, cng_g_exe_guest,
                        cng_g_fs ? cng_g_fs->cwd : "/");
    set_comm(cng_g_exe_guest);
}
