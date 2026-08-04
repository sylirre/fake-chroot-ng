/* Unified IPC broker (see include/cng/broker.h): the rendezvous, the transport,
 * the detached daemon, and — daemon-side — the System V shared-memory registry.
 *
 * Ported from arm64chroot's proctab.c. Freestanding throughout: raw syscalls
 * through the gate, no allocator, no libc. Every field of the segment table
 * lives only in the daemon process and is mutated single-threaded from
 * ipc_serve, so nothing here needs locking.
 *
 * The daemon is forked from a guest process, so it inherits our seccomp filter
 * and SIGSYS handler — harmless, because every syscall it makes goes through
 * the gate, whose instruction range the filter allows. (It must therefore never
 * call anything that would route through cng_dispatch: a path syscall here must
 * not be translated into the rootfs.)
 */
#include "cng/broker.h"
#include "cng/ipcreg.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

/* ---- namespace key ------------------------------------------------------ */

static u64 g_session;

static u64 now_sec(void) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_REALTIME, &ts);
    return (u64)ts.tv_sec;
}

/* Monotonic milliseconds, for the loop's own timing: grace windows, reclaim
 * ticks and semtimedop deadlines must not move when the wall clock is set. */
static u64 now_ms(void) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
}

/* The root pid makes the nonce unique among live invocations; mixing in the
 * wall clock keeps a pid reused within a dying daemon's grace window from
 * rejoining the namespace it had last time. */
void cng_broker_seed_session(void) {
    struct cng_timespec ts = {0, 0};
    sys_clock_gettime(CNG_CLOCK_REALTIME, &ts);
    g_session = ((u64)sys_getpid() << 32) ^
                ((u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec);
    if (!g_session)
        g_session = 1; /* 0 means "per-rootfs" in broker_addr */
}

static u64 session(void) {
    if (!g_session)
        cng_broker_seed_session(); /* no cng_run ran: a -t self-test */
    return g_session;
}

u32 cng_broker_key_hash(const char *s) {
    u32 h = 2166136261u;
    for (; *s; s++) {
        h ^= (u8)*s;
        h *= 16777619u;
    }
    return h;
}

/* Abstract rendezvous name (path[0] == NUL => no filesystem entry), keyed by
 * uid plus either the rootfs hash (`sess` == 0: --shared-proc, one daemon per
 * rootfs) or the per-invocation nonce. The version tag covers the request
 * protocol AND struct proc_ent's layout: bump it if either changes, so a
 * differently versioned build never joins an incompatible daemon. (v2 added the
 * semaphore and message-queue operations, which widened struct cng_breq.)
 * Returns the sockaddr length. */
static unsigned broker_addr(struct cng_sockaddr_un *a, u32 hash, u64 sess) {
    memset(a, 0, sizeof *a);
    a->family = CNG_AF_UNIX;
    size_t n;
    if (sess)
        n = cng_snprintf(a->path + 1, sizeof a->path - 1, "cng-ipc.v2.%u.s%016llx",
                         (unsigned)sys_getuid(), (unsigned long long)sess);
    else
        n = cng_snprintf(a->path + 1, sizeof a->path - 1, "cng-ipc.v2.%u.%08x",
                         (unsigned)sys_getuid(), hash);
    /* cng_snprintf reports what the format would have produced, so clamp to
     * what it actually wrote before this becomes an addrlen. These names are
     * ~40 bytes against sun_path's 108 and cannot overflow, but an addrlen past
     * the buffer would be the kind of thing nobody notices until it is. */
    if (n > sizeof a->path - 2)
        n = sizeof a->path - 2;
    return (unsigned)(sizeof a->family + 1 + n);
}

/* This process's namespace: per-rootfs under --shared-proc (the same daemon
 * procreg.c fetches its table from), else per-invocation. */
static unsigned ipc_addr(struct cng_sockaddr_un *a) {
    if (cng_g_shared_proc && cng_g_fs && cng_g_fs->rootfs[0])
        return broker_addr(a, cng_broker_key_hash(cng_g_fs->rootfs), 0);
    return broker_addr(a, 0, session());
}

/* ---- transport ---------------------------------------------------------- */

/* Exactly `len` bytes in each direction, looping over short transfers. The
 * variable-length payloads (a semop's operation vector, a message's bytes)
 * ride behind their fixed request on the same stream, so both ends have to be
 * able to insist on a whole one. MSG_NOSIGNAL on the write: a dead peer must
 * yield EPIPE, never a signal — a host SIGPIPE here would be indistinguishable
 * from one meant for the guest. */
int cng_broker_read_full(int fd, void *buf, unsigned len) {
    char *p = (char *)buf;
    while (len) {
        long n = sys_read(fd, p, len);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (unsigned)n;
    }
    return 0;
}

int cng_broker_write_full(int fd, const void *buf, unsigned len) {
    const char *p = (const char *)buf;
    while (len) {
        long n = CNG_SYS(__NR_sendto, fd, p, len, CNG_MSG_NOSIGNAL, 0, 0);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (unsigned)n;
    }
    return 0;
}

/* Send a fixed-size payload plus an optional fd (fd < 0: none) over a connected
 * AF_UNIX stream; the fd rides as SCM_RIGHTS ancillary data. MSG_NOSIGNAL: a
 * dead peer must yield EPIPE, not kill the daemon. */
int cng_broker_send(int sock, const void *data, unsigned len, int fd) {
    struct cng_iovec iov = {(void *)data, len};
    struct {
        struct cng_cmsghdr h;
        int fd;
        int pad;
    } cm;
    struct cng_msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&cm, 0, sizeof cm);
    msg.iov = &iov;
    msg.iovlen = 1;
    if (fd >= 0) {
        cm.h.len = sizeof(struct cng_cmsghdr) + sizeof(int); /* CMSG_LEN(4) */
        cm.h.level = CNG_SOL_SOCKET;
        cm.h.type = CNG_SCM_RIGHTS;
        cm.fd = fd;
        msg.control = &cm;
        msg.controllen = sizeof cm; /* CMSG_SPACE(4): header + padded data */
    }
    long r;
    do {
        r = CNG_SYS(__NR_sendmsg, sock, &msg, CNG_MSG_NOSIGNAL, 0, 0, 0);
    } while (r == -EINTR);
    if (r < 0)
        return -1;
    /* A stream socket may take less than the whole payload; on a local socket
     * with an empty buffer it never does, but a short write must not desync the
     * protocol. The ancillary fd went with the first byte either way. */
    while ((unsigned)r < len) {
        long w = cng_write_all(sock, (const char *)data + r, len - (unsigned)r);
        if (w <= 0)
            return -1;
        r += w;
    }
    return 0;
}

/* Receive a fixed-size payload plus an optional fd; *fd_out gets it or -1. */
int cng_broker_recv(int sock, void *data, unsigned len, int *fd_out) {
    if (fd_out)
        *fd_out = -1;
    struct cng_iovec iov = {data, len};
    struct {
        struct cng_cmsghdr h;
        int fd;
        int pad;
    } cm;
    struct cng_msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&cm, 0, sizeof cm);
    cm.fd = -1;
    msg.iov = &iov;
    msg.iovlen = 1;
    msg.control = &cm;
    msg.controllen = sizeof cm;
    long r;
    do {
        r = CNG_SYS(__NR_recvmsg, sock, &msg, 0, 0, 0, 0);
    } while (r == -EINTR);
    if (r <= 0)
        return -1;
    if (fd_out && cm.h.level == CNG_SOL_SOCKET && cm.h.type == CNG_SCM_RIGHTS &&
        cm.h.len == sizeof(struct cng_cmsghdr) + sizeof(int))
        *fd_out = cm.fd;
    while ((unsigned)r < len) { /* top up a short stream read (see broker_send) */
        long n = sys_read(sock, (char *)data + r, len - (unsigned)r);
        if (n <= 0) {
            /* The ancillary fd arrived with the first byte, so a message that
             * fails to complete has already installed one — and host fd ==
             * guest fd here, so leaving it open hands the guest a descriptor
             * onto whatever it named (a segment's backing memfd). The peer
             * dying mid-message and the 2 s SO_RCVTIMEO both land here. */
            if (fd_out && *fd_out >= 0) {
                sys_close(*fd_out);
                *fd_out = -1;
            }
            return -1;
        }
        r += n;
    }
    return 0;
}

/* ---- shared state locations --------------------------------------------- */

const char *cng_broker_env(const char *name) {
    size_t nl = strlen(name);
    for (char **e = cng_g_host_envp; e && *e; e++)
        if (!strncmp(*e, name, nl) && (*e)[nl] == '=' && (*e)[nl + 1])
            return *e + nl + 1;
    return 0;
}

const char *cng_broker_shared_dir(void) {
    static const char *fixed[] = {"/dev/shm", 0, 0, "/data/local/tmp", "/tmp"};
    fixed[1] = cng_broker_env("XDG_RUNTIME_DIR");
    fixed[2] = cng_broker_env("TMPDIR");
    for (unsigned i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
        if (!fixed[i])
            continue;
        if (CNG_SYS(__NR_faccessat, CNG_AT_FDCWD, fixed[i], 2 /*W_OK*/, 0, 0,
                    0) == 0)
            return fixed[i];
    }
    return 0;
}

/* ---- daemon: the System V shm registry ---------------------------------- */

#define SHM_SEG_MAX   1024 /* concurrent segments in one namespace */
#define SHM_ATT_TRACK 32   /* per-segment attacher slots (death reclaim) */

struct seg_att {
    s32 pid;
    u64 start; /* the attacher's starttime: its incarnation */
    u32 n;     /* live attaches held by that pid */
};

struct seg {
    int used;
    s32 shmid, key; /* key 0 = private or removed: unfindable by key */
    u64 size;       /* the size as requested, which is what IPC_STAT reports */
    u32 mode;       /* permission bits (low 9) */
    u32 uid, gid, cuid, cgid;
    s32 cpid, lpid;
    s64 atime, dtime, ctime;
    int memfd;      /* the daemon-owned backing fd */
    char path[128]; /* file-tier backing path to unlink, else "" */
    u64 nattch;
    int rmid; /* IPC_RMID pending: free at the last detach */
    struct seg_att att[SHM_ATT_TRACK];
    int natt;
};

static struct seg *g_seg; /* SHM_SEG_MAX entries, mmap'd by the daemon */
static s32 g_next_shmid = 1;

static struct seg *shm_find(s32 shmid) {
    if (shmid <= 0)
        return 0;
    for (int i = 0; i < SHM_SEG_MAX; i++)
        if (g_seg[i].used && g_seg[i].shmid == shmid)
            return &g_seg[i];
    return 0;
}

static void shm_free(struct seg *s) {
    if (s->memfd >= 0)
        sys_close(s->memfd);
    if (s->path[0])
        CNG_SYS(__NR_unlinkat, CNG_AT_FDCWD, s->path, 0, 0, 0, 0);
    memset(s, 0, sizeof *s); /* used = 0 */
}

/* The standard SysV access triad, advisory in this single-user sandbox: the
 * guest's (possibly faked) credentials ride in the request and there is no
 * host-kernel enforcement behind them. Guest root passes everything. */
static int shm_permitted(const struct seg *s, u32 uid, u32 gid, int need_w,
                         int need_x) {
    if (uid == 0)
        return 1;
    u32 m = s->mode;
    unsigned r, w, x;
    if (uid == s->uid || uid == s->cuid) {
        r = m & 0400;
        w = m & 0200;
        x = m & 0100;
    } else if (gid == s->gid || gid == s->cgid) {
        r = m & 0040;
        w = m & 0020;
        x = m & 0010;
    } else {
        r = m & 0004;
        w = m & 0002;
        x = m & 0001;
    }
    return r && (!need_w || w) && (!need_x || x);
}

static int shm_owner(const struct seg *s, u32 uid) {
    return uid == 0 || uid == s->uid || uid == s->cuid;
}

static void shm_att_add(struct seg *s, s32 pid) {
    for (int i = 0; i < s->natt; i++)
        if (s->att[i].pid == pid) {
            s->att[i].n++;
            return;
        }
    if (s->natt < SHM_ATT_TRACK) {
        s->att[s->natt].pid = pid;
        s->att[s->natt].start = cng_proc_starttime(pid, 0);
        s->att[s->natt].n = 1;
        s->natt++;
    }
    /* overflow (> SHM_ATT_TRACK distinct attachers): untracked — nattch still
     * counts it, but this attacher's death is not reclaimed precisely; the
     * segment is freed at namespace-idle GC instead. */
}

static void shm_att_del(struct seg *s, s32 pid) {
    for (int i = 0; i < s->natt; i++)
        if (s->att[i].pid == pid) {
            if (--s->att[i].n == 0)
                s->att[i] = s->att[--s->natt];
            return;
        }
}

/* Drop the attaches of every process that died without detaching them.
 *
 * arm64chroot detaches from its exit/exit_group handlers and needs this only
 * for a SIGKILL. chroot-ng traps neither exit path (see the note in
 * procreg.c), so here it is the *normal* way an attach goes away, and it has to
 * be accurate enough that a guest reading nattch right after waitpid() sees
 * what a real kernel would. Hence the zombie test: a process that has exited
 * but not yet been reaped still owns its pid — so its starttime still matches —
 * yet the kernel has already torn down its mappings. */
static void shm_reclaim_seg(struct seg *s) {
    for (int j = 0; j < s->natt;) {
        int zombie = 0;
        u64 start = cng_proc_starttime(s->att[j].pid, &zombie);
        if (start != s->att[j].start || zombie) {
            s->nattch = s->nattch >= s->att[j].n ? s->nattch - s->att[j].n : 0;
            s->att[j] = s->att[--s->natt];
        } else {
            j++;
        }
    }
    if (s->rmid && s->nattch == 0)
        shm_free(s);
}

static void shm_reclaim_all(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++)
        if (g_seg[i].used)
            shm_reclaim_seg(&g_seg[i]);
}

static s32 shm_alloc_id(void) {
    for (int tries = 0; tries < SHM_SEG_MAX * 4; tries++) {
        s32 id = g_next_shmid++;
        if (g_next_shmid <= 0)
            g_next_shmid = 1;
        if (id > 0 && !shm_find(id))
            return id;
    }
    return -1;
}

/* Create a segment's backing: an anonymous memfd (the normal, Android-safe
 * path) or — where memfd_create is unavailable, or CNG_SHM_FORCE_FILE forces it
 * for a test — a file in the first writable dir. `path_out` gets the file path
 * (to unlink on free) or "". Returns the fd, or -1 (no backing: the caller
 * fails the syscall rather than handing back memory nobody can share). */
static int shm_make_backing(u64 size, s32 shmid, char *path_out, size_t path_sz) {
    path_out[0] = '\0';
    long fd = -1;
    if (!cng_broker_env("CNG_SHM_FORCE_FILE"))
        fd = sys_memfd_create("cng-shm", CNG_MFD_CLOEXEC);
    if (fd < 0) {
        const char *dir = cng_broker_shared_dir();
        if (!dir)
            return -1;
        size_t n = cng_snprintf(path_out, path_sz, "%s/chroot-ng-shm.v1.%u.%d",
                                dir, (unsigned)sys_getuid(), (int)shmid);
        if (n >= path_sz) {
            path_out[0] = '\0';
            return -1;
        }
        fd = sys_openat(CNG_AT_FDCWD, path_out,
                        CNG_O_RDWR | CNG_O_CREAT | CNG_O_TRUNC | CNG_O_CLOEXEC,
                        0600);
        if (fd < 0) {
            path_out[0] = '\0';
            return -1;
        }
    }
    /* Back the whole page span an attacher's mmap will round up to, so a store
     * past the requested size never faults SIGBUS beyond end-of-file. seg->size
     * keeps the requested size, which is what IPC_STAT must report. */
    if (sys_ftruncate((int)fd, (long)cng_page_up(size)) != 0) {
        sys_close((int)fd);
        if (path_out[0]) {
            CNG_SYS(__NR_unlinkat, CNG_AT_FDCWD, path_out, 0, 0, 0, 0);
            path_out[0] = '\0';
        }
        return -1;
    }
    return (int)fd;
}

static s32 shm_do_get(const struct cng_breq *q) {
    s64 now = (s64)now_sec();
    if (q->key != 0) { /* keyed: find an existing segment first */
        for (int i = 0; i < SHM_SEG_MAX; i++) {
            struct seg *s = &g_seg[i];
            if (!s->used || s->key != q->key)
                continue;
            if ((q->arg & CNG_IPC_CREAT) && (q->arg & CNG_IPC_EXCL))
                return -EEXIST;
            if (q->size && s->size < q->size)
                return -EINVAL;
            if (!shm_permitted(s, q->uid, q->gid, 0, 0))
                return -EACCES;
            return s->shmid;
        }
        if (!(q->arg & CNG_IPC_CREAT))
            return -ENOENT;
    }
    /* Zero is EINVAL, and so is a size no mapping could represent: the page
     * round-up on the attach side wraps to 0 for anything within a page of
     * 2^64, and the emulation's own IPC_INFO advertises shmmax as
     * 0x7fffffffffffffff. The kernel answers EINVAL for an over-large size
     * too, so this is its answer as well as the only safe one. */
    if (q->size == 0 ||
        q->size > (u64)0x7fffffffffffffffULL - (cng_page_size - 1))
        return -EINVAL;
    int slot = -1;
    for (int i = 0; i < SHM_SEG_MAX; i++)
        if (!g_seg[i].used) {
            slot = i;
            break;
        }
    if (slot < 0)
        return -ENOSPC;
    s32 id = shm_alloc_id();
    if (id < 0)
        return -ENOSPC;
    char path[128];
    int fd = shm_make_backing(q->size, id, path, sizeof path);
    if (fd < 0)
        return -ENOSPC; /* fail loud: no backing available */
    struct seg *s = &g_seg[slot];
    memset(s, 0, sizeof *s);
    s->used = 1;
    s->shmid = id;
    s->key = q->key;
    s->size = q->size;
    s->mode = q->arg & 0777;
    s->uid = s->cuid = q->uid;
    s->gid = s->cgid = q->gid;
    s->cpid = q->pid;
    s->ctime = now;
    s->memfd = fd;
    cng_strlcpy(s->path, path, sizeof s->path);
    return id;
}

static s32 shm_do_at(const struct cng_breq *q, struct cng_bresp *r, int *outfd) {
    struct seg *s = shm_find(q->id);
    if (!s)
        return -EINVAL;
    /* A plain attach is a write attach; SHM_RDONLY asks for read only, and
     * SHM_EXEC additionally asks for execute — each checked against the
     * segment's mode the way the kernel checks them. */
    if (!shm_permitted(s, q->uid, q->gid, !(q->arg & CNG_SHMAT_RDONLY),
                       q->arg & CNG_SHMAT_EXEC))
        return -EACCES;
    *outfd = s->memfd; /* SCM_RIGHTS dups it into the caller */
    s->nattch++;
    shm_att_add(s, q->pid);
    s->lpid = q->pid;
    s->atime = (s64)now_sec();
    r->size = s->size;
    return 0;
}

static s32 shm_do_dt(const struct cng_breq *q) {
    struct seg *s = shm_find(q->id);
    if (!s)
        return 0; /* already gone: a detach is a no-op */
    if (s->nattch)
        s->nattch--;
    shm_att_del(s, q->pid);
    s->lpid = q->pid;
    s->dtime = (s64)now_sec();
    if (s->rmid && s->nattch == 0)
        shm_free(s);
    return 0;
}

static s32 shm_do_fork(const struct cng_breq *q) {
    struct seg *s = shm_find(q->id);
    if (!s)
        return 0;
    s->nattch++;
    shm_att_add(s, q->pid); /* q->pid is the child */
    return 0;
}

static void shm_fill_stat(struct cng_bresp *r, const struct seg *s) {
    r->key = s->key;
    r->size = s->size;
    r->nattch = s->nattch;
    r->mode = s->mode;
    r->uid = s->uid;
    r->gid = s->gid;
    r->cuid = s->cuid;
    r->cgid = s->cgid;
    r->cpid = s->cpid;
    r->lpid = s->lpid;
    r->atime = s->atime;
    r->dtime = s->dtime;
    r->ctime = s->ctime;
}

static s32 shm_do_ctl(const struct cng_breq *q, struct cng_bresp *r) {
    /* Index-based and global commands, which is how ipcs enumerates:
     * SHM_STAT/SHM_STAT_ANY take a kernel-array index (not a shmid) and return
     * the shmid; SHM_INFO/IPC_INFO return the highest used index (-1 for none)
     * plus the aggregate. */
    switch (q->arg) {
    case CNG_SHM_INFO:
    case CNG_IPC_INFO: {
        shm_reclaim_all();
        int used = 0;
        s32 maxidx = -1;
        u64 tot = 0;
        for (int i = 0; i < SHM_SEG_MAX; i++)
            if (g_seg[i].used) {
                used++;
                maxidx = i;
                tot += cng_page_up(g_seg[i].size) / cng_page_size;
            }
        r->info_used = used;
        r->info_tot = tot;
        return maxidx; /* -1 when none, matching the kernel */
    }
    case CNG_SHM_STAT:
    case CNG_SHM_STAT_ANY: {
        s32 idx = q->id;
        if (idx < 0 || idx >= SHM_SEG_MAX || !g_seg[idx].used)
            return -EINVAL;
        struct seg *s = &g_seg[idx];
        if (q->arg == CNG_SHM_STAT && !shm_permitted(s, q->uid, q->gid, 0, 0))
            return -EACCES;
        shm_reclaim_seg(s);
        if (!s->used)
            return -EINVAL; /* the reclaim freed a removed segment */
        shm_fill_stat(r, s);
        return s->shmid; /* the id the caller displays */
    }
    }

    struct seg *s = shm_find(q->id);
    if (!s)
        return -EINVAL;
    switch (q->arg) {
    case CNG_IPC_STAT:
        if (!shm_permitted(s, q->uid, q->gid, 0, 0))
            return -EACCES;
        shm_reclaim_seg(s);
        if (!s->used)
            return -EINVAL;
        shm_fill_stat(r, s);
        return 0;
    case CNG_IPC_SET:
        if (!shm_owner(s, q->uid))
            return -EPERM;
        s->mode = (s->mode & ~0777u) | (q->set_mode & 0777);
        s->uid = q->set_uid;
        s->gid = q->set_gid;
        s->ctime = (s64)now_sec();
        return 0;
    case CNG_IPC_RMID:
        if (!shm_owner(s, q->uid))
            return -EPERM;
        s->key = 0; /* unfindable by key henceforth */
        s->rmid = 1;
        shm_reclaim_seg(s); /* frees it if the last attacher is already gone */
        return 0;
    case CNG_SHM_LOCK:
    case CNG_SHM_UNLOCK:
        /* Owner-checked no-ops. The kernel pins the segment's pages against
         * swap; there is nothing here to pin (the pages belong to a memfd the
         * broker holds) and no way to ask the host to, since the guest cannot
         * reach the segment through any host IPC object. Reporting the
         * refusal the caller would get from an unprivileged kernel would be
         * the worse answer: the owner is allowed to lock, and callers treat
         * success as "it will stay resident", which under a memfd it does
         * unless the host swaps — exactly the guarantee we could not have
         * strengthened anyway. arm64chroot answers EINVAL here. */
        if (!shm_owner(s, q->uid))
            return -EPERM;
        return 0;
    default:
        return -EINVAL;
    }
}

/* Is any segment still anchoring the namespace? A tracked live attacher, or an
 * un-removed segment whose creator is alive and may yet attach it. */
static int shm_any_live(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++) {
        struct seg *s = &g_seg[i];
        if (!s->used)
            continue;
        if (s->natt > 0)
            return 1;
        if (!s->rmid && s->cpid > 0 && cng_proc_starttime(s->cpid, 0) != 0)
            return 1;
    }
    return 0;
}

static void shm_free_all(void) {
    for (int i = 0; i < SHM_SEG_MAX; i++)
        if (g_seg[i].used)
            shm_free(&g_seg[i]);
}

/* ---- daemon: main loop -------------------------------------------------- */

/* The procreg table memfd, created on the first CNG_REQ_TAB. Lazy rather than
 * eager (arm64chroot creates it up front for a --shared-proc daemon) so that a
 * daemon started by the shm side can still serve a later --shared-proc joiner
 * instead of leaving it to spin and degrade. */
static int tab_memfd(void **tab_out) {
    static int memfd = -1;
    static void *tab;
    if (memfd < 0) {
        long fd = sys_memfd_create("cng-procreg", CNG_MFD_CLOEXEC);
        if (fd < 0)
            return -1;
        unsigned long size = cng_procreg_table_size();
        if (sys_ftruncate((int)fd, (long)size) != 0) {
            sys_close((int)fd);
            return -1;
        }
        void *p = sys_mmap(0, size, CNG_PROT_READ | CNG_PROT_WRITE,
                           CNG_MAP_SHARED, (int)fd, 0);
        if (p == CNG_MAP_FAILED || cng_is_err((long)p)) {
            sys_close((int)fd);
            return -1;
        }
        memfd = (int)fd;
        tab = p;
    }
    *tab_out = tab;
    return memfd;
}

/* Serve one connected client: dispatch the request and reply. Returns 1 when the
 * connection has been parked in a waiter slot (a blocking semop/msgsnd/msgrcv),
 * in which case the caller must not close it. */
static int ipc_serve(int cfd, const struct cng_breq *q, void **tab) {
    struct cng_bresp r;
    memset(&r, 0, sizeof r);
    int outfd = -1;
    if (q->op == CNG_REQ_TAB) {
        outfd = tab_memfd(tab);
        r.ret = outfd < 0 ? -ENOSYS : 0;
        cng_broker_send(cfd, &r, sizeof r, outfd);
        return 0;
    }
    switch (q->op) {
    case CNG_REQ_SHMGET:
        r.ret = shm_do_get(q);
        break;
    case CNG_REQ_SHMAT:
        r.ret = shm_do_at(q, &r, &outfd);
        break;
    case CNG_REQ_SHMDT:
        r.ret = shm_do_dt(q);
        break;
    case CNG_REQ_SHMFORK:
        r.ret = shm_do_fork(q);
        break;
    case CNG_REQ_SHMCTL:
        r.ret = shm_do_ctl(q, &r);
        break;
    default:
        /* Semaphores and message queues stream payloads and can park, so they
         * drive the connection themselves (ipcreg.c). */
        return cng_ipc_serve(cfd, q);
    }
    cng_broker_send(cfd, &r, sizeof r, outfd);
    return 0;
}

/* How many fds the poll array holds: the listener plus one per parked waiter. */
#define BROKER_POLL_MAX (1 + CNG_IPC_WAITER_MAX)

#define BROKER_GRACE_MS 10000 /* linger this long past the last user's exit */
#define BROKER_TICK_MS  1000  /* reclaim cadence while waiters or undo exist */

/* Daemon main loop; never returns. Owns the rendezvous socket, the table memfd
 * (once asked for), every segment backing and all semaphore / message-queue
 * state, and exits once nothing — a live guest, segment, set, queue, undo row or
 * parked waiter — has anchored the namespace for the grace window.
 *
 * The loop watches the listener and every parked waiter's connection at once,
 * which is what lets a blocking semop sleep without wedging the daemon for
 * everyone else. A timed wait's deadline bounds the poll directly, so it expires
 * on time rather than at tick granularity; the tick is only for the /proc reads
 * that notice a dead waiter or apply a dead process's SEM_UNDO. */
static _Noreturn void broker_main(struct cng_sockaddr_un *a, unsigned al) {
    long ls = CNG_SYS(__NR_socket, CNG_AF_UNIX,
                      CNG_SOCK_STREAM | CNG_SOCK_CLOEXEC, 0, 0, 0, 0);
    if (ls < 0)
        sys_exit_group(0);
    if (CNG_SYS(__NR_bind, ls, a, al, 0, 0, 0) != 0)
        sys_exit_group(0); /* lost the spawn race: the winner serves */
    if (CNG_SYS(__NR_listen, ls, 64, 0, 0, 0, 0) != 0)
        sys_exit_group(0);
    /* Every parked waiter holds one fd, so lift the soft descriptor limit to the
     * hard one: a default soft limit must not starve accept() under sleepers. */
    struct cng_rlimit rl;
    if (sys_prlimit64(0, CNG_RLIMIT_NOFILE, 0, &rl) == 0 && rl.cur < rl.max) {
        rl.cur = rl.max;
        sys_prlimit64(0, CNG_RLIMIT_NOFILE, &rl, 0);
    }
    void *p = sys_mmap(0, (unsigned long)SHM_SEG_MAX * sizeof(struct seg),
                       CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        sys_exit_group(0); /* clients keep missing and fail loud */
    g_seg = (struct seg *)p;
    void *tab = 0;

    static struct cng_pollfd pf[BROKER_POLL_MAX];
    s64 last_active = (s64)now_ms(), last_tick = last_active;
    for (;;) {
        s64 now = (s64)now_ms();
        pf[0].fd = (int)ls;
        pf[0].events = CNG_POLLIN;
        pf[0].revents = 0;
        s64 next = last_active + BROKER_GRACE_MS - now; /* the idle-exit check */
        if (cng_ipc_pending() && next > BROKER_TICK_MS)
            next = BROKER_TICK_MS;
        int nfds = cng_ipc_poll_add(pf, 1, BROKER_POLL_MAX, now, &next);
        if (next < 0)
            next = 0;
        struct cng_timespec to = {next / 1000, (next % 1000) * 1000000};
        long r = CNG_SYS(__NR_ppoll, pf, nfds, &to, 0, 8 /*sigsetsize*/, 0);
        if (r < 0) {
            if (r == -EINTR)
                continue;
            break;
        }
        now = (s64)now_ms();
        if (r > 0) {
            last_active = now;
            /* Parked connections first: cancels, deaths, protocol garbage. */
            cng_ipc_poll_ready(pf, 1, nfds);
            if (pf[0].revents & CNG_POLLIN) {
                long c = CNG_SYS(__NR_accept4, ls, 0, 0, CNG_SOCK_CLOEXEC, 0, 0);
                if (c >= 0) {
                    struct cng_timeval tv = {2, 0}; /* never wedge on a client */
                    CNG_SYS(__NR_setsockopt, c, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO,
                            &tv, sizeof tv, 0);
                    struct cng_breq q;
                    int parked = 0;
                    if (cng_broker_recv((int)c, &q, sizeof q, 0) == 0)
                        parked = ipc_serve((int)c, &q, &tab);
                    if (!parked)
                        sys_close((int)c);
                }
            }
            cng_ipc_rescan(); /* any request served may have unblocked a waiter */
        }
        cng_ipc_expire(now); /* cheap: no /proc reads */
        if (cng_ipc_pending() && now - last_tick >= BROKER_TICK_MS) {
            last_tick = now;
            cng_ipc_reclaim();
        }
        if (r == 0 && now - last_active >= BROKER_GRACE_MS) {
            /* Idle grace elapsed: leave once nothing anchors the namespace. */
            shm_reclaim_all();
            cng_ipc_reclaim();
            if (!(tab && cng_procreg_table_live(tab)) && !shm_any_live() &&
                !cng_ipc_any_live())
                break;
            last_active = now; /* still anchored: re-arm the grace window */
        }
    }
    shm_free_all();
    cng_ipc_free_all();
    sys_exit_group(0);
}

/* ---- daemon: spawn ------------------------------------------------------ */

/* Close every fd inherited from the launching process except 0/1/2 (already
 * pointed at /dev/null), so the detached daemon holds nothing of the caller's —
 * no tty, no pipe an $(...) capture could wait on, no guest file. A raw
 * getdents64 walk of /proc/self/fd touches only the fds actually open. */
static void broker_close_inherited(void) {
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc/self/fd",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0) {
        for (int fd = 3; fd < 1024; fd++)
            sys_close(fd);
        return;
    }
    char buf[2048];
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, dfd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        for (long o = 0; o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            int fd = 0;
            for (; *nm >= '0' && *nm <= '9'; nm++)
                fd = fd * 10 + (*nm - '0');
            if (*nm == '\0' && fd >= 3 && fd != (int)dfd)
                sys_close(fd);
            o += reclen;
        }
    }
    sys_close((int)dfd);
}

/* Spawn the daemon as a detached grandchild (double fork + setsid: reparented
 * to init, own session, immune to the shell's job control). Idempotent under
 * races — a loser's bind() fails and it exits. The parent returns at once and
 * retries connect().
 *
 * The shm side reaches this from inside the SIGSYS handler of a guest that may
 * be multithreaded: fork clones only the calling thread, and everything the
 * daemon then runs is our own gate-issued syscalls, so it is safe there. The
 * one wart is the wait4 for the middle child — a guest sitting in wait4(-1) on
 * another thread can reap it first and see an exit status it never spawned. */
static void broker_spawn(struct cng_sockaddr_un *a, unsigned al) {
    long p = sys_fork();
    if (p < 0)
        return;
    if (p > 0) {
        sys_wait4((int)p, 0, 0, 0); /* reap the middle child */
        return;
    }
    CNG_SYS(__NR_setsid, 0, 0, 0, 0, 0, 0);
    p = sys_fork();
    if (p != 0)
        sys_exit_group(0); /* middle exits (or fork failed): grandchild stays */
    long nul = sys_openat(CNG_AT_FDCWD, "/dev/null", CNG_O_RDWR, 0);
    if (nul >= 0) {
        CNG_SYS(__NR_dup3, nul, 0, 0, 0, 0, 0);
        CNG_SYS(__NR_dup3, nul, 1, 0, 0, 0, 0);
        CNG_SYS(__NR_dup3, nul, 2, 0, 0, 0, 0);
    }
    broker_close_inherited();
    broker_main(a, al); /* never returns */
}

/* ---- client ------------------------------------------------------------- */

/* Connect to the namespace daemon, starting it if nobody has. Returns a
 * connected socket or -1. */
static int broker_connect(struct cng_sockaddr_un *a, unsigned al) {
    int spawns = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        long s = CNG_SYS(__NR_socket, CNG_AF_UNIX,
                         CNG_SOCK_STREAM | CNG_SOCK_CLOEXEC, 0, 0, 0, 0);
        if (s < 0)
            return -1;
        struct cng_timeval tv = {2, 0}; /* never block on a wedged daemon */
        CNG_SYS(__NR_setsockopt, s, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO, &tv,
                sizeof tv, 0);
        CNG_SYS(__NR_setsockopt, s, CNG_SOL_SOCKET, CNG_SO_SNDTIMEO, &tv,
                sizeof tv, 0);
        long cr = CNG_SYS(__NR_connect, s, a, al, 0, 0, 0);
        if (cr == 0)
            return (int)s;
        sys_close((int)s);
        if (cr != -ECONNREFUSED && cr != -ENOENT)
            return -1; /* unexpected (sandbox?): give up */
        /* Start a daemon on the first miss and retry connect while it binds;
         * re-spawn only occasionally as a safety net (a loser of the bind race
         * whose winner then died). */
        if (spawns == 0 || attempt % 16 == 0) {
            broker_spawn(a, al);
            spawns++;
        }
        struct cng_timespec ms = {0, 1000000}; /* 1 ms for the bind */
        CNG_SYS(__NR_nanosleep, &ms, 0, 0, 0, 0, 0);
    }
    return -1; /* pathological churn */
}

int cng_broker_open(struct cng_breq *q) {
    /* The daemon has no other way to know who is asking, and the permission
     * checks are against the guest's (possibly faked) identity, not the host's. */
    q->pid = (s32)sys_getpid();
    q->uid = cng_g_fake_id ? cng_g_cred.euid : (u32)sys_geteuid();
    q->gid = cng_g_fake_id ? cng_g_cred.egid : (u32)sys_getegid();
    struct cng_sockaddr_un a;
    unsigned al = ipc_addr(&a);
    return broker_connect(&a, al);
}

int cng_broker_rpc(struct cng_breq *q, struct cng_bresp *r, int *fd_out) {
    int s = cng_broker_open(q);
    if (s < 0)
        return -1;
    int ok = -1;
    if (cng_broker_send(s, q, sizeof *q, -1) == 0 &&
        cng_broker_recv(s, r, sizeof *r, fd_out) == 0)
        ok = 0;
    sys_close(s); /* transient: keep no persistent broker fd */
    return ok;
}

int cng_broker_table_fd(const char *rootfs_key) {
    /* Fail fast where memfd is unavailable (pre-3.17 kernel, or a seccomp
     * filter blocking it) so we degrade without spawning a doomed daemon. */
    long probe = sys_memfd_create("cng-procreg", CNG_MFD_CLOEXEC);
    if (probe < 0)
        return -1;
    sys_close((int)probe);

    struct cng_sockaddr_un a;
    unsigned al = broker_addr(&a, cng_broker_key_hash(rootfs_key), 0);
    int s = broker_connect(&a, al);
    if (s < 0)
        return -1;
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_TAB;
    q.pid = (s32)sys_getpid();
    struct cng_bresp r;
    int memfd = -1;
    if (cng_broker_send(s, &q, sizeof q, -1) != 0 ||
        cng_broker_recv(s, &r, sizeof r, &memfd) != 0) {
        sys_close(s);
        if (memfd >= 0)
            sys_close(memfd);
        return -1;
    }
    sys_close(s);
    if (r.ret < 0 && memfd >= 0) {
        sys_close(memfd);
        memfd = -1;
    }
    return memfd;
}
