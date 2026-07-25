/* Guest-PID registry (see include/cng/procreg.h). Freestanding: raw syscalls,
 * no allocator, no locks — a CAS-claimed slot per process and a seqlock around
 * the payload. */
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

struct proc_ent {
    u32 seq;   /* seqlock: odd = write in progress */
    s32 pid;   /* 0 = free, claimed by CAS */
    u64 start; /* /proc/<pid>/stat starttime: the pid-reuse guard */
    u32 cmd_len, env_len, auxv_len;
    u16 exe_len, cwd_len;
    char cmd[CNG_PROCREG_CMDLINE];  /* NUL-joined guest argv */
    char env[CNG_PROCREG_ENVIRON];  /* NUL-joined guest environ */
    char auxv[CNG_PROCREG_AUXV];    /* raw guest auxv block */
    char exe[CNG_PROCREG_PATH];     /* canonical guest exe path */
    char cwd[CNG_PROCREG_PATH];     /* canonical guest cwd */
};

static struct proc_ent *g_tab; /* MAP_SHARED region, or NULL if unavailable */
static int g_tab_n;

/* starttime, field 22 of /proc/<pid>/stat: skip past the last ')' (comm may
 * contain spaces and parens), then take the 20th field after it. 0 when the
 * process is gone or /proc is unreadable — which is also how a dead slot is
 * recognized, so a missing /proc only costs fidelity, never correctness.
 *
 * Opened as dir-then-openat("stat") rather than by full path. On a real
 * kernel that is the same file; under qemu-user (the dev workflow) it is the
 * only route to the truth for our own pid: qemu realpath()s an open's path
 * and serves every absolute spelling of the caller's own stat from a
 * synthesized copy whose starttime is frozen at emulator startup — which a
 * fork inherits, so a child's self-sample would disagree with every other
 * process's read of the same pid and the registry's starttime checks would
 * misjudge the child as stale. The relative form is never intercepted. */
static u64 proc_starttime(int pid) {
    char path[64];
    size_t n = cng_strlcpy(path, "/proc/", sizeof path);
    char num[16];
    int ni = 0;
    int v = pid;
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0 && ni < 15);
    while (ni > 0 && n < sizeof path - 1)
        path[n++] = num[--ni];
    path[n] = '\0';

    long dfd = sys_openat(CNG_AT_FDCWD, path,
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return 0;
    long fd = sys_openat((int)dfd, "stat", CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    sys_close((int)dfd);
    if (fd < 0)
        return 0;
    char buf[512];
    long r = sys_read((int)fd, buf, sizeof buf - 1);
    sys_close((int)fd);
    if (r <= 0)
        return 0;
    buf[r] = '\0';
    char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    p++;
    for (int field = 0; *p;) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        if (++field == 20) {
            u64 t = 0;
            for (; *p >= '0' && *p <= '9'; p++)
                t = t * 10 + (u64)(*p - '0');
            return t ? t : 1; /* 0 means "gone"; never report it for a live pid */
        }
        while (*p && *p != ' ')
            p++;
    }
    return 0;
}

/* ---- --shared-proc backing: broker daemon + named-file fallback ----------
 * Ported from arm64chroot's proctab.c (its unified IPC daemon minus the SysV
 * shm side — guests here use the host's IPC natively). A per-rootfs daemon
 * owns the table memfd and an abstract-namespace rendezvous socket, and hands
 * the memfd to each joining invocation over SCM_RIGHTS. Clients hold no
 * persistent broker fd (host fd == guest fd, so a held fd would be visible to
 * and closable by the guest); the daemon uses the registry itself as its
 * liveness signal and exits — freeing the memfd and the socket name — once no
 * guest of the rootfs has been alive for a grace window. All of this runs in
 * cng_procreg_init, before the seccomp filter installs and before any guest
 * fork, so the daemon fork is single-threaded and unfiltered. */

int cng_g_shared_proc = 0;
int cng_g_procreg_backing = CNG_PROCREG_B_NONE;

static u32 fnv1a32(const char *s) {
    u32 h = 2166136261u;
    for (; *s; s++) {
        h ^= (u8)*s;
        h *= 16777619u;
    }
    return h;
}

/* Abstract rendezvous name, keyed by uid + rootfs hash. The v1 tag covers the
 * request protocol AND struct proc_ent's layout: bump it if either changes so
 * a differently-versioned build never joins an incompatible daemon. Returns
 * the sockaddr length. */
static unsigned broker_addr(struct cng_sockaddr_un *a, u32 hash) {
    memset(a, 0, sizeof *a);
    a->family = CNG_AF_UNIX;
    /* a->path[0] stays NUL (abstract); the name follows from index 1. */
    int n = cng_snprintf(a->path + 1, sizeof a->path - 1, "cng-proc.v1.%u.%x",
                         (unsigned)sys_getuid(), hash);
    return (unsigned)(sizeof a->family + 1 + n);
}

/* One request byte, one reply byte + the table memfd as SCM_RIGHTS. */
#define BROKER_REQ_TAB 'P'
#define BROKER_ACK_TAB 'T'

/* Send one byte plus an fd (fd < 0: none) over a connected AF_UNIX stream.
 * MSG_NOSIGNAL: a dead peer must yield EPIPE, not kill the daemon. */
static int broker_send(int sock, char tag, int fd) {
    struct cng_iovec iov = {&tag, 1};
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
    return r < 0 ? -1 : 0;
}

/* Receive one byte plus an optional fd; *fd_out gets it or -1. */
static int broker_recv(int sock, char *tag, int *fd_out) {
    if (fd_out)
        *fd_out = -1;
    struct cng_iovec iov = {tag, 1};
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
    return 0;
}

/* Any guest of this rootfs still alive? The registry is the liveness signal: a
 * dead process's slot reads a dead starttime, so an all-dead scan means the
 * session is truly over. */
static int broker_table_live(struct proc_ent *tab) {
    for (int i = 0; i < CNG_PROCREG_MAX; i++) {
        s32 pid = __atomic_load_n(&tab[i].pid, __ATOMIC_ACQUIRE);
        if (pid > 0 && proc_starttime(pid) != 0)
            return 1;
    }
    return 0;
}

/* Close every fd inherited from the launching process except 0/1/2 (already
 * pointed at /dev/null), so the detached daemon holds nothing of the caller's
 * — no tty, no pipe an $(...) capture could wait on. A raw getdents64 walk of
 * /proc/self/fd touches only the fds actually open. */
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

/* Daemon main loop; never returns. Owns the socket and the table memfd,
 * serves each connector one handshake, and exits once no guest has anchored
 * the session for the grace window. */
static _Noreturn void broker_main(struct cng_sockaddr_un *a, unsigned al,
                                  unsigned long size) {
    long ls = CNG_SYS(__NR_socket, CNG_AF_UNIX,
                      CNG_SOCK_STREAM | CNG_SOCK_CLOEXEC, 0, 0, 0, 0);
    if (ls < 0)
        sys_exit_group(0);
    if (CNG_SYS(__NR_bind, ls, a, al, 0, 0, 0) != 0)
        sys_exit_group(0); /* lost the spawn race: the winner serves */
    if (CNG_SYS(__NR_listen, ls, 64, 0, 0, 0, 0) != 0)
        sys_exit_group(0);
    long memfd = sys_memfd_create("cng-procreg", CNG_MFD_CLOEXEC);
    if (memfd < 0)
        sys_exit_group(0); /* clients keep missing and degrade */
    if (sys_ftruncate((int)memfd, (long)size) != 0)
        sys_exit_group(0);
    void *p = sys_mmap(0, size, CNG_PROT_READ | CNG_PROT_WRITE, CNG_MAP_SHARED,
                       (int)memfd, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        sys_exit_group(0);
    struct proc_ent *tab = (struct proc_ent *)p;

    struct cng_pollfd pf = {(int)ls, CNG_POLLIN, 0};
    for (;;) {
        struct cng_timespec grace = {10, 0}; /* linger past the last exit */
        long r = CNG_SYS(__NR_ppoll, &pf, 1, &grace, 0, 8 /*sigsetsize*/, 0);
        if (r < 0) {
            if (r == -EINTR)
                continue;
            break;
        }
        if (r > 0 && (pf.revents & CNG_POLLIN)) {
            long c = CNG_SYS(__NR_accept4, ls, 0, 0, CNG_SOCK_CLOEXEC, 0, 0);
            if (c >= 0) {
                struct cng_timeval tv = {2, 0}; /* never wedge on a client */
                CNG_SYS(__NR_setsockopt, c, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO,
                        &tv, sizeof tv, 0);
                char req = 0;
                if (sys_read((int)c, &req, 1) == 1 && req == BROKER_REQ_TAB)
                    broker_send((int)c, BROKER_ACK_TAB, (int)memfd);
                sys_close((int)c);
            }
            continue; /* served a joiner: re-arm the full grace window */
        }
        if (!broker_table_live(tab))
            break; /* idle grace elapsed with nobody alive */
    }
    sys_exit_group(0);
}

/* Spawn the daemon as a detached grandchild (double fork + setsid: reparented
 * to init, own session, immune to the shell's job control). Idempotent under
 * races — a loser's bind() fails and it exits. The parent returns at once and
 * retries connect(). */
static void broker_spawn(struct cng_sockaddr_un *a, unsigned al,
                         unsigned long size) {
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
    broker_main(a, al, size); /* never returns */
}

/* Join (or start) the per-rootfs broker and map its memfd. Returns 1 with
 * g_tab set, 0 to degrade to the file / anonymous tiers. Holds no fd past
 * return. */
static int open_broker(const char *key, unsigned long size) {
    /* Fail fast where memfd is unavailable (pre-3.17 kernel, or a seccomp
     * filter blocking it) so we degrade without spawning a doomed daemon. */
    long probe = sys_memfd_create("cng-procreg", CNG_MFD_CLOEXEC);
    if (probe < 0)
        return 0;
    sys_close((int)probe);

    struct cng_sockaddr_un a;
    unsigned al = broker_addr(&a, fnv1a32(key));
    int spawns = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        long s = CNG_SYS(__NR_socket, CNG_AF_UNIX,
                         CNG_SOCK_STREAM | CNG_SOCK_CLOEXEC, 0, 0, 0, 0);
        if (s < 0)
            return 0;
        struct cng_timeval tv = {2, 0}; /* never block on a wedged daemon */
        CNG_SYS(__NR_setsockopt, s, CNG_SOL_SOCKET, CNG_SO_RCVTIMEO, &tv,
                sizeof tv, 0);
        long cr = CNG_SYS(__NR_connect, s, &a, al, 0, 0, 0);
        if (cr == 0) {
            char req = BROKER_REQ_TAB, ack = 0;
            int memfd = -1;
            if (cng_write_all((int)s, &req, 1) == 1)
                broker_recv((int)s, &ack, &memfd);
            sys_close((int)s); /* transient: keep no persistent broker fd */
            if (memfd >= 0) {
                void *p = 0;
                if (ack == BROKER_ACK_TAB)
                    p = sys_mmap(0, size, CNG_PROT_READ | CNG_PROT_WRITE,
                                 CNG_MAP_SHARED, memfd, 0);
                sys_close(memfd);
                if (p && p != CNG_MAP_FAILED && !cng_is_err((long)p)) {
                    g_tab = (struct proc_ent *)p;
                    g_tab_n = CNG_PROCREG_MAX;
                    return 1;
                }
                return 0; /* bad ack or mmap failure: don't spin */
            }
            /* connected but no fd (daemon exited mid-handshake): retry */
        } else {
            sys_close((int)s);
            if (cr != -ECONNREFUSED && cr != -ENOENT)
                return 0; /* unexpected (sandbox?): degrade */
            /* Start a daemon on the first miss and retry connect while it
             * binds; re-spawn only occasionally as a safety net (a loser of
             * the bind race whose winner then died). */
            if (spawns == 0 || attempt % 16 == 0) {
                broker_spawn(&a, al, size);
                spawns++;
            }
        }
        struct cng_timespec ms = {0, 1000000}; /* 1 ms for the bind */
        CNG_SYS(__NR_nanosleep, &ms, 0, 0, 0, 0, 0);
    }
    return 0; /* pathological churn: degrade */
}

/* Scan the exec-time environment for `name` (no libc getenv here). */
static const char *env_get(const char *name) {
    size_t nl = strlen(name);
    for (char **e = cng_g_envp; e && *e; e++)
        if (!strncmp(*e, name, nl) && (*e)[nl] == '=' && (*e)[nl + 1])
            return *e + nl + 1;
    return 0;
}

/* First writable directory that can hold the fallback registry file. Desktop
 * RAM-backed tmpfs is preferred; Android has no ownerless tmpfs an app may
 * write, so the app's own tmp dirs are accepted next. Registry writes are
 * rare (exec/fork/chdir), so a non-tmpfs dir costs nothing noticeable. */
static const char *shared_dir(void) {
    static const char *fixed[] = {"/dev/shm", 0, 0, "/data/local/tmp", "/tmp"};
    fixed[1] = env_get("XDG_RUNTIME_DIR");
    fixed[2] = env_get("TMPDIR");
    for (unsigned i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
        if (!fixed[i])
            continue;
        if (CNG_SYS(__NR_faccessat, CNG_AT_FDCWD, fixed[i], 2 /*W_OK*/, 0, 0,
                    0) == 0)
            return fixed[i];
    }
    return 0;
}

/* Named-file fallback: a 0600 file keyed by uid + rootfs hash that every
 * invocation maps MAP_SHARED. The ftruncate is idempotent under racing
 * creators and guarantees a fully-backed, zero-filled mapping (a fresh file
 * is an all-free table, since pid == 0 means free). */
static int open_shared_file(const char *key, unsigned long size) {
    const char *dir = shared_dir();
    if (!dir)
        return 0;
    char path[CNG_PATH_MAX + 64];
    int n = cng_snprintf(path, sizeof path, "%s/chroot-ng-procreg.v1.%u.%x",
                         dir, (unsigned)sys_getuid(), fnv1a32(key));
    if (n <= 0 || (unsigned)n >= sizeof path)
        return 0;
    long fd = sys_openat(CNG_AT_FDCWD, path,
                         CNG_O_RDWR | CNG_O_CREAT | CNG_O_CLOEXEC, 0600);
    if (fd < 0)
        return 0;
    if (sys_ftruncate((int)fd, (long)size) != 0) {
        sys_close((int)fd);
        return 0;
    }
    void *p = sys_mmap(0, size, CNG_PROT_READ | CNG_PROT_WRITE, CNG_MAP_SHARED,
                       (int)fd, 0);
    sys_close((int)fd);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    g_tab = (struct proc_ent *)p;
    g_tab_n = CNG_PROCREG_MAX;
    return 1;
}

void cng_procreg_init(const char *shared_key) {
    if (g_tab)
        return;
    unsigned long sz = (unsigned long)CNG_PROCREG_MAX * sizeof(struct proc_ent);
    if (shared_key && *shared_key) {
        if (open_broker(shared_key, sz)) {
            cng_g_procreg_backing = CNG_PROCREG_B_BROKER;
            return;
        }
        if (open_shared_file(shared_key, sz)) {
            cng_g_procreg_backing = CNG_PROCREG_B_FILE;
            return;
        }
    }
    void *p = sys_mmap(0, sz, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_SHARED | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return; /* no registry: procfs.c degrades to host passthrough */
    g_tab = (struct proc_ent *)p;
    g_tab_n = CNG_PROCREG_MAX;
    cng_g_procreg_backing = CNG_PROCREG_B_ANON;
}

/* Our slot: the one already holding `pid`, else a free one, else one whose
 * process is gone (a slot is released when cng_procreg_has catches a reused
 * pid, or reclaimed here — there is no exit hook, since exit_group is not a
 * syscall we trap and a SIGKILL never could be). The old starttime is zeroed
 * before the pid CAS publishes the claim, so a reader that races the claim
 * sees "not stamped yet" rather than judging the new pid against the previous
 * occupant's starttime. */
static struct proc_ent *slot_for(int pid) {
    if (!g_tab || pid <= 0)
        return 0;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid)
            return &g_tab[i];
    for (int i = 0; i < g_tab_n; i++) {
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) != 0)
            continue;
        __atomic_store_n(&g_tab[i].start, 0, __ATOMIC_RELEASE);
        s32 expect = 0;
        if (__atomic_compare_exchange_n(&g_tab[i].pid, &expect, (s32)pid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return &g_tab[i];
    }
    for (int i = 0; i < g_tab_n; i++) {
        s32 dead = __atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE);
        if (dead <= 0 || proc_starttime(dead) != 0)
            continue;
        __atomic_store_n(&g_tab[i].start, 0, __ATOMIC_RELEASE);
        if (__atomic_compare_exchange_n(&g_tab[i].pid, &dead, (s32)pid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return &g_tab[i];
    }
    return 0; /* full: this process stays invisible (host passthrough) */
}

/* Begin a seqlock write: CAS the count even -> odd. A child's slot can see two
 * writers — the parent publishing the fork while the child already publishes
 * its own exec — and interleaved plain stores could leave a torn payload
 * behind an even count. With the CAS the loser backs off (its data is the
 * older of the two). Returns the odd count, or 0 when the spin runs out. */
static u32 seq_acquire(struct proc_ent *e, int spins) {
    for (int t = 0; t < spins; t++) {
        u32 s = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        if (!(s & 1) &&
            __atomic_compare_exchange_n(&e->seq, &s, s + 1, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return s + 1; /* even + 1: never 0 */
        __asm__ volatile("yield");
    }
    return 0;
}

static void seq_release(struct proc_ent *e, u32 odd) {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&e->seq, odd + 1, __ATOMIC_RELAXED); /* even: write done */
}

/* Flatten a NULL-terminated string vector into NUL-joined bytes, as the kernel
 * stores cmdline/environ. Returns the byte count written. */
static u32 join_vec(char *dst, u32 cap, char **vec) {
    u32 n = 0;
    for (int i = 0; vec && vec[i]; i++) {
        size_t l = strlen(vec[i]) + 1;
        if (n + l > cap)
            break; /* truncate at an element boundary */
        memcpy(dst + n, vec[i], l);
        n += (u32)l;
    }
    return n;
}

static u16 copy_path(char *dst, u32 cap, const char *s) {
    if (!s)
        return 0;
    size_t l = strlen(s);
    if (l > cap)
        l = cap;
    memcpy(dst, s, l);
    return (u16)l;
}

void cng_procreg_publish(char **argv, char **envp, const void *auxv,
                         unsigned auxv_len, const char *exe_guest,
                         const char *cwd_guest) {
    /* Sampled before the write window so the critical section is syscall-free
     * (a smaller kill-safe window, and nothing slow under the odd count). */
    u64 start = proc_starttime((int)sys_getpid());
    struct proc_ent *e = slot_for((int)sys_getpid());
    if (!e)
        return;
    if (auxv_len > CNG_PROCREG_AUXV)
        auxv_len = CNG_PROCREG_AUXV;

    u32 s = seq_acquire(e, 1 << 20);
    if (!s) {
        /* A writer died inside its window (only the forking parent ever
         * writes another process's slot). We own this pid, the dead writer's
         * data is stale either way: reset the count and take the lock. */
        u32 cur = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        __atomic_store_n(&e->seq, (cur | 1) + 1, __ATOMIC_RELAXED);
        s = seq_acquire(e, 1 << 20);
        if (!s)
            return;
    }
    e->start = start;
    e->cmd_len = join_vec(e->cmd, CNG_PROCREG_CMDLINE, argv);
    e->env_len = join_vec(e->env, CNG_PROCREG_ENVIRON, envp);
    e->auxv_len = auxv_len;
    if (auxv && auxv_len)
        memcpy(e->auxv, auxv, auxv_len);
    e->exe_len = copy_path(e->exe, CNG_PROCREG_PATH, exe_guest);
    e->cwd_len = copy_path(e->cwd, CNG_PROCREG_PATH, cwd_guest);
    seq_release(e, s);
}

void cng_procreg_fork(int child) {
    if (!g_tab || child <= 0)
        return;
    struct cng_procsnap snap;
    if (!cng_procreg_get((int)sys_getpid(), &snap))
        return; /* we are not registered: nothing to inherit */
    /* The child may not be scheduled yet, but its stat file exists the moment
     * clone() returns, so its starttime is already readable. */
    u64 start = proc_starttime(child);
    struct proc_ent *e = slot_for(child);
    if (!e)
        return;
    /* The child itself may have beaten us here: it publishes its own identity
     * when it loads a program, and that is newer than this forked copy. A slot
     * already stamped with the child's live starttime is its work — leave it.
     * Failing to take the lock means the same thing (the child is the only
     * other writer of its slot), so back off there too. */
    if (start && __atomic_load_n(&e->start, __ATOMIC_ACQUIRE) == start)
        return;
    u32 s = seq_acquire(e, 4096);
    if (!s)
        return;
    e->start = start;
    e->cmd_len = snap.cmd_len;
    e->env_len = snap.env_len;
    e->auxv_len = snap.auxv_len;
    e->exe_len = snap.exe_len;
    e->cwd_len = snap.cwd_len;
    memcpy(e->cmd, snap.cmd, snap.cmd_len);
    memcpy(e->env, snap.env, snap.env_len);
    memcpy(e->auxv, snap.auxv, snap.auxv_len);
    memcpy(e->exe, snap.exe, snap.exe_len);
    memcpy(e->cwd, snap.cwd, snap.cwd_len);
    seq_release(e, s);
}

void cng_procreg_set_cwd(const char *cwd_guest) {
    if (!g_tab)
        return;
    int pid = (int)sys_getpid();
    struct proc_ent *e = 0;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) {
            e = &g_tab[i];
            break;
        }
    if (!e)
        return;
    u32 s = seq_acquire(e, 4096);
    if (!s)
        return; /* contended refresh: the next chdir writes the live value */
    e->cwd_len = copy_path(e->cwd, CNG_PROCREG_PATH, cwd_guest);
    seq_release(e, s);
}

int cng_procreg_has(int pid) {
    if (pid <= 0)
        return 0;
    if (pid == (int)sys_getpid())
        return 1; /* always ourselves, registry or not */
    if (!g_tab)
        return 0;
    for (int i = 0; i < g_tab_n; i++) {
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) != pid)
            continue;
        /* The pid-reuse guard. Exit is not a trapped syscall (and a SIGKILL
         * never could be), so a slot outlives its process and the host may
         * hand the number to a foreign process — which must not inherit guest
         * visibility through the hidden view. An unstamped slot (a claim whose
         * payload write hasn't landed, or never did) stays invisible: every
         * completed publish stamps a starttime. */
        u64 start = __atomic_load_n(&g_tab[i].start, __ATOMIC_ACQUIRE);
        if (!start)
            return 0;
        u64 live = proc_starttime(pid);
        if (live != start) {
            if (live) { /* a true reuse: scrub the slot for the free list */
                s32 expect = (s32)pid;
                __atomic_compare_exchange_n(&g_tab[i].pid, &expect, 0, 0,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_RELAXED);
            } /* gone (or unreadable): slot_for reclaims it lazily */
            return 0;
        }
        return 1;
    }
    return 0;
}

int cng_procreg_get(int pid, struct cng_procsnap *out) {
    if (!g_tab || pid <= 0)
        return 0;
    struct proc_ent *e = 0;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab[i].pid, __ATOMIC_ACQUIRE) == pid) {
            e = &g_tab[i];
            break;
        }
    if (!e)
        return 0;
    for (int tries = 0; tries < 100; tries++) {
        u32 s1 = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        if (s1 & 1)
            continue; /* writer active */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->pid, __ATOMIC_RELAXED) != pid)
            return 0; /* slot recycled under us */
        u64 start = e->start;
        u32 cl = e->cmd_len, el = e->env_len, al = e->auxv_len;
        u32 xl = e->exe_len, wl = e->cwd_len;
        if (cl > CNG_PROCREG_CMDLINE)
            cl = CNG_PROCREG_CMDLINE;
        if (el > CNG_PROCREG_ENVIRON)
            el = CNG_PROCREG_ENVIRON;
        if (al > CNG_PROCREG_AUXV)
            al = CNG_PROCREG_AUXV;
        if (xl > CNG_PROCREG_PATH)
            xl = CNG_PROCREG_PATH;
        if (wl > CNG_PROCREG_PATH)
            wl = CNG_PROCREG_PATH;
        memcpy(out->cmd, e->cmd, cl);
        memcpy(out->env, e->env, el);
        memcpy(out->auxv, e->auxv, al);
        memcpy(out->exe, e->exe, xl);
        memcpy(out->cwd, e->cwd, wl);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&e->seq, __ATOMIC_RELAXED) != s1)
            continue; /* torn read: retry */
        /* A recycled pid would otherwise inherit the dead process's guest
         * identity, and an unstamped slot has no incarnation to check against
         * (cng_procreg_has treats it as invisible; agree with that). Our own
         * entry is exempt: we know we are alive, and publish() may have
         * recorded 0 where /proc was unreadable. */
        if (pid != (int)sys_getpid() &&
            (!start || start != proc_starttime(pid)))
            return 0;
        out->cmd_len = cl;
        out->env_len = el;
        out->auxv_len = al;
        out->exe_len = (u16)xl;
        out->cwd_len = (u16)wl;
        return 1;
    }
    return 0;
}
