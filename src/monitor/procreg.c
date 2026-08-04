/* Guest-PID registry (see include/cng/procreg.h). Freestanding: raw syscalls,
 * no allocator, no locks — a CAS-claimed slot per process and a seqlock around
 * the payload. */
#include "cng/broker.h"
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

struct proc_ent {
    u32 seq;   /* seqlock: odd = write in progress */
    u64 start; /* /proc/<pid>/stat starttime: the pid-reuse guard */
    u32 cmd_len, env_len, auxv_len;
    u16 exe_len, cwd_len;
    char cmd[CNG_PROCREG_CMDLINE];  /* NUL-joined guest argv */
    char env[CNG_PROCREG_ENVIRON];  /* NUL-joined guest environ */
    char auxv[CNG_PROCREG_AUXV];    /* raw guest auxv block */
    char exe[CNG_PROCREG_PATH];     /* canonical guest exe path */
    char cwd[CNG_PROCREG_PATH];     /* canonical guest cwd */
};

/* The claim array is kept apart from the payload, because it is what every
 * lookup walks. "Is this pid a guest?" is asked for each numeric name in a
 * /proc listing — `ps` asks it several hundred times — and a miss has to look
 * at every slot. Interleaved with the payload each of those loads would land on
 * its own cache line ~6.5 KiB from the last; dense, the whole 4096-slot scan is
 * 16 KiB, which is less work than the old 256-slot table cost. */
struct proc_tab {
    s32 pid[CNG_PROCREG_MAX]; /* 0 = free, claimed by CAS */
    struct proc_ent ent[CNG_PROCREG_MAX];
};

static struct proc_tab *g_tab; /* MAP_SHARED region, or NULL if unavailable */
static int g_tab_n;

/* starttime, field 22 of /proc/<pid>/stat: skip past the last ')' (comm may
 * contain spaces and parens), then take the 20th field after it. 0 when the
 * process is gone or /proc is unreadable — which is also how a dead slot is
 * recognized, so a missing /proc only costs fidelity, never correctness.
 * `zombie_out`, when non-NULL, gets the state field's 'Z' verdict: a process
 * that has exited but not been reaped still owns its pid (so this is not a
 * reuse) yet holds nothing — which is what the shm attach reclaim keys on.
 *
 * Opened as dir-then-openat("stat") rather than by full path. On a real
 * kernel that is the same file; under qemu-user (the dev workflow) it is the
 * only route to the truth for our own pid: qemu realpath()s an open's path
 * and serves every absolute spelling of the caller's own stat from a
 * synthesized copy whose starttime is frozen at emulator startup — which a
 * fork inherits, so a child's self-sample would disagree with every other
 * process's read of the same pid and the registry's starttime checks would
 * misjudge the child as stale. The relative form is never intercepted. */
u64 cng_proc_starttime(int pid, int *zombie_out) {
    if (zombie_out)
        *zombie_out = 0;
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
    /* Fields, counting the state as 1 (i.e. proc(5)'s field 3): 1 state,
     * 18 num_threads, 20 starttime.
     *
     * State 'Z' alone does not mean the process is gone. A thread group whose
     * *leader* exits — which is what main() calling pthread_exit() does, and
     * every Go program and most Java ones end that way — reports 'Z' on
     * /proc/<tgid>/stat while the rest of its threads run on. Reading that as
     * death made the broker apply a live process's SEM_UNDO rows behind its
     * back (releasing a lock it still holds) and answer its parked waiters
     * -EIDRM. num_threads tells the two apart and is in this same line, so it
     * costs nothing: a genuinely dead, unreaped process is 'Z' with 1, a live
     * group with a dead leader is 'Z' with 2 or more. */
    int is_z = 0;
    u64 nthr = 1;
    for (int field = 0; *p;) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        if (++field == 1)
            is_z = (*p == 'Z');
        if (field == 18) {
            nthr = 0;
            for (const char *q = p; *q >= '0' && *q <= '9'; q++)
                nthr = nthr * 10 + (u64)(*q - '0');
        }
        if (field == 20) {
            u64 t = 0;
            for (; *p >= '0' && *p <= '9'; p++)
                t = t * 10 + (u64)(*p - '0');
            if (zombie_out)
                *zombie_out = is_z && nthr <= 1;
            return t ? t : 1; /* 0 means "gone"; never report it for a live pid */
        }
        while (*p && *p != ' ')
            p++;
    }
    return 0;
}

/* Byte size of the shared region, for whoever creates the backing (the broker
 * daemon, or the file / anonymous tiers below). */
unsigned long cng_procreg_table_size(void) {
    return sizeof(struct proc_tab);
}

/* Any guest of this namespace still alive? The registry is the broker daemon's
 * liveness signal: a dead process's slot reads a dead starttime, so an all-dead
 * scan means the session is truly over. */
int cng_procreg_table_live(const void *tabp) {
    const struct proc_tab *tab = (const struct proc_tab *)tabp;
    for (int i = 0; i < CNG_PROCREG_MAX; i++) {
        s32 pid = __atomic_load_n(&tab->pid[i], __ATOMIC_ACQUIRE);
        if (pid > 0 && cng_proc_starttime(pid, 0) != 0)
            return 1;
    }
    return 0;
}

/* ---- --shared-proc backing: broker daemon + named-file fallback ----------
 * The daemon itself is broker.c (shared with the System V shm registry): a
 * per-rootfs process owns the table memfd and an abstract-namespace rendezvous
 * socket, and hands the memfd to each joining invocation over SCM_RIGHTS.
 * Clients hold no persistent broker fd (host fd == guest fd, so a held fd would
 * be visible to and closable by the guest); the daemon uses this registry
 * itself as its liveness signal and exits — freeing the memfd and the socket
 * name — once no guest of the rootfs has been alive for a grace window. All of
 * this runs in cng_procreg_init, before the seccomp filter installs and before
 * any guest fork, so the daemon fork is single-threaded and unfiltered. */

int cng_g_shared_proc = 0;
int cng_g_procreg_backing = CNG_PROCREG_B_NONE;

/* Join (or start) the per-rootfs broker and map its table memfd. Returns 1 with
 * g_tab set, 0 to degrade to the file / anonymous tiers. Holds no fd past
 * return. */
static int open_broker(const char *key, unsigned long size) {
    int memfd = cng_broker_table_fd(key);
    if (memfd < 0)
        return 0;
    void *p = sys_mmap(0, size, CNG_PROT_READ | CNG_PROT_WRITE, CNG_MAP_SHARED,
                       memfd, 0);
    sys_close(memfd);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    g_tab = (struct proc_tab *)p;
    g_tab_n = CNG_PROCREG_MAX;
    return 1;
}

/* Named-file fallback: a 0600 file keyed by uid + rootfs hash that every
 * invocation maps MAP_SHARED. The ftruncate is idempotent under racing
 * creators and guarantees a fully-backed, zero-filled mapping (a fresh file
 * is an all-free table, since pid == 0 means free). Registry writes are rare
 * (exec/fork/chdir), so a non-tmpfs dir costs nothing noticeable. */
static int open_shared_file(const char *key, unsigned long size) {
    const char *dir = cng_broker_shared_dir();
    if (!dir)
        return 0;
    char path[CNG_PATH_MAX + 64];
    size_t n = cng_snprintf(path, sizeof path, "%s/chroot-ng-procreg.v1.%u.%x",
                            dir, (unsigned)sys_getuid(),
                            cng_broker_key_hash(key));
    if (n >= sizeof path)
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
    g_tab = (struct proc_tab *)p;
    g_tab_n = CNG_PROCREG_MAX;
    return 1;
}

void cng_procreg_init(const char *shared_key) {
    if (g_tab)
        return;
    /* CNG_PROCREG_NONE=1: behave as if the table could not be mapped at all.
     * That degraded tier is what every /proc answer has to survive — a host
     * without memfd, a full table — and a working host never reaches it on its
     * own, so there is no other way to exercise it. Same testing convention as
     * CNG_SHM_FORCE_FILE and CNG_NETLINK_FORCE_BLOCK. */
    if (cng_broker_env("CNG_PROCREG_NONE"))
        return;
    unsigned long sz = cng_procreg_table_size();
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
    g_tab = (struct proc_tab *)p;
    g_tab_n = CNG_PROCREG_MAX;
    cng_g_procreg_backing = CNG_PROCREG_B_ANON;
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

/* Take slot `i` from `want` for `pid`, clearing the previous occupant's
 * starttime, under the entry's own seqlock.
 *
 * Neither half of that can be dropped. Zeroing before the CAS — which is what
 * this used to do — writes a slot we may not get: the winner of the race has by
 * then published its own starttime, and the loser's zero lands on top of it,
 * leaving a live process stamped "never registered" and so invisible in /proc
 * until its next exec. Zeroing after winning instead leaves a window where the
 * new pid is already visible against the OLD occupant's starttime, and
 * starttimes are jiffies since boot, so two processes really can share one — a
 * reader hitting that coincidence accepts the slot and reports the previous
 * occupant's cmdline as this pid's.
 *
 * The seqlock closes that window: cng_procreg_get reads the starttime and the
 * payload inside it, so a reader that races the claim retries and finds the
 * zero. The pid itself is still published by one CAS, which is what keeps a
 * forking parent and an exec'ing child converging on the same slot.
 *
 * A slot whose owner was killed mid-write has an odd count nobody will clear;
 * taking it without the lock is what the publish path's own recovery does, and
 * leaves that (already degenerate) case no worse than before. Returns the entry,
 * or 0 if the CAS was lost. */
static struct proc_ent *slot_take(int i, s32 want, int pid) {
    struct proc_ent *e = &g_tab->ent[i];
    u32 s = seq_acquire(e, 1024);
    s32 exp = want;
    if (!__atomic_compare_exchange_n(&g_tab->pid[i], &exp, (s32)pid, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        if (s)
            seq_release(e, s);
        return 0;
    }
    __atomic_store_n(&e->start, 0, __ATOMIC_RELEASE);
    if (s)
        seq_release(e, s);
    return e;
}

/* Our slot: the one already holding `pid`, else a free one, else one whose
 * process is gone (a slot is released when cng_procreg_has catches a reused
 * pid, or reclaimed here — there is no exit hook, since exit_group is not a
 * syscall we trap and a SIGKILL never could be). A reader that races a claim
 * sees "not stamped yet" rather than judging the new pid against the previous
 * occupant's starttime — see slot_take. */
static struct proc_ent *slot_for(int pid) {
    if (!g_tab || pid <= 0)
        return 0;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE) == pid)
            return &g_tab->ent[i];
    for (int i = 0; i < g_tab_n; i++) {
        if (__atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE) != 0)
            continue;
        struct proc_ent *e = slot_take(i, 0, pid);
        if (e)
            return e;
    }
    for (int i = 0; i < g_tab_n; i++) {
        s32 dead = __atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE);
        if (dead <= 0 || cng_proc_starttime(dead, 0) != 0)
            continue;
        struct proc_ent *e = slot_take(i, dead, pid);
        if (e)
            return e;
    }
    return 0; /* full: this process stays invisible (host passthrough) */
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
    u64 start = cng_proc_starttime((int)sys_getpid(), 0);
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
    u64 start = cng_proc_starttime(child, 0);
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
        if (__atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE) == pid) {
            e = &g_tab->ent[i];
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
        if (__atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE) != pid)
            continue;
        /* The pid-reuse guard. Exit is not a trapped syscall (and a SIGKILL
         * never could be), so a slot outlives its process and the host may
         * hand the number to a foreign process — which must not inherit guest
         * visibility through the hidden view. An unstamped slot (a claim whose
         * payload write hasn't landed, or never did) stays invisible: every
         * completed publish stamps a starttime. */
        u64 start = __atomic_load_n(&g_tab->ent[i].start, __ATOMIC_ACQUIRE);
        if (!start)
            return 0;
        u64 live = cng_proc_starttime(pid, 0);
        if (live != start) {
            if (live) { /* a true reuse: scrub the slot for the free list */
                s32 expect = (s32)pid;
                __atomic_compare_exchange_n(&g_tab->pid[i], &expect, 0, 0,
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
    int slot = -1;
    for (int i = 0; i < g_tab_n; i++)
        if (__atomic_load_n(&g_tab->pid[i], __ATOMIC_ACQUIRE) == pid) {
            e = &g_tab->ent[i];
            slot = i;
            break;
        }
    if (!e)
        return 0;
    for (int tries = 0; tries < 100; tries++) {
        u32 s1 = __atomic_load_n(&e->seq, __ATOMIC_RELAXED);
        if (s1 & 1)
            continue; /* writer active */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&g_tab->pid[slot], __ATOMIC_RELAXED) != pid)
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
            (!start || start != cng_proc_starttime(pid, 0)))
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
