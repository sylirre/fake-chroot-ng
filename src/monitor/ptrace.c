/* Guest ptrace(2): the shared link registry, the tracee's stop/service loop,
 * and the tracer's request and wait4 handling. See include/cng/ptrace.h for the
 * model; this file is its implementation.
 *
 * Two things make the in-process design work where a cross-process one would
 * need host ptrace permission we do not have:
 *
 *  - the tracee answers requests about *itself*. It is parked inside our own
 *    code at the stop, so its memory is simply our memory (guest VA == host VA
 *    here) and its register file is the frame the kernel handed us.
 *  - the registry is one MAP_SHARED anonymous mapping created before the first
 *    guest fork, so every guest process sees the same links at the same
 *    addresses, and a futex in one of them is a cross-process wakeup.
 *
 * Everything is lock-free: a stopped tracee and its tracer alternate through a
 * sequence-numbered mailbox, and the registry's slots are CAS-claimed. That is
 * not for speed — it is because all of this runs inside the SIGSYS handler,
 * where a sleeping lock could deadlock against the thread it interrupted.
 */
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

int cng_g_no_ptrace = 0;

/* Set once the SIGSYS handler is installed (cng_install_monitor). The stacked
 * ptrace filters are gated on it: a RET_TRAP with no handler for the signal
 * would kill the task outright, which is what a self-test driving this code
 * with no monitor installed would otherwise do to itself. */
int cng_g_sigsys_ready = 0;

#define PT_MAX  128  /* concurrent traced tasks in one session */
#define PT_MBOX 1024 /* mailbox payload cap (>= the largest regset, 528) */

/* Link state. */
enum { PT_ST_RUNNING = 0, PT_ST_STOPPED = 1, PT_ST_EXITED = 2 };

/* Mailbox commands (tracer -> parked tracee). Requests answerable from the
 * link's own published fields (GETEVENTMSG, GETSIGINFO, GET_SYSCALL_INFO,
 * SETOPTIONS) never reach the mailbox at all. */
enum {
    PT_CMD_NONE = 0,
    PT_CMD_PEEK,    /* addr -> 8 bytes in data[] */
    PT_CMD_POKE,    /* addr, arg = value; writes through a read-only text page */
    PT_CMD_READ,    /* addr, arg = len: tracee memory -> data[]; result = bytes */
    PT_CMD_WRITE,   /* addr, arg = len: data[] -> tracee memory */
    PT_CMD_GETREGS, /* addr = NT_* -> regset in data[], rlen bytes */
    PT_CMD_SETREGS, /* addr = NT_*, rlen bytes in data[] */
    PT_CMD_RESUME,  /* addr = inject sig, arg = PT_RES_* */
    PT_CMD_DETACH,  /* addr = inject sig */
};

/* Resume submodes. */
enum { PT_RES_CONT = 0, PT_RES_SYSCALL = 1, PT_RES_SINGLESTEP = 2 };

/* PTRACE_GET_SYSCALL_INFO ops. */
#define PT_SCI_NONE  0
#define PT_SCI_ENTRY 1
#define PT_SCI_EXIT  2

struct pt_link {
    s32 tracee; /* 0 = free (CAS-claimed); tid (a main thread's tid is its pid) */
    s32 tgid;   /* the tracee's thread group */
    s32 tracer; /* tracer pid, 0 once detached */
    u32 options;
    u32 state;             /* PT_ST_*; release/acquire flag for the stop fields */
    u32 reported;          /* a wait already consumed the current stop */
    u32 stop_sig;          /* WSTOPSIG of the current stop */
    u32 event;             /* PTRACE_EVENT_* of the current stop (0 = none) */
    u32 syscall_stop;      /* current stop is a syscall-entry/exit stop */
    u32 attach_pending;    /* a tracer ATTACH/SEIZE'd us; adopt at the next stop point */
    u32 interrupt_pending; /* PTRACE_INTERRUPT */
    u32 stopsig_pending;   /* a stop signal to report as a cooperative group-stop */
    u32 seize;             /* attached with SEIZE (no initial SIGSTOP; group stops) */
    u32 listening;         /* PTRACE_LISTEN: parked awaiting SIGCONT */
    s32 exit_status;       /* PT_ST_EXITED: the wait-status word for the tracer */
    u64 eventmsg;          /* PTRACE_GETEVENTMSG payload */
    s32 si_signo, si_code, si_errno;
    u64 fault_addr; /* siginfo si_addr of a fault stop */
    /* PTRACE_GET_SYSCALL_INFO, published at each syscall stop. */
    u32 sc_op;
    s64 sc_nr; /* the in-flight syscall number: the arm64 kernel's regs->syscallno,
                * which is what NT_ARM_SYSTEM_CALL reads and writes (x8 itself is
                * not re-read after the entry stop) */
    u64 sc_args[6], sc_pc, sc_sp;
    s64 sc_rval;
    /* Mailbox: the tracer bumps cmd_seq to submit, the tracee bumps done_seq. */
    u32 cmd_seq, done_seq;
    u32 cmd;
    u64 addr, arg;
    s64 result;
    u32 rlen;
    u8 data[PT_MBOX];
};

struct pt_tab {
    u32 global_gen; /* bumped on every stop/exit; the wait-poll sleep futex */
    u32 any_trace;  /* set once anything in the session starts tracing */
    struct pt_link links[PT_MAX];
};

static struct pt_tab *g_tab;

/* Per-task state. chroot-ng cannot use __thread: it runs on the guest's own
 * threads, whose TPIDR_EL0 belongs to the guest's libc, so a thread-local of
 * ours would be resolved against the guest's TLS block. Per-task state is
 * therefore a tid-keyed table, claimed lock-free exactly like the SIGSYS
 * handler's scratch stacks. Only traced or tracing tasks ever claim a slot. */
struct pt_self {
    long tid; /* 0 = free */
    struct pt_link *link;
    struct cng_uregs *regs;  /* the frame this entry into monitor code runs on */
    struct cng_ucontext *uc; /* and the signal frame it came from, if any */
    int active;              /* this task is a tracee */
    int armed;               /* resumed with PTRACE_SYSCALL */
    int entry_seen;          /* an entry stop was reported for the syscall in
                              * flight, so its exit stop is owed */
    int step;                /* resumed with PTRACE_SINGLESTEP */
    int skip_exit_stop;      /* one-shot: skip the next syscall-exit stop */
    int in_stop;             /* re-entrancy guard */
    int traceall;            /* the trap-everything filter is installed here */
    int tracer_armed;        /* the tracer filter is installed here */
};
#define PT_SELF_N 128
static struct pt_self g_self[PT_SELF_N];

/* Does this *process* have any traced or tracing task? An ordinary global, so
 * it is inherited by fork exactly as the seccomp filter and the dispositions
 * are. Every hot-path entry point tests it before touching anything else. */
static int g_pt_local;

/* How many of this process's tasks are tracees. Signal dispositions are
 * process-wide, so our handlers may only be taken down when the last of them is
 * gone — one thread detaching must not stop its siblings' stops from being
 * reported. */
static int g_pt_traced;

static void pt_traced_inc(void) {
    if (__atomic_add_fetch(&g_pt_traced, 1, __ATOMIC_SEQ_CST) == 1)
        cng_pt_sig_trace_enter();
}

static void pt_traced_dec(int restore) {
    if (__atomic_sub_fetch(&g_pt_traced, 1, __ATOMIC_SEQ_CST) <= 0 && restore)
        cng_pt_sig_trace_leave();
}

/* ---- futex ---- */

struct pt_timespec {
    long tv_sec, tv_nsec;
};

#define PT_FUTEX_WAIT 0
#define PT_FUTEX_WAKE 1

static void fx_wake(volatile u32 *a) {
    /* No FUTEX_PRIVATE_FLAG: tracer and tracee are different processes. */
    CNG_SYS(__NR_futex, a, PT_FUTEX_WAKE, 0x7fffffff, 0, 0, 0);
}

static void fx_wait(volatile u32 *a, u32 val, int ms) {
    struct pt_timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    CNG_SYS(__NR_futex, a, PT_FUTEX_WAIT, val, ms >= 0 ? &ts : 0, 0, 0);
}

/* ---- registry ---- */

void cng_pt_init(void) {
    if (g_tab || cng_g_no_ptrace)
        return;
    void *p = sys_mmap(0, sizeof(struct pt_tab), CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_SHARED | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return; /* no registry: ptrace answers -EPERM, as with --no-ptrace */
    g_tab = (struct pt_tab *)p;
    cng_pt_pick_kicksig();
}

static struct pt_link *pt_find(s32 tid) {
    if (!g_tab || tid <= 0)
        return 0;
    for (int i = 0; i < PT_MAX; i++)
        if (__atomic_load_n(&g_tab->links[i].tracee, __ATOMIC_ACQUIRE) == tid)
            return &g_tab->links[i];
    return 0;
}

/* Reserves a slot while its body is cleared, so no scan ever sees a link that
 * is about to be wiped. Never a valid tid, which is always > 0. */
#define PT_CLAIMING ((s32)-1)

/* Find or create the link for `tid`.
 *
 * The find and the create cannot be one atomic step, and both callers of the
 * fork pair race for the same key: the parent publishes the child from
 * cng_pt_report_event while the child claims itself from cng_pt_fork_child, and
 * a fork gives pid == tid so both ask for the same value. The scan is not
 * quick — a link is ~1.2 KiB and PT_MAX of them is well over 100 KiB of shared
 * memory — so the window between "not found" and "claimed" is microseconds, and
 * a followed fork lands two links for one tid often enough to be seen: it is
 * what made `pt_case fork` flaky here, reporting a death for a pid that had
 * already been reaped.
 *
 * Two links for one tid is not merely untidy. pt_find takes the lowest index,
 * and the ghost the parent made has state PT_ST_RUNNING, so every
 * PTRACE_CONT/SYSCALL/GETREGS against the real stop answers -ESRCH and the
 * tracee is never resumed.
 *
 * So publish, then look below: whoever holds the lower index keeps it, and the
 * other releases and adopts it. Each racer scans only strictly below itself, so
 * exactly one can conclude it lost — and the SEQ_CST publish is what guarantees
 * the loser sees the winner. */
static struct pt_link *pt_claim(s32 tid, s32 tgid) {
    if (!g_tab)
        return 0;
    struct pt_link *e = pt_find(tid);
    if (e)
        return e;
    for (int i = 0; i < PT_MAX; i++) {
        s32 expect = 0;
        if (!__atomic_compare_exchange_n(&g_tab->links[i].tracee, &expect,
                                         PT_CLAIMING, 0, __ATOMIC_ACQ_REL,
                                         __ATOMIC_RELAXED))
            continue;
        e = &g_tab->links[i];
        /* Everything but the claim key: a recycled slot must not inherit the
         * previous tenant's stop state or mailbox sequence. Done under the
         * reservation, so a concurrent pt_find cannot be handed the link
         * between its key going in and its body being cleared. */
        memset((char *)e + sizeof(s32), 0, sizeof *e - sizeof(s32));
        e->tgid = tgid;
        __atomic_store_n(&e->tracee, tid, __ATOMIC_SEQ_CST);
        for (int j = 0; j < i; j++)
            if (__atomic_load_n(&g_tab->links[j].tracee, __ATOMIC_SEQ_CST) ==
                tid) {
                __atomic_store_n(&e->tracee, 0, __ATOMIC_RELEASE);
                return &g_tab->links[j];
            }
        return e;
    }
    return 0; /* registry full: the caller degrades to untraced */
}

static void pt_free(struct pt_link *e) {
    if (!e)
        return;
    __atomic_store_n(&e->tracer, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&e->tracee, 0, __ATOMIC_RELEASE); /* slot free */
}

static void pt_bump_gen(void) {
    if (!g_tab)
        return;
    __atomic_add_fetch(&g_tab->global_gen, 1, __ATOMIC_SEQ_CST);
    fx_wake(&g_tab->global_gen);
}

/* Wake tracer `tr` after publishing a stop or an exit. Three channels, because
 * a tracer can be waiting in any of three ways: the poll futex (our own wait4),
 * SIGCHLD exactly as the kernel raises it on a tracee state change (a gdb-style
 * event loop), and the reserved kick signal, whose handler does nothing but
 * inflict EINTR on a tracer still blocked in a *native* wait4 — the window
 * before its first trapped wait. */
static void pt_wake_tracer(s32 tr) {
    if (tr <= 0)
        return;
    CNG_SYS(__NR_kill, tr, 17 /*SIGCHLD*/, 0, 0, 0, 0);
    cng_pt_kick(tr, tr, CNG_PT_KICK_WAKE);
}

/* Queue the reserved kick signal at one task, carrying `magic` in si_value so
 * the handler can tell it from a guest-directed signal of the same number.
 * Thread-targeted (rt_tgsigqueueinfo): the kick sets per-task state, and a
 * process-directed signal could land on any thread. */
void cng_pt_kick(s32 tgid, s32 tid, int magic) {
    struct {
        int signo, errno_, code;
        int pad;
        int pid;
        unsigned uid;
        int sival_int;
        int pad2;
        u64 rest[12];
    } si;
    memset(&si, 0, sizeof si);
    si.signo = cng_g_kicksig;
    si.code = -1; /* SI_QUEUE: the kernel refuses si_code >= 0 from a stranger */
    si.pid = (int)sys_getpid();
    si.uid = 0;
    si.sival_int = magic;
    if (CNG_SYS(__NR_rt_tgsigqueueinfo, tgid, tid, cng_g_kicksig, &si, 0, 0) < 0)
        CNG_SYS(__NR_rt_sigqueueinfo, tgid, cng_g_kicksig, &si, 0, 0, 0);
}

/* ---- per-task state ---- */

/* Claim `*p` from 0 to `tid` (inline LL/SC; same as sigsys.c's scratch table). */
static int pt_claim_slot(volatile long *p, long tid) {
    long old;
    int fail;
    __asm__ volatile("1: ldaxr %[old], [%[p]]\n"
                     "   cbnz  %[old], 2f\n"
                     "   stlxr %w[f], %[tid], [%[p]]\n"
                     "   cbnz  %w[f], 1b\n"
                     "   b     3f\n"
                     "2: clrex\n"
                     "   mov   %w[f], #1\n"
                     "3:\n"
                     : [old] "=&r"(old), [f] "=&r"(fail)
                     : [p] "r"(p), [tid] "r"(tid)
                     : "cc", "memory");
    return fail == 0;
}

static struct pt_self *pt_self_get(int create) {
    long tid = sys_gettid();
    unsigned h = (unsigned)((unsigned long)tid * 2654435761u) % PT_SELF_N;
    for (unsigned k = 0; k < PT_SELF_N; k++) {
        unsigned i = (h + k) % PT_SELF_N;
        long t = __atomic_load_n(&g_self[i].tid, __ATOMIC_ACQUIRE);
        if (t == tid)
            return &g_self[i];
        if (t == 0) {
            if (!create)
                return 0;
            if (pt_claim_slot(&g_self[i].tid, tid)) {
                struct pt_self *s = &g_self[i];
                s->link = 0;
                s->regs = 0;
                s->uc = 0;
                s->active = s->armed = s->step = 0;
                s->entry_seen = s->skip_exit_stop = s->in_stop = 0;
                s->traceall = s->tracer_armed = 0;
                return s;
            }
            k--; /* lost the race for this slot; re-probe it */
        }
    }
    return 0;
}

int cng_pt_active(void) {
    if (!g_pt_local || !g_tab)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s && s->active;
}

int cng_pt_syscall_armed(void) {
    if (!g_pt_local || !g_tab)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s && s->active && s->armed;
}

int cng_pt_traceall(void) {
    if (!g_pt_local)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s && s->traceall;
}

void cng_pt_set_frame(struct cng_uregs *r, struct cng_ucontext *uc) {
    if (!g_pt_local)
        return;
    struct pt_self *s = pt_self_get(0);
    if (s) {
        s->regs = r;
        s->uc = uc;
    }
}

struct cng_uregs *cng_pt_cur_regs(void) {
    if (!g_pt_local)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s ? s->regs : 0;
}

struct cng_ucontext *cng_pt_cur_uc(void) {
    if (!g_pt_local)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s ? s->uc : 0;
}

/* ---- regset marshalling (runs in the tracee, on its own live frame) ---- */

/* The FP/SIMD state of the current stop, when it happened in a signal frame:
 * the kernel appends an _aarch64_ctx-tagged record list to the sigcontext, and
 * writes back whatever we leave there on sigreturn — so this is both the read
 * and the write path for NT_PRFPREG. A stop reached from an -R trampoline has
 * no signal frame and answers -EINVAL. */
#define PT_FPSIMD_MAGIC 0x46508001

struct pt_aarch64_ctx {
    u32 magic, size;
};

static void *pt_fpsimd(struct pt_self *s, struct cng_uregs *r) {
    if (!s || !s->uc || cng_pt_uregs(s->uc) != r)
        return 0;
    unsigned char *p = s->uc->uc_mcontext.__reserved;
    unsigned char *end = p + sizeof s->uc->uc_mcontext.__reserved;
    while (p + sizeof(struct pt_aarch64_ctx) <= end) {
        struct pt_aarch64_ctx *c = (struct pt_aarch64_ctx *)p;
        if (c->magic == 0 || c->size == 0)
            return 0; /* end of the record list */
        if (c->magic == PT_FPSIMD_MAGIC)
            return p + sizeof *c; /* struct user_fpsimd_state follows the header */
        if (c->size < sizeof *c)
            return 0;
        p += c->size;
    }
    return 0;
}

#define PT_FPSIMD_SZ 528 /* 32 * 16 vregs + fpsr + fpcr */

/* PACIA <Xd>, <Xn>: 0xDAC10000 | (Rn << 5) | Rd, spelled as a raw instruction
 * word so a baseline armv8-a assembler accepts it. Only ever executed once
 * AT_HWCAP has said the CPU has address authentication — it is UNDEFINED, not a
 * NOP, on one that does not. */
static u64 pt_pac_sign(u64 ptr, u64 mod) {
    register u64 x0 __asm__("x0") = ptr;
    register u64 x1 __asm__("x1") = mod;
    __asm__ volatile(".inst 0xdac10020" : "+r"(x0) : "r"(x1));
    return x0;
}

static unsigned long pt_auxval(unsigned long tag) {
    unsigned long *a = cng_host_auxv;
    if (!a)
        return 0;
    for (; a[0]; a += 2)
        if (a[0] == tag)
            return a[1];
    return 0;
}

/* The pointer-authentication mask, for NT_ARM_PAC_MASK.
 *
 * The kernel's answer is GENMASK(54, vabits_actual) — the bits a signed user
 * pointer carries its PAC in — and we have no way to ask it for that: reading
 * it back is itself a ptrace request, and the VA size is not exported anywhere
 * a program can read. So it is measured instead. Sign one pointer under many
 * modifiers and OR the differences: every bit of the PAC field flips in about
 * half the samples, so after this many the union *is* the field, while every
 * bit outside it never moves. Bits above 54 are dropped, since the kernel's
 * mask never includes the top byte whether or not TBI is on.
 *
 * gdb asks for this whenever AT_HWCAP advertises PACA — which we forward from
 * the host verbatim — and treats a failure as fatal, so an -EINVAL here is the
 * "unable to fetch pauth registers" that stops a session before it starts. */
#define PT_HWCAP_PACA (1UL << 30)

static u64 pt_pac_mask(void) {
    static u64 cached;
    static int done;
    if (__atomic_load_n(&done, __ATOMIC_ACQUIRE))
        return cached;
    u64 mask = 0;
    if (pt_auxval(16 /*AT_HWCAP*/) & PT_HWCAP_PACA) {
        u64 p = (u64)(unsigned long)&cached & 0x00FFFFFFFFFFFFFFuLL;
        for (int i = 0; i < 96; i++)
            mask |= pt_pac_sign(p, (u64)i * 0x9E3779B97F4A7C15uLL) ^ p;
        mask &= 0x007FFFFFFFFFFFFFuLL;
    }
    cached = mask;
    __atomic_store_n(&done, 1, __ATOMIC_RELEASE);
    return mask;
}

static u32 pt_build_regset(struct pt_self *s, struct cng_uregs *r, u32 which,
                           u8 *out) {
    switch (which) {
    case CNG_NT_PRSTATUS:
        memcpy(out, r, sizeof *r);
        return (u32)sizeof *r;
    case CNG_NT_PRFPREG: {
        void *f = pt_fpsimd(s, r);
        if (!f)
            return 0;
        memcpy(out, f, PT_FPSIMD_SZ);
        return PT_FPSIMD_SZ;
    }
    case CNG_NT_ARM_TLS: {
        u64 tls;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tls));
        memcpy(out, &tls, 8);
        return 8;
    }
    case CNG_NT_ARM_SYSTEM_CALL: {
        s32 nr = s && s->link ? (s32)s->link->sc_nr : -1;
        memcpy(out, &nr, 4);
        return 4;
    }
    case CNG_NT_ARM_PAC_MASK: {
        /* struct user_pac_mask { data_mask, insn_mask } — one value twice, as
         * the kernel reports it (the two can differ only under TCR_EL1.TBID*,
         * which Linux does not use). */
        u64 m = pt_pac_mask();
        if (!m)
            return 0; /* no address authentication: -EINVAL, as the kernel says */
        u64 pac[2] = {m, m};
        memcpy(out, pac, sizeof pac);
        return (u32)sizeof pac;
    }
    case CNG_NT_ARM_TAGGED_ADDR_CTRL: {
        /* MTE's tagged-address control. gdb asks for it whenever AT_HWCAP2 says
         * MTE, and is fatal about a failure the same way. The task can read its
         * own through prctl, so no ptrace is needed to answer. */
        long v = sys_prctl(CNG_PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
        if (v < 0)
            return 0;
        u64 ctl = (u64)v;
        memcpy(out, &ctl, sizeof ctl);
        return (u32)sizeof ctl;
    }
    default:
        return 0;
    }
}

static long pt_apply_regset(struct pt_self *s, struct cng_uregs *r, u32 which,
                            const u8 *in, u32 len) {
    switch (which) {
    case CNG_NT_PRSTATUS:
        if (len < sizeof *r)
            return -EINVAL;
        memcpy(r, in, sizeof *r);
        return 0;
    case CNG_NT_PRFPREG: {
        void *f = pt_fpsimd(s, r);
        if (!f)
            return -EINVAL;
        if (len > PT_FPSIMD_SZ)
            len = PT_FPSIMD_SZ;
        memcpy(f, in, len);
        return 0;
    }
    case CNG_NT_ARM_TLS: {
        u64 tls;
        if (len < 8)
            return -EINVAL;
        memcpy(&tls, in, 8);
        __asm__ volatile("msr tpidr_el0, %0" ::"r"(tls));
        return 0;
    }
    case CNG_NT_ARM_TAGGED_ADDR_CTRL: {
        u64 ctl;
        if (len < 8)
            return -EINVAL;
        memcpy(&ctl, in, 8);
        return sys_prctl(CNG_PR_SET_TAGGED_ADDR_CTRL, (long)ctl, 0, 0, 0) < 0
                   ? -EINVAL
                   : 0;
    }
    /* NT_ARM_PAC_MASK is read-only in the kernel too (its regset has no
     * setter), so it falls through to the -EINVAL below. */
    case CNG_NT_ARM_SYSTEM_CALL: {
        s32 nr;
        if (len < 4)
            return -EINVAL;
        memcpy(&nr, in, 4);
        /* Redirect or cancel (-1) the in-flight syscall — the only way to do
         * that on arm64, where the kernel does not re-read x8 after the stop. */
        if (s && s->link)
            s->link->sc_nr = nr;
        return 0;
    }
    default:
        return -EINVAL;
    }
}

/* ---- tracee memory access ---- */

/* Protection of the mapping holding `addr`, from /proc/self/maps, or -1 if it
 * cannot be determined. Only used to put a text page back the way it was after
 * a breakpoint poke, so a miss falls back to the r-xp that text always is. */
static u64 pt_hex(char **p) {
    u64 v = 0;
    for (;; (*p)++) {
        char c = **p;
        int d = (c >= '0' && c <= '9')   ? c - '0'
                : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                                         : -1;
        if (d < 0)
            return v;
        v = v * 16 + (u64)d;
    }
}

static int pt_prot_of(u64 addr) {
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/maps",
                         CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    /* Small on purpose: a POKETEXT can be serviced from a stop taken on a
     * guest thread's stack, which for a Go goroutine is 8 KiB and already holds
     * the kernel's ~4.5 KiB signal frame. A line split across two reads is
     * carried over by keeping the tail at the front of the next buffer. */
    char buf[1024];
    int prot = -1;
    long n, keep = 0;
    while ((n = sys_read((int)fd, buf + keep, sizeof buf - 1 - (size_t)keep)) >
           0) {
        n += keep;
        buf[n] = 0;
        char *p = buf, *nl;
        while (prot < 0 && (nl = strchr(p, '\n'))) {
            *nl = 0;
            char *q = p;
            u64 lo = pt_hex(&q); /* "lo-hi perms ..." */
            if (*q == '-') {
                q++;
                u64 hi = pt_hex(&q);
                if (*q == ' ' && addr >= lo && addr < hi) {
                    prot = (q[1] == 'r' ? CNG_PROT_READ : 0) |
                           (q[2] == 'w' ? CNG_PROT_WRITE : 0) |
                           (q[3] == 'x' ? CNG_PROT_EXEC : 0);
                }
            }
            p = nl + 1;
        }
        if (prot >= 0)
            break;
        keep = (long)strlen(p);
        if (keep >= (long)sizeof buf - 1)
            keep = 0; /* pathological line: drop it */
        else
            memmove(buf, p, (size_t)keep);
    }
    sys_close((int)fd);
    return prot;
}

/* Write `len` bytes at `addr` the way PTRACE_POKETEXT does: through a
 * write-protected mapping (a breakpoint lands in read-only text), and coherent
 * with the instruction stream afterwards. Returns 0 or -EIO. */
long cng_pt_poke_text(u64 addr, const void *src, unsigned len) {
    if (!cng_user_readable(src, len))
        return -EIO;
    if (cng_user_writable((void *)addr, len)) {
        /* Already writable: the probe zeroed it, so copy immediately. */
        memcpy((void *)addr, src, len);
        cng_flush_icache((void *)addr, (void *)(addr + len));
        return 0;
    }
    u64 page = addr & ~4095ULL;
    u64 end = (addr + len + 4095) & ~4095ULL;
    int prot = pt_prot_of(addr);
    if (prot < 0)
        prot = CNG_PROT_READ | CNG_PROT_EXEC;
    if (sys_mprotect((void *)page, (size_t)(end - page),
                     prot | CNG_PROT_READ | CNG_PROT_WRITE) < 0)
        return -EIO;
    memcpy((void *)addr, src, len);
    cng_flush_icache((void *)addr, (void *)(addr + len));
    sys_mprotect((void *)page, (size_t)(end - page), prot);
    return 0;
}

/* Copy as much of [addr, addr+len) as is accessible, the way process_vm_readv
 * reports a partial transfer. Returns the byte count. */
static u32 pt_copy_out(u64 addr, u8 *dst, u32 len) {
    if (cng_user_readable((const void *)addr, len)) {
        memcpy(dst, (const void *)addr, len);
        return len;
    }
    u32 done = 0;
    while (done < len && cng_user_readable((const void *)(addr + done), 1))
        dst[done] = *(const u8 *)(addr + done), done++;
    return done;
}

static u32 pt_copy_in(u64 addr, const u8 *src, u32 len) {
    if (cng_user_writable((void *)addr, len)) {
        memcpy((void *)addr, src, len);
        return len;
    }
    u32 done = 0;
    while (done < len && cng_user_writable((void *)(addr + done), 1))
        *(u8 *)(addr + done) = src[done], done++;
    return done;
}

/* ---- tracee: leaving traced state ---- */

static void pt_self_detach(struct pt_self *s) {
    if (!s)
        return;
    struct pt_link *e = s->link;
    int was = s->active;
    s->link = 0;
    s->active = s->armed = s->step = s->skip_exit_stop = 0;
    if (e) {
        __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
        pt_free(e);
    }
    if (was) {
        cng_pt_step_clear();
        pt_traced_dec(1);
    }
}

/* Is task `tid` gone (reaped) or a zombie? A tracer that died leaves its
 * tracees parked forever otherwise. */
static int pt_task_dead(s32 tid) {
    char path[64];
    cng_snprintf(path, sizeof path, "/proc/%d/stat", (int)tid);
    long fd = sys_openat(CNG_AT_FDCWD, path, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return 1; /* gone */
    char buf[256];
    long n = sys_read((int)fd, buf, sizeof buf - 1);
    sys_close((int)fd);
    if (n <= 0)
        return 0;
    buf[n] = 0;
    char *rp = strrchr(buf, ')'); /* comm can hold spaces and parens */
    if (!rp || !rp[1])
        return 0;
    char st = (rp[1] == ' ') ? rp[2] : rp[1];
    return st == 'Z' || st == 'X' || st == 'x';
}

/* ---- tracee: the service loop ---- */

/* Answer tracer commands while parked. Returns the signal to inject on resume
 * (0 = none/suppressed). `seen` is the cmd_seq sampled *before* the stop was
 * published: the tracer can only post a command after observing STOPPED, so any
 * command it posts advances past `seen` and cannot be missed. */
static int pt_service_loop(struct pt_self *s, struct cng_uregs *r,
                           struct pt_link *e, u32 seen) {
    int inject = 0;
    for (;;) {
        while (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) == seen) {
            fx_wait(&e->cmd_seq, seen, 500);
            if (__atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE) != seen)
                break;
            s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
            if (tr <= 0 || pt_task_dead(tr)) {
                /* The tracer died. The kernel detaches its tracees (killing
                 * them first under PTRACE_O_EXITKILL); do the same rather than
                 * park here forever. */
                u32 opts = __atomic_load_n(&e->options, __ATOMIC_ACQUIRE);
                pt_self_detach(s);
                if (opts & CNG_PTRACE_O_EXITKILL)
                    CNG_SYS(__NR_exit_group, 0, 0, 0, 0, 0, 0);
                return 0;
            }
            /* Still unreaped after 500 ms: our publish-time wake may have raced
             * the tracer's entry into its wait. Re-kick until it is collected. */
            if (!__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE))
                pt_wake_tracer(tr);
        }
        seen = __atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE);
        int leave = 0;
        switch (e->cmd) {
        case PT_CMD_PEEK: {
            u64 w = 0;
            e->result = pt_copy_out(e->addr, (u8 *)&w, 8) == 8 ? 0 : -EIO;
            memcpy(e->data, &w, 8);
            e->rlen = 8;
            break;
        }
        case PT_CMD_POKE:
            e->result = cng_pt_poke_text(e->addr, &e->arg, 8);
            break;
        case PT_CMD_READ: {
            u32 n = e->arg > PT_MBOX ? PT_MBOX : (u32)e->arg;
            e->rlen = pt_copy_out(e->addr, e->data, n);
            e->result = (s64)e->rlen;
            break;
        }
        case PT_CMD_WRITE: {
            u32 n = e->arg > PT_MBOX ? PT_MBOX : (u32)e->arg;
            e->rlen = pt_copy_in(e->addr, e->data, n);
            e->result = (s64)e->rlen;
            break;
        }
        case PT_CMD_GETREGS: {
            u32 n = pt_build_regset(s, r, (u32)e->addr, e->data);
            e->rlen = n;
            e->result = n ? 0 : -EINVAL;
            break;
        }
        case PT_CMD_SETREGS:
            e->result = pt_apply_regset(s, r, (u32)e->addr, e->data, e->rlen);
            break;
        case PT_CMD_RESUME:
            s->armed = (e->arg == PT_RES_SYSCALL);
            s->step = (e->arg == PT_RES_SINGLESTEP);
            inject = (int)e->addr;
            e->result = 0;
            __atomic_store_n(&e->state, PT_ST_RUNNING, __ATOMIC_RELEASE);
            leave = 1;
            break;
        case PT_CMD_DETACH:
            inject = (int)e->addr;
            e->result = 0;
            pt_self_detach(s);
            leave = 1;
            break;
        default:
            e->result = -EIO;
            break;
        }
        __atomic_add_fetch(&e->done_seq, 1, __ATOMIC_RELEASE);
        fx_wake(&e->done_seq);
        if (leave)
            return inject;
    }
}

/* Publish a stop and park until the tracer resumes us. Returns the signal it
 * asked us to inject (0 = none). */
static int pt_stop(struct pt_self *s, struct cng_uregs *r, int stop_sig,
                   int event, int sc_stop, int si_code, u64 addr) {
    struct pt_link *e = s ? s->link : 0;
    if (!e || s->in_stop)
        return stop_sig;
    s->in_stop = 1;
    /* Our own step breakpoint must not be visible to the tracer's PEEKTEXT. */
    cng_pt_step_clear();
    int inject = 0;
    for (;;) {
        u32 seen = __atomic_load_n(&e->cmd_seq, __ATOMIC_ACQUIRE);
        e->stop_sig = (u32)stop_sig;
        e->event = (u32)event;
        e->syscall_stop = (u32)sc_stop;
        e->sc_op = sc_stop == 1   ? PT_SCI_ENTRY
                   : sc_stop == 2 ? PT_SCI_EXIT
                                  : PT_SCI_NONE;
        e->si_signo = stop_sig;
        e->si_code =
            si_code ? si_code : (event ? ((event << 8) | 5 /*SIGTRAP*/) : 0);
        e->fault_addr = addr;
        e->si_errno = 0;
        __atomic_store_n(&e->reported, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&e->state, PT_ST_STOPPED, __ATOMIC_RELEASE);
        pt_bump_gen();
        pt_wake_tracer(__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE));
        inject = pt_service_loop(s, r, e, seen);
        /* Resumed with PTRACE_SINGLESTEP: arm the temporary breakpoint that
         * brings us back after one instruction. Not at a syscall-*entry* stop,
         * where the step is the syscall itself and the stop is reported once it
         * returns (cng_pt_step_report) — exactly where TIF_SINGLESTEP reports
         * it. */
        if (!s->step || !s->active || sc_stop == 1)
            break;
        if (cng_pt_step_plant(r) == 0)
            break;
        /* The instruction cannot be decoded (a pointer-authenticated branch),
         * so there is nowhere to put the breakpoint. Report the step stop again
         * at the same pc — a step that did not advance, which a debugger can
         * see and act on — rather than resume a "stepping" tracee that would
         * then run to the next syscall or signal without stopping. */
        stop_sig = 5 /*SIGTRAP*/;
        event = 0;
        sc_stop = 0;
        si_code = 2 /*TRAP_TRACE*/;
        addr = r->pc;
    }
    s->in_stop = 0;
    return inject;
}

/* ---- tracee: stop reports ---- */

int cng_pt_syscall_entry(struct cng_uregs *r, long *nr_out) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link)
        return 1;
    struct pt_link *e = s->link;
    long nr = (long)r->x[8];
    s->entry_seen = s->armed;
    if (!s->armed) {
        e->sc_nr = nr;
        *nr_out = nr;
        return 1;
    }
    e->sc_nr = nr;
    for (int i = 0; i < 6; i++)
        e->sc_args[i] = r->x[i];
    e->sc_pc = r->pc;
    e->sc_sp = r->sp;
    /* A syscall the guest itself issued with an invalid number answers -ENOSYS,
     * and the tracer sees that as the pending result — exactly as arm64's
     * el0_svc_common sets it before the entry stop. */
    if (nr < 0)
        r->x[0] = (u64)(s64)-ENOSYS;
    u64 x8_before = r->x[8];
    pt_stop(s, r, 5 /*SIGTRAP*/, 0, 1, 0, 0);
    if (!s->active) { /* detached at the stop */
        *nr_out = (long)r->x[8];
        return 1;
    }
    /* The syscall number after the stop. NT_ARM_SYSTEM_CALL is the kernel's
     * only channel for this on arm64 (x8 is not re-read), and it is what
     * proot-style tracers use; we also honor a plain x8 rewrite, which the
     * kernel ignores, so a tracer carrying x86 habits still works here. */
    long nr2 = (long)e->sc_nr;
    if (r->x[8] != x8_before)
        nr2 = (long)r->x[8];
    e->sc_nr = nr2;
    *nr_out = nr2;
    if (nr2 == -1)
        return 0; /* cancelled: x0 is whatever the tracer left */
    return 1;
}

void cng_pt_syscall_exit(struct cng_uregs *r) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link || !s->armed)
        return;
    /* Only a syscall whose entry stop was reported owes an exit stop. Without
     * this, a tracer that armed PTRACE_SYSCALL from a stop taken *inside* a
     * syscall — the group-stop of a self-directed SIGSTOP, which is where every
     * strace session starts — would be handed a stray exit stop and have its
     * entry/exit pairing inverted for the rest of the run. */
    if (!s->entry_seen)
        return;
    s->entry_seen = 0;
    if (s->skip_exit_stop) {
        s->skip_exit_stop = 0;
        return;
    }
    struct pt_link *e = s->link;
    e->sc_rval = (s64)r->x[0];
    e->sc_pc = r->pc;
    e->sc_sp = r->sp;
    pt_stop(s, r, 5 /*SIGTRAP*/, 0, 2, 0, 0);
}

int cng_pt_stepping(void) {
    if (!g_pt_local || !g_tab)
        return 0;
    struct pt_self *s = pt_self_get(0);
    return s && s->active && s->step;
}

void cng_pt_step_report(struct cng_uregs *r) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->step || !s->link)
        return;
    cng_pt_step_clear();
    /* si_code TRAP_TRACE: a step completed, as opposed to the TRAP_BRKPT of a
     * breakpoint. gdb distinguishes them. */
    pt_stop(s, r, 5 /*SIGTRAP*/, 0, 0, 2 /*TRAP_TRACE*/, r->pc);
}

void cng_pt_report_exec(struct cng_uregs *r) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link)
        return;
    int event = (__atomic_load_n(&s->link->options, __ATOMIC_ACQUIRE) &
                 CNG_PTRACE_O_TRACEEXEC)
                    ? CNG_PTRACE_EVENT_EXEC
                    : 0;
    /* A freshly exec'd tracee is stopped and must be re-armed by its tracer. */
    s->armed = 0;
    s->step = 0;
    pt_stop(s, r, 5 /*SIGTRAP*/, event, 0, 0, 0);
}

/* Publish the new child's link from the parent, before the event stop that
 * announces it. The child claims the same link when it runs its own
 * cng_pt_fork_child, but the tracer typically waits on the new pid the instant
 * it sees the event — and that pid is not the tracer's own child, so a host
 * wait4 answers ECHILD. Without a link already in the registry that ECHILD is
 * terminal, and the tracer misses a child that is about to stop. */
static void pt_child_claim(s32 pid, struct pt_link *parent) {
    if (pid <= 0 || !parent)
        return;
    struct pt_link *e = pt_claim(pid, pid);
    if (!e)
        return;
    __atomic_store_n(&e->options,
                     __atomic_load_n(&parent->options, __ATOMIC_ACQUIRE),
                     __ATOMIC_RELAXED);
    e->seize = parent->seize;
    s32 zero = 0;
    __atomic_compare_exchange_n(&e->tracer, &zero,
                                __atomic_load_n(&parent->tracer, __ATOMIC_ACQUIRE),
                                0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

void cng_pt_report_event(struct cng_uregs *r, int event, u64 msg) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link || !event)
        return;
    if (event == CNG_PTRACE_EVENT_FORK || event == CNG_PTRACE_EVENT_VFORK ||
        event == CNG_PTRACE_EVENT_CLONE)
        pt_child_claim((s32)msg, s->link);
    s->link->eventmsg = msg;
    pt_stop(s, r, 5 /*SIGTRAP*/, event, 0, 0, 0);
}

/* What a followed child inherits from its creator. Captured in the parent (by
 * cng_pt_clone_event, which every clone path calls before cloning) because the
 * child cannot look it up: the per-task table is keyed by tid, and in the child
 * that key is new. Plain memory, so the fork carries it across. */
static struct {
    s32 tracer;
    u32 options;
    u32 seize;
} g_fork_inherit;

int cng_pt_clone_event(unsigned long flags) {
    if (!g_pt_local || !g_tab)
        return 0;
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link)
        return 0;
    u32 o = __atomic_load_n(&s->link->options, __ATOMIC_ACQUIRE);
    /* The kernel's rule, in order: CLONE_UNTRACED disables following; a clone
     * carrying an exit signal other than SIGCHLD is a "clone" event, a vfork is
     * a vfork event, anything else a fork event. */
    int ev = 0;
    if (!(flags & 0x00800000UL /*CLONE_UNTRACED*/)) {
        if (flags & CNG_CLONE_VFORK)
            ev = (o & CNG_PTRACE_O_TRACEVFORK) ? CNG_PTRACE_EVENT_VFORK : 0;
        else if ((flags & 0xff) != 17 /*SIGCHLD*/)
            ev = (o & CNG_PTRACE_O_TRACECLONE) ? CNG_PTRACE_EVENT_CLONE : 0;
        else
            ev = (o & CNG_PTRACE_O_TRACEFORK) ? CNG_PTRACE_EVENT_FORK : 0;
    }
    if (ev) {
        g_fork_inherit.tracer =
            __atomic_load_n(&s->link->tracer, __ATOMIC_ACQUIRE);
        g_fork_inherit.options = o;
        g_fork_inherit.seize = s->link->seize;
    }
    return ev;
}

void cng_pt_fork_child(struct cng_uregs *r, int event) {
    /* A single-step breakpoint planted in the parent came across the fork in
     * our copy-on-write text, and the bookkeeping that would take it out again
     * (g_step_addr/g_step_orig, plain BSS) came with it. The parent unplants
     * its own copy when the step lands; nothing unplants ours. An unfollowed
     * child never reaches a stop that would, so it runs into a `brk` nobody is
     * expecting — a SIGTRAP with no tracer to report it to, at an instruction
     * that re-executes, forever.
     *
     * Cleared here, before the table wipe below, while the inherited addresses
     * still describe this process's own text. Ahead of the `!g_tab` return too:
     * an untraced child of a traced parent is exactly the case that has nobody
     * left to fix it up later. */
    cng_pt_step_clear();
    if (!g_tab)
        return;
    /* The per-task table came across the fork describing the *parent's*
     * threads; only the forking thread exists here, and it has a new tid. Clear
     * it wholesale so a recycled tid can never match a stale entry. */
    memset(g_self, 0, sizeof g_self);
    __atomic_store_n(&g_pt_traced, 0, __ATOMIC_SEQ_CST);
    s32 tracer = g_fork_inherit.tracer;
    u32 opts = g_fork_inherit.options;
    u32 seize = g_fork_inherit.seize;
    if (!event || tracer <= 0) {
        /* Not followed: an ordinary untraced process. It still carries the
         * inherited trap-everything filter, which costs time and nothing else. */
        g_pt_local = 0;
        return;
    }
    s32 me = (s32)sys_getpid();
    struct pt_link *e = pt_claim(me, me);
    if (!e) {
        g_pt_local = 0;
        return; /* registry full: degrade to untraced */
    }
    __atomic_store_n(&e->options, opts, __ATOMIC_RELAXED);
    e->seize = seize;
    __atomic_store_n(&e->tracer, tracer, __ATOMIC_RELEASE);
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    struct pt_self *s = pt_self_get(1);
    if (!s) {
        pt_free(e);
        g_pt_local = 0;
        return;
    }
    s->link = e;
    s->active = 1;
    g_pt_local = 1;
    cng_pt_arm_tracee();
    pt_traced_inc();
    /* The initial attach stop the kernel gives an auto-attached child: SIGSTOP
     * for a PTRACE_ATTACH'd tracer, PTRACE_EVENT_STOP for a SEIZE'd one. */
    if (seize)
        pt_stop(s, r, 5 /*SIGTRAP*/, CNG_PTRACE_EVENT_STOP, 0, 0, 0);
    else
        pt_stop(s, r, 19 /*SIGSTOP*/, 0, 0, 0, 0);
    /* The tracer has typically armed PTRACE_SYSCALL by now; suppress the
     * syscall-exit stop of the clone we were born from, which we never entered
     * at an entry stop and which would desync the tracer's entry/exit pairing. */
    if (s->armed)
        s->skip_exit_stop = 1;
}

void cng_pt_exit_stop(struct cng_uregs *r, int wstatus) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link)
        return;
    if (!(__atomic_load_n(&s->link->options, __ATOMIC_ACQUIRE) &
          CNG_PTRACE_O_TRACEEXIT))
        return;
    s->link->eventmsg = (u64)(u32)wstatus;
    pt_stop(s, r, 5 /*SIGTRAP*/, CNG_PTRACE_EVENT_EXIT, 0, 0, 0);
}

void cng_pt_exit_report(int wstatus) {
    if (!g_tab)
        return;
    struct pt_self *s = pt_self_get(0);
    struct pt_link *e = s ? s->link : 0;
    if (s) {
        int was = s->active;
        s->link = 0;
        s->active = s->armed = s->step = s->skip_exit_stop = 0;
        if (was)
            pt_traced_dec(0); /* dying: no point putting dispositions back */
    }
    if (!e) {
        cng_pt_wake_waiters();
        return;
    }
    /* Publish a synthetic exit whenever the tracer cannot reap this death
     * through its own wait4: a tracer that is not our parent (strace -p, an
     * auto-attached child) never sees the host notification. A direct child's
     * tracer IS its parent and reaps it for real, so just drop the link. */
    s32 tr = __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE);
    s32 me = (s32)sys_getpid();
    s32 tid = (s32)sys_gettid();
    long ppid = CNG_SYS(__NR_getppid, 0, 0, 0, 0, 0, 0);
    if (tr > 0 && (tid != me || tr != (s32)ppid)) {
        e->exit_status = wstatus;
        __atomic_store_n(&e->state, PT_ST_EXITED, __ATOMIC_RELEASE);
        pt_bump_gen();
        pt_wake_tracer(tr);
        return; /* the tracer frees the link when it collects the exit */
    }
    pt_free(e);
    cng_pt_wake_waiters();
}

void cng_pt_wake_waiters(void) {
    if (!g_tab || !__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE))
        return;
    pt_bump_gen();
}

int cng_pt_report_signal(struct cng_uregs *r, int sig, int si_code, u64 addr) {
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active || !s->link || sig == 9 /*SIGKILL*/)
        return sig;
    /* A SEIZE'd tracee reports a job-control stop signal as a group-stop
     * (PTRACE_EVENT_STOP); an ATTACH'd one sees a plain signal-delivery-stop. */
    int stopsig = (sig == 19 || sig == 20 || sig == 21 || sig == 22);
    int event = (s->link->seize && stopsig) ? CNG_PTRACE_EVENT_STOP : 0;
    return pt_stop(s, r, sig, event, 0, si_code, addr);
}

void cng_pt_service_kick(struct cng_uregs *r) {
    if (!g_tab)
        return;
    struct pt_self *s = pt_self_get(0);
    if (!s || !s->active) {
        /* A pending PTRACE_ATTACH/SEIZE keyed by this task's own tid. */
        struct pt_link *e = pt_find((s32)sys_gettid());
        if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0 ||
            !__atomic_load_n(&e->attach_pending, __ATOMIC_ACQUIRE))
            return;
        __atomic_store_n(&e->attach_pending, 0, __ATOMIC_RELEASE);
        s = pt_self_get(1);
        if (!s)
            return;
        s->link = e;
        s->active = 1;
        g_pt_local = 1;
        cng_pt_arm_tracee();
        pt_traced_inc();
        if (!e->seize) {
            pt_stop(s, r, 19 /*SIGSTOP*/, 0, 0, 0, 0);
            return;
        }
        /* SEIZE attaches without a stop; fall through in case an INTERRUPT
         * kick coalesced with the attach kick. */
    }
    struct pt_link *e = s->link;
    if (!e)
        return;
    if (__atomic_load_n(&e->interrupt_pending, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&e->interrupt_pending, 0, __ATOMIC_RELEASE);
        pt_stop(s, r, 5 /*SIGTRAP*/, CNG_PTRACE_EVENT_STOP, 0, 0, 0);
    }
    u32 ss = __atomic_load_n(&e->stopsig_pending, __ATOMIC_ACQUIRE);
    if (ss) {
        __atomic_store_n(&e->stopsig_pending, 0, __ATOMIC_RELEASE);
        int event = e->seize ? CNG_PTRACE_EVENT_STOP : 0;
        pt_stop(s, r, (int)ss, event, 0, 0, 0);
    }
}

/* ---- tracer: mailbox round-trip ---- */

static void pt_cmd(struct pt_link *e, u32 cmd, u64 addr, u64 arg) {
    e->cmd = cmd;
    e->addr = addr;
    e->arg = arg;
    u32 d = __atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&e->cmd_seq, 1, __ATOMIC_RELEASE);
    fx_wake(&e->cmd_seq);
    while (__atomic_load_n(&e->done_seq, __ATOMIC_ACQUIRE) == d) {
        /* The tracee vanished while we waited — its slot freed, or its exit
         * published by a sibling's exit_group fan-out. Checked while done_seq
         * is still unbumped, so an answer that did land is never discarded. */
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0 ||
            __atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED) {
            e->result = -ESRCH;
            return;
        }
        fx_wait(&e->done_seq, d, 500);
    }
}

/* ---- tracer: PTRACE_TRACEME ---- */

static long pt_traceme(void) {
    if (!g_tab)
        return -EPERM;
    struct pt_self *s = pt_self_get(1);
    if (!s)
        return -ENOMEM;
    if (s->link)
        return -EPERM; /* already traced */
    s32 me = (s32)sys_getpid();
    struct pt_link *e = pt_claim((s32)sys_gettid(), me);
    if (!e)
        return -ENOMEM;
    long ppid = CNG_SYS(__NR_getppid, 0, 0, 0, 0, 0, 0);
    __atomic_store_n(&e->tracer, (s32)ppid, __ATOMIC_RELEASE);
    __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
    s->link = e;
    s->active = 1;
    g_pt_local = 1;
    cng_pt_arm_tracee();
    pt_traced_inc();
    /* Our parent is now a tracer, but it has not called ptrace yet — the whole
     * point of TRACEME — so nothing has armed its side of the interception.
     * Kick it: its handler installs the tracer filter, and the EINTR that comes
     * with the kick knocks it out of any native wait4 it is already blocked in,
     * so the retry lands in the trapped one that can see our stops. */
    cng_pt_kick((s32)ppid, (s32)ppid, CNG_PT_KICK_ARM);
    return 0;
}

/* Thread group of host task `tid`, from /proc/<tid>/status. -1 if gone. */
static s32 pt_tgid_of(s32 tid) {
    char path[64];
    cng_snprintf(path, sizeof path, "/proc/%d/status", (int)tid);
    long fd = sys_openat(CNG_AT_FDCWD, path, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[512]; /* Tgid: is within the first few lines */
    long n = sys_read((int)fd, buf, sizeof buf - 1);
    sys_close((int)fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    for (char *p = buf; *p;) {
        if (!strncmp(p, "Tgid:", 5)) {
            p += 5;
            while (*p == ' ' || *p == '\t')
                p++;
            s32 v = 0;
            while (*p >= '0' && *p <= '9')
                v = v * 10 + (*p++ - '0');
            return v;
        }
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    return -1;
}

/* ---- tracer: the guest's ptrace(2) ---- */

long cng_pt_syscall(long req, long pid, u64 addr, u64 data) {
    if (cng_g_no_ptrace)
        return -EPERM;
    if (req == CNG_PTRACE_TRACEME)
        return pt_traceme();
    if (!g_tab)
        return -EPERM;
    cng_pt_arm_tracer();

    s32 me = (s32)sys_getpid();
    if (req == CNG_PTRACE_ATTACH || req == CNG_PTRACE_SEIZE) {
        if (pid <= 0 || (s32)pid == me)
            return -EPERM;
        s32 tgid = (s32)pid;
        if (!cng_procreg_has((int)pid)) {
            /* Not a guest pid: it may be a secondary thread's tid, whose thread
             * group must itself be a live guest process. */
            tgid = pt_tgid_of((s32)pid);
            if (tgid <= 0 || !cng_procreg_has((int)tgid))
                return -ESRCH;
        }
        if (tgid == me)
            return -EPERM; /* our own thread group: the kernel's rule */
        struct pt_link *e = pt_claim((s32)pid, tgid);
        if (!e)
            return -ENOMEM;
        s32 zero = 0;
        if (!__atomic_compare_exchange_n(&e->tracer, &zero, me, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return -EPERM; /* already traced by someone */
        e->seize = (req == CNG_PTRACE_SEIZE);
        __atomic_store_n(&e->options,
                         e->seize ? ((u32)data & CNG_PTRACE_O_MASK) : 0,
                         __ATOMIC_RELAXED);
        __atomic_store_n(&e->attach_pending, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&g_tab->any_trace, 1, __ATOMIC_RELEASE);
        g_pt_local = 1;
        cng_pt_kick(tgid, (s32)pid, CNG_PT_KICK_ATTACH);
        return 0;
    }

    struct pt_link *e = pt_find((s32)pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me)
        return -ESRCH;

    if (req == CNG_PTRACE_INTERRUPT) {
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_STOPPED)
            return 0; /* already stopped */
        __atomic_store_n(&e->interrupt_pending, 1, __ATOMIC_RELEASE);
        cng_pt_kick(e->tgid, (s32)pid, CNG_PT_KICK_ATTACH);
        return 0;
    }

    /* Requests answerable from the link alone. */
    switch (req) {
    case CNG_PTRACE_SETOPTIONS:
        if (data & ~(u64)CNG_PTRACE_O_MASK)
            return -EINVAL;
        __atomic_store_n(&e->options, (u32)data, __ATOMIC_RELEASE);
        return 0;
    case CNG_PTRACE_KILL:
        CNG_SYS(__NR_kill, e->tgid, 9 /*SIGKILL*/, 0, 0, 0, 0);
        return 0;
    case CNG_PTRACE_GETEVENTMSG: {
        u64 msg = e->eventmsg;
        if (!cng_user_writable((void *)data, 8))
            return -EFAULT;
        memcpy((void *)data, &msg, 8);
        return 0;
    }
    case CNG_PTRACE_GETSIGINFO: {
        u8 si[128];
        if (!cng_user_writable((void *)data, sizeof si))
            return -EFAULT;
        memset(si, 0, sizeof si);
        s32 *w = (s32 *)si;
        w[0] = e->si_signo;
        w[1] = e->si_errno;
        w[2] = e->si_code;
        /* si_addr lives in the _sigfault member, at offset 16 on arm64 (after
         * signo/errno/code and the pointer-alignment pad). gdb reads it for
         * SIGSEGV/SIGBUS, and for the TRAP_BRKPT of a breakpoint. */
        switch (e->si_signo) {
        case 4: case 5: case 7: case 8: case 11: /* ILL TRAP BUS FPE SEGV */
            memcpy(si + 16, &e->fault_addr, 8);
            break;
        }
        memcpy((void *)data, si, sizeof si);
        return 0;
    }
    case CNG_PTRACE_GET_SYSCALL_INFO: {
        /* struct ptrace_syscall_info: op, pad[3], arch, ip, sp, then the
         * per-op union. Modern strace prefers this over pairing entry and exit
         * stops itself, and it is exact here — the tracee published it at the
         * stop. The kernel keys the op off the stop's si_code, which only
         * carries the syscall marker when PTRACE_O_TRACESYSGOOD is set, so
         * without that option even a syscall stop answers "none"; strace always
         * sets it, and a tracer that does not must not be told otherwise. */
        u8 info[88];
        memset(info, 0, sizeof info);
        u32 op = e->sc_op;
        if (!(__atomic_load_n(&e->options, __ATOMIC_ACQUIRE) &
              CNG_PTRACE_O_TRACESYSGOOD))
            op = PT_SCI_NONE;
        info[0] = (u8)op;
        *(u32 *)(info + 4) = 0xC00000B7u; /* AUDIT_ARCH_AARCH64 */
        *(u64 *)(info + 8) = e->sc_pc;
        *(u64 *)(info + 16) = e->sc_sp;
        /* The size the kernel reports (and copies up to) is the end of the
         * member the op actually fills, not the whole struct. */
        u64 actual = 24;
        if (op == PT_SCI_ENTRY) {
            *(u64 *)(info + 24) = (u64)e->sc_nr;
            for (int i = 0; i < 6; i++)
                *(u64 *)(info + 32 + 8 * i) = e->sc_args[i];
            actual = 80;
        } else if (op == PT_SCI_EXIT) {
            *(s64 *)(info + 24) = e->sc_rval;
            info[32] = (u8)(e->sc_rval < 0 && e->sc_rval >= -4095);
            actual = 33;
        }
        u64 n = addr < actual ? addr : actual;
        if (n) {
            if (!cng_user_writable((void *)data, (unsigned long)n))
                return -EFAULT;
            memcpy((void *)data, info, (size_t)n);
        }
        return (long)actual;
    }
    }

    /* Everything else needs the tracee parked. */
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED)
        return -ESRCH;

    /* A listening tracee (post-LISTEN, parked awaiting SIGCONT) is stopped but
     * counts as running to data operations, exactly as the kernel treats it. */
    if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE)) {
        switch (req) {
        case CNG_PTRACE_CONT:
        case CNG_PTRACE_SYSCALL:
        case CNG_PTRACE_SINGLESTEP:
        case CNG_PTRACE_DETACH:
            __atomic_store_n(&e->listening, 0, __ATOMIC_RELEASE);
            break;
        case CNG_PTRACE_LISTEN:
            return 0;
        default:
            return -ESRCH;
        }
    }

    switch (req) {
    case CNG_PTRACE_PEEKTEXT:
    case CNG_PTRACE_PEEKDATA:
        pt_cmd(e, PT_CMD_PEEK, addr, 0);
        if (e->result < 0)
            return -EIO;
        if (!cng_user_writable((void *)data, 8))
            return -EFAULT;
        memcpy((void *)data, e->data, 8);
        return 0;
    case CNG_PTRACE_POKETEXT:
    case CNG_PTRACE_POKEDATA:
        pt_cmd(e, PT_CMD_POKE, addr, data);
        return e->result < 0 ? -EIO : 0;
    case CNG_PTRACE_PEEKUSR:
    case CNG_PTRACE_POKEUSR:
        return -EIO; /* arm64 has no user area; the kernel answers this too */
    case CNG_PTRACE_GETREGSET: {
        u64 iov[2]; /* {base, len} */
        if (!cng_user_readable((void *)data, sizeof iov))
            return -EFAULT;
        memcpy(iov, (void *)data, sizeof iov);
        pt_cmd(e, PT_CMD_GETREGS, addr, 0);
        if (e->result < 0)
            return -EINVAL;
        u32 n = e->rlen;
        if (iov[1] < n)
            n = (u32)iov[1];
        if (n) {
            if (!cng_user_writable((void *)iov[0], n))
                return -EFAULT;
            memcpy((void *)iov[0], e->data, n);
        }
        iov[1] = e->rlen;
        if (!cng_user_writable((void *)data, sizeof iov))
            return -EFAULT;
        memcpy((void *)data, iov, sizeof iov);
        return 0;
    }
    case CNG_PTRACE_SETREGSET: {
        u64 iov[2];
        if (!cng_user_readable((void *)data, sizeof iov))
            return -EFAULT;
        memcpy(iov, (void *)data, sizeof iov);
        u32 n = (u32)(iov[1] > PT_MBOX ? PT_MBOX : iov[1]);
        if (n) {
            if (!cng_user_readable((void *)iov[0], n))
                return -EFAULT;
            memcpy(e->data, (void *)iov[0], n);
        }
        e->rlen = n;
        pt_cmd(e, PT_CMD_SETREGS, addr, 0);
        return e->result < 0 ? (long)e->result : 0;
    }
    case CNG_PTRACE_CONT:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_CONT);
        return 0;
    case CNG_PTRACE_SYSCALL:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_SYSCALL);
        return 0;
    case CNG_PTRACE_SINGLESTEP:
        pt_cmd(e, PT_CMD_RESUME, data, PT_RES_SINGLESTEP);
        return 0;
    case CNG_PTRACE_DETACH:
        pt_cmd(e, PT_CMD_DETACH, data, 0);
        return 0;
    case CNG_PTRACE_LISTEN:
        /* Only for a SEIZE'd tracee in a group/INTERRUPT stop. It stays parked
         * but "listening": a later SIGCONT ends the group-stop with a fresh
         * PTRACE_EVENT_STOP (cng_pt_signal_route). */
        if (!e->seize || e->event != CNG_PTRACE_EVENT_STOP)
            return -EIO;
        __atomic_store_n(&e->listening, 1, __ATOMIC_RELEASE);
        return 0;
    default:
        return -EIO;
    }
}

/* ---- tracer: wait4 / waitid ---- */

static int pt_have_tracee(s32 wpid) {
    if (!g_tab)
        return 0;
    s32 me = (s32)sys_getpid();
    for (int i = 0; i < PT_MAX; i++) {
        struct pt_link *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0)
            continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me)
            continue;
        if (wpid > 0 && wpid != e->tracee)
            continue;
        return 1;
    }
    return 0;
}

/* Consume one ready stop or synthetic exit matching wpid (<=0 means any).
 * Fills *status with a wait-status word and returns the tid, or 0. */
static s32 pt_collect(s32 wpid, int *status) {
    if (!g_tab)
        return 0;
    s32 me = (s32)sys_getpid();
    for (int i = 0; i < PT_MAX; i++) {
        struct pt_link *e = &g_tab->links[i];
        if (__atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE) <= 0)
            continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me)
            continue;
        s32 t = e->tracee;
        if (wpid > 0 && wpid != t)
            continue;
        u32 st = __atomic_load_n(&e->state, __ATOMIC_ACQUIRE);
        if (st == PT_ST_EXITED) {
            *status = e->exit_status;
            pt_free(e);
            return t;
        }
        if (st != PT_ST_STOPPED)
            continue;
        if (__atomic_load_n(&e->reported, __ATOMIC_ACQUIRE))
            continue;
        if (__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE))
            continue;
        int sig = (int)e->stop_sig;
        int w;
        if (e->event) {
            /* A group-stop reports its own stop signal with EVENT_STOP in the
             * high bits; every other event reports SIGTRAP. */
            if (e->event == CNG_PTRACE_EVENT_STOP && sig != 5)
                w = (CNG_PTRACE_EVENT_STOP << 16) | ((sig & 0xff) << 8) | 0x7f;
            else
                w = (((int)e->event << 8) | 5 /*SIGTRAP*/) << 8 | 0x7f;
        } else {
            if (e->syscall_stop &&
                (__atomic_load_n(&e->options, __ATOMIC_ACQUIRE) &
                 CNG_PTRACE_O_TRACESYSGOOD))
                sig |= 0x80;
            w = (sig << 8) | 0x7f;
        }
        __atomic_store_n(&e->reported, 1, __ATOMIC_RELEASE);
        *status = w;
        return t;
    }
    return 0;
}

/* A tracee that vanished without publishing an exit was killed by an
 * uncatchable SIGKILL (every catchable death is mediated). Report a synthetic
 * WIFSIGNALED(SIGKILL) so a tracer polling on it does not hang forever. */
static s32 pt_reap_dead(s32 wpid, int *status) {
    if (!g_tab)
        return 0;
    s32 me = (s32)sys_getpid();
    for (int i = 0; i < PT_MAX; i++) {
        struct pt_link *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0)
            continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != me)
            continue;
        if (wpid > 0 && wpid != t)
            continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_RUNNING)
            continue;
        if (!pt_task_dead(t))
            continue;
        *status = 9; /* WIFSIGNALED(SIGKILL) */
        pt_free(e);
        return t;
    }
    return 0;
}

void cng_pt_note_reaped(long pid) {
    struct pt_link *e = pt_find((s32)pid);
    if (e && __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) == (s32)sys_getpid())
        pt_free(e);
}

/* Is a signal pending that the guest would have taken delivery of? Our handler
 * runs with everything but SIGSYS masked, so a signal that arrives while we
 * poll here cannot interrupt the poll by itself — but the guest's wait4 must
 * still answer -EINTR for it, or a tracer becomes unkillable while waiting. The
 * guest's own mask is the one the signal frame will restore. */
static int pt_signal_pending(const struct cng_ucontext *uc) {
    unsigned long set = 0;
    if (CNG_SYS(__NR_rt_sigpending, &set, 8, 0, 0, 0, 0) < 0)
        return 0;
    unsigned long blocked = 0;
    if (uc) {
        /* On a signal frame the live mask is ours (everything but SIGSYS); the
         * guest's is the one sigreturn will restore. */
        blocked = uc->uc_sigmask.sig[0];
    } else if (CNG_SYS(__NR_rt_sigprocmask, 0 /*SIG_BLOCK*/, 0, &blocked,
                       sizeof(unsigned long), 0, 0) < 0) {
        blocked = 0;
    }
    return (set & ~blocked) != 0;
}

#define PT_WNOHANG   1
#define PT_WPOLL_MS  50

long cng_pt_wait4(long pid, u64 status, long options, u64 rusage,
                  const struct cng_ucontext *uc) {
    for (;;) {
        u32 gen = g_tab ? __atomic_load_n(&g_tab->global_gen, __ATOMIC_ACQUIRE) : 0;
        int st = 0;
        s32 t = pt_collect((s32)pid, &st);
        if (t > 0) {
            if (status) {
                if (!cng_user_writable((void *)status, 4))
                    return -EFAULT;
                *(int *)status = st;
            }
            return t;
        }
        long r = CNG_SYS(__NR_wait4, pid, status, options | PT_WNOHANG, rusage,
                         0, 0);
        if (r > 0) {
            cng_pt_note_reaped(r);
            return r;
        }
        /* ECHILD is not terminal while we trace something: a tracee attached to
         * with PTRACE_ATTACH is not our child, so its stops arrive through the
         * registry and never through the host wait. */
        if (r < 0 && !(r == -ECHILD && pt_have_tracee((s32)pid)))
            return r;
        if (options & PT_WNOHANG)
            return r == -ECHILD ? 0 : r;
        if ((t = pt_reap_dead((s32)pid, &st)) > 0) {
            if (status) {
                if (!cng_user_writable((void *)status, 4))
                    return -EFAULT;
                *(int *)status = st;
            }
            return t;
        }
        if (pt_signal_pending(uc))
            return -EINTR;
        if (g_tab)
            fx_wait(&g_tab->global_gen, gen, PT_WPOLL_MS);
    }
}

#define PT_WSTOPPED  2
#define PT_WEXITED   4
#define PT_WNOWAIT   0x01000000
#define PT_CLD_EXITED   1
#define PT_CLD_KILLED   2
#define PT_CLD_DUMPED   3
#define PT_CLD_TRAPPED  4

long cng_pt_waitid(long idtype, long id, u64 infop, long options, u64 rusage,
                   const struct cng_ucontext *uc) {
    /* P_ALL = 0, P_PID = 1, P_PGID = 2. Only a specific pid narrows the
     * registry scan; a process-group wait cannot match an emulated stop, so it
     * is left to the host wait entirely. */
    s32 wpid = (idtype == 1) ? (s32)id : (idtype == 0) ? -1 : 0;
    for (;;) {
        u32 gen = g_tab ? __atomic_load_n(&g_tab->global_gen, __ATOMIC_ACQUIRE) : 0;
        int st = 0;
        s32 t = 0;
        if (wpid && (options & PT_WSTOPPED) && (t = pt_collect(wpid, &st)) > 0) {
            if (infop) {
                if (!cng_user_writable((void *)infop, 128))
                    return -EFAULT;
                u8 si[128];
                memset(si, 0, sizeof si);
                s32 *w = (s32 *)si;
                w[0] = 17; /* SIGCHLD */
                w[2] = (st & 0xff) == 0x7f ? PT_CLD_TRAPPED
                       : ((st & 0x7f) == 0) ? PT_CLD_EXITED
                                            : PT_CLD_KILLED;
                w[4] = t;                          /* si_pid */
                w[5] = 0;                          /* si_uid */
                w[6] = (st & 0xff) == 0x7f ? (st >> 8) & 0xff
                       : ((st & 0x7f) == 0) ? (st >> 8) & 0xff
                                            : (st & 0x7f); /* si_status */
                memcpy((void *)infop, si, sizeof si);
            }
            return 0;
        }
        if (infop && cng_user_writable((void *)infop, 128))
            memset((void *)infop, 0, 128);
        long r = CNG_SYS(__NR_waitid, idtype, id, infop, options | PT_WNOHANG,
                         rusage, 0);
        if (r == 0) {
            /* WNOHANG semantics: si_pid == 0 means nothing was ready — which is
             * only readable because the buffer was zeroed just above. */
            int got = 1;
            if (infop && cng_user_readable((void *)infop, 128))
                got = *(int *)((char *)infop + 16) != 0;
            if (got || (options & PT_WNOHANG))
                return 0;
        } else if (!(r == -ECHILD && pt_have_tracee(wpid))) {
            return r;
        } else if (options & PT_WNOHANG) {
            return r;
        }
        if (pt_signal_pending(uc))
            return -EINTR;
        if (g_tab)
            fx_wait(&g_tab->global_gen, gen, PT_WPOLL_MS);
    }
}

/* ---- tracer: process_vm_readv/writev against a stopped tracee ---- */

int cng_pt_vm_rw(long nr, long pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt,
                 long *out) {
    if (!g_tab || !g_pt_local)
        return 0;
    struct pt_link *e = pt_find((s32)pid);
    if (!e || __atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) != (s32)sys_getpid())
        return 0; /* not our tracee: let the host answer */
    if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != PT_ST_STOPPED) {
        *out = -ESRCH;
        return 1;
    }
    int write = (nr == __NR_process_vm_writev);
    u64 *lv = (u64 *)lvec, *rv = (u64 *)rvec;
    /* Narrow the counts the way the kernel does before anything else looks at
     * them: import_iovec takes nr_segs as an `unsigned`, so the top half of a
     * 64-bit count is simply dropped, and only then is what is left refused
     * above UIO_MAXIOV. Both halves of that matter here.
     *
     * The bound is what keeps `count * 16` from being a 64-bit multiply that
     * wraps. A count whose low 60 bits are small wrapped the product to almost
     * nothing — 1<<60 gives exactly 0, and cng_user_readable answers 1 for a
     * zero-length range — so the validation passed having probed nothing, and
     * the walk below then indexed lv[]/rv[] for as many entries as the count
     * claimed, off the end of whatever the guest had mapped. In the handler
     * that is an unblockable SIGSEGV.
     *
     * The truncation is what keeps the answer the kernel's: a guest passing
     * 1<<60 is not refused there, it is read as *zero* segments and gets back
     * 0, and (1<<60)+1 transfers one. Rejecting those with -EINVAL would have
     * been a divergence of its own. */
    unsigned lc = (unsigned)lcnt, rc = (unsigned)rcnt;
    if (lc > CNG_UIO_MAXIOV || rc > CNG_UIO_MAXIOV) {
        *out = -EINVAL;
        return 1;
    }
    if (!cng_user_readable(lv, (unsigned long)lc * 16) ||
        !cng_user_readable(rv, (unsigned long)rc * 16)) {
        *out = -EFAULT;
        return 1;
    }
    /* Walk the two iovec lists in lockstep, as the kernel does. */
    unsigned long li = 0, ri = 0, loff = 0, roff = 0, total = 0;
    while (li < lc && ri < rc) {
        u64 lbase = lv[li * 2] + loff, llen = lv[li * 2 + 1] - loff;
        u64 rbase = rv[ri * 2] + roff, rlen = rv[ri * 2 + 1] - roff;
        if (!llen) { li++, loff = 0; continue; }
        if (!rlen) { ri++, roff = 0; continue; }
        u64 n = llen < rlen ? llen : rlen;
        if (n > PT_MBOX)
            n = PT_MBOX;
        if (write) {
            if (!cng_user_readable((void *)lbase, (unsigned long)n))
                break;
            memcpy(e->data, (void *)lbase, (size_t)n);
            pt_cmd(e, PT_CMD_WRITE, rbase, n);
        } else {
            pt_cmd(e, PT_CMD_READ, rbase, n);
        }
        if (e->result < 0)
            break;
        u64 got = (u64)e->result;
        if (!write && got) {
            if (!cng_user_writable((void *)lbase, (unsigned long)got))
                break;
            memcpy((void *)lbase, e->data, (size_t)got);
        }
        total += got;
        loff += got;
        roff += got;
        if (got < n)
            break; /* a fault on the tracee side: short, as the kernel reports */
    }
    *out = (long)total;
    return 1;
}

/* ---- signal routing: cooperative group-stops ---- */

static int pt_is_stopsig(int sig) {
    return sig == 19 || sig == 20 || sig == 21 || sig == 22; /* STOP TSTP TTIN TTOU */
}

int cng_pt_signal_route(long pid, int sig) {
    if (!g_tab || pid <= 0)
        return 0;
    if (!__atomic_load_n(&g_tab->any_trace, __ATOMIC_ACQUIRE))
        return 0;
    if (!pt_is_stopsig(sig) && sig != 18 /*SIGCONT*/)
        return 0;
    /* Resolve to a thread group: an exact link match maps a tid to its group,
     * otherwise treat the argument as a tgid (whose main thread may be
     * untraced). */
    struct pt_link *hit = pt_find((s32)pid);
    s32 tgid = hit ? hit->tgid : (s32)pid;
    int routed = 0;
    for (int i = 0; i < PT_MAX; i++) {
        struct pt_link *e = &g_tab->links[i];
        s32 t = __atomic_load_n(&e->tracee, __ATOMIC_ACQUIRE);
        if (t <= 0 || e->tgid != tgid)
            continue;
        if (__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE) <= 0)
            continue;
        if (__atomic_load_n(&e->state, __ATOMIC_ACQUIRE) == PT_ST_EXITED)
            continue;
        if (sig == 18) {
            /* SIGCONT ends a listening group-stop with a fresh EVENT_STOP. The
             * tracee never left its service loop, so only the link is re-armed
             * and the tracer woken. */
            if (!__atomic_load_n(&e->listening, __ATOMIC_ACQUIRE))
                continue;
            __atomic_store_n(&e->listening, 0, __ATOMIC_RELEASE);
            e->stop_sig = 5 /*SIGTRAP*/;
            e->event = CNG_PTRACE_EVENT_STOP;
            e->syscall_stop = 0;
            e->si_signo = 5;
            e->si_code = (CNG_PTRACE_EVENT_STOP << 8) | 5;
            __atomic_store_n(&e->reported, 0, __ATOMIC_RELEASE);
            pt_bump_gen();
            pt_wake_tracer(__atomic_load_n(&e->tracer, __ATOMIC_ACQUIRE));
            routed = 1;
            continue;
        }
        /* A real SIGSTOP would freeze the tracee inside its service loop, and
         * every later tracer request would deadlock — so a stop signal aimed at
         * a tracee becomes a cooperative group-stop instead. The kernel stops
         * every thread of the group and each traced one reports its own stop;
         * we kick each live link, which is the same thing for a group whose
         * threads are all traced. */
        __atomic_store_n(&e->stopsig_pending, (u32)sig, __ATOMIC_RELEASE);
        cng_pt_kick(e->tgid, t, CNG_PT_KICK_ATTACH);
        routed = 1;
    }
    return routed;
}

/* ---- arming ---- */

void cng_pt_arm_tracee(void) {
    struct pt_self *s = pt_self_get(1);
    if (!s || s->traceall)
        return;
    s->traceall = 1;
    g_pt_local = 1;
    if (!cng_g_sigsys_ready)
        return;
    /* Our base filter traps only the path-bearing set; a tracee must stop on
     * every syscall, so stack a filter that traps everything. Filters cannot be
     * removed, so this outlives a later detach — a cost, never a correctness
     * problem (the dispatcher re-issues what it does not handle). */
    cng_install_seccomp_traceall();
}

void cng_pt_arm_tracer(void) {
    struct pt_self *s = pt_self_get(1);
    if (!s || s->tracer_armed)
        return;
    s->tracer_armed = 1;
    g_pt_local = 1;
    if (!cng_g_sigsys_ready || cng_install_seccomp_tracer() < 0)
        return;
    /* A multithreaded tracer (gdb) may wait on a thread other than the one that
     * attached, and a seccomp filter is per-task, so kick the siblings to
     * install it too. Threads created later inherit it. */
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/task",
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return;
    s32 me = (s32)sys_getpid(), self = (s32)sys_gettid();
    char buf[1024];
    long n;
    while ((n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0)) > 0) {
        for (long o = 0; o < n;) {
            struct {
                u64 ino, off;
                u16 reclen;
                u8 type;
                char name[];
            } *d = (void *)(buf + o);
            o += d->reclen;
            s32 tid = 0;
            const char *p = d->name;
            if (*p < '0' || *p > '9')
                continue;
            while (*p >= '0' && *p <= '9')
                tid = tid * 10 + (*p++ - '0');
            if (*p || tid == self)
                continue;
            cng_pt_kick(me, tid, CNG_PT_KICK_ARM);
        }
    }
    sys_close((int)fd);
}
