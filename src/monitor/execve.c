/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* In-process execve/execveat emulation.
 *
 * A real kernel execve replaces the address space, wiping our SIGSYS handler
 * (the seccomp filter survives, but with no handler the next trap kills the
 * process). So we never let execve reach the kernel: we load the new program
 * ourselves and rewrite the trapped signal context to enter it, leaving the
 * monitor resident. This is the piece that makes the in-process model hold
 * together across program replacement.
 *
 * We do not tear down the previous program's mappings; the new program gets a
 * fresh stack and a kernel-chosen load base, so they don't collide. Repeated
 * execve leaks the old images (acceptable for now; noted in STATUS).
 */
#include "cng/broker.h" /* cng_broker_env: no getenv in a freestanding build */
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/procfs.h"
#include "cng/ptrace.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

unsigned long *cng_host_auxv = 0;

/* A real execve closes every FD_CLOEXEC descriptor. Our in-process emulation
 * never issues a real execve, so we must do this ourselves — otherwise the
 * exec-notify pipe that fork/exec launchers (git's run-command, posix_spawn)
 * open with O_CLOEXEC never closes, and the parent blocks forever waiting for
 * the EOF that signals "exec succeeded". Iterate /proc/self/fd and close each fd
 * whose FD_CLOEXEC bit is set (skipping the directory fd we are scanning). */
/* A real execve resets signal dispositions (caught -> default, ignored kept)
 * and disables the alternate signal stack. Our in-process emulation must do the
 * same, or the new program inherits the previous one's handlers and altstack —
 * e.g. a C compiler exec'd from Go would inherit Go's SIGSEGV/SIGURG handlers
 * and Go's small per-thread sigaltstack, onto which our SA_ONSTACK SIGSYS
 * handler would then deliver. SIGSYS is left alone (our monitor owns it). */
static void cng_reset_signals(void) {
    /* kernel struct sigaction: handler, flags, restorer, mask (32 bytes). */
    unsigned long cur[4], dfl[4] = {0, 0, 0, 0};
    for (int s = 1; s <= 64; s++) {
        if (s == CNG_SIGSYS)
            continue;
        if (CNG_SYS(__NR_rt_sigaction, s, 0, cur, 8, 0, 0) < 0)
            continue;             /* SIGKILL/SIGSTOP etc.: unqueryable, skip */
        if (cur[0] == 0 || cur[0] == 1)
            continue;             /* already SIG_DFL, or SIG_IGN (keep ignored) */
        CNG_SYS(__NR_rt_sigaction, s, dfl, 0, 8, 0, 0);
    }
    /* stack_t: ss_sp(8), ss_flags(4)@8, ss_size(8)@16 => 24 bytes. SS_DISABLE=2. */
    unsigned long ss[3] = {0, 2, 0};
    CNG_SYS(__NR_sigaltstack, ss, 0, 0, 0, 0, 0);
    /* Same reset applied to the record ptsig.c keeps of what the guest asked
     * for, and reinstatement of the dispositions that must outlive an exec:
     * the ptrace kick handler, and our own hooks if this task is still traced
     * (ptrace survives execve — that is what strace relies on). */
    cng_pt_sig_exec_reset();
}

void cng_close_cloexec(void) {
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc/self/fd",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return;
    char buf[4096];
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)dfd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        long o = 0;
        while (o + 19 <= n) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19; /* d_name at record offset +19 */
            o += reclen;
            int fd = 0, ok = (nm[0] >= '0' && nm[0] <= '9');
            for (const char *c = nm; *c; c++) {
                if (*c < '0' || *c > '9') {
                    ok = 0;
                    break;
                }
                fd = fd * 10 + (*c - '0');
            }
            if (!ok || fd == (int)dfd)
                continue;
            long fl = CNG_SYS(__NR_fcntl, fd, 1 /*F_GETFD*/, 0, 0, 0, 0);
            if (fl >= 0 && (fl & 1 /*FD_CLOEXEC*/))
                sys_close(fd);
        }
    }
    sys_close((int)dfd);
}

/* Shebang nesting, as fs/exec.c bounds it: a chain of SHEB_MAX #! files runs and
 * the next one is -ELOOP. Each level needs its interpreter (and optional
 * argument) to stay alive until the stack is built, since both end up in the
 * new argv.
 *
 * Measured, not read — at four this refused a chain the kernel executes. And it
 * is not one number across kernels: the same ladder of scripts ending in an ELF
 * runs six deep on the Android 13 device (5.15 GKI, seventh -ELOOP) and five
 * deep on a 6.17 dev host (sixth -ELOOP). We advertise 6.1.0 through uname and
 * exist to run on Android, so the device's answer is the one to match; a guest
 * never reaches the host kernel with these anyway, which is why the divergence
 * costs a level of nesting off-device and nothing else. */
#define SHEB_MAX   6
#define SHEB_WORD  256
/* Pointer slots reserved ahead of the snapshot's argv for the shebang chain.
 * Each level contributes its interpreter and at most one argument, and the
 * script the guest named goes in once at the end: 2 * SHEB_MAX + 1. The
 * rebuilt vector is written into those slots, ending where the caller's own
 * argv[1] already sits — so the tail is not copied at all and there is no
 * length to run out of. */
#define SHEB_RESERVE (2 * SHEB_MAX + 1)

/* argv/envp snapshot.
 *
 * The strings the exec'ing program hands us are copied into the NEW program's
 * stack, and that copy happens after the new image is mapped. An ET_EXEC guest
 * is mapped MAP_FIXED at its own link-time vaddr — so when the program calling
 * execve is itself ET_EXEC at that same vaddr (every binary a plain `-static`
 * toolchain produces lands at 0x400000), the load lands right on top of the
 * .rodata/.data/heap holding those strings, and the exec'd program came up with
 * garbage argv. The old image is legitimately dead by then, being replaced; what
 * was wrong is reading the caller's arguments out of it afterwards.
 *
 * So take our own copy of path/argv/envp up front, before anything is mapped.
 * One kernel-placed anonymous mapping: it lands in the high mmap region, which
 * no ET_EXEC vaddr reaches, and is released once the stack is built. The total
 * is bounded the way a real execve bounds it, with the same -E2BIG (which the
 * emulation never answered before — the strings just ran off the guest stack). */
struct exec_args {
    void *mem;
    unsigned long len;
    const char *path;
    char **argv;
    char **envp;
};

/* Per-string and per-vector bounds, as fs/exec.c has them: MAX_ARG_STRLEN is
 * 32 pages, and the entry count is capped well above anything real (the kernel's
 * MAX_ARG_STRINGS is 0x7FFFFFFF, but the byte budget below bites long before
 * that, and a bounded walk is what keeps a bogus vector from costing a probe
 * per entry forever). Both answer -E2BIG, as the kernel does.
 *
 * 32 *pages*, which is not 32 * 4096 everywhere: the Android devices this
 * exists for run 16 KiB pages, where the kernel's own MAX_ARG_STRLEN is 512 KiB
 * and a hard-coded 128 KiB refused, with an -E2BIG of our own invention,
 * strings a real execve there takes. exec_arg_max() below reads the page size
 * for the same reason. */
static unsigned long exec_max_strlen(void) { return 32 * cng_page_size; }
#define EXEC_MAX_STRINGS 0x40000u

/* What a real execve accepts: a quarter of RLIMIT_STACK, floored at 32 pages
 * (fs/exec.c). Read the limit rather than inventing a number, so a command line
 * the kernel would take is not refused here — but clamp to what the stack we
 * actually hand the guest can hold, since ours is a fixed mapping rather than
 * one that grows to RLIMIT_STACK. Being the kernel's own formula, it also cannot
 * refuse anything that reached this process through a real execve: only a guest
 * assembling an oversized argv itself can hit it, which is the case the kernel
 * answers E2BIG for too. */
static unsigned long exec_arg_max(void) {
    unsigned long lim = CNG_GUEST_STACK_SIZE / 4;
    struct cng_rlimit rl;
    if (sys_prlimit64(0, CNG_RLIMIT_STACK, 0, &rl) == 0 &&
        rl.cur != CNG_RLIM_INFINITY && rl.cur / 4 < lim)
        lim = rl.cur / 4;
    if (lim < 32 * cng_page_size)
        lim = 32 * cng_page_size;
    return lim;
}

/* Copy one NULL-terminated string vector in: pointers into dst_vec, strings out
 * of *pool. Nothing here is trusted twice — src is guest memory, and another
 * thread of the exec'ing process is free to change it between the sizing pass
 * and this one. Two ways it used to bite:
 *
 *  - a strlen/memcpy straight off src[i] read guest memory the sizing pass had
 *    validated some syscalls ago. A thread that unmapped the strings in the gap
 *    turned execve's -EFAULT into a SIGSEGV inside the handler, where every
 *    signal but SIGSYS is masked and the fault is fatal. So the bytes are taken
 *    with cng_user_strcopyin, which measures and copies in one act and answers
 *    -EFAULT for what will not come across.
 *  - the vector itself is guest memory too, and it was walked a slot at a time
 *    with the same exposure. It comes across in one act now, into the very slots
 *    the strings' own pointers then replace — the entry count staying the sizing
 *    pass's, which is also how fs/exec.c holds it (count() fixes bprm->argc and
 *    copy_strings() copies exactly that many).
 *
 * Writes the slot after the terminator through *next. Returns 0, or -E2BIG /
 * -EFAULT, which is what execve(2) answers for the same two inputs. */
static long copy_vec(char **src, char **dst_vec, int slots, char **pool,
                     char *end, char ***next) {
    int i = 0;
    if (src && slots > 1) {
        long r = cng_user_copyin(dst_vec, src, (unsigned long)slots * sizeof *src);
        if (r < 0)
            return r;
        for (; i < slots - 1 && dst_vec[i]; i++) {
            /* Whichever bites first: the room left in the pool, or the per-string
             * bound the sizing pass held this string to (MAX_ARG_STRLEN). */
            unsigned long cap = (unsigned long)(end - *pool);
            if (cap > exec_max_strlen())
                cap = exec_max_strlen();
            long n = cng_user_strcopyin(*pool, dst_vec[i], cap);
            if (n < 0)
                return n;
            dst_vec[i] = *pool;
            *pool += n + 1;
        }
    }
    dst_vec[i] = 0; /* slots >= 1 always: the terminator has a slot of its own */
    *next = dst_vec + i + 1;
    return 0;
}

static void exec_args_free(struct exec_args *a) {
    if (a->mem)
        sys_munmap(a->mem, a->len);
    a->mem = 0;
}

/* Measure one vector, validating as it goes. argv/envp are guest memory the
 * kernel never gets to check for us — walking them with a bare strlen is how a
 * wild pointer became a fatal SIGSEGV inside the handler instead of the -EFAULT
 * execve(2) promises.
 *
 * The slots are taken a window at a time rather than read where they lie: a
 * validated vector is not a frozen one, and another thread of the exec'ing
 * process can put a wild pointer into a slot the count pass already blessed.
 * The strings themselves are measured out of a copy too (cng_user_strlen), and
 * neither measurement is trusted afterwards — copy_vec re-takes both. What this
 * pass is for is the arena size and the -E2BIG the kernel would give.
 * Returns the total bytes of its strings, or -errno. */
#define VEC_WIN 64
static long vec_bytes(char **v, int *count) {
    long n = cng_user_veclen(v, EXEC_MAX_STRINGS);
    if (n < 0)
        return n;
    unsigned long bytes = 0;
    char *win[VEC_WIN];
    for (long i = 0; i < n;) {
        long k = n - i < VEC_WIN ? n - i : VEC_WIN;
        if (cng_user_copyin(win, v + i, (unsigned long)k * sizeof *win) < 0)
            return -EFAULT;
        for (long j = 0; j < k; j++) {
            long len = cng_user_strlen(win[j], exec_max_strlen());
            if (len < 0)
                return len;
            bytes += (unsigned long)len + 1;
        }
        i += k;
    }
    *count = (int)n;
    return (long)bytes;
}

static long exec_args_take(struct exec_args *a, const char *path, char **argv,
                           char **envp) {
    int argc = 0, envc = 0;
    long pn = cng_user_strlen(path, exec_max_strlen());
    if (pn < 0)
        return pn;
    long ab = vec_bytes(argv, &argc);
    if (ab < 0)
        return ab;
    long eb = vec_bytes(envp, &envc);
    if (eb < 0)
        return eb;
    unsigned long bytes = (unsigned long)pn + 1 + (unsigned long)ab +
                          (unsigned long)eb;
    /* Two NULL-terminated pointer arrays, 8-aligned, ahead of the strings —
     * plus the slots a shebang chain prepends into (see SHEB_RESERVE). */
    unsigned long vecs = ((unsigned long)SHEB_RESERVE + (unsigned long)argc + 1 +
                          (unsigned long)envc + 1) * 8;
    unsigned long max = exec_arg_max();
    if (bytes > max || vecs > max - bytes)
        return -E2BIG;

    a->len = cng_page_up(vecs + bytes);
    a->mem = sys_mmap(0, a->len, CNG_PROT_READ | CNG_PROT_WRITE,
                      CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (a->mem == CNG_MAP_FAILED || cng_is_err((long)a->mem)) {
        a->mem = 0;
        return -ENOMEM;
    }

    char *pool = (char *)a->mem + vecs;
    char *end = (char *)a->mem + a->len;
    a->argv = (char **)a->mem + SHEB_RESERVE;
    char **envslot = 0, **after = 0;
    long rc = copy_vec(argv, a->argv, argc + 1, &pool, end, &envslot);
    a->envp = envslot;
    if (rc == 0)
        rc = copy_vec(envp, a->envp, envc + 1, &pool, end, &after);
    /* The path last, into what the two vectors left. It is re-measured as it is
     * taken, like every other string here: `pn` sized the arena, it does not
     * decide what gets copied out of memory the guest may since have changed. */
    if (rc == 0) {
        long pl = cng_user_strcopyin(pool, path, (unsigned long)(end - pool));
        rc = pl < 0 ? pl : 0;
    }
    if (rc < 0) { /* raced its own measurement, or ran off it: -E2BIG/-EFAULT */
        exec_args_free(a);
        return rc;
    }
    a->path = pool;
    return 0;
}

/* Emulation body: resolve the target (shebang-aware), plan the program and its
 * ELF interpreter, map them, build the stack, and pass the commit point (close
 * FD_CLOEXEC fds, reset signal dispositions, retarget /proc/self/exe). Returns
 * -errno on failure — every one of which is raised before the first mapping, so
 * the caller is still there to receive it — or 0 with *out_sp and *out_entry set
 * for the caller to transfer control into the new program. Past that first
 * mapping the caller no longer exists and a failure is fatal (exec_fatal).
 *
 * path/argv/envp are the snapshot taken by execve_core, not the guest's own
 * pointers: everything from cng_load_elf onwards would otherwise be reading
 * memory the load just replaced. */
unsigned long cng_g_brk0 = 0;

/* POSIX timers the guest created. There is no syscall that enumerates a
 * process's timers, and the id the guest was handed is the only handle there is,
 * so they are recorded as they are created (dispatch traps timer_create and
 * timer_delete for exactly this) and deleted at the next exec. /proc/self/timers
 * lists them too, but the number in that file is the kernel's own id, which is
 * not what a guest under an emulator holds — recording what we handed out is
 * both simpler and true on every tier. Best-effort: a full table just means a
 * timer outlives the exec, as it did before. */
#define CNG_TIMERS_MAX 64
static int g_timers[CNG_TIMERS_MAX];
static int g_ntimers;

void cng_timer_note(int id) {
    if (g_ntimers < CNG_TIMERS_MAX)
        g_timers[g_ntimers++] = id;
}

void cng_timer_forget(int id) {
    for (int i = 0; i < g_ntimers; i++)
        if (g_timers[i] == id) {
            g_timers[i] = g_timers[--g_ntimers];
            return;
        }
}

/* ---- the address space of the program being replaced --------------------
 *
 * A real execve throws the whole mm away. Ours cannot: the monitor's code, its
 * gate and its state are pages of the same address space, so the previous
 * program's mappings were simply left behind and an exec chain accumulated all
 * of them. Measured, a static guest exec'ing itself eight times: 66.8 MB of
 * address space per generation — 64 MiB of it the stack, the rest the image.
 *
 * What can be given back is exactly what the loader mapped for the program
 * being replaced: its image, its interpreter's, and the stack built for it.
 * Each is one reservation with a recorded extent (cng_loaded.map_lo/map_len,
 * cng_g_stack_lo/len), so nothing has to be inferred from /proc/self/maps and
 * no mapping of ours can be caught up in it by accident.
 *
 * What cannot is what the previous program mapped itself — the libraries its
 * ld.so loaded, its arenas, its thread stacks. Following those would mean a VMA
 * table of our own maintained on every mmap/munmap/mremap, which is the
 * per-syscall cost the -R tier exists to avoid. The brk heap, the one such
 * region with a handle on it, is already wound back in cng_exec_reset.
 *
 * Two conditions, both of them load-bearing:
 *
 *  - The process must be single-threaded. A real execve kills the other threads
 *    (de_thread); ours cannot, so they go on running the old program's code on
 *    the old program's stacks, and unmapping either would fault them where today
 *    they merely keep running. fork() clones one thread, so the ordinary
 *    fork+exec — which is how nearly every exec happens — arrives here alone.
 *
 *  - The old stack cannot be handed back at the exec itself. The SIGSYS tier
 *    returns into the new program through rt_sigreturn, and the frame that
 *    reads is on the stack the guest was interrupted on — that same stack,
 *    whenever the guest has no sigaltstack. So a generation is *retired* rather
 *    than freed, and given back at the next dispatched syscall, which is the new
 *    program's first and is long past that sigreturn.
 *
 * The reap also refuses to unmap anything overlapping the live generation. An
 * ET_EXEC guest is MAP_FIXED at its link-time vaddr, so a program that execs
 * another one built the same way has the new image standing exactly where the
 * old one did — and there the old range is not memory to give back, it is the
 * new program. */
#define EXEC_GEN_MAX 3 /* program, interpreter, stack */

struct exec_range {
    unsigned long lo, len;
};

static struct exec_range g_gen_live[EXEC_GEN_MAX];
static struct exec_range g_gen_dead[EXEC_GEN_MAX];
static int g_gen_have_dead;

static int range_overlap(const struct exec_range *a, const struct exec_range *b) {
    return a->len && b->len && a->lo < b->lo + b->len && b->lo < a->lo + a->len;
}

/* Is this the only thread of the process? /proc/self/task is the kernel's own
 * answer rather than a count of ours, and it is two syscalls. A directory we
 * cannot read answers "no", which costs the reclaim and not correctness. */
static int exec_single_threaded(void) {
    /* CNG_EXEC_RECLAIM_FORCE=1: take the answer as yes. It is meant for
     * qemu-user, which runs a thread of its own (call_rcu) beside the guest's
     * one and so never reads as single-threaded from inside — the emulator's
     * thread touches no guest mapping, but nothing here can tell it from a
     * guest's. Everything the reclaim then does is exercised as it is on a
     * device. Same testing convention as CNG_SCRATCH_NONE and CNG_PROCREG_NONE;
     * setting it against a genuinely multithreaded guest unmaps memory those
     * threads are running on. */
    if (cng_broker_env("CNG_EXEC_RECLAIM_FORCE"))
        return 1;
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/task",
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    int tids = 0;
    char buf[1024];
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, fd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        for (long o = 0; o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n) {
                tids = 2; /* a record we cannot walk: do not claim to know */
                break;
            }
            if (buf[o + 19] >= '1' && buf[o + 19] <= '9') /* skip . and .. */
                tids++;
            o += reclen;
        }
        if (tids > 1)
            break;
    }
    sys_close((int)fd);
    return tids == 1;
}

void cng_exec_reap(void) {
    if (!g_gen_have_dead)
        return;
    g_gen_have_dead = 0;
    unsigned long sp = (unsigned long)&sp;
    for (int i = 0; i < EXEC_GEN_MAX; i++) {
        struct exec_range d = g_gen_dead[i];
        g_gen_dead[i].lo = g_gen_dead[i].len = 0;
        if (!d.len)
            continue;
        if (sp >= d.lo && sp < d.lo + d.len)
            continue; /* we are standing on it; leave it to the kernel */
        int clash = 0;
        for (int j = 0; j < EXEC_GEN_MAX; j++)
            if (range_overlap(&d, &g_gen_live[j]))
                clash = 1;
        if (!clash)
            sys_munmap((void *)d.lo, d.len);
    }
}

void cng_exec_generation(const struct cng_loaded *prog,
                         const struct cng_loaded *interp,
                         unsigned long stack_lo, unsigned long stack_len) {
    struct exec_range neu[EXEC_GEN_MAX];
    memset(neu, 0, sizeof neu);
    if (prog) {
        neu[0].lo = prog->map_lo;
        neu[0].len = prog->map_len;
    }
    if (interp) {
        neu[1].lo = interp->map_lo;
        neu[1].len = interp->map_len;
    }
    neu[2].lo = stack_lo;
    neu[2].len = stack_len;

    /* Retire the outgoing generation, unless another thread may still be in it.
     * A range the incoming one has already taken over is dropped rather than
     * retired: unmapping it would unmap the new program. (The thread count is
     * a /proc read, so it is only asked when there is something to retire —
     * which the first program of an invocation, registering itself, has not.) */
    int outgoing = 0;
    for (int i = 0; i < EXEC_GEN_MAX; i++)
        outgoing |= g_gen_live[i].len != 0;
    if (outgoing && exec_single_threaded()) {
        for (int i = 0; i < EXEC_GEN_MAX; i++) {
            g_gen_dead[i] = g_gen_live[i];
            for (int j = 0; j < EXEC_GEN_MAX; j++)
                if (range_overlap(&g_gen_dead[i], &neu[j]))
                    g_gen_dead[i].lo = g_gen_dead[i].len = 0;
            if (g_gen_dead[i].len)
                g_gen_have_dead = 1;
        }
    }
    memcpy(g_gen_live, neu, sizeof g_gen_live);
}

/* State a real execve drops with the address space, and ours does not.
 *
 * We keep the address space — that is the whole point of the in-process model —
 * so each of these outlives the program that set it and goes on pointing into
 * memory the next program now owns:
 *
 *  - POSIX timers keep firing, into a signal handler that no longer exists.
 *  - clear_child_tid is where the kernel writes a zero and issues a FUTEX_WAKE
 *    when the thread exits. Left pointing at the old libc's TCB, that write
 *    lands in whatever the new program put there.
 *  - the robust futex list is walked by the kernel on exit, following pointers
 *    the old program owned.
 *  - the heap keeps every byte the old program allocated, and an exec chain
 *    (a wrapper script running a wrapper script) accumulates all of them.
 *
 * All best-effort: a kernel without POSIX timers has no such file, and a failed
 * brk simply leaves the heap where it was. */
static void cng_exec_reset(void) {
    cng_rewrite_lazy_reset(); /* the sites those pools branch from are gone */
    for (int i = 0; i < g_ntimers; i++)
        CNG_SYS(__NR_timer_delete, g_timers[i], 0, 0, 0, 0, 0);
    g_ntimers = 0;
    CNG_SYS(__NR_set_tid_address, 0, 0, 0, 0, 0, 0);
    /* Android blocks set_robust_list (measured: SIGSYS from the zygote filter on
     * Android 13), and a syscall we know is refused is not one to issue — the
     * trap would be answered by the gate-net, i.e. by the nested SIGSYS delivery
     * the design does not want to depend on, and where no handler is installed
     * at all (the direct-drive `-t exectest` driver) it is simply fatal.
     *
     * Nothing is left behind by skipping it, either. The filter that refuses it
     * is one ambient filter over the whole process — which is what cng_blocked
     * measures — so it refused the old program's own set_robust_list too, and a
     * program that could never register a list has none for the kernel to walk
     * at exit. The reset matters exactly where the call works, which is where
     * it is made. */
    if (!cng_blocked[__NR_set_robust_list])
        CNG_SYS(__NR_set_robust_list, 0,
                24 /* sizeof(struct robust_list_head) */, 0, 0, 0, 0);
    if (cng_g_brk0) {
        long cur = CNG_SYS(__NR_brk, 0, 0, 0, 0, 0, 0);
        if (cur > 0 && (unsigned long)cur > cng_g_brk0)
            CNG_SYS(__NR_brk, cng_g_brk0, 0, 0, 0, 0, 0);
    }
}

/* A failure after the point of no return.
 *
 * The kernel draws exactly this line around begin_new_exec(): everything that
 * can be refused is refused before it, and a failure after it force_sigsegv()s
 * the process — there is no caller left to hand an errno to. Ours is the same
 * situation for the same reason: an ET_EXEC image goes down MAP_FIXED at its
 * link-time vaddr, which is the calling program's own text, so `return -Esomething`
 * would resume a program whose code has just been replaced.
 *
 * Die by the signal rather than by exit(), so a wait() sees WIFSIGNALED with
 * SIGSEGV — what the shell prints as "Segmentation fault", and what a real
 * kernel would have reported. Name only the guest path: `host` spells out where
 * the rootfs lives on the device (see the load-failure trace below). */
static _Noreturn void exec_fatal(const char *path, const char *what, long err) {
    cng_dprintf(2,
                "chroot-ng: exec %s: %s failed (code %d) with the new image "
                "already mapped over the old one; nothing left to return to\n",
                path, what, (int)err);
    unsigned long dfl[4] = {0, 0, 0, 0};
    CNG_SYS(__NR_rt_sigaction, CNG_SIGSEGV, dfl, 0, sizeof(cng_sigset_t), 0, 0);
    unsigned long unblock = 1UL << (CNG_SIGSEGV - 1);
    CNG_SYS(__NR_rt_sigprocmask, 1 /*SIG_UNBLOCK*/, &unblock, 0,
            sizeof(cng_sigset_t), 0, 0);
    CNG_SYS(__NR_tgkill, sys_getpid(), sys_gettid(), CNG_SIGSEGV, 0, 0, 0);
    /* A blocked-or-ignored corner: leave no doubt about the outcome. */
    CNG_SYS(__NR_exit_group, 0x80 | CNG_SIGSEGV, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

/* What the kernel answers when an image cannot be loaded. All of it is measured
 * on the host, because the two roles do not answer alike and neither is one
 * errno:
 *
 *   image is...         program      interpreter
 *   missing             ENOENT       ENOENT
 *   a directory         EACCES       EACCES
 *   not executable      EACCES       EACCES
 *   shorter than a hdr  ENOEXEC      EIO
 *   not an ELF for us   ENOEXEC      ELIBBAD
 *   PT_INTERP past EOF  EIO          EIO
 *
 * The split is in fs/binfmt_elf.c: the program's header arrives in the 256-byte
 * buffer bprm_execve already read, so a short file is simply a header that does
 * not check out and every format declines it — ENOEXEC — while the interpreter
 * is read on its own with elf_read(), which turns a short read into EIO and a
 * failed check into ELIBBAD. The last row is that same elf_read() reached from
 * the *program* side: the PT_INTERP string lives past the header buffer, so a
 * file too short to hold it answers EIO whichever of the two roles it was in.
 *
 * This mattered less when it could not be observed: an interpreter that failed
 * to load did so after the program had been mapped over the caller, so the
 * guest died rather than read an errno. It is answered before anything is
 * mapped now, and the caller lives to see which of the five it was. */
static long exec_load_errno(int rc, const struct cng_elf_plan *plan, int interp) {
    switch (rc) {
    case CNG_LOAD_EOPEN:
        return plan->err ? plan->err : -ENOENT;
    case CNG_LOAD_EACCES:
        return -EACCES;
    case CNG_LOAD_EIO:
        return interp ? -EIO : -ENOEXEC;
    case CNG_LOAD_EINTERP:
        return -EIO;
    case CNG_LOAD_EINVAL:
        /* fs/binfmt_elf.c answers -EINVAL for a PT_LOAD it cannot make sense
         * of — a file part longer than its memory part, a segment mmap refuses
         * — and answers it past its own point of no return, so a real caller
         * never lives to read it (measured: execve reports EINVAL and the
         * process is killed with SIGSEGV). Ours is refused in the pass that
         * maps nothing, so the caller is still there. For an ELF interpreter
         * the kernel's answer is unreachable in its own way — load_elf_interp
         * reports into a process it is about to kill — so it joins the other
         * malformed-interpreter cases at -ELIBBAD, which a caller can act on. */
        return interp ? -ELIBBAD : -EINVAL;
    default: /* EFORMAT, ETOOBIG, ECLOBBER: a header that does not check out */
        return interp ? -ELIBBAD : -ENOEXEC;
    }
}

static long execve_load(int dirfd, const char *path, char **argv, char **envp,
                        int flags, unsigned long *out_sp,
                        unsigned long *out_entry) {
    char host[CNG_PATH_MAX];
    char sheb_interp[SHEB_MAX][SHEB_WORD], sheb_arg[SHEB_MAX][SHEB_WORD];
    int sheb_hasarg[SHEB_MAX];
    const char *cur = path; /* the guest path of the image at this level */
    int gfd = -1;           /* an open fd for the image, when we have one */
    int nofollow = (flags & CNG_AT_SYMLINK_NOFOLLOW) != 0;
    int depth = 0;          /* how many #! levels were followed */

    /* Whatever the last exec retired, before this one maps anything. It cannot
     * be given back after: an ET_EXEC image goes down at its link-time vaddr,
     * so a retired range may be exactly where the incoming program is about to
     * land, and the range would then be the new program. Safe here — the frame
     * that stood on the retired stack belonged to the exec before this one, and
     * its sigreturn is what put the caller here. */
    cng_exec_reap();

    for (;; depth++) {
        if (depth > SHEB_MAX) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] execve %s -> shebang nesting\n", path);
            return -ELOOP;
        }
        /* Resolve through the rootfs/bind map. Level 0 honors the execveat
         * dirfd — a relative name used to be handed to the kernel as-is, so it
         * resolved against the HOST cwd and left the guest view entirely — and
         * its AT_SYMLINK_NOFOLLOW; every level after it is an interpreter path
         * from a #! line, which is absolute or cwd-relative by definition. */
        if (depth == 0) {
            if (cng_resolve_at(dirfd, cur, !nofollow, host, sizeof host) != 0) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] execve %s -> unresolved\n", cur);
                return -ENOENT;
            }
            /* AT_SYMLINK_NOFOLLOW does not open the link's target, it refuses:
             * the kernel answers ELOOP for a final symlink. */
            if (nofollow) {
                char st[144];
                if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, host, st,
                            CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0 &&
                    (*(unsigned *)(st + 16) & 0170000) == 0120000)
                    return -ELOOP;
            }
        } else if (cng_resolve(cur, 1, host, sizeof host) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] execve interp %s -> unresolved\n", cur);
            return -ENOENT;
        }
        /* Every failure below this point is silent otherwise, and the guest only
         * sees an errno — trace the resolution so a device-side failure says
         * which stage produced it (and which build is running). */
        if (cng_g_debug)
            cng_dprintf(2, "[cng] execve resolve %s -> %s\n", cur, host);

        /* When the target names one of our own fds ("/proc/self/fd/N", how apk
         * runs package scripts, and what execveat(AT_EMPTY_PATH) becomes) work
         * from that open file description instead of reopening the magic link.
         * execve(2) checks *execute* permission on the inode; a reopen checks
         * *read* — so a script a real (root) chroot execs happily can come back
         * EACCES here, since our fake root has no DAC bypass. The fd we already
         * hold needs no permission check at all, and covers the anonymous files
         * (memfd, O_TMPFILE, deleted) that have no readable name. Everything
         * below reads it with pread/mmap, so the guest's file offset — shared
         * with its parent through fork — is left alone. */
        gfd = cng_proc_self_fd(host); /* the guest's fd: never close it */
        if (gfd >= 0 && cng_g_debug) {
            char st[128]; /* AArch64 struct stat: mode@16, uid@24, gid@28 */
            if (CNG_SYS(__NR_fstat, gfd, st, 0, 0, 0, 0) == 0)
                cng_dprintf(2, "[cng] execve fd=%d mode=%o uid=%u gid=%u\n", gfd,
                            *(unsigned *)(st + 16) & 07777,
                            *(unsigned *)(st + 24), *(unsigned *)(st + 28));
        }

        char hdr[257];
        long fd = gfd;
        if (gfd < 0) {
            fd = sys_openat(CNG_AT_FDCWD, host, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
            if (fd < 0) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] execve open %s -> errno=%d\n", host,
                                (int)-fd);
                return fd; /* the real errno (EACCES, ELOOP, ENOENT, ...) */
            }
        }
        /* Read the header the way the loader reads its own (read_exact in
         * elf.c): accumulate and retry EINTR. A single pread may come back
         * short of what was asked for, and treating that as "not a script"
         * hands a perfectly good `#!` file to the ELF loader, which then
         * rejects it as a short read — a valid script answered ENOEXEC. */
        long n = 0;
        for (;;) {
            long r = sys_pread64((int)fd, hdr + n, (size_t)(256 - n), n);
            if (r < 0) {
                if (r == -EINTR)
                    continue;
                n = r; /* a hard error: let the loader produce the errno */
                break;
            }
            if (r == 0 || (n += r) >= 256)
                break; /* EOF, or the whole shebang line and then some */
        }
        if (gfd < 0)
            sys_close((int)fd);
        if (!(n >= 2 && hdr[0] == '#' && hdr[1] == '!'))
            break; /* an ELF (or something the loader will reject) */

        /* `#! interp [arg]`: the kernel replaces argv[0] with the interpreter,
         * then the optional argument, then the path of the script being run —
         * which at depth > 0 is the previous level's interpreter, so the chain
         * accumulates rather than resetting. */
        hdr[n < 256 ? n : 256] = '\0';
        char *p = hdr + 2;
        while (*p == ' ' || *p == '\t')
            p++;
        char *i0 = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            p++;
        size_t ilen = (size_t)(p - i0);
        while (*p == ' ' || *p == '\t')
            p++;
        char *a0 = p;
        while (*p && *p != '\n' && *p != '\r')
            p++;
        size_t alen = (size_t)(p - a0);
        /* The argument runs to the end of the line, embedded blanks and all
         * ("#!/usr/bin/env python3 -u" is one argument) — but not the line's
         * *trailing* blanks, which fs/binfmt_script.c walks back over before it
         * parses anything. Keeping them handed the interpreter "-e   " where
         * the kernel hands it "-e", and a shell rejects that as an illegal
         * option: a shebang line with a stray space at the end, which editors
         * leave behind routinely, ran everywhere but here. */
        while (alen > 0 && (a0[alen - 1] == ' ' || a0[alen - 1] == '\t'))
            alen--;
        if (ilen == 0 || ilen >= SHEB_WORD) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] execve %s -> bad shebang\n", cur);
            return -ENOEXEC;
        }
        if (depth == SHEB_MAX)
            return -ELOOP; /* no room to record another level */
        memcpy(sheb_interp[depth], i0, ilen);
        sheb_interp[depth][ilen] = '\0';
        sheb_hasarg[depth] = alen > 0 && alen < SHEB_WORD;
        if (sheb_hasarg[depth]) {
            memcpy(sheb_arg[depth], a0, alen);
            sheb_arg[depth][alen] = '\0';
        }
        cur = sheb_interp[depth];
        gfd = -1; /* the image to load is now the interpreter, by path */
        nofollow = 0;
    }

    if (cng_g_debug)
        cng_dprintf(2, "[cng] exec %s host=%s file_backed=%d\n", path, host,
                    cng_g_loader_file);

    /* Header pass, program and ELF interpreter both: read, validate, map
     * nothing. Every refusal an execve can produce has to be produced here,
     * because the map pass below is what replaces the calling program. */
    struct cng_elf_plan pplan, iplan;
    struct cng_loaded prog;
    int rc = gfd >= 0 ? cng_elf_plan_fd(gfd, &pplan, &prog)
                      : cng_elf_plan(host, &pplan, &prog);
    if (rc != CNG_LOAD_OK) {
        /* A failed exec tells the guest what the kernel would: the errno, and
         * nothing else. This was an unconditional line on the guest's own
         * stderr, and it named `host` — the one thing the whole path layer
         * exists to keep from the guest, since it spells out where the rootfs
         * lives on the device. It also put text no real execve produces into a
         * stream package managers capture and log. Both belong under CNG_DEBUG
         * with the rest of the exec tracing. */
        if (cng_g_debug)
            cng_dprintf(2, "[cng] exec %s (%s): load failed rc=%d\n", path,
                        host, rc);
        return exec_load_errno(rc, &pplan, 0);
    }
    if (cng_g_debug)
        cng_dprintf(2, "[cng]   prog dyn=%d lo=%lx hi=%lx interp=%d\n",
                    pplan.is_dyn, pplan.lo, pplan.hi, prog.has_interp);

    /* The interpreter is planned here rather than loaded after the program,
     * which is the whole point of the split: a rootfs without the loader the
     * binary names is an ordinary, common failure — a partially populated tree,
     * a musl binary under glibc — and the kernel answers it with ENOENT while
     * the caller keeps running. Loading it *after* the program answered the same
     * ENOENT into a program that had already been overwritten. */
    struct cng_loaded interp;
    int have_interp = 0;
    if (prog.has_interp) {
        char ip[CNG_PATH_MAX];
        iplan.err = -ENOENT; /* a name that did not resolve has no open to ask */
        int irc = cng_resolve(prog.interp, 1, ip, sizeof ip) != 0
                      ? CNG_LOAD_EOPEN
                      : cng_elf_plan(ip, &iplan, &interp);
        if (irc != CNG_LOAD_OK) {
            if (cng_g_debug) /* guest-visible stderr: see the load failure above */
                cng_dprintf(2, "[cng] exec %s: interp %s load failed rc=%d\n",
                            path, prog.interp, irc);
            cng_elf_plan_release(&pplan);
            return exec_load_errno(irc, &iplan, 1);
        }
        have_interp = 1;
    }

    /* --- point of no return ------------------------------------------------
     * Both images are known good; from here the address space is being taken
     * apart and a failure can only be fatal (see exec_fatal). The program goes
     * down first and the interpreter second, which is also the only safe order:
     * the program is MAP_FIXED at a fixed vaddr while the interpreter is
     * kernel-placed, so mapping the interpreter first risks the kernel putting
     * it inside the span the program is about to claim. */
    rc = cng_elf_map(&pplan, 0, &prog);
    cng_elf_plan_release(&pplan);
    if (rc != CNG_LOAD_OK)
        exec_fatal(path, "mapping the program", rc);
    if (cng_g_debug)
        cng_dprintf(2, "[cng]   prog base=%lx entry=%lx phdr=%lx lo=%lx hi=%lx\n",
                    prog.base, prog.entry, prog.phdr, prog.load_lo,
                    prog.load_hi);
    if (have_interp) {
        rc = cng_elf_map(&iplan, 0, &interp);
        cng_elf_plan_release(&iplan);
        if (rc != CNG_LOAD_OK)
            exec_fatal(path, "mapping the ELF interpreter", rc);
        if (cng_g_debug)
            cng_dprintf(2, "[cng]   interp %s base=%lx entry=%lx lo=%lx hi=%lx\n",
                        prog.interp, interp.base, interp.entry, interp.load_lo,
                        interp.load_hi);
    }

    /* The argv the kernel would have built for a #! chain: each level's
     * interpreter and optional argument, innermost first, then the script as
     * the guest named it, then the caller's argv from [1] on — [0] is what the
     * interpreter name replaces.
     *
     * Written into the slots reserved in front of the caller's own vector, so
     * the tail stays exactly where it already is. It used to be copied into a
     * fixed 128-entry array, which silently dropped everything past ~123: a
     * `#!/bin/sh` script run as `./s.sh *` in a directory of 500 files saw the
     * first 123 of them and exited 0. The kernel has no such limit — argv is
     * bounded by bytes, not entries — so nothing was reported and the rest of
     * the files were simply never processed.
     *
     * An *empty* argv is a legal exec (the kernel's remove_arg_zero has nothing
     * to remove), and there the tail is the terminator itself. */
    char **eff_argv = argv;
    int argc = 0;
    if (argv)
        while (argv[argc])
            argc++;
    if (depth > 0) {
        char *pre[SHEB_RESERVE];
        int np = 0;
        for (int d = depth - 1; d >= 0; d--) {
            pre[np++] = sheb_interp[d];
            if (sheb_hasarg[d])
                pre[np++] = sheb_arg[d];
        }
        pre[np++] = (char *)path; /* the script, as the guest named it */
        char **tail = argc >= 1 ? argv + 1 : argv;
        eff_argv = tail - np;
        for (int i = 0; i < np; i++)
            eff_argv[i] = pre[i];
        argc = np + (argc >= 1 ? argc - 1 : 0);
    }

    /* The stack has to be built after the images, since AT_PHDR/AT_BASE/AT_ENTRY
     * are only known once they are placed — so this is the one remaining thing
     * that can fail past the commit, and it is fatal rather than -E2BIG.
     *
     * It should not be reachable: exec_args_take already refused anything above
     * exec_arg_max(), which is clamped to a quarter of CNG_GUEST_STACK_SIZE,
     * and the stack needs at most twice the vector plus once the strings — half
     * the region, with the shebang chain's own additions (bounded by
     * SHEB_RESERVE entries of SHEB_WORD) far inside the margin. Raise that clamp
     * and the arithmetic stops holding, which is what this line is here to say. */
    unsigned long sp = cng_build_stack(argc, eff_argv, envp, cng_host_auxv,
                                       &prog, have_interp ? &interp : 0,
                                       argc > 0 ? eff_argv[0] : path);
    if (!sp)
        exec_fatal(path, "building the initial stack", -E2BIG);
    unsigned long entry = have_interp ? interp.entry : prog.entry;
    if (cng_g_debug)
        cng_dprintf(2, "[cng]   argc=%d sp=%lx entry=%lx -> enter\n", argc, sp,
                    entry);

    /* Anything that needs a descriptor has to ask before the commit point below
     * closes them. `host` may be a /proc/self/fd/N path — how apk runs a package
     * script, and what every memfd exec looks like — and the kernel records
     * /proc/self/exe as the file that fd names, so the magic link has to be read
     * while the fd is still open. Asked afterwards, it answered ENOENT for the
     * one caller shape that needs it (those fds are opened O_CLOEXEC, which is
     * the point of them), the untranslated /proc/self/fd/N was kept instead, and
     * /proc/self/exe came out as "/". `go` computes GOROOT from it. */
    char linked[CNG_PATH_MAX];
    const char *exe_host = host;
    if (!strncmp(host, "/proc/", 6)) {
        long n = sys_readlinkat(CNG_AT_FDCWD, host, linked, sizeof linked - 1);
        if (n > 0) {
            linked[n] = '\0';
            if (linked[0] == '/')
                exe_host = linked;
        }
    }

    /* Commit point: the new image loaded successfully, so from here we behave
     * like a real execve. Close FD_CLOEXEC descriptors (see cng_close_cloexec)
     * before entering the new program. */
    cng_close_cloexec();
    cng_reset_signals();
    /* System V shm attaches do not survive execve. A real one tears down the
     * address space; ours keeps it, so the mappings have to go explicitly (and
     * the broker's nattch with them). */
    cng_shm_detach_all();
    /* ...and neither do POSIX timers, the clear_child_tid futex, the robust
     * futex list, or the heap. A real execve drops all four with the address
     * space; ours keeps the address space, so each is state of a program that no
     * longer exists, pointing into memory the new one now owns. */
    cng_exec_reset();

    /* setuid/setgid-on-exec against the fake credential set (--setuid-root /
     * --setgid-root): `host` is the ELF the kernel would honor the set-id bit on
     * (the interpreter for a #! script, matching the kernel's script exception). */
    cng_cred_exec(host);

    /* Track the running program for /proc/self/exe fixups. A real kernel updates
     * /proc/self/exe on every execve (symlinks resolved); tools derive their
     * install root from it — notably `go`, which computes GOROOT from
     * os.Executable(). `host` is the resolved host path of the ELF we actually
     * load (the shebang interpreter for scripts, matching the kernel); store its
     * guest path in a persistent buffer. */
    static char exe_guest[CNG_PATH_MAX];
    if (cng_fs_untranslate(cng_g_fs, exe_host, exe_guest, sizeof exe_guest) == 0)
        cng_g_exe_guest = exe_guest;

    /* Republish the guest identity: a real execve replaces cmdline, environ,
     * auxv and comm, and this is where those change for us too. */
    if (!cng_g_no_proc)
        cng_procfs_publish_stack(sp);

    /* ...and the address space itself: the images and stack just mapped are the
     * generation now running, and the one they replace is retired. After the
     * republish above, which is the last reader of the outgoing stack. */
    cng_exec_generation(&prog, have_interp ? &interp : 0, cng_g_stack_lo,
                        cng_g_stack_len);

    *out_sp = sp;
    *out_entry = entry;
    return 0;
}

/* A guest string for the debug log, taken into `buf` rather than printed where
 * it lies. CNG_DEBUG must never change what the guest gets, and %s on a guest
 * pointer does exactly that: the print walks memory the guest owns, so a wild
 * path — the very -EFAULT case the line below is tracing — faulted inside the
 * SIGSYS handler, where every signal but SIGSYS is masked and the fault is the
 * death of the guest. dispatch.c's dbg_path takes the same copy for the same
 * reason. A string too long for the window is shown as far as it fits: a
 * truncated path says more in a log than a placeholder does. */
static const char *dbg_str(const char *s, char *buf, unsigned long sz) {
    if (!s)
        return "(null)";
    long n = cng_user_strcopyin(buf, s, sz);
    if (n >= 0)
        return buf;
    if (n != -E2BIG)
        return "(unreadable)";
    buf[sz - 1] = '\0';
    return buf;
}

/* Shared emulation core: the checks that need nothing but the arguments as they
 * arrive, then the snapshot (see exec_args_take), and from there on every check
 * reads the snapshot rather than the guest's own memory. */
static long execve_core(int dirfd, const char *path, char **argv, char **envp,
                        int flags, unsigned long *out_sp,
                        unsigned long *out_entry) {
    if (cng_g_debug) {
        char pb[CNG_PATH_MAX];
        cng_dprintf(2, "[cng] execve enter path=%s flags=%x\n",
                    dbg_str(path, pb, sizeof pb), (unsigned)flags);
    }

    /* execveat's flags word was never read, so AT_EMPTY_PATH and
     * AT_SYMLINK_NOFOLLOW were both silently ignored — and so was every
     * undefined bit, which the kernel refuses. */
    if (flags & ~(CNG_AT_EMPTY_PATH | CNG_AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    /* The path is guest memory, and it is measured out of a copy (`path[0]` was
     * a bare dereference once) because its length is what decides AT_EMPTY_PATH
     * below. Only the length is kept: the bytes themselves are taken again by
     * the snapshot, and every check past that point reads the snapshot. */
    long plen = cng_user_strlen(path, exec_max_strlen());
    if (plen < 0)
        return plen;

    /* AT_EMPTY_PATH: the dirfd IS the file to execute. Naming it through
     * /proc/self/fd puts it back on the ordinary path — the resolver keeps that
     * spelling in the host namespace, and the loader then works from the open
     * description itself, which is what reaches an anonymous or deleted image. */
    char fdpath[40];
    if (!plen) {
        if (!(flags & CNG_AT_EMPTY_PATH))
            return -ENOENT;
        if (sys_fcntl(dirfd, CNG_F_GETFD, 0) < 0)
            return -EBADF;
        cng_snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", dirfd);
        path = fdpath;
        dirfd = CNG_AT_FDCWD;
        flags &= ~CNG_AT_SYMLINK_NOFOLLOW; /* nothing left to follow */
    }

    struct exec_args a;
    long rc = exec_args_take(&a, path, argv, envp);
    if (rc < 0) {
        if (cng_g_debug) {
            /* `path` measured clean a moment ago, which is not the same as
             * still being there: the snapshot failing is itself a sign the
             * guest's memory moved under us. */
            char pb[CNG_PATH_MAX];
            cng_dprintf(2, "[cng] execve %s -> args snapshot errno=%ld\n",
                        dbg_str(path, pb, sizeof pb), -rc);
        }
        return rc;
    }

    /* l2s machinery is invisible to the guest — not executable either. Both
     * tiers (SIGSYS cng_emulate_execve, -R cng_execve_tramp) come through
     * here, so this covers every exec path.
     *
     * Judged on the snapshot, never on the guest's own pointer. The string this
     * reads has to be the string that then gets loaded, and between the check
     * and the copy the memory belongs to the exec'ing process: another of its
     * threads can put a hidden name there once the check has passed on an
     * innocent one, and can unmap it outright — which inside the handler, where
     * SIGSEGV is masked, is not an -ENOENT but the death of the guest.
     * cng_l2s_deny walks the path itself (basename, and a canonicalization for
     * "/.l2s"), so it is exactly the kind of caller dispatch.c already hands a
     * copy to. Being after the snapshot also puts the answer in the order the
     * rest of this path already gives it: a name that does not resolve is
     * -ENOENT from execve_load, likewise after -E2BIG/-EFAULT. */
    if (cng_g_l2s && cng_l2s_deny(dirfd, a.path)) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] execve %s -> l2s-hidden\n", a.path);
        exec_args_free(&a);
        return -ENOENT;
    }

    rc = execve_load(dirfd, a.path, a.argv, a.envp, flags, out_sp, out_entry);
    /* The new stack owns its own copy of everything by now (on the failure paths
     * nothing was consumed at all), so the snapshot goes either way. */
    exec_args_free(&a);
    return rc;
}

void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp, int flags) {
    unsigned long long *r = uc->uc_mcontext.regs;
    unsigned long sp, entry;
    long rc = execve_core(dirfd, path, argv, envp, flags, &sp, &entry);
    if (rc < 0) {
        r[0] = (unsigned long long)rc;
        return;
    }

    /* Rewrite the signal context to the new program's fresh entry state, then
     * return: rt_sigreturn resumes at `entry` with the new stack, handler and
     * filter still installed. */
    for (int i = 0; i < 31; i++)
        r[i] = 0;
    uc->uc_mcontext.sp = sp;
    uc->uc_mcontext.pc = entry;
    /* The post-execve stop. A real execve traps to the tracer with SIGTRAP once
     * the new image is in place — the stop strace waits for before it starts
     * following the program it launched, and the one our emulation would
     * otherwise never produce, since it never enters the kernel's exec path. */
    cng_pt_set_frame(cng_pt_uregs(uc), uc);
    cng_pt_report_exec(cng_pt_uregs(uc));
}

long cng_execve_tramp(int dirfd, const char *path, char **argv, char **envp,
                      int flags) {
    unsigned long sp, entry;
    long rc = execve_core(dirfd, path, argv, envp, flags, &sp, &entry);
    if (rc < 0)
        return rc;
    /* Ordinary call context (no signal frame): abandon the old program's stack
     * and enter the new image directly, like the initial `run` does. */
    if (cng_pt_active()) {
        /* The post-execve stop, on a frame describing the entry state we are
         * about to jump to — there is no signal context here to rewrite, so the
         * tracer's register edits are read back before the jump. */
        struct cng_uregs regs;
        memset(&regs, 0, sizeof regs);
        regs.sp = sp;
        regs.pc = entry;
        cng_pt_set_frame(&regs, 0);
        cng_pt_report_exec(&regs);
        sp = regs.sp;
        entry = regs.pc;
        cng_pt_set_frame(0, 0);
    }
    /* This is the one path out of the trampoline dispatcher that does not
     * return: we enter the new program instead. Hand the scratch stack back
     * first, or the flag stays set and every syscall the new program makes on
     * this thread runs the dispatcher on the guest's own stack again. */
    cng_scratch_leave();
    cng_enter(sp, entry);
}
