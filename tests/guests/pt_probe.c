/* ptrace(2) protocol exerciser — the differential guest for tests/m18_ptrace.sh.
 *
 * The same source is built twice: as an AArch64 guest run under chroot-ng, and
 * for the host, run directly against the real kernel's ptrace. The two runs must
 * print the same lines, so everything printed here is protocol — stop kinds,
 * wait statuses, event codes, exit codes — and never an address, a pid or a
 * syscall count, all of which legitimately differ.
 *
 * Only the register file itself is architecture-specific, and it is confined to
 * the shim below: which register holds the syscall number, how a syscall is
 * cancelled at an entry stop, and what a breakpoint instruction looks like.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#define NT_ARM_SYSTEM_CALL 0x404

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif
#define PT_GET_SYSCALL_INFO 0x420e
#define PT_SYSCALL_INFO_ENTRY 1
#define PT_SYSCALL_INFO_EXIT  2
#define O_TRACESYSGOOD 0x01
#define O_TRACEFORK    0x02
#define O_TRACEEXEC    0x10
#define O_TRACEEXIT    0x40
#define EV_FORK 1
#define EV_EXEC 4

#if defined(__aarch64__)
struct uregs {
    unsigned long long x[31], sp, pc, pstate;
};
#define R_SYSNO(r)     ((long)(r).x[8])
#define R_RET(r)       ((long)(r).x[0])
#define R_SETRET(r, v) ((r).x[0] = (unsigned long long)(long)(v))
#define R_PC(r)        ((r).pc)
#define R_SETPC(r, v)  ((r).pc = (unsigned long long)(v))
#define R_ARG1(r)      ((r).x[1])
#define NR_GETPID      172
#define NR_OPENAT      56
#define BP_STEP_BACK   0 /* BRK leaves PC on the breakpoint itself */
typedef unsigned int bp_word;
#define BP_INSN ((bp_word)0xd4200000u) /* brk #0 */
#elif defined(__x86_64__)
struct uregs {
    unsigned long long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx,
        rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss, fs_base, gs_base, ds,
        es, fs, gs;
};
#define R_SYSNO(r)     ((long)(r).orig_rax)
#define R_RET(r)       ((long)(r).rax)
#define R_SETRET(r, v) ((r).rax = (unsigned long long)(long)(v))
#define R_PC(r)        ((r).rip)
#define R_SETPC(r, v)  ((r).rip = (unsigned long long)(v))
#define R_ARG1(r)      ((r).rsi)
#define NR_GETPID      39
#define NR_OPENAT      257
#define BP_STEP_BACK   1 /* INT3 leaves RIP one past the trap byte */
typedef unsigned char bp_word;
#define BP_INSN ((bp_word)0xcc) /* int3 */
#else
#error "unsupported architecture"
#endif

static int getregs(pid_t pid, struct uregs *r) {
    struct iovec io = {r, sizeof *r};
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 ? 0 : -1;
}

static int setregs(pid_t pid, struct uregs *r) {
    struct iovec io = {r, sizeof *r};
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 ? 0 : -1;
}

/* Cancel the syscall the tracee is stopped at its entry to. On arm64 the
 * in-flight number lives in its own regset — writing x8 back is ignored by the
 * kernel — while on x86-64 it is orig_rax in the main one. */
static int cancel_syscall(pid_t pid, struct uregs *r) {
#if defined(__aarch64__)
    int nr = -1;
    struct iovec io = {&nr, sizeof nr};
    (void)r;
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &io) == 0
               ? 0
               : -1;
#else
    r->orig_rax = (unsigned long long)-1;
    return setregs(pid, r);
#endif
}

/* ---- reporting ---- */

static void show(int st) {
    if (WIFEXITED(st))
        printf("exited %d\n", WEXITSTATUS(st));
    else if (WIFSIGNALED(st))
        printf("killed %d\n", WTERMSIG(st));
    else if (WIFSTOPPED(st)) {
        int ev = st >> 16;
        if (ev)
            printf("event %d\n", ev);
        else
            printf("stop %d\n", WSTOPSIG(st));
    } else
        printf("status %#x\n", st);
}

static int wait_for(pid_t pid, int *st) {
    int r;
    do {
        r = waitpid(pid, st, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0) {
        printf("wait failed %d\n", errno);
        exit(1);
    }
    return r;
}

/* Wait for the child's first stop after PTRACE_TRACEME + a self-directed
 * SIGSTOP, which is where every scenario below starts. */
static void expect_first_stop(pid_t pid) {
    int st;
    wait_for(pid, &st);
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        printf("bad first stop ");
        show(st);
        exit(1);
    }
    printf("attached\n");
}

static void child_start(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
        _exit(90);
    raise(SIGSTOP);
}

/* ---- scenarios ---- */

/* A tracee stops when told to, resumes when told to, and its exit status
 * reaches the tracer. */
static int sc_basic(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        _exit(7);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* Syscall-entry and syscall-exit stops, filtered down to one syscall the child
 * makes on purpose so the count does not depend on the libc. */
static int sc_sysstop(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        getpid();
        getpid();
        _exit(3);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACESYSGOOD);
    int entry = 1, seen = 0;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
            break;
        int st;
        wait_for(pid, &st);
        if (!WIFSTOPPED(st)) {
            show(st);
            break;
        }
        if (WSTOPSIG(st) != (SIGTRAP | 0x80)) {
            printf("unexpected ");
            show(st);
            continue;
        }
        struct uregs r;
        if (getregs(pid, &r) != 0) {
            printf("getregs failed\n");
            return 1;
        }
        if (R_SYSNO(r) == NR_GETPID) {
            if (entry)
                printf("entry getpid\n");
            else
                printf("exit getpid %s\n", R_RET(r) == pid ? "ok" : "bad");
            seen++;
        }
        entry = !entry;
    }
    printf("syscall stops %d\n", seen);
    return 0;
}

/* The tracer cancels a syscall at its entry stop and substitutes a return
 * value — proot's whole method. */
static int sc_cancel(void) {
    int fds[2];
    if (pipe(fds) != 0)
        return 1;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        child_start();
        long v = (long)getpid();
        ssize_t ignore = write(fds[1], &v, sizeof v);
        (void)ignore;
        _exit(0);
    }
    close(fds[1]);
    expect_first_stop(pid);
    int done = 0, entry = 1;
    while (!done) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
            break;
        int st;
        wait_for(pid, &st);
        if (!WIFSTOPPED(st))
            break;
        struct uregs r;
        if (getregs(pid, &r) != 0)
            break;
        if (entry && R_SYSNO(r) == NR_GETPID) {
            cancel_syscall(pid, &r);
            printf("cancelled\n");
            /* The exit stop of the cancelled call is where the substituted
             * return value is written. */
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
                break;
            wait_for(pid, &st);
            if (getregs(pid, &r) == 0) {
                R_SETRET(r, 4242);
                setregs(pid, &r);
            }
            done = 1;
            entry = 1;
            continue;
        }
        entry = !entry;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    long got = 0;
    ssize_t n = read(fds[0], &got, sizeof got);
    printf("child saw %s\n", (n == (ssize_t)sizeof got && got == 4242) ? "4242"
                                                                       : "other");
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PEEKDATA / POKEDATA against the tracee's own data. */
static volatile long g_magic = 0x1234;

static int sc_poke(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        _exit(g_magic == 0x5678 ? 0 : 1);
    }
    expect_first_stop(pid);
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)&g_magic, 0);
    printf("peek %s\n", (v == 0x1234 && errno == 0) ? "ok" : "bad");
    if (ptrace(PTRACE_POKEDATA, pid, (void *)&g_magic, (void *)0x5678) != 0)
        printf("poke failed %d\n", errno);
    v = ptrace(PTRACE_PEEKDATA, pid, (void *)&g_magic, 0);
    printf("readback %s\n", v == 0x5678 ? "ok" : "bad");
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* A signal-delivery stop, and the tracer suppressing the signal. SIGUSR1's
 * default action would terminate the child, so "exited 5" is only reachable if
 * the suppression worked. */
static int sc_signal(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        raise(SIGUSR1);
        _exit(5);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st); /* stop 10 (SIGUSR1) */
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* The same stop, with the signal delivered rather than suppressed: the child
 * dies of it, and the tracer sees WIFSIGNALED. */
static int sc_deliver(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        raise(SIGUSR1);
        _exit(5);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    ptrace(PTRACE_CONT, pid, 0, (void *)(long)SIGUSR1);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PTRACE_O_TRACEFORK: the event stop in the parent, the new pid in
 * GETEVENTMSG, and the auto-attached child's own initial stop — which the
 * tracer must be able to wait for even though that child is not its own. */
static int sc_fork(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        pid_t k = fork();
        if (k == 0)
            _exit(11);
        _exit(12);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACEFORK);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st); /* event 1 (PTRACE_EVENT_FORK) */
    unsigned long msg = 0;
    ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
    int gst;
    pid_t g = waitpid((pid_t)msg, &gst, 0);
    printf("newchild %s\n",
           (g == (pid_t)msg && WIFSTOPPED(gst)) ? "stopped" : "missing");
    ptrace(PTRACE_CONT, (pid_t)msg, 0, 0);
    ptrace(PTRACE_CONT, pid, 0, 0);
    /* Both deaths reach the tracer: one through its own child, one through the
     * ptrace relationship. They can arrive in either order, so report the pair
     * of exit codes sorted. */
    int codes[2] = {-1, -1};
    for (int i = 0; i < 2; i++) {
        int s2;
        pid_t w = wait(&s2);
        if (w < 0)
            break;
        codes[i] = WIFEXITED(s2) ? WEXITSTATUS(s2) : -WTERMSIG(s2);
    }
    if (codes[0] > codes[1]) {
        int t = codes[0];
        codes[0] = codes[1];
        codes[1] = t;
    }
    printf("deaths %d %d\n", codes[0], codes[1]);
    return 0;
}

/* PTRACE_O_TRACEEXEC: ptrace survives an exec, and the tracee stops once the
 * new image is in place. argv[2] is the path to exec (this same binary, in
 * whatever namespace the run happens to have). */
static int sc_exec(const char *self) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        execl(self, self, "hello", (char *)0);
        _exit(88);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACEEXEC);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st); /* event 4 (PTRACE_EVENT_EXEC) */
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* How strace actually starts a program: the child asks to be traced and execs
 * straight away, and the tracer's first stop is the post-exec SIGTRAP — which
 * an emulated execve has to produce for itself, since it never enters the
 * kernel's exec path. */
static int sc_execstart(const char *self) {
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0)
            _exit(90);
        execl(self, self, "hello", (char *)0);
        _exit(88);
    }
    int st;
    wait_for(pid, &st);
    show(st); /* stop 5: SIGTRAP, no PTRACE_EVENT_EXEC without the option */
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PTRACE_GET_SYSCALL_INFO: what modern strace asks for instead of pairing
 * entry and exit stops itself. */
struct sysinfo_buf {
    unsigned char op, pad[3];
    unsigned int arch;
    unsigned long long ip, sp;
    unsigned long long nr, args[6];
};

static int sc_sysinfo(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        getpid();
        _exit(9);
    }
    expect_first_stop(pid);
    /* Without TRACESYSGOOD the kernel reports op=NONE even at a syscall stop,
     * because the op is derived from the stop's si_code. */
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACESYSGOOD);
    int printed = 0;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
            break;
        int st;
        wait_for(pid, &st);
        if (!WIFSTOPPED(st)) {
            show(st);
            break;
        }
        struct sysinfo_buf si;
        memset(&si, 0, sizeof si);
        long n = ptrace(PT_GET_SYSCALL_INFO, pid, (void *)sizeof si, &si);
        if (n <= 0) {
            printf("syscall_info unsupported\n");
            break;
        }
        if (si.op == PT_SYSCALL_INFO_ENTRY && (long)si.nr == NR_GETPID &&
            !printed) {
            printf("info entry getpid %s\n", si.ip && si.sp ? "ok" : "bad");
            printed = 1;
        }
    }
    printf("info seen %d\n", printed);
    return 0;
}

/* What a tracer reads out of a path-bearing syscall's arguments. Under
 * chroot-ng the syscall is about to be translated into the rootfs, so this is
 * where a host path would leak into the trace — the tracer must see the string
 * the guest itself passed, and the result the guest itself gets. */
static int sc_patharg(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        int fd = open("/cng-probe-path", O_RDONLY);
        if (fd >= 0)
            close(fd);
        _exit(errno == ENOENT ? 0 : 1);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACESYSGOOD);
    int entry = 1, done = 0;
    while (!done) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
            break;
        int st;
        wait_for(pid, &st);
        if (!WIFSTOPPED(st))
            break;
        if (WSTOPSIG(st) != (SIGTRAP | 0x80))
            continue;
        struct uregs r;
        if (getregs(pid, &r) != 0)
            break;
        if (R_SYSNO(r) == NR_OPENAT) {
            if (entry) {
                /* Read the path out of the tracee, one word at a time, the way
                 * a tracer without process_vm_readv has to. */
                char path[128];
                unsigned long base = (unsigned long)R_ARG1(r);
                size_t i = 0;
                while (i + sizeof(long) <= sizeof path) {
                    errno = 0;
                    long w = ptrace(PTRACE_PEEKDATA, pid, (void *)(base + i), 0);
                    if (errno != 0)
                        break;
                    memcpy(path + i, &w, sizeof w);
                    if (memchr(path + i, 0, sizeof w))
                        break;
                    i += sizeof w;
                }
                path[sizeof path - 1] = 0;
                printf("openat path %s\n", path);
            } else {
                printf("openat rc %s\n", R_RET(r) == -ENOENT ? "ENOENT"
                                                             : "other");
                done = 1;
            }
        }
        entry = !entry;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PTRACE_O_TRACEEXIT: the tracee parks before it actually dies, with the
 * pending wait status readable through GETEVENTMSG. */
static int sc_exitstop(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        _exit(23);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)O_TRACEEXIT);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st); /* event 6 (PTRACE_EVENT_EXIT) */
    unsigned long msg = 0;
    ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
    printf("pending status %s\n", WIFEXITED((int)msg) && WEXITSTATUS((int)msg) == 23
                                       ? "ok"
                                       : "bad");
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* A breakpoint: poke a trap instruction over a function's first word, run into
 * it, put the original back, and let the child finish. */
/* noinline, and with a side effect, so the call survives optimization and
 * &bp_target really is the first instruction the child executes there — a
 * breakpoint poked into an inlined copy would never be reached. */
static volatile int g_bp_hits;

__attribute__((noinline)) static void bp_target(void) {
    g_bp_hits++;
}

static int sc_break(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        bp_target();
        _exit(21);
    }
    expect_first_stop(pid);
    void *addr = (void *)(unsigned long)&bp_target;
    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (errno != 0) {
        printf("peektext failed %d\n", errno);
        return 1;
    }
    long mask = (long)(unsigned long)(bp_word) ~(bp_word)0;
    long patched = (orig & ~mask) | (long)(unsigned long)BP_INSN;
    if (ptrace(PTRACE_POKETEXT, pid, addr, (void *)patched) != 0) {
        printf("poketext failed %d\n", errno);
        return 1;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) {
        printf("no trap ");
        show(st);
        return 1;
    }
    struct uregs r;
    getregs(pid, &r);
    printf("trap at %s\n",
           R_PC(r) - BP_STEP_BACK == (unsigned long long)(unsigned long)addr
               ? "bp"
               : "elsewhere");
    ptrace(PTRACE_POKETEXT, pid, addr, (void *)orig);
    if (BP_STEP_BACK) {
        R_SETPC(r, R_PC(r) - BP_STEP_BACK);
        setregs(pid, &r);
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PTRACE_SINGLESTEP: three steps, each landing on a different PC, and the
 * child still runs to completion afterwards. */
static int sc_step(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        bp_target();
        _exit(13);
    }
    expect_first_stop(pid);
    unsigned long long prev = 0;
    int moved = 0;
    for (int i = 0; i < 3; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0) {
            printf("singlestep failed %d\n", errno);
            return 1;
        }
        int st;
        wait_for(pid, &st);
        if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) {
            printf("bad step ");
            show(st);
            return 1;
        }
        struct uregs r;
        if (getregs(pid, &r) != 0) {
            printf("getregs failed\n");
            return 1;
        }
        if (R_PC(r) != prev)
            moved++;
        prev = R_PC(r);
    }
    printf("stepped %d\n", moved);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* PTRACE_ATTACH to a running process that is not our child's tracer-to-be:
 * here a child that is already running a loop. */
static volatile int g_spin;

static int sc_attach(void) {
    int fds[2];
    if (pipe(fds) != 0)
        return 1;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        /* Announce readiness, then spin until killed. */
        ssize_t ignore = write(fds[1], "x", 1);
        (void)ignore;
        for (;;) {
            g_spin++;
            usleep(1000);
        }
    }
    close(fds[1]);
    char c;
    ssize_t n = read(fds[0], &c, 1);
    (void)n;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        printf("attach failed %d\n", errno);
        kill(pid, SIGKILL);
        return 1;
    }
    int st;
    wait_for(pid, &st);
    printf("attach %s\n",
           (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP) ? "stopped" : "odd");
    struct uregs r;
    printf("regs %s\n", getregs(pid, &r) == 0 ? "ok" : "bad");
    if (ptrace(PTRACE_DETACH, pid, 0, 0) != 0)
        printf("detach failed %d\n", errno);
    else
        printf("detached\n");
    kill(pid, SIGKILL);
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* process_vm_readv against a stopped tracee: the fast path strace takes before
 * falling back to PEEKDATA, and the one the emulation has to serve itself
 * because the host has no reason to believe we are attached.
 *
 * What is asserted is what it does with the iovec counts, which a tracer passes
 * through from its caller and the emulation walks the arrays by. The kernel's
 * import_iovec takes nr_segs as an `unsigned`, so a 64-bit count is truncated
 * first and only then refused above UIO_MAXIOV — which makes 1<<60 read as zero
 * segments and succeed, not fail. Protocol only, so the host build is the
 * oracle for all of it. */
static const char *vmres(ssize_t n) {
    if (n >= 0)
        return n == 0 ? "zero" : "bytes";
    switch (errno) {
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case ESRCH:  return "ESRCH";
    case EPERM:  return "EPERM";
    default:     return "other";
    }
}

static int sc_vmrw(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        _exit(9);
    }
    expect_first_stop(pid);

    char buf[64];
    struct iovec liov = {buf, sizeof buf};
    struct iovec riov = {(void *)&g_magic, sizeof g_magic};
    ssize_t n;

    errno = 0;
    n = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
    printf("vmrw plain %s\n", vmres(n));

    /* 1<<60 entries of 16 bytes is exactly 2^64: the count that wraps a
     * length check to zero, and the one the kernel truncates to no segments. */
    errno = 0;
    n = process_vm_readv(pid, &liov, 1UL << 60, &riov, 1, 0);
    printf("vmrw wrapcnt %s\n", vmres(n));

    errno = 0;
    n = process_vm_readv(pid, &liov, (1UL << 60) + 1, &riov, 1, 0);
    printf("vmrw wrapcnt1 %s\n", vmres(n));

    errno = 0;
    n = process_vm_readv(pid, &liov, 2048, &riov, 1, 0);
    printf("vmrw overmax %s\n", vmres(n));

    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

/* Signals the emulation deliberately does NOT take over must still reach the
 * kernel while the task is traced. It hooks every catchable signal to route
 * delivery through the stop machinery, but SIGKILL and SIGSTOP are not among
 * them — nothing can be, the kernel refuses — and treating "traced" as "we own
 * every signal" made rt_sigaction(SIGKILL, act) report success from a private
 * mirror where the kernel answers EINVAL.
 *
 * Raw rt_sigaction, because a libc wrapper is free to pre-screen SIGKILL itself
 * and we want the kernel's answer, not glibc's. */
struct ksigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};

static const char *sigact_res(long r) {
    if (r == 0)
        return "ok";
    return errno == EINVAL ? "EINVAL" : "other";
}

static int sc_sigact(void) {
    pid_t pid = fork();
    if (pid == 0) {
        child_start();
        struct ksigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.handler = (void *)1; /* SIG_IGN */
        errno = 0;
        printf("traced_setkill=%s\n",
               sigact_res(syscall(SYS_rt_sigaction, SIGKILL, &sa, (void *)0, 8)));
        errno = 0;
        printf("traced_setstop=%s\n",
               sigact_res(syscall(SYS_rt_sigaction, SIGSTOP, &sa, (void *)0, 8)));
        /* Query-only is allowed for both, and must stay allowed. */
        struct ksigaction o;
        errno = 0;
        printf("traced_querykill=%s\n",
               sigact_res(syscall(SYS_rt_sigaction, SIGKILL, (void *)0, &o, 8)));
        _exit(5);
    }
    expect_first_stop(pid);
    ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    wait_for(pid, &st);
    show(st);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "hello")) {
        printf("hello\n");
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: pt_probe <scenario> [arg]\n");
        return 2;
    }
    const char *s = argv[1];
    if (!strcmp(s, "basic"))
        return sc_basic();
    if (!strcmp(s, "sysstop"))
        return sc_sysstop();
    if (!strcmp(s, "cancel"))
        return sc_cancel();
    if (!strcmp(s, "poke"))
        return sc_poke();
    if (!strcmp(s, "signal"))
        return sc_signal();
    if (!strcmp(s, "deliver"))
        return sc_deliver();
    if (!strcmp(s, "fork"))
        return sc_fork();
    if (!strcmp(s, "exec"))
        return sc_exec(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(s, "execstart"))
        return sc_execstart(argc > 2 ? argv[2] : argv[0]);
    if (!strcmp(s, "sysinfo"))
        return sc_sysinfo();
    if (!strcmp(s, "exitstop"))
        return sc_exitstop();
    if (!strcmp(s, "patharg"))
        return sc_patharg();
    if (!strcmp(s, "break"))
        return sc_break();
    if (!strcmp(s, "step"))
        return sc_step();
    if (!strcmp(s, "attach"))
        return sc_attach();
    if (!strcmp(s, "vmrw"))
        return sc_vmrw();
    if (!strcmp(s, "sigact"))
        return sc_sigact();
    fprintf(stderr, "unknown scenario %s\n", s);
    return 2;
}
