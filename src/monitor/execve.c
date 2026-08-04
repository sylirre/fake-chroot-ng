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
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/procfs.h"
#include "cng/ptrace.h"
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

/* Shebang nesting, as fs/exec.c bounds it. The kernel's limit is
 * BINPRM_MAX_RECURSION, and what that works out to in scripts is five: a chain
 * of five #! files runs, and the sixth is -ELOOP. Measured, not read — at four
 * this refused a chain the kernel executes. Each level needs its interpreter
 * (and optional argument) to stay alive until the stack is built, since both
 * end up in the new argv. */
#define SHEB_MAX   5
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
 * per entry forever). Both answer -E2BIG, as the kernel does. */
#define EXEC_MAX_STRLEN  (32u * 4096u)
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
 * of *pool. Both bounds are enforced rather than trusted — src is guest memory,
 * and another thread of the exec'ing process can grow it between the sizing pass
 * and this one. Returns the slot after the terminator, or NULL if it would not
 * fit (the caller answers -E2BIG, as the kernel does). */
static char **copy_vec(char **src, char **dst_vec, int slots, char **pool,
                       char *end) {
    int i = 0;
    for (; src && src[i]; i++) {
        if (i + 1 >= slots) /* +1: the terminator needs a slot too */
            return 0;
        size_t n = strlen(src[i]) + 1;
        if (n > (size_t)(end - *pool))
            return 0;
        memcpy(*pool, src[i], n);
        dst_vec[i] = *pool;
        *pool += n;
    }
    if (i >= slots)
        return 0;
    dst_vec[i] = 0;
    return dst_vec + i + 1;
}

static void exec_args_free(struct exec_args *a) {
    if (a->mem)
        sys_munmap(a->mem, a->len);
    a->mem = 0;
}

/* Measure one vector, validating as it goes. argv/envp are guest memory the
 * kernel never gets to check for us — walking them with a bare strlen is how a
 * wild pointer became a fatal SIGSEGV inside the handler instead of the -EFAULT
 * execve(2) promises. Returns the total bytes of its strings, or -errno. */
static long vec_bytes(char **v, int *count) {
    long n = cng_user_veclen(v, EXEC_MAX_STRINGS);
    if (n < 0)
        return n;
    unsigned long bytes = 0;
    for (long i = 0; i < n; i++) {
        long len = cng_user_strlen(v[i], EXEC_MAX_STRLEN);
        if (len < 0)
            return len;
        bytes += (unsigned long)len + 1;
    }
    *count = (int)n;
    return (long)bytes;
}

static long exec_args_take(struct exec_args *a, const char *path, char **argv,
                           char **envp) {
    int argc = 0, envc = 0;
    long pn = cng_user_strlen(path, EXEC_MAX_STRLEN);
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
    a->envp = copy_vec(argv, a->argv, argc + 1, &pool, end);
    if (!a->envp || !copy_vec(envp, a->envp, envc + 1, &pool, end) ||
        (size_t)pn + 1 > (size_t)(end - pool)) {
        exec_args_free(a);
        return -E2BIG; /* raced its own measurement: treat as too big */
    }
    memcpy(pool, path, (size_t)pn + 1);
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
    for (int i = 0; i < g_ntimers; i++)
        CNG_SYS(__NR_timer_delete, g_timers[i], 0, 0, 0, 0, 0);
    g_ntimers = 0;
    CNG_SYS(__NR_set_tid_address, 0, 0, 0, 0, 0, 0);
    CNG_SYS(__NR_set_robust_list, 0, 24 /* sizeof(struct robust_list_head) */, 0,
            0, 0, 0);
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
        return rc == CNG_LOAD_EOPEN ? -ENOENT : -ENOEXEC;
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
        if (cng_resolve(prog.interp, 1, ip, sizeof ip) != 0 ||
            cng_elf_plan(ip, &iplan, &interp) != CNG_LOAD_OK) {
            if (cng_g_debug) /* guest-visible stderr: see the load failure above */
                cng_dprintf(2, "[cng] exec %s: interp %s load failed\n", path,
                            prog.interp);
            cng_elf_plan_release(&pplan);
            return -ENOENT;
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

    *out_sp = sp;
    *out_entry = entry;
    return 0;
}

/* Shared emulation core: the checks that need only the guest's own pointers,
 * then the snapshot (see exec_args_take) around the part that maps the image. */
static long execve_core(int dirfd, const char *path, char **argv, char **envp,
                        int flags, unsigned long *out_sp,
                        unsigned long *out_entry) {
    if (cng_g_debug)
        cng_dprintf(2, "[cng] execve enter path=%s flags=%x\n",
                    path ? path : "(null)", (unsigned)flags);

    /* execveat's flags word was never read, so AT_EMPTY_PATH and
     * AT_SYMLINK_NOFOLLOW were both silently ignored — and so was every
     * undefined bit, which the kernel refuses. */
    if (flags & ~(CNG_AT_EMPTY_PATH | CNG_AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    /* The path is guest memory and everything below reads it — the l2s check,
     * the resolver, the snapshot — so it is validated once, here, before the
     * first dereference (`path[0]` was one). */
    long plen = cng_user_strlen(path, EXEC_MAX_STRLEN);
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

    /* l2s machinery is invisible to the guest — not executable either. Both
     * tiers (SIGSYS cng_emulate_execve, -R cng_execve_tramp) come through
     * here, so this covers every exec path. */
    if (cng_g_l2s && cng_l2s_deny(dirfd, path)) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] execve %s -> l2s-hidden\n", path);
        return -ENOENT;
    }

    struct exec_args a;
    long rc = exec_args_take(&a, path, argv, envp);
    if (rc < 0) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] execve %s -> args snapshot errno=%ld\n", path,
                        -rc);
        return rc;
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
