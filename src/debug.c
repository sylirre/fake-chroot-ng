/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] [-c CHROOT] PATH...
 * prints guest->host path translations (-c first emulates a chroot to CHROOT).
 * Used by the M5 unit tests (the path core is pure logic, fully exercisable
 * under qemu).
 */
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

#include <asm/unistd.h>

/* aarch64 struct stat accessors (for _l2stest). */
#define ST_INO(b)   (*(unsigned long long *)((char *)(b) + 8))
#define ST_MODE(b)  (*(unsigned *)((char *)(b) + 16))
#define ST_NLINK(b) (*(unsigned *)((char *)(b) + 20))
#define ST_MTIME(b) (*(long long *)((char *)(b) + 88))
#define ST_ISREG(b) ((ST_MODE(b) & 0170000) == 0100000)
/* struct statx accessors. */
#define STX_MASK(b)  (*(unsigned *)(char *)(b))
#define STX_NLINK(b) (*(unsigned *)((char *)(b) + 16))

int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;

    const char *rootfs = "/";
    const char *cwd = 0;
    const char *chroot_to = 0;
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int nb = 0;
    const char *paths[256];
    int np = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
            char *spec = argv[++i];
            char *c = strchr(spec, ':');
            if (c && nb < CNG_MAX_BINDS) {
                *c = '\0';
                bind_g[nb] = spec;
                bind_h[nb] = c + 1;
                nb++;
            }
        } else if (!strcmp(argv[i], "-C") && i + 1 < argc) {
            cwd = argv[++i];
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            chroot_to = argv[++i];
        } else if (np < 256) {
            paths[np++] = argv[i];
        }
    }

    struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    for (int i = 0; i < nb; i++)
        cng_fs_add_bind(&fs, bind_g[i], bind_h[i]);
    if (cwd)
        cng_fs_set_cwd(&fs, cwd);
    if (chroot_to) { /* what cng_dispatch does for chroot(2), minus the stat */
        char canon[CNG_PATH_MAX], hp[CNG_PATH_MAX];
        if (cng_fs_abscanon(&fs, chroot_to, canon, sizeof canon) == 0 &&
            cng_fs_translate(&fs, canon, hp, sizeof hp) == 0)
            cng_fs_chroot(&fs, canon, hp);
    }

    char out[CNG_PATH_MAX];
    for (int i = 0; i < np; i++) {
        if (cng_fs_translate(&fs, paths[i], out, sizeof out) == 0)
            cng_dprintf(1, "%s -> %s\n", paths[i], out);
        else
            cng_dprintf(1, "%s -> <overflow>\n", paths[i]);
    }
    return 0;
}

/* _dtest -r ROOT (open|access) GUESTPATH
 * Drives cng_dispatch directly (no seccomp) to verify translate+reissue: the
 * real syscall must hit ROOT/GUESTPATH. Exercised under qemu. */
int cng_cmd_dtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = "/";
    const char *op = 0, *gpath = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc)
            rootfs = argv[++i];
        else if (!op)
            op = argv[i];
        else if (!gpath)
            gpath = argv[i];
    }
    if (!op || !gpath) {
        cng_dprintf(2,
                    "usage: _dtest -r ROOT (open|access|dbgpath) GUESTPATH\n");
        return 2;
    }

    static struct cng_fs fs; /* referenced by dispatcher via cng_g_fs */
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;

    if (!strcmp(op, "open")) {
        long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)gpath,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
        if (fd < 0) {
            cng_dprintf(1, "open: errno %d\n", (int)-fd);
            return 1;
        }
        char buf[128];
        long n = sys_read((int)fd, buf, sizeof buf - 1);
        sys_close((int)fd);
        if (n < 0) {
            cng_dprintf(1, "read: errno %d\n", (int)-n);
            return 1;
        }
        buf[n] = '\0';
        cng_dprintf(1, "read: %s\n", buf);
        return 0;
    }
    /* CNG_DEBUG error logging must never dereference a syscall arg that is a
     * scalar rather than a path: truncate's length here is large enough to look
     * like a pointer, and reading it killed the guest (SIGSEGV in the handler,
     * with SIGSEGV masked). The dispatch must survive and report EISDIR. */
    if (!strcmp(op, "dbgpath")) {
        int save = cng_g_debug;
        cng_g_debug = 1;
        long r = cng_dispatch(__NR_truncate, (long)gpath, 0x7ffffff0, 0, 0, 0, 0,
                              /*trapped=*/0);
        cng_g_debug = save;
        cng_dprintf(1, "dbgpath: survived rc=%d -> %s\n", (int)r,
                    r == -EISDIR ? "OK" : "FAIL");
        return r == -EISDIR ? 0 : 1;
    }
    if (!strcmp(op, "access")) {
        long r = cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)gpath, 0, 0, 0,
                              0, /*trapped=*/0);
        cng_dprintf(1, "access: %s\n", r == 0 ? "ok" : "no");
        return r == 0 ? 0 : 1;
    }
    cng_dprintf(2, "_dtest: unknown op %s\n", op);
    return 2;
}

/* _sigtest — install a SIGUSR1 handler with our restorer, self-signal, and
 * confirm the handler ran and the AArch64 ucontext was readable (validates the
 * signal round-trip and sigcontext offsets that the SIGSYS path relies on). */
static volatile int g_sig_ran;
static volatile unsigned long g_sig_pc;

static void sigtest_handler(int s, cng_siginfo_t *si, void *ucv) {
    (void)s;
    (void)si;
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    g_sig_pc = (unsigned long)uc->uc_mcontext.pc;
    g_sig_ran = 1;
}

int cng_cmd_sigtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    if (cng_sig_install(CNG_SIGUSR1, sigtest_handler) < 0) {
        cng_dprintf(1, "sigtest: sigaction failed\n");
        return 1;
    }
    long pid = sys_getpid();
    long tid = sys_gettid();
    cng_syscall6(pid, tid, CNG_SIGUSR1, 0, 0, 0, __NR_tgkill);
    if (g_sig_ran && g_sig_pc > 0x1000) {
        cng_dprintf(1, "sigtest: handler ran, pc=0x%lx\n", g_sig_pc);
        return 0;
    }
    cng_dprintf(1, "sigtest: handler did not run cleanly\n");
    return 1;
}

/* _jmptest — validate the ucontext-redirect that M6's execve emulation relies
 * on: a handler rewrites uc->pc so sigreturn resumes at a different function.
 * If the redirect works we land in jmptest_landing and exit 7. */
static void jmptest_landing(void) {
    cng_dprintf(1, "jmptest: landed in redirected context\n");
    sys_exit_group(7);
}

static void jmptest_handler(int s, cng_siginfo_t *si, void *ucv) {
    (void)s;
    (void)si;
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    uc->uc_mcontext.pc = (unsigned long long)(unsigned long)(void *)jmptest_landing;
}

int cng_cmd_jmptest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    if (cng_sig_install(CNG_SIGUSR1, jmptest_handler) < 0) {
        cng_dprintf(1, "jmptest: sigaction failed\n");
        return 1;
    }
    cng_syscall6(sys_getpid(), sys_gettid(), CNG_SIGUSR1, 0, 0, 0,
                 __NR_tgkill);
    /* Reached only if the redirect did NOT take effect. */
    cng_dprintf(1, "jmptest: fell through (redirect failed)\n");
    return 1;
}

/* _faketest -r ROOT FILE — exercise the M7 fidelity fixups through the
 * dispatcher: credential faking, stat ownership rewrite, /proc/self/exe. */
int cng_cmd_faketest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = "/";
    const char *file = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc)
            rootfs = argv[++i];
        else if (!file)
            file = argv[i];
    }
    if (!file) {
        cng_dprintf(2, "usage: _faketest -r ROOT FILE\n");
        return 2;
    }

    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    cng_g_fake_id = 1;
    cng_g_fake_uid = 0;
    cng_g_fake_gid = 0;
    /* The remap source is the real owner of the test file (this process). */
    cng_g_host_uid = (unsigned)sys_getuid();
    cng_g_host_gid = (unsigned)sys_getgid();
    cng_cred_seed();
    cng_g_exe_guest = "/bin/sh";

    cng_dprintf(1, "getuid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 0));
    cng_dprintf(1, "geteuid=%d\n",
                (int)cng_dispatch(__NR_geteuid, 0, 0, 0, 0, 0, 0, 0));
    /* fchown a real fd (stdout) to root: the unprivileged host can't, so
     * fake-root must turn the denial into success. */
    cng_dprintf(1, "fchown=%d\n",
                (int)cng_dispatch(__NR_fchown, 1, 0, 0, 0, 0, 0, 1));

    char sb[256];
    long r = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)file, (long)sb,
                          0, 0, 0, /*trapped=*/0);
    if (r == 0)
        cng_dprintf(1, "st_uid=%u st_gid=%u\n", *(unsigned *)(sb + 24),
                    *(unsigned *)(sb + 28));
    else
        cng_dprintf(1, "stat errno %d\n", (int)-r);

    char lb[256];
    long n = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD,
                          (long)"/proc/self/exe", (long)lb, sizeof lb, 0, 0,
                          /*trapped=*/0);
    if (n > 0) {
        lb[n] = '\0';
        cng_dprintf(1, "exe=%s\n", lb);
    }

    /* Fake-root reads what real root could. apk hands its package scripts to
     * the shebang interpreter as "/proc/self/fd/N", and their inode grants
     * execute but not read — real root reopens it anyway, we get EACCES. Take
     * the read bits off the test file and the reopen must still succeed, with
     * the file's mode put back exactly as it was. */
    {
        char hp[CNG_PATH_MAX], pfd[40];
        long ffd = -1, ofd = -1;
        int mode_kept = 0;
        if (cng_fs_translate(&fs, file, hp, sizeof hp) == 0)
            ffd = sys_openat(CNG_AT_FDCWD, hp, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
        if (ffd >= 0) {
            CNG_SYS(__NR_fchmod, (int)ffd, 0111, 0, 0, 0, 0);
            size_t k = cng_strlcpy(pfd, "/proc/self/fd/", sizeof pfd);
            char d[8];
            int di = 0;
            for (long v = ffd; di < 7; v /= 10) {
                d[di++] = (char)('0' + v % 10);
                if (v < 10)
                    break;
            }
            while (di > 0 && k + 1 < sizeof pfd)
                pfd[k++] = d[--di];
            pfd[k] = '\0';
            ofd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)pfd,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
            char st[128];
            mode_kept = (CNG_SYS(__NR_fstat, (int)ffd, st, 0, 0, 0, 0) == 0 &&
                         (ST_MODE(st) & 07777) == 0111);
            CNG_SYS(__NR_fchmod, (int)ffd, 0644, 0, 0, 0, 0);
            if (ofd >= 0)
                sys_close((int)ofd);
            sys_close((int)ffd);
        }
        cng_dprintf(1, "fakeroot_reopen: opened=%d mode_kept=%d -> %s\n",
                    ofd >= 0, mode_kept,
                    (ofd >= 0 && mode_kept) ? "OK" : "FAIL");
    }

    /* The other refusal kind, which no DAC change can fix: the inode grants
     * the access and the open is still denied (on Android, SELinux on the
     * tmpfs inode behind a memfd — where apk 3 keeps package scripts). The
     * refusal cannot be provoked on a devbox, so drive cng_fd_reopen directly
     * with a memfd and a simulated EACCES: it must hand back a usable
     * duplicate, rewound to the start even though ours sits at EOF. */
    {
        long mfd = sys_memfd_create("cng-fdreopen", 1 /*MFD_CLOEXEC*/);
        int dup_ok = 0, content = 0;
        if (mfd >= 0) {
            sys_write((int)mfd, "SCRIPT", 6); /* our offset is now at EOF */
            char pfd[40];
            size_t k = cng_strlcpy(pfd, "/proc/self/fd/", sizeof pfd);
            char d[8];
            int di = 0;
            for (long v = mfd; di < 7; v /= 10) {
                d[di++] = (char)('0' + v % 10);
                if (v < 10)
                    break;
            }
            while (di > 0 && k + 1 < sizeof pfd)
                pfd[k++] = d[--di];
            pfd[k] = '\0';
            long nfd = cng_fd_reopen(pfd, CNG_O_RDONLY, 0, -EACCES);
            if (nfd >= 0) {
                dup_ok = 1;
                char b[8];
                long n = sys_read((int)nfd, b, sizeof b);
                content = (n == 6 && b[0] == 'S' && b[5] == 'T');
                sys_close((int)nfd);
            }
            sys_close((int)mfd);
        }
        cng_dprintf(1, "fd_reopen: dup=%d content=%d -> %s\n", dup_ok, content,
                    (dup_ok && content) ? "OK" : "FAIL");
    }

    /* Full credential model. Supplementary groups start empty; capabilities are
     * the full set while fake-root (euid still 0 at this point). */
    cng_dprintf(1, "ngroups=%d\n",
                (int)cng_dispatch(__NR_getgroups, 0, 0, 0, 0, 0, 0, 1));
    unsigned caphdr[2] = { 0x20080522u, 0 };   /* _LINUX_CAPABILITY_VERSION_3 */
    unsigned capdata[6] = { 0 };               /* two {eff,perm,inh} blocks */
    cng_dispatch(__NR_capget, (long)caphdr, (long)capdata, 0, 0, 0, 0, 1);
    cng_dprintf(1, "cap_eff=%x\n", capdata[0]);

    /* A privilege drop is real and, for the resulting non-root id, irreversible:
     * setuid(1000) succeeds, getuid then reports 1000, and setuid(0) is EPERM. */
    long su = cng_dispatch(__NR_setuid, 1000, 0, 0, 0, 0, 0, 1);
    long u2 = cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1);
    long re = cng_dispatch(__NR_setuid, 0, 0, 0, 0, 0, 0, 1);
    cng_dprintf(1, "setuid_drop rc=%d uid=%d regain=%d\n", (int)su, (int)u2,
                (int)re);

    /* --setuid-root / --setgid-root: as a non-root fake id (1000), a setuid+
     * setgid executable ("/suid", mode 6755) is shown as owned by root:root, and
     * exec of it elevates euid/egid to 0 while ruid stays 1000 — after which the
     * guest's own setuid(0) is privileged and sticks. This is the `su` chain. */
    cng_g_fake_uid = 1000;
    cng_g_fake_gid = 1000;
    cng_cred_seed();
    cng_g_setuid_root = 1;
    cng_g_setgid_root = 1;

    char sub[256];
    long sr = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/suid",
                           (long)sub, 0, 0, 0, /*trapped=*/0);
    if (sr == 0)
        cng_dprintf(1, "suid_stat st_uid=%u st_gid=%u\n",
                    *(unsigned *)(sub + 24), *(unsigned *)(sub + 28));
    else
        cng_dprintf(1, "suid_stat errno %d\n", (int)-sr);

    char suidhost[CNG_PATH_MAX];
    if (cng_fs_translate(&fs, "/suid", suidhost, sizeof suidhost) == 0)
        cng_cred_exec(suidhost);
    cng_dprintf(1, "suid_exec ruid=%d euid=%d egid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_geteuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getegid, 0, 0, 0, 0, 0, 0, 1));
    long root = cng_dispatch(__NR_setuid, 0, 0, 0, 0, 0, 0, 1);
    cng_dprintf(1, "su_to_root rc=%d uid=%d\n", (int)root,
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1));

    /* Identity resolution (cng_cred_setup): an id only implied by --setuid-root
     * (explicit=0) defaults to the real invoking id, so those flags alone don't
     * turn the guest into root; an explicit -u/--fake-id (explicit=1) wins. */
    cng_g_setuid_root = 0;
    cng_g_setgid_root = 0;
    cng_g_fake_id_explicit = 0;
    cng_g_fake_uid = 0;
    cng_g_fake_gid = 0; /* CLI defaults before the run seeds the identity */
    cng_cred_setup(4321, 8765);
    cng_dprintf(1, "implied_id uid=%d gid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getgid, 0, 0, 0, 0, 0, 0, 1));
    cng_g_fake_id_explicit = 1;
    cng_g_fake_uid = 1000;
    cng_g_fake_gid = 1000;
    cng_cred_setup(4321, 8765);
    cng_dprintf(1, "explicit_id uid=%d gid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getgid, 0, 0, 0, 0, 0, 0, 1));
    return 0;
}

/* _rwtest — copy a self-checking function containing an `svc #0`, rewrite the
 * svc to a trampoline, run it, and confirm it returns the real pid with all
 * caller registers preserved (validates M8's trampoline: x30/x18/args survive
 * the C dispatch call). No seccomp involved. */
extern char cng_rwtest_fn[];
extern char cng_rwtest_fn_end[];

int cng_cmd_rwtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;

    size_t fsz = (size_t)(cng_rwtest_fn_end - cng_rwtest_fn);
    /* One mapping: [code page | trampoline pool], so the pool is adjacent and
     * within a `b`'s reach (same reason the loader over-allocates). */
    unsigned long total = 4096 + CNG_TRAMP_POOL;
    void *region = sys_mmap(0, total, CNG_PROT_READ | CNG_PROT_WRITE,
                            CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (region == CNG_MAP_FAILED || cng_is_err((long)region)) {
        cng_dprintf(1, "rwtest: mmap failed\n");
        return 1;
    }
    void *buf = region;
    memcpy(buf, cng_rwtest_fn, fsz);
    unsigned long pool = (unsigned long)region + 4096;
    unsigned long used = 0;

    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    cng_g_rewrite = 1;

    int n = cng_rewrite_seg((unsigned long)buf, (unsigned long)buf + fsz, pool,
                            CNG_TRAMP_POOL, &used);
    sys_mprotect(region, total, CNG_PROT_READ | CNG_PROT_EXEC);
    cng_flush_icache(buf, (char *)buf + fsz);
    cng_flush_icache((void *)pool, (void *)(pool + used));

    long real = sys_getpid();
    long (*fn)(void) = (long (*)(void))buf;
    long got = fn();

    int ok = (n >= 1 && got == real);
    cng_dprintf(1, "rwtest: rewrote %d site(s); real_pid=%d fn_pid=%d -> %s\n",
                n, (int)real, (int)got, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _blocktest — validate that a syscall marked blocked (as cng_probe_blocked
 * would on Android) is emulated to ENOSYS by the dispatcher instead of being
 * re-issued, while an unblocked one still runs. */
int cng_cmd_blocktest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    int fails = 0;

    cng_blocked[__NR_fchownat] = 1; /* pretend Android blocks chown */
    long r = cng_dispatch(__NR_fchownat, CNG_AT_FDCWD, (long)"/x", 0, 0, 0, 0,
                          /*trapped=*/1);
    int ok1 = (r == -ENOSYS);
    cng_dprintf(1, "blocktest fchownat(blocked)=%d want=%d -> %s\n", (int)r,
                (int)-ENOSYS, ok1 ? "OK" : "FAIL");
    fails += !ok1;

    cng_blocked[__NR_faccessat] = 0; /* allowed -> still re-issued */
    long r2 = cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)"/", 0, 0, 0, 0,
                           /*trapped=*/1);
    int ok2 = (r2 == 0);
    cng_dprintf(1, "blocktest faccessat(allowed)=%d -> %s\n", (int)r2,
                ok2 ? "OK" : "FAIL");
    fails += !ok2;

    cng_blocked[__NR_fchownat] = 0; /* reset */
    return fails ? 1 : 0;
}

/* _loadtwice PATH — load the same ELF twice into this address space (as execve
 * emulation does, without tearing down the first) to surface re-load failures. */
int cng_cmd_loadtwice(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    if (argc < 2) {
        cng_dprintf(2, "usage: _loadtwice PATH\n");
        return 2;
    }
    struct cng_loaded p1, p2;
    int rc1 = cng_load_elf(argv[1], 0, &p1);
    int rc2 = cng_load_elf(argv[1], 0, &p2);
    cng_dprintf(1, "load1 rc=%d base=%lx; load2 rc=%d base=%lx\n", rc1,
                p1.base, rc2, p2.base);
    return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}

/* _exectest -r ROOT PROG [args] — drive cng_emulate_execve (incl. shebang) and,
 * on success, enter the loaded program. Exercises execve emulation under qemu
 * where neither the SIGSYS nor trampoline route reaches it. */
int cng_cmd_exectest(int argc, char **argv, char **envp, unsigned long *auxv) {
    const char *rootfs = "/";
    int i = 1;
    while (i < argc && !strcmp(argv[i], "-r") && i + 1 < argc) {
        rootfs = argv[i + 1];
        i += 2;
    }
    if (i >= argc) {
        cng_dprintf(2, "usage: _exectest -r ROOT PROG [args]\n");
        return 2;
    }
    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    cng_host_auxv = auxv;

    char **gargv = argv + i;
    static struct cng_ucontext uc;
    memset(&uc, 0, sizeof uc);
    cng_emulate_execve(&uc, CNG_AT_FDCWD, gargv[0], gargv, envp);
    unsigned long entry = (unsigned long)uc.uc_mcontext.pc;
    unsigned long sp = (unsigned long)uc.uc_mcontext.sp;
    if (entry == 0) {
        cng_dprintf(2, "exectest: emulate_execve failed x0=%ld\n",
                    (long)uc.uc_mcontext.regs[0]);
        return 1;
    }
    /* /proc/self/exe fixup tracks the exec'd program (symlinks resolved). */
    cng_dprintf(2, "exectest: exe=%s\n", cng_g_exe_guest);
    cng_enter(sp, entry); /* never returns */
}

/* Host-path builder for the l2s store checks: "<a><b>" plus, when with_ino,
 * the decimal of `ino` appended. */
static void dbg_mkpath(char *out, size_t sz, const char *a, const char *b,
                       unsigned long long ino, int with_ino) {
    size_t n = cng_strlcpy(out, a, sz);
    if (b && n < sz)
        n += cng_strlcpy(out + n, b, sz - n);
    if (with_ino) {
        char tmp[24];
        int t = 0;
        do {
            tmp[t++] = (char)('0' + (ino % 10));
            ino /= 10;
        } while (ino);
        while (t > 0 && n + 1 < sz)
            out[n++] = tmp[--t];
        if (n < sz)
            out[n] = '\0';
    }
}

/* 1 if the host directory contains any ".l2s.*" entry, 0 if none, -1 on open
 * failure. Raw getdents64 walk (linux_dirent64: reclen @16, name @19). */
static int dbg_has_l2s(const char *dir) {
    long fd = sys_openat(CNG_AT_FDCWD, dir,
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int found = 0;
    long n;
    while (!found &&
           (n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0)) >
               0) {
        long o = 0;
        while (o + 19 <= n) {
            unsigned short rl;
            memcpy(&rl, buf + o + 16, 2);
            if (rl == 0 || o + rl > n)
                break;
            if (!strncmp(buf + o + 19, ".l2s.", 5)) {
                found = 1;
                break;
            }
            o += rl;
        }
    }
    sys_close((int)fd);
    return found;
}

/* _l2stest ROOT — exercise link2symlink (target must be a guest/relative path,
 * not a host path) and fchdir cwd tracking. ROOT must contain a dir "w". The
 * emulation is opt-in on the command line, so the test drives cng_g_l2s itself:
 * first off (the refusal must pass through), then on for the rest. */
int cng_cmd_l2stest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = argc > 1 ? argv[1] : "/";
    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    int fails = 0;

    /* link2symlink backing-file scheme. Force the fallback (tmpfs allows real
     * hardlinks) by marking linkat blocked. The emulated "hardlink" must present
     * as a regular file: shared inode, st_nlink counted, readlink refused. */
    cng_blocked[__NR_linkat] = 1;
    long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/a",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (fd >= 0) {
        sys_write((int)fd, "hi", 2);
        sys_close((int)fd);
    }

    /* The emulation is opt-in (-l/--link2symlink), so with the flag still off
     * the host's refusal must reach the guest verbatim and no name appear. */
    long loff = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                             CNG_AT_FDCWD, (long)"/w/z", 0, 0, 0);
    char sz[144];
    long rz = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/z",
                           (long)sz, 0, 0, 0, 0);
    int ok_off = (loff == -ENOSYS && rz == -ENOENT);
    cng_dprintf(1, "l2s-off: rc=%d created=%d -> %s\n", (int)loff, rz == 0,
                ok_off ? "OK" : "FAIL");
    fails += !ok_off;

    cng_g_l2s = 1; /* everything below exercises the enabled emulation */
    long lr = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a", CNG_AT_FDCWD,
                           (long)"/w/b", 0, 0, 0);
    /* linking onto an existing name must fail with EEXIST, like real link(2) */
    long lr2 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0);

    char sa[144], sb[144];
    long ra = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                           (long)sa, 0, 0, 0, 0);
    long rb = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)sb, 0, 0, 0, 0);
    int reg = (ra == 0 && rb == 0 && ST_ISREG(sa) && ST_ISREG(sb));
    int nlink = (reg && ST_NLINK(sa) == 2 && ST_NLINK(sb) == 2);
    int sameino = (reg && ST_INO(sa) == ST_INO(sb));

    char lb[256]; /* readlink must be transparent (EINVAL), never leak backing */
    long rl = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)lb, sizeof lb - 1, 0, 0, 0);
    int noleak = (rl == -EINVAL);

    char cbuf[8]; /* contents are shared through the backing file */
    long bf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/b",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    long rd = -1;
    if (bf >= 0) {
        rd = sys_read((int)bf, cbuf, sizeof cbuf);
        sys_close((int)bf);
    }
    int content = (rd == 2 && cbuf[0] == 'h' && cbuf[1] == 'i');

    int ok_l2s = (lr == 0 && lr2 == -EEXIST && reg && nlink && sameino &&
                  noleak && content);
    cng_dprintf(1,
                "l2s: rc=%d eexist=%d reg=%d nlink2=%d sameino=%d noleak=%d "
                "content=%d -> %s\n",
                (int)lr, lr2 == -EEXIST, reg, nlink, sameino, noleak, content,
                ok_l2s ? "OK" : "FAIL");
    fails += !ok_l2s;

    /* Central store: the backing pair lives in "<root>/.l2s" (data keeping the
     * original inode, marker at count 2), and nothing appears beside the
     * names in /w. */
    char hdata[CNG_PATH_MAX], hmark[CNG_PATH_MAX], hw[CNG_PATH_MAX];
    dbg_mkpath(hdata, sizeof hdata, rootfs, "/.l2s/.l2s.", ST_INO(sa), 1);
    dbg_mkpath(hmark, sizeof hmark, rootfs, "/.l2s/.l2s.", ST_INO(sa), 1);
    size_t hml = strlen(hmark);
    cng_strlcpy(hmark + hml, ".0002", sizeof hmark - hml);
    dbg_mkpath(hw, sizeof hw, rootfs, "/w", 0, 0);
    char sd[144];
    long rsd = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, hdata, sd,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    long rsm = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, hmark, sd,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    int store_ok = (rsd == 0 && rsm == 0);
    int user_clean = (dbg_has_l2s(hw) == 0);
    int ok_store = (store_ok && user_clean);
    cng_dprintf(1, "l2s-store: store=%d user_clean=%d -> %s\n", store_ok,
                user_clean, ok_store ? "OK" : "FAIL");
    fails += !ok_store;

    /* fd-based stat: fstat and the AT_EMPTY_PATH forms must report the
     * emulated st_nlink too (tar/rsync/coreutils stat open fds), and statx
     * must pass the guest's mask through while advertising STATX_NLINK. */
    int f_nlink = 0, ep_nlink = 0, epx = 0, xmask = 0;
    long bf2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/b",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    if (bf2 >= 0) {
        char sfd[144];
        long r1 = cng_dispatch(__NR_fstat, bf2, (long)sfd, 0, 0, 0, 0, 0);
        f_nlink = (r1 == 0 && ST_NLINK(sfd) == 2);
        long r2 = cng_dispatch(__NR_newfstatat, bf2, (long)"", (long)sfd,
                               CNG_AT_EMPTY_PATH, 0, 0, 0);
        ep_nlink = (r2 == 0 && ST_NLINK(sfd) == 2);
        char sxb[256];
        long r3 = cng_dispatch(__NR_statx, bf2, (long)"", CNG_AT_EMPTY_PATH,
                               CNG_STATX_BASIC_STATS, (long)sxb, 0, 0);
        epx = (r3 == 0 && STX_NLINK(sxb) == 2 &&
               (STX_MASK(sxb) & CNG_STATX_NLINK));
        sys_close((int)bf2);
    }
    char sxp[256];
    long rxp = cng_dispatch(__NR_statx, CNG_AT_FDCWD, (long)"/w/b", 0,
                            CNG_STATX_NLINK, (long)sxp, 0, 0);
    xmask = (rxp == 0 && STX_NLINK(sxp) == 2 &&
             (STX_MASK(sxp) & CNG_STATX_NLINK));
    int ok_fd = (f_nlink && ep_nlink && epx && xmask);
    cng_dprintf(1, "l2s-fstat: fd=%d empty=%d emptyx=%d mask=%d -> %s\n",
                f_nlink, ep_nlink, epx, xmask, ok_fd ? "OK" : "FAIL");
    fails += !ok_fd;

    /* readlink through a real dirfd must also refuse (the emulated link is a
     * regular file to the guest, wherever the name comes from). */
    int rlrel = 0;
    long wfd0 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    if (wfd0 >= 0) {
        char rb[64];
        long rr = cng_dispatch(__NR_readlinkat, wfd0, (long)"b", (long)rb,
                               sizeof rb, 0, 0, 0);
        rlrel = (rr == -EINVAL);
        sys_close((int)wfd0);
    }
    cng_dprintf(1, "l2s-dirfd-readlink: einval=%d -> %s\n", rlrel,
                rlrel ? "OK" : "FAIL");
    fails += !rlrel;

    /* mtime preserve (apk's scenario): set an explicit mtime on one name, read
     * it back through the other — must land on the shared backing file. */
    long times[4] = {0x11223344, 0, 0x11223344, 0}; /* atime, mtime = T */
    long um = cng_dispatch(__NR_utimensat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)times, 0, 0, 0, 0);
    char sm[144];
    long rm = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                           (long)sm, 0, 0, 0, 0);
    int mtime_ok = (um == 0 && rm == 0 && ST_MTIME(sm) == 0x11223344);
    cng_dprintf(1, "l2s-mtime: set=%d mtime=%lld -> %s\n", (int)um,
                rm == 0 ? ST_MTIME(sm) : -1, mtime_ok ? "OK" : "FAIL");
    fails += !mtime_ok;

    /* dirfd-relative link (as apk does): open /w, linkat(fd,"d",fd,"e"). */
    long df = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/d",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (df >= 0) {
        sys_write((int)df, "x", 1);
        sys_close((int)df);
    }
    long wfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w", CNG_O_RDONLY,
                            0, 0, 0, 0);
    long lr3 = -1;
    int dreg = 0;
    if (wfd >= 0) {
        lr3 = cng_dispatch(__NR_linkat, wfd, (long)"d", wfd, (long)"e", 0, 0, 0);
        char se[144];
        long re = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/e",
                               (long)se, 0, 0, 0, 0);
        dreg = (re == 0 && ST_ISREG(se) && ST_NLINK(se) == 2);
        sys_close((int)wfd);
    }
    int ok_dirfd = (lr3 == 0 && dreg);
    cng_dprintf(1, "l2s-dirfd: rc=%d reg2=%d -> %s\n", (int)lr3, dreg,
                ok_dirfd ? "OK" : "FAIL");
    fails += !ok_dirfd;

    /* decref: removing one name drops st_nlink; removing the last reclaims the
     * backing file (the name then no longer exists). */
    long ub = cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0,
                           0, 0);
    char sa2[144];
    long ra2 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sa2, 0, 0, 0, 0);
    int after1 = (ub == 0 && ra2 == 0 && ST_NLINK(sa2) == 1);
    long ua = cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/a", 0, 0, 0,
                           0, 0);
    long ra3 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sa2, 0, 0, 0, 0);
    int gone = (ua == 0 && ra3 == -ENOENT);
    int ok_dec = (after1 && gone);
    cng_dprintf(1, "l2s-decref: nlink_after1=%d gone=%d -> %s\n", after1, gone,
                ok_dec ? "OK" : "FAIL");
    fails += !ok_dec;

    /* Cross-directory hardlink via the central store: shared inode and count,
     * content reachable both through the guest resolver (absolute path walks
     * the store target) and through the host kernel (dirfd-relative open
     * follows the absolute target natively). */
    long ff = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (ff >= 0) {
        sys_write((int)ff, "yo", 2);
        sys_close((int)ff);
    }
    cng_dispatch(__NR_mkdirat, CNG_AT_FDCWD, (long)"/w/sub", 0755, 0, 0, 0, 0);
    long xg = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_AT_FDCWD, (long)"/w/g", 0, 0, 0);
    long xr = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_AT_FDCWD, (long)"/w/sub/x", 0, 0, 0);
    char sf[144], sx[144];
    long rf = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                           (long)sf, 0, 0, 0, 0);
    long rx = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/sub/x",
                           (long)sx, 0, 0, 0, 0);
    int x_ino = (rf == 0 && rx == 0 && ST_INO(sf) == ST_INO(sx));
    int x_nlink = (rf == 0 && rx == 0 && ST_NLINK(sf) == 3 &&
                   ST_NLINK(sx) == 3);
    char xb[8];
    long xrd = -1;
    long xf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/sub/x",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    if (xf >= 0) {
        xrd = sys_read((int)xf, xb, sizeof xb);
        sys_close((int)xf);
    }
    int x_abs = (xrd == 2 && xb[0] == 'y' && xb[1] == 'o');
    long wfd2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    int x_rel = 0;
    if (wfd2 >= 0) {
        long xf2 = cng_dispatch(__NR_openat, wfd2, (long)"sub/x", CNG_O_RDONLY,
                                0, 0, 0, 0);
        if (xf2 >= 0) {
            xrd = sys_read((int)xf2, xb, sizeof xb);
            x_rel = (xrd == 2 && xb[0] == 'y' && xb[1] == 'o');
            sys_close((int)xf2);
        }
        sys_close((int)wfd2);
    }
    int ok_xdir = (xg == 0 && xr == 0 && x_ino && x_nlink && x_abs && x_rel);
    cng_dprintf(1, "l2s-xdir: rc=%d ino=%d nlink3=%d abs=%d rel=%d -> %s\n",
                (int)xr, x_ino, x_nlink, x_abs, x_rel, ok_xdir ? "OK" : "FAIL");
    fails += !ok_xdir;

    /* Directory hiding: the ".l2s" store entry never shows in the root
     * listing (while real entries do). */
    int root_clean = 1, have_w = 0;
    long rfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/",
                            CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
    if (rfd >= 0) {
        char db[4096];
        long dn;
        while ((dn = cng_dispatch(__NR_getdents64, rfd, (long)db, sizeof db, 0,
                                  0, 0, 0)) > 0) {
            long o = 0;
            while (o + 19 <= dn) {
                unsigned short rl;
                memcpy(&rl, db + o + 16, 2);
                if (rl == 0 || o + rl > dn)
                    break;
                const char *nm = db + o + 19;
                if (!strncmp(nm, ".l2s", 4))
                    root_clean = 0;
                if (!strcmp(nm, "w"))
                    have_w = 1;
                o += rl;
            }
        }
        sys_close((int)rfd);
    }
    int ok_hide = (root_clean && have_w);
    cng_dprintf(1, "l2s-hide: root_clean=%d have_w=%d -> %s\n", root_clean,
                have_w, ok_hide ? "OK" : "FAIL");
    fails += !ok_hide;

    /* Handcraft a dir holding only legacy hidden files (raw host syscalls
     * bypass the guard), then list it through the dispatcher with a buffer so
     * small each batch holds one record: every batch filters away and the
     * listing must still terminate (the re-read loop, not a fake EOF). */
    char hh[CNG_PATH_MAX], hf1[CNG_PATH_MAX], hf2[CNG_PATH_MAX];
    dbg_mkpath(hh, sizeof hh, rootfs, "/w/h", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, hh, 0755, 0, 0, 0);
    dbg_mkpath(hf1, sizeof hf1, rootfs, "/w/h/.l2s.7", 0, 0);
    dbg_mkpath(hf2, sizeof hf2, rootfs, "/w/h/.l2s.7.0002", 0, 0);
    long tf = sys_openat(CNG_AT_FDCWD, hf1, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (tf >= 0)
        sys_close((int)tf);
    tf = sys_openat(CNG_AT_FDCWD, hf2, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (tf >= 0)
        sys_close((int)tf);
    int hb_clean = 1, hb_eof = 0;
    long hfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/h",
                            CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
    if (hfd >= 0) {
        char sb[48];
        for (int it = 0; it < 64; it++) {
            long dn = cng_dispatch(__NR_getdents64, hfd, (long)sb, sizeof sb,
                                   0, 0, 0, 0);
            if (dn == 0) {
                hb_eof = 1;
                break;
            }
            if (dn < 0)
                break;
            long o = 0;
            while (o + 19 <= dn) {
                unsigned short rl;
                memcpy(&rl, sb + o + 16, 2);
                if (rl == 0 || o + rl > dn)
                    break;
                const char *nm = sb + o + 19;
                if (strcmp(nm, ".") && strcmp(nm, ".."))
                    hb_clean = 0;
                o += rl;
            }
        }
        sys_close((int)hfd);
    }
    int ok_hb = (hb_clean && hb_eof);
    cng_dprintf(1, "l2s-hide-batch: clean=%d eof=%d -> %s\n", hb_clean, hb_eof,
                ok_hb ? "OK" : "FAIL");
    fails += !ok_hb;

    /* The machinery must appear nonexistent by name: creating a grammar-
     * matching file, statting the real data file, opening or chdir'ing into
     * the store — all ENOENT. */
    long dcr = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/.l2s.999",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    char gd[CNG_PATH_MAX];
    dbg_mkpath(gd, sizeof gd, "/.l2s/.l2s.", 0, ST_INO(sf), 1);
    char sdn[144];
    long dstt = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)gd,
                             (long)sdn, 0, 0, 0, 0);
    long dop = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/.l2s",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    long dch = cng_dispatch(__NR_chdir, (long)"/.l2s", 0, 0, 0, 0, 0, 0);
    int ok_deny = (dcr == -ENOENT && dstt == -ENOENT && dop == -ENOENT &&
                   dch == -ENOENT);
    cng_dprintf(1, "l2s-deny: create=%d data=%d store=%d chdir=%d -> %s\n",
                dcr == -ENOENT, dstt == -ENOENT, dop == -ENOENT,
                dch == -ENOENT, ok_deny ? "OK" : "FAIL");
    fails += !ok_deny;

    /* NOFOLLOW chown must land on the backing file: give the file setuid via
     * chmod (follows to the data), then chown with NOFOLLOW — the kernel
     * clears setuid on whichever inode it really chowned. */
    cng_dispatch(__NR_fchmodat, CNG_AT_FDCWD, (long)"/w/g", 04755, 0, 0, 0, 0);
    long cr = cng_dispatch(__NR_fchownat, CNG_AT_FDCWD, (long)"/w/g",
                           (long)sys_getuid(), (long)sys_getgid(),
                           CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    char sg[144];
    long rg = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/g",
                           (long)sg, 0, 0, 0, 0);
    int suid_cleared = (cr == 0 && rg == 0 && !(ST_MODE(sg) & 04000));
    cng_dprintf(1, "l2s-chown: suid_cleared=%d -> %s\n", suid_cleared,
                suid_cleared ? "OK" : "FAIL");
    fails += !suid_cleared;

    /* renameat2 flags: NOREPLACE refuses to clobber a link name (no decref);
     * EXCHANGE swaps the names without touching the count. */
    long pf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/p",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (pf >= 0) {
        sys_write((int)pf, "pp", 2);
        sys_close((int)pf);
    }
    long nrr = cng_dispatch(__NR_renameat2, CNG_AT_FDCWD, (long)"/w/p",
                            CNG_AT_FDCWD, (long)"/w/g", CNG_RENAME_NOREPLACE,
                            0, 0);
    char snr[144];
    long rnr = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                            (long)snr, 0, 0, 0, 0);
    int nr_ok = (nrr == -EEXIST && rnr == 0 && ST_NLINK(snr) == 3);
    cng_dprintf(1, "l2s-noreplace: eexist=%d nlink=%d -> %s\n", nrr == -EEXIST,
                rnr == 0 && ST_NLINK(snr) == 3, nr_ok ? "OK" : "FAIL");
    fails += !nr_ok;

    long exr = cng_dispatch(__NR_renameat2, CNG_AT_FDCWD, (long)"/w/p",
                            CNG_AT_FDCWD, (long)"/w/g", CNG_RENAME_EXCHANGE, 0,
                            0);
    char sp1[144], sf3[144];
    long rp1 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/p",
                            (long)sp1, 0, 0, 0, 0);
    long rf3 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                            (long)sf3, 0, 0, 0, 0);
    int swapped = (rp1 == 0 && rf3 == 0 && ST_INO(sp1) == ST_INO(sf3));
    int ex_nlink = (rf3 == 0 && ST_NLINK(sf3) == 3);
    int ex_ok = (exr == 0 && swapped && ex_nlink);
    cng_dprintf(1, "l2s-exchange: rc=%d swapped=%d nlink3=%d -> %s\n",
                (int)exr, swapped, ex_nlink, ex_ok ? "OK" : "FAIL");
    fails += !ex_ok;

    /* Legacy (bare-basename) group: mv one name to another directory — the
     * dispatcher must repoint it at the unmoved data file. */
    char ofdir[CNG_PATH_MAX], od[CNG_PATH_MAX], om[CNG_PATH_MAX],
        ox[CNG_PATH_MAX], oy[CNG_PATH_MAX];
    dbg_mkpath(ofdir, sizeof ofdir, rootfs, "/w/of", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, ofdir, 0755, 0, 0, 0);
    dbg_mkpath(od, sizeof od, rootfs, "/w/of/.l2s.11", 0, 0);
    dbg_mkpath(om, sizeof om, rootfs, "/w/of/.l2s.11.0002", 0, 0);
    dbg_mkpath(ox, sizeof ox, rootfs, "/w/of/x", 0, 0);
    dbg_mkpath(oy, sizeof oy, rootfs, "/w/of/y", 0, 0);
    long odf = sys_openat(CNG_AT_FDCWD, od, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0) {
        sys_write((int)odf, "zz", 2);
        sys_close((int)odf);
    }
    odf = sys_openat(CNG_AT_FDCWD, om, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (odf >= 0)
        sys_close((int)odf);
    CNG_SYS(__NR_symlinkat, ".l2s.11", CNG_AT_FDCWD, ox, 0, 0, 0);
    CNG_SYS(__NR_symlinkat, ".l2s.11", CNG_AT_FDCWD, oy, 0, 0, 0);
    long mvr = cng_dispatch(__NR_renameat, CNG_AT_FDCWD, (long)"/w/of/x",
                            CNG_AT_FDCWD, (long)"/w/mvx", 0, 0, 0);
    char smx[144];
    long rmx = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/mvx",
                            (long)smx, 0, 0, 0, 0);
    int mv_reg = (mvr == 0 && rmx == 0 && ST_ISREG(smx));
    int mv_nlink = (rmx == 0 && ST_NLINK(smx) == 2);
    char mb[8];
    long mrd = -1;
    long mf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/mvx",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    if (mf >= 0) {
        mrd = sys_read((int)mf, mb, sizeof mb);
        sys_close((int)mf);
    }
    int mv_content = (mrd == 2 && mb[0] == 'z' && mb[1] == 'z');
    int ok_mv = (mv_reg && mv_nlink && mv_content);
    cng_dprintf(1, "l2s-mvfix: reg=%d nlink2=%d content=%d -> %s\n", mv_reg,
                mv_nlink, mv_content, ok_mv ? "OK" : "FAIL");
    fails += !ok_mv;

    /* O_TMPFILE + linkat(fd, "", ..., AT_EMPTY_PATH): the anonymous file is
     * published (by content copy — nothing to symlink to). */
    long tmf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                            CNG_O_TMPFILE | CNG_O_RDWR, 0644, 0, 0, 0);
    long tlr = -1;
    int t_reg = 0, t_content = 0, t_mode = 0;
    if (tmf >= 0) {
        sys_write((int)tmf, "tt", 2);
        tlr = cng_dispatch(__NR_linkat, tmf, (long)"", CNG_AT_FDCWD,
                           (long)"/w/t", CNG_AT_EMPTY_PATH, 0, 0);
        sys_close((int)tmf);
        char stt[144];
        long rt = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/t",
                               (long)stt, 0, 0, 0, 0);
        t_reg = (rt == 0 && ST_ISREG(stt));
        /* a real link shares the inode's mode, so the copy must keep 0644 */
        t_mode = (rt == 0 && (ST_MODE(stt) & 07777) == 0644);
        char tb[8];
        long trd = -1;
        long tf2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/t",
                                CNG_O_RDONLY, 0, 0, 0, 0);
        if (tf2 >= 0) {
            trd = sys_read((int)tf2, tb, sizeof tb);
            sys_close((int)tf2);
        }
        t_content = (trd == 2 && tb[0] == 't' && tb[1] == 't');
    }
    int ok_tmp = (tlr == 0 && t_reg && t_content && t_mode);
    cng_dprintf(1, "l2s-tmpfile: rc=%d reg=%d content=%d mode=%d -> %s\n",
                (int)tlr, t_reg, t_content, t_mode, ok_tmp ? "OK" : "FAIL");
    fails += !ok_tmp;

    /* linkat by fd on a live group member bumps that group. */
    long lff = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/f",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    long flr = -1;
    int fd_nl = 0;
    if (lff >= 0) {
        flr = cng_dispatch(__NR_linkat, lff, (long)"", CNG_AT_FDCWD,
                           (long)"/w/j", CNG_AT_EMPTY_PATH, 0, 0);
        sys_close((int)lff);
        char sj[144];
        long rj = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/j",
                               (long)sj, 0, 0, 0, 0);
        fd_nl = (rj == 0 && ST_NLINK(sj) == 4 && ST_INO(sj) == ST_INO(sf));
    }
    int ok_fdl = (flr == 0 && fd_nl);
    cng_dprintf(1, "l2s-fdlink: rc=%d nlink4=%d -> %s\n", (int)flr, fd_nl,
                ok_fdl ? "OK" : "FAIL");
    fails += !ok_fdl;

    /* O_NOFOLLOW: opening a link name through a dirfd succeeds on the backing
     * file, while a real guest symlink still draws ELOOP. */
    int nf_open = 0, nf_content = 0, nf_sym = 0;
    long wfd3 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    if (wfd3 >= 0) {
        long nff = cng_dispatch(__NR_openat, wfd3, (long)"f",
                                CNG_O_RDONLY | CNG_O_NOFOLLOW, 0, 0, 0, 0);
        if (nff >= 0) {
            nf_open = 1;
            char nb[8];
            long nrd = sys_read((int)nff, nb, sizeof nb);
            nf_content = (nrd == 2 && nb[0] == 'y' && nb[1] == 'o');
            sys_close((int)nff);
        }
        cng_dispatch(__NR_symlinkat, (long)"f", wfd3, (long)"sym", 0, 0, 0, 0);
        long nfs = cng_dispatch(__NR_openat, wfd3, (long)"sym",
                                CNG_O_RDONLY | CNG_O_NOFOLLOW, 0, 0, 0, 0);
        nf_sym = (nfs == -ELOOP);
        if (nfs >= 0)
            sys_close((int)nfs);
        sys_close((int)wfd3);
    }
    int ok_nf = (nf_open && nf_content && nf_sym);
    cng_dprintf(1, "l2s-nofollow: open=%d content=%d sym_eloop=%d -> %s\n",
                nf_open, nf_content, nf_sym, ok_nf ? "OK" : "FAIL");
    fails += !ok_nf;

    /* Legacy per-dir format end to end (what arm64chroot writes, and what a
     * pre-store chroot-ng left behind): stat, same-dir bump keeping the
     * legacy look, cross-dir join via absolute target, decref, readlink. */
    char ogdir[CNG_PATH_MAX], od2[CNG_PATH_MAX], om2[CNG_PATH_MAX],
        ou[CNG_PATH_MAX], ov[CNG_PATH_MAX], om3[CNG_PATH_MAX];
    dbg_mkpath(ogdir, sizeof ogdir, rootfs, "/w/og", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, ogdir, 0755, 0, 0, 0);
    dbg_mkpath(od2, sizeof od2, rootfs, "/w/og/.l2s.13", 0, 0);
    dbg_mkpath(om2, sizeof om2, rootfs, "/w/og/.l2s.13.0002", 0, 0);
    dbg_mkpath(om3, sizeof om3, rootfs, "/w/og/.l2s.13.0003", 0, 0);
    dbg_mkpath(ou, sizeof ou, rootfs, "/w/og/u", 0, 0);
    dbg_mkpath(ov, sizeof ov, rootfs, "/w/og/v", 0, 0);
    odf = sys_openat(CNG_AT_FDCWD, od2, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0) {
        sys_write((int)odf, "qq", 2);
        sys_close((int)odf);
    }
    odf = sys_openat(CNG_AT_FDCWD, om2, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (odf >= 0)
        sys_close((int)odf);
    CNG_SYS(__NR_symlinkat, ".l2s.13", CNG_AT_FDCWD, ou, 0, 0, 0);
    CNG_SYS(__NR_symlinkat, ".l2s.13", CNG_AT_FDCWD, ov, 0, 0, 0);
    char sdn2[144], su[144];
    long rdn2 = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, od2, sdn2,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    long ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/u",
                           (long)su, 0, 0, 0, 0);
    int old_reg = (ru == 0 && ST_ISREG(su) && ST_NLINK(su) == 2);
    int old_same = (rdn2 == 0 && ru == 0 && ST_INO(su) == ST_INO(sdn2));
    long ol1 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            CNG_AT_FDCWD, (long)"/w/og/z", 0, 0, 0);
    char smk[144];
    long rm3 = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, om3, smk,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/z",
                      (long)su, 0, 0, 0, 0);
    int old_bump = (ol1 == 0 && rm3 == 0 && ru == 0 && ST_NLINK(su) == 3);
    long ol2 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            CNG_AT_FDCWD, (long)"/w/z2", 0, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/z2", (long)su,
                      0, 0, 0, 0);
    int old_xdir = (ol2 == 0 && ru == 0 && ST_NLINK(su) == 4 &&
                    rdn2 == 0 && ST_INO(su) == ST_INO(sdn2));
    cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/z2", 0, 0, 0, 0, 0);
    cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/og/z", 0, 0, 0, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/u",
                      (long)su, 0, 0, 0, 0);
    int old_back = (ru == 0 && ST_NLINK(su) == 2);
    char orb[64];
    long orl = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            (long)orb, sizeof orb, 0, 0, 0);
    int old_einval = (orl == -EINVAL);
    int ok_old = (old_reg && old_same && old_bump && old_xdir && old_back &&
                  old_einval);
    cng_dprintf(1,
                "l2s-old: reg=%d same=%d bump3=%d xdir4=%d back2=%d "
                "einval=%d -> %s\n",
                old_reg, old_same, old_bump, old_xdir, old_back, old_einval,
                ok_old ? "OK" : "FAIL");
    fails += !ok_old;

    /* Store unusable (a plain file squats on "<root>/.l2s"): first links fall
     * back to the per-dir scheme beside the source. Exercised under a second
     * rootfs so the real store stays live. */
    char fbroot[CNG_PATH_MAX], fbsq[CNG_PATH_MAX], fbw[CNG_PATH_MAX];
    dbg_mkpath(fbroot, sizeof fbroot, rootfs, "/fb", 0, 0);
    dbg_mkpath(fbsq, sizeof fbsq, rootfs, "/fb/.l2s", 0, 0);
    dbg_mkpath(fbw, sizeof fbw, rootfs, "/fb/w", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, fbroot, 0755, 0, 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, fbw, 0755, 0, 0, 0);
    odf = sys_openat(CNG_AT_FDCWD, fbsq, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0)
        sys_close((int)odf);
    static struct cng_fs fs2;
    cng_fs_init(&fs2, fbroot);
    cng_g_fs = &fs2;
    long fbf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (fbf >= 0) {
        sys_write((int)fbf, "ff", 2);
        sys_close((int)fbf);
    }
    long fbl = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0);
    char sfa[144], sfb[144];
    long rfa = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sfa, 0, 0, 0, 0);
    long rfb = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/b",
                            (long)sfb, 0, 0, 0, 0);
    int fb_reg = (fbl == 0 && rfa == 0 && rfb == 0 && ST_ISREG(sfa) &&
                  ST_NLINK(sfa) == 2 && ST_NLINK(sfb) == 2);
    int fb_same = (rfa == 0 && rfb == 0 && ST_INO(sfa) == ST_INO(sfb));
    int fb_beside = (dbg_has_l2s(fbw) == 1);
    cng_g_fs = &fs;
    int ok_fb = (fb_reg && fb_same && fb_beside);
    cng_dprintf(1, "l2s-storefail: rc=%d reg=%d sameino=%d beside=%d -> %s\n",
                (int)fbl, fb_reg, fb_same, fb_beside, ok_fb ? "OK" : "FAIL");
    fails += !ok_fb;

    /* glibc passes int args (dirfds) in w-registers and may leave the
     * x-register's top half dirty; the monitor must truncate before
     * comparing (Debian `ln a b` regression: AT_FDCWD arrived garbage-topped
     * and source resolution failed with ENOENT). */
    long dirty = (long)0xdeadbeef00000000ULL | (unsigned)CNG_AT_FDCWD;
    cng_dispatch(__NR_chdir, (long)"/w", 0, 0, 0, 0, 0, 0);
    long dcf = cng_dispatch(__NR_openat, dirty, (long)"da",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (dcf >= 0) {
        sys_write((int)dcf, "dd", 2);
        sys_close((int)dcf);
    }
    long dlr = cng_dispatch(__NR_linkat, dirty, (long)"da", dirty, (long)"db",
                            0, 0, 0);
    char sdd[144];
    long drr = cng_dispatch(__NR_newfstatat, dirty, (long)"da", (long)sdd, 0,
                            0, 0, 0);
    int dirty_ok = (dlr == 0 && drr == 0 && ST_NLINK(sdd) == 2);
    cng_dprintf(1, "l2s-dirtyfd: rc=%d nlink2=%d -> %s\n", (int)dlr,
                drr == 0 && ST_NLINK(sdd) == 2, dirty_ok ? "OK" : "FAIL");
    fails += !dirty_ok;
    cng_dispatch(__NR_chdir, (long)"/", 0, 0, 0, 0, 0, 0);

    cng_blocked[__NR_linkat] = 0;
    cng_g_l2s = 0;

    /* fchdir cwd tracking. */
    long dfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    if (dfd >= 0) {
        cng_dispatch(__NR_fchdir, dfd, 0, 0, 0, 0, 0, 0);
        sys_close((int)dfd);
    }
    int ok_cwd = (strcmp(cng_g_fs->cwd, "/w") == 0);
    cng_dprintf(1, "fchdir: cwd=%s -> %s\n", cng_g_fs->cwd,
                ok_cwd ? "OK" : "FAIL");
    fails += !ok_cwd;
    return fails ? 1 : 0;
}

/* _cloexectest — emulated execve must close FD_CLOEXEC fds like a real execve
 * (else fork/exec launchers' O_CLOEXEC notify pipes never close and the parent
 * hangs — the git-clone symptom). Open one CLOEXEC and one plain fd, run the
 * close pass, and check only the CLOEXEC one went away. */
int cng_cmd_cloexectest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    long ce = sys_openat(CNG_AT_FDCWD, "/dev/null",
                         CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    long pl = sys_openat(CNG_AT_FDCWD, "/dev/null", CNG_O_RDONLY, 0);
    cng_close_cloexec();
    long ce_fl = CNG_SYS(__NR_fcntl, (int)ce, 1 /*F_GETFD*/, 0, 0, 0, 0);
    long pl_fl = CNG_SYS(__NR_fcntl, (int)pl, 1 /*F_GETFD*/, 0, 0, 0, 0);
    int ok = (ce >= 0 && pl >= 0 && ce_fl == -EBADF && pl_fl >= 0);
    cng_dprintf(1, "cloexec: cloexec_closed=%d plain_open=%d -> %s\n",
                ce_fl == -EBADF, pl_fl >= 0, ok ? "OK" : "FAIL");
    if (pl >= 0)
        sys_close((int)pl);
    return ok ? 0 : 1;
}

/* _stackswtest — validate the handler's stack switch (cng_run_on_stack): the
 * callee must run on the scratch stack, its result must propagate, and the
 * caller's stack must be intact afterward. */
extern long cng_run_on_stack(void *newsp, void *fn, void *a0, void *a1);

static long sp_probe(void *lo, void *hi) {
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    /* return 1 iff we are running on the [lo,hi] scratch region */
    return (sp > (unsigned long)lo && sp <= (unsigned long)hi) ? 0xC0DE : sp;
}

int cng_cmd_stackswtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    unsigned long marker = 0xA5A5A5A5;
    void *base = sys_mmap(0, 256 * 1024, CNG_PROT_READ | CNG_PROT_WRITE,
                          CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    int mapped = !(base == CNG_MAP_FAILED || cng_is_err((long)base));
    unsigned long top = mapped ? (((unsigned long)base + 256 * 1024) & ~15UL) : 0;
    long r = mapped ? cng_run_on_stack((void *)top, (void *)sp_probe, base,
                                       (void *)top)
                    : -1;
    /* If SP was corrupted by the switch, `marker` on our frame would be clobbered
     * and subsequent use would crash; check it survived. */
    int ok = (mapped && r == 0xC0DE && marker == 0xA5A5A5A5);
    cng_dprintf(1, "stacksw: ran_on_scratch=%d ret=0x%lx caller_ok=%d -> %s\n",
                r == 0xC0DE, (unsigned long)r, marker == 0xA5A5A5A5,
                ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _clonetest — a CLONE_VFORK|CLONE_VM clone must be converted to a real (COW)
 * fork by the dispatcher, so the child gets a private address space (our
 * emulated execve would otherwise corrupt the shared parent). Verify the child
 * runs and exits, and that a write in the child is NOT visible in the parent. */
int cng_cmd_clonetest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    volatile long marker = 0;
    long pid = cng_dispatch(__NR_clone,
                            CNG_CLONE_VM | CNG_CLONE_VFORK | 17 /*SIGCHLD*/, 0, 0,
                            0, 0, 0, /*trapped=*/1);
    if (pid == 0) {        /* child */
        marker = 1;        /* if the VM were shared, the parent would see this */
        sys_exit_group(7);
    }
    int status = 0;
    sys_wait4((int)pid, &status, 0, 0);
    int exited7 = ((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 7);
    int private_vm = (marker == 0); /* real fork => parent's copy untouched */
    int ok = (pid > 0 && exited7 && private_vm);
    cng_dprintf(1, "clone: pid>0=%d child_exit7=%d private_vm=%d -> %s\n",
                pid > 0, exited7, private_vm, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _clonestktest — a vfork-style clone with a caller-provided child stack (as
 * musl's __clone/posix_spawn passes) must, after conversion, resume the child on
 * that stack. Drive cng_sigsys_body (the real SIGSYS path) with a synthetic
 * clone context and check it forks and sets the child's uc->sp to the child
 * stack while leaving the parent's untouched. */
int cng_cmd_clonestktest(int argc, char **argv, char **envp,
                         unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;

    void *cs = sys_mmap(0, 65536, CNG_PROT_READ | CNG_PROT_WRITE,
                        CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (cs == CNG_MAP_FAILED || cng_is_err((long)cs)) {
        cng_dprintf(1, "clonestk: mmap -> FAIL\n");
        return 1;
    }
    unsigned long cs_top = ((unsigned long)cs + 65536) & ~15UL;
    unsigned long sentinel = 0x5eed0d5eed0d0000UL;

    static struct cng_ucontext uc;
    memset(&uc, 0, sizeof uc);
    unsigned long long *r = uc.uc_mcontext.regs;
    r[8] = __NR_clone;
    r[0] = CNG_CLONE_VM | CNG_CLONE_VFORK | 17; /* SIGCHLD */
    r[1] = cs_top;                              /* caller-provided child stack */
    uc.uc_mcontext.sp = sentinel;               /* guest's original sp */

    cng_siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_code = CNG_SYS_SECCOMP;
    si._u._sigsys.call_addr = (void *)0x1000; /* not in gate -> guest syscall */
    si._u._sigsys.syscall = __NR_clone;

    cng_sigsys_body(&uc, &si); /* forks internally */

    if (uc.uc_mcontext.regs[0] == 0)           /* child */
        sys_exit_group(uc.uc_mcontext.sp == cs_top ? 7 : 8);

    long pid = (long)uc.uc_mcontext.regs[0];
    int status = 0;
    sys_wait4((int)pid, &status, 0, 0);
    int child_sp_ok = ((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 7);
    int parent_sp_ok = (uc.uc_mcontext.sp == sentinel);
    int ok = (pid > 0 && child_sp_ok && parent_sp_ok);
    cng_dprintf(1,
                "clonestk: pid>0=%d child_sp=childstk=%d parent_sp=orig=%d "
                "-> %s\n",
                pid > 0, child_sp_ok, parent_sp_ok, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _nettest — drive cng_sigsys_body with synthetic seccomp contexts to validate
 * the Android SIGSYS net branching (no real seccomp needed). */
int cng_cmd_nettest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    int fails = 0;

    /* 1) gate-net: a seccomp trap whose svc is our gate -> ENOSYS. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)__cng_gate_start;
        si._u._sigsys.syscall = 144; /* setgid */
        uc.uc_mcontext.regs[8] = 144;
        uc.uc_mcontext.regs[0] = 0x1234;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == -ENOSYS);
        cng_dprintf(1, "nettest gate-net: regs0=%d want=%d -> %s\n", (int)got,
                    (int)-ENOSYS, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2) non-gate seccomp trap of a translated path syscall -> dispatched and
     * re-issued (faccessat "/" with identity rootfs succeeds). */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        const char *root = "/";
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000; /* not the gate */
        uc.uc_mcontext.regs[8] = __NR_faccessat;
        uc.uc_mcontext.regs[0] = (unsigned long long)(long)CNG_AT_FDCWD;
        uc.uc_mcontext.regs[1] = (unsigned long long)(unsigned long)root;
        uc.uc_mcontext.regs[2] = 0; /* F_OK */
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == 0);
        cng_dprintf(1, "nettest dispatch: faccessat(/)=%d -> %s\n", (int)got,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2b) a blocked non-path syscall reaching default -> emulated ENOSYS. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;
        uc.uc_mcontext.regs[8] = __NR_setgid;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == -ENOSYS);
        cng_dprintf(1, "nettest blocked-direct: setgid=%d want=%d -> %s\n",
                    (int)got, (int)-ENOSYS, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2c) rt_sigprocmask(SETMASK, block-all) must apply the mask but leave
     * SIGSYS unblocked (else a later blocked seccomp trap force-kills). */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        unsigned long block_all = ~0UL;
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;
        uc.uc_mcontext.regs[8] = __NR_rt_sigprocmask;
        uc.uc_mcontext.regs[0] = 2; /* SIG_SETMASK */
        uc.uc_mcontext.regs[1] = (unsigned long)&block_all;
        uc.uc_sigmask.sig[0] = 0;
        cng_sigsys_body(&uc, &si);
        int sigsys_blocked = (uc.uc_sigmask.sig[0] >> (CNG_SIGSYS - 1)) & 1;
        long ret = (long)uc.uc_mcontext.regs[0];
        int ok = (ret == 0 && !sigsys_blocked);
        cng_dprintf(1, "nettest sigprocmask: ret=%d sigsys_blocked=%d -> %s\n",
                    (int)ret, sigsys_blocked, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 3) guest-directed SIGSYS (si_code != SYS_SECCOMP) -> untouched. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = 0;
        uc.uc_mcontext.regs[0] = 0xABCD;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == 0xABCD);
        cng_dprintf(1, "nettest passthrough: regs0=0x%lx -> %s\n",
                    (unsigned long)got, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    return fails ? 1 : 0;
}
