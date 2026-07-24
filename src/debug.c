/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] PATH...
 * prints guest->host path translations. Used by the M5 unit tests (the path
 * core is pure logic, fully exercisable under qemu).
 */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

#include <asm/unistd.h>

int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;

    const char *rootfs = "/";
    const char *cwd = 0;
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
        cng_dprintf(2, "usage: _dtest -r ROOT (open|access) GUESTPATH\n");
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
    cng_g_exe_guest = "/bin/sh";

    cng_dprintf(1, "getuid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 0));
    cng_dprintf(1, "geteuid=%d\n",
                (int)cng_dispatch(__NR_geteuid, 0, 0, 0, 0, 0, 0, 0));

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

/* _l2stest ROOT — exercise link2symlink (target must be a guest/relative path,
 * not a host path) and fchdir cwd tracking. ROOT must contain a dir "w". */
int cng_cmd_l2stest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = argc > 1 ? argv[1] : "/";
    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    int fails = 0;

    /* link2symlink: force the fallback by marking linkat blocked. */
    cng_blocked[__NR_linkat] = 1;
    long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/a",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (fd >= 0) {
        sys_write((int)fd, "hi", 2);
        sys_close((int)fd);
    }
    long lr = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a", CNG_AT_FDCWD,
                           (long)"/w/b", 0, 0, 0);
    char buf[256];
    long n = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/w/b",
                          (long)buf, sizeof buf - 1, 0, 0, 0);
    cng_blocked[__NR_linkat] = 0;
    buf[n > 0 ? n : 0] = '\0';
    int leak = (strncmp(buf, "/data", 5) == 0) ||
               (strlen(rootfs) > 1 &&
                strncmp(buf, rootfs, strlen(rootfs)) == 0);
    int ok_l2s = (lr == 0 && n > 0 && !leak);
    cng_dprintf(1, "l2s: link rc=%d target=%s leak=%d -> %s\n", (int)lr, buf,
                leak, ok_l2s ? "OK" : "FAIL");
    fails += !ok_l2s;

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
