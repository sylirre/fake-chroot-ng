/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] PATH...
 * prints guest->host path translations. Used by the M5 unit tests (the path
 * core is pure logic, fully exercisable under qemu).
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

    cng_blocked[__NR_linkat] = 0;

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
