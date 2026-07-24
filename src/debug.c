/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] PATH...
 * prints guest->host path translations. Used by the M5 unit tests (the path
 * core is pure logic, fully exercisable under qemu).
 */
#include "cng/monitor.h"
#include "cng/path.h"
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
                               CNG_O_RDONLY, 0, 0, 0);
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
                              0);
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
