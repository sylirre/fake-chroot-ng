/* chroot-ng probe — report the capabilities the in-process design depends on.
 *
 * Run this FIRST on any target device. The whole primary tier (seccomp
 * RET_TRAP + ul_exec loader off a noexec mount) requires:
 *   - kernel >= 3.5  (seccomp-BPF filter mode)
 *   - seccomp filter installation permitted (not blocked by SELinux)
 *   - execmem: anonymous mmap(RW) -> mprotect(RX) allowed (ART-JIT flow)
 * and it must know which mounts are noexec.
 */
#include "cng/rt.h"
#include "cng/seccomp.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

/* ---- small local UAPI structs ---------------------------------------- */

struct new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct cng_statfs {
    u64 f_type;
    u64 f_bsize;
    u64 f_blocks;
    u64 f_bfree;
    u64 f_bavail;
    u64 f_files;
    u64 f_ffree;
    u32 f_fsid[2];
    u64 f_namelen;
    u64 f_frsize;
    u64 f_flags;
    u64 f_spare[4];
};

/* ---- auxv --------------------------------------------------------------*/

#define CNG_AT_NULL    0
#define CNG_AT_PAGESZ  6
#define CNG_AT_HWCAP   16
#define CNG_AT_HWCAP2  26
#define CNG_AT_SECURE  23
#define CNG_AT_EXECFN  31

static unsigned long auxv_get(unsigned long *auxv, unsigned long type,
                              unsigned long dflt) {
    for (unsigned long *p = auxv; p[0] != CNG_AT_NULL; p += 2)
        if (p[0] == type)
            return p[1];
    return dflt;
}

/* ---- kernel version ----------------------------------------------------*/

/* Parse leading "MAJOR.MINOR" from a uname release string. */
static void parse_kver(const char *rel, int *maj, int *min) {
    *maj = *min = 0;
    const char *p = rel;
    while (*p >= '0' && *p <= '9')
        *maj = *maj * 10 + (*p++ - '0');
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9')
            *min = *min * 10 + (*p++ - '0');
    }
}

static int kver_ge(int maj, int min, int wmaj, int wmin) {
    return maj > wmaj || (maj == wmaj && min >= wmin);
}

/* ---- execmem functional test ------------------------------------------*/

/* Returns 0 if anon RW->RX works and a copied thunk executes (returns 0x5a);
 * otherwise returns the negative errno (or a sentinel) explaining the failure. */
static long test_execmem(void) {
    unsigned long len = 4096;
    void *p = sys_mmap(0, len, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return cng_is_err((long)p) ? (long)p : -ENOMEM;

    /* AArch64: `movz w0, #0x5a` ; `ret` */
    u32 code[2] = {0x52800B40u, 0xD65F03C0u};
    memcpy(p, code, sizeof code);

    long r = sys_mprotect(p, len, CNG_PROT_READ | CNG_PROT_EXEC);
    if (r < 0) {
        sys_munmap(p, len);
        return r; /* -EACCES here == execmem denied by SELinux */
    }
    cng_flush_icache(p, (char *)p + sizeof code);

    int (*fn)(void) = (int (*)(void))p;
    int got = fn();
    sys_munmap(p, len);
    return got == 0x5a ? 0 : -EINVAL;
}

/* ---- seccomp functional test (in a child) -----------------------------*/

/* Child installs a filter that returns errno 0x5a for gettid(), then calls
 * gettid(). Exit codes: 0 = filter observed (RET_ERRNO works), 10 = NNP
 * failed, 11 = filter install failed, 12 = filter inert (e.g. under qemu). */
static int seccomp_child(void) {
    static struct sock_filter prog[] = {
        CNG_BPF_STMT(CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARCH),
        CNG_BPF_JUMP(CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K,
                     CNG_AUDIT_ARCH_AARCH64, 1, 0),
        CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_KILL_THREAD),
        CNG_BPF_STMT(CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR),
        CNG_BPF_JUMP(CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, __NR_gettid, 0, 1),
        CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                     CNG_SECCOMP_RET_ERRNO | 0x5a),
        CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = {.len = sizeof(prog) / sizeof(prog[0]),
                               .filter = prog};

    if (sys_prctl(CNG_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return 10;
    /* prctl path works on 3.5+ (seccomp() syscall is only 3.17+). */
    if (sys_prctl(CNG_PR_SET_SECCOMP, CNG_SECCOMP_MODE_FILTER,
                  (unsigned long)&fprog, 0, 0) < 0)
        return 11;
    long tid = sys_gettid();
    return (tid == -0x5a) ? 0 : 12;
}

/* ---- report -----------------------------------------------------------*/

static void hr(void) { cng_puts(1, "\n"); }

int cng_cmd_probe(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    int blocked = 0;

    cng_puts(1, "chroot-ng probe\n");

    /* kernel */
    struct new_utsname u;
    memset(&u, 0, sizeof u);
    int kmaj = 0, kmin = 0;
    hr();
    cng_puts(1, "kernel:\n");
    if (sys_uname(&u) == 0) {
        parse_kver(u.release, &kmaj, &kmin);
        cng_dprintf(1, "  sysname   %s\n", u.sysname);
        cng_dprintf(1, "  release   %s  (parsed %d.%d)\n", u.release, kmaj, kmin);
        cng_dprintf(1, "  machine   %s\n", u.machine);
    } else {
        cng_puts(1, "  uname failed\n");
    }
    int kernel_ok = kver_ge(kmaj, kmin, 3, 5);
    cng_dprintf(1, "  seccomp-BPF floor (>=3.5): %s\n",
                kernel_ok ? "yes" : "NO");
    if (!kernel_ok)
        blocked++;

    /* auxv / identity */
    hr();
    cng_puts(1, "process:\n");
    cng_dprintf(1, "  pagesize  %lu\n", auxv_get(auxv, CNG_AT_PAGESZ, 4096));
    cng_dprintf(1, "  hwcap     0x%lx\n", auxv_get(auxv, CNG_AT_HWCAP, 0));
    cng_dprintf(1, "  at_secure %lu\n", auxv_get(auxv, CNG_AT_SECURE, 0));
    cng_dprintf(1, "  uid=%d euid=%d gid=%d egid=%d\n", (int)sys_getuid(),
                (int)sys_geteuid(), (int)sys_getgid(), (int)sys_getegid());

    /* seccomp */
    hr();
    cng_puts(1, "seccomp:\n");
    long mode = sys_prctl(CNG_PR_GET_SECCOMP, 0, 0, 0, 0);
    if (mode < 0)
        cng_dprintf(1, "  prctl(GET_SECCOMP)  unavailable (errno %d)\n",
                    (int)-mode);
    else
        cng_dprintf(1, "  prctl(GET_SECCOMP)  present (current mode %d)\n",
                    (int)mode);

    long child = sys_fork();
    if (child == 0)
        sys_exit_group(seccomp_child());
    if (child < 0) {
        cng_dprintf(1, "  filter test         could not fork (errno %d)\n",
                    (int)-child);
    } else {
        int status = 0;
        sys_wait4((int)child, &status, 0, 0);
        int ec = (status & 0x7f) ? -1 : ((status >> 8) & 0xff);
        int sig = status & 0x7f;
        if (sig)
            cng_dprintf(1, "  filter test         child killed by signal %d\n",
                        sig);
        else if (ec == 0)
            cng_puts(1, "  filter RET_ERRNO    WORKS\n");
        else if (ec == 10)
            cng_puts(1, "  filter test         no_new_privs rejected\n");
        else if (ec == 11)
            cng_puts(1, "  filter test         SET_SECCOMP rejected"
                        " (SELinux denial on real HW, or qemu-user)\n");
        else
            cng_puts(1, "  filter test         inert (expected under qemu-user)\n");
    }

    /* execmem */
    hr();
    cng_puts(1, "execmem (anon mmap RW -> mprotect RX -> execute):\n");
    long em = test_execmem();
    if (em == 0) {
        cng_puts(1, "  RESULT    OK (executed thunk)\n");
    } else {
        cng_dprintf(1, "  RESULT    DENIED/FAILED (errno %d)\n",
                    (int)(em < 0 ? -em : em));
        blocked++;
    }

    /* noexec mounts */
    hr();
    cng_puts(1, "noexec mounts (statfs f_flags):\n");
    const char *defpaths[] = {"/", "."};
    int npaths = argc - 1;
    char **paths = argv + 1;
    if (npaths <= 0) {
        npaths = 2;
        paths = (char **)defpaths;
    }
    for (int i = 0; i < npaths; i++) {
        struct cng_statfs sf;
        memset(&sf, 0, sizeof sf);
        long r = sys_statfs(paths[i], &sf);
        if (r < 0) {
            cng_dprintf(1, "  %s statfs failed (errno %d)\n", paths[i],
                        (int)-r);
            continue;
        }
        int noexec = (sf.f_flags & CNG_ST_NOEXEC) ? 1 : 0;
        cng_dprintf(1, "  %s noexec=%s  (f_type=0x%lx)\n", paths[i],
                    noexec ? "YES" : "no", (unsigned long)sf.f_type);
    }

    /* verdict */
    hr();
    cng_puts(1, "verdict:\n");
    if (blocked == 0)
        cng_puts(1, "  primary in-process tier: LIKELY VIABLE\n"
                    "  hard prerequisites (kernel, execmem) pass. On REAL hardware\n"
                    "  the seccomp line above must also read 'filter RET_ERRNO WORKS';\n"
                    "  a rejection there (not under qemu) is itself a hard blocker.\n");
    else
        cng_dprintf(1, "  primary in-process tier: BLOCKED (%d hard prerequisite%s failing)\n"
                       "  see the kernel/execmem lines above; without execmem there is\n"
                       "  no in-process way to run code off a true noexec mount.\n",
                    blocked, blocked == 1 ? "" : "s");

    return blocked == 0 ? 0 : 1;
}
