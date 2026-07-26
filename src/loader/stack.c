/* Build the initial process stack the way the kernel would for execve:
 *   [argc][argv..][NULL][envp..][NULL][auxv pairs..][AT_NULL] + string data.
 * We synthesize the loader-controlled auxv entries (AT_PHDR/ENTRY/BASE/...) and
 * carry through the host's hardware/identity/vDSO entries so glibc/musl/Go all
 * see a faithful environment.
 */
#include "cng/elf.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

/* Generous fixed stack for each loaded program. A real main-thread stack grows
 * on demand to RLIMIT_STACK; ours is a fixed anonymous mapping, so size it well
 * above the common 8 MiB rlimit that recursion-heavy tools (e.g. gcc's cc1) size
 * themselves against. It is virtual — only touched pages commit. */
#define GUEST_STACK_SIZE (64UL << 20)

static unsigned long auxval(unsigned long *av, unsigned long t) {
    if (!av)
        return 0;
    for (unsigned long *p = av; p[0] != AT_NULL; p += 2)
        if (p[0] == t)
            return p[1];
    return 0;
}

unsigned long cng_build_stack(int argc, char **argv, char **envp,
                              unsigned long *host_auxv,
                              const struct cng_loaded *prog,
                              const struct cng_loaded *interp,
                              const char *execfn) {
    int envc = 0;
    while (envp && envp[envc])
        envc++;

    void *stk = sys_mmap(0, GUEST_STACK_SIZE, CNG_PROT_READ | CNG_PROT_WRITE,
                         CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (stk == CNG_MAP_FAILED || cng_is_err((long)stk))
        cng_die("guest stack mmap", (long)stk);
    unsigned long top = (unsigned long)stk + GUEST_STACK_SIZE;

    /* String pool grows down from the top of the stack region. */
    unsigned long sp_str = top;
#define PUSH_STR(s)                                                            \
    ({                                                                         \
        const char *_s = (s);                                                  \
        size_t _n = strlen(_s) + 1;                                            \
        sp_str -= _n;                                                          \
        memcpy((void *)sp_str, _s, _n);                                        \
        (unsigned long)sp_str;                                                 \
    })

    unsigned long argv_addr[argc > 0 ? argc : 1];
    for (int i = 0; i < argc; i++)
        argv_addr[i] = PUSH_STR(argv[i]);
    unsigned long env_addr[envc > 0 ? envc : 1];
    for (int i = 0; i < envc; i++)
        env_addr[i] = PUSH_STR(envp[i]);

    unsigned long execfn_addr =
        PUSH_STR(execfn ? execfn : (argc > 0 ? argv[0] : ""));
    unsigned long platform_addr = PUSH_STR("aarch64");

    /* AT_RANDOM: 16 bytes, 16-aligned. glibc and musl take the stack canary and
     * pointer guard from here, and a real execve re-randomizes it per exec —
     * so copying our own host value (which is what this used to do) gave every
     * program in an exec chain the same canary, and made it predictable from any
     * single leak. Draw fresh bytes instead, falling back to the host's own
     * value and then to a constant only if getrandom is unavailable. */
    sp_str = (sp_str - 16) & ~15UL;
    unsigned long random_addr = sp_str;
    if (sys_getrandom((void *)random_addr, 16, 0) != 16) {
        unsigned long hr = auxval(host_auxv, AT_RANDOM);
        if (hr)
            memcpy((void *)random_addr, (void *)hr, 16);
        else
            memset((void *)random_addr, 0x5a, 16);
    }

    /* Assemble auxv (type,val pairs). */
    unsigned long aux[64 * 2];
    int an = 0;
#define AUX(t, v)                                                              \
    do {                                                                       \
        aux[an * 2] = (unsigned long)(t);                                      \
        aux[an * 2 + 1] = (unsigned long)(v);                                  \
        an++;                                                                  \
    } while (0)
    AUX(AT_PHDR, prog->phdr);
    AUX(AT_PHENT, prog->phent);
    AUX(AT_PHNUM, prog->phnum);
    AUX(AT_PAGESZ, cng_page_size);
    AUX(AT_BASE, interp ? interp->base : 0);
    AUX(AT_FLAGS, 0);
    AUX(AT_ENTRY, prog->entry);
    AUX(AT_EXECFN, execfn_addr);
    AUX(AT_PLATFORM, platform_addr);
    AUX(AT_RANDOM, random_addr);
    /* Identity: under --fake-id these must agree with what the credential
     * syscalls report, or getauxval(AT_UID) contradicts getuid() — and musl
     * derives libc.secure from exactly this comparison. */
    unsigned long a_uid, a_euid, a_gid, a_egid;
    if (cng_g_fake_id) {
        a_uid = cng_g_cred.ruid;
        a_euid = cng_g_cred.euid;
        a_gid = cng_g_cred.rgid;
        a_egid = cng_g_cred.egid;
    } else {
        a_uid = auxval(host_auxv, AT_UID);
        a_euid = auxval(host_auxv, AT_EUID);
        a_gid = auxval(host_auxv, AT_GID);
        a_egid = auxval(host_auxv, AT_EGID);
    }
    AUX(AT_UID, a_uid);
    AUX(AT_EUID, a_euid);
    AUX(AT_GID, a_gid);
    AUX(AT_EGID, a_egid);
    /* AT_SECURE is what makes glibc's __libc_enable_secure (and musl's
     * libc.secure) sanitize LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT. It was
     * hardcoded 0, so a --setuid-root exec that really did elevate the fake
     * identity ran *unguarded* — the one case where it matters most. Compute it
     * from the transition the way the kernel does. */
    AUX(AT_SECURE, (a_uid != a_euid || a_gid != a_egid) ? 1 : 0);
    unsigned long clk = auxval(host_auxv, AT_CLKTCK);
    AUX(AT_CLKTCK, clk ? clk : 100);
    unsigned long hw = auxval(host_auxv, AT_HWCAP);
    if (hw)
        AUX(AT_HWCAP, hw);
    unsigned long hw2 = auxval(host_auxv, AT_HWCAP2);
    if (hw2)
        AUX(AT_HWCAP2, hw2);
    unsigned long vdso = auxval(host_auxv, AT_SYSINFO_EHDR);
    if (vdso)
        AUX(AT_SYSINFO_EHDR, vdso);
    /* AT_MINSIGSTKSZ is the kernel's own answer for how much signal-frame space
     * this CPU needs, and on an SVE machine it is far above the compile-time
     * constant glibc falls back to. Dropping it while forwarding AT_HWCAP
     * verbatim (so guests do enable SVE) left them sizing SA_ONSTACK alt-stacks
     * too small for the frame our own SIGSYS handler is delivered on. */
    unsigned long mss = auxval(host_auxv, AT_MINSIGSTKSZ);
    if (mss)
        AUX(AT_MINSIGSTKSZ, mss);
    AUX(AT_NULL, 0);

    /* Fixed region below the strings: argc + argv[] + NULL + envp[] + NULL
     * + auxv pairs. Align argc (== initial sp) to 16 bytes. */
    unsigned long words =
        1 + (unsigned long)(argc + 1) + (unsigned long)(envc + 1) +
        (unsigned long)an * 2;
    unsigned long sp = (sp_str - words * 8) & ~15UL;

    unsigned long *w = (unsigned long *)sp;
    unsigned long idx = 0;
    w[idx++] = (unsigned long)argc;
    for (int i = 0; i < argc; i++)
        w[idx++] = argv_addr[i];
    w[idx++] = 0;
    for (int i = 0; i < envc; i++)
        w[idx++] = env_addr[i];
    w[idx++] = 0;
    for (int i = 0; i < an; i++) {
        w[idx++] = aux[i * 2];
        w[idx++] = aux[i * 2 + 1];
    }

    return sp;
}
