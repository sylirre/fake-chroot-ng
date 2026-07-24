/* Build the initial process stack the way the kernel would for execve:
 *   [argc][argv..][NULL][envp..][NULL][auxv pairs..][AT_NULL] + string data.
 * We synthesize the loader-controlled auxv entries (AT_PHDR/ENTRY/BASE/...) and
 * carry through the host's hardware/identity/vDSO entries so glibc/musl/Go all
 * see a faithful environment.
 */
#include "cng/elf.h"
#include "cng/loader.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#define GUEST_STACK_SIZE (8UL << 20)

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

    /* AT_RANDOM: 16 bytes, 16-aligned; reuse host randomness if available. */
    sp_str = (sp_str - 16) & ~15UL;
    unsigned long random_addr = sp_str;
    unsigned long hr = auxval(host_auxv, AT_RANDOM);
    if (hr)
        memcpy((void *)random_addr, (void *)hr, 16);
    else
        memset((void *)random_addr, 0x5a, 16);

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
    AUX(AT_UID, auxval(host_auxv, AT_UID));
    AUX(AT_EUID, auxval(host_auxv, AT_EUID));
    AUX(AT_GID, auxval(host_auxv, AT_GID));
    AUX(AT_EGID, auxval(host_auxv, AT_EGID));
    AUX(AT_SECURE, 0);
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
