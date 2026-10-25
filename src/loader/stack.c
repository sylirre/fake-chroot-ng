/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Build the initial process stack the way the kernel would for execve:
 *   [argc][argv..][NULL][envp..][NULL][auxv pairs..][AT_NULL]
 *   [AT_RANDOM bytes]["aarch64"][argv strings..][envp strings..][execfn][0]
 * with the strings one contiguous ascending run, as fs/exec.c leaves them.
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
 * themselves against. It is virtual — only touched pages commit.
 * (CNG_GUEST_STACK_SIZE in loader.h: the argv/envp bound is derived from it, the
 * way the kernel derives ARG_MAX from RLIMIT_STACK.)
 *
 * Below it, a guard. The kernel keeps stack_guard_gap — 256 pages — of nothing
 * under a real stack, and a stack that grows into it faults; ours was one RW
 * mapping with whatever the kernel had happened to place beneath it, which is
 * top-down allocation's most recent mapping: a library the guest loaded, or a
 * scratch stack of ours. A recursion that ran off the end wrote into that and
 * went on running. The same 256 pages are reserved with the stack and made
 * PROT_NONE, so nothing else can be mapped there and the first store past the
 * bottom is the SIGSEGV a real stack overflow is. Virtual, like the rest. */
#define GUEST_STACK_SIZE  CNG_GUEST_STACK_SIZE
#define GUEST_STACK_GUARD (256 * cng_page_size)

unsigned long cng_g_stack_lo, cng_g_stack_len;
unsigned long cng_g_arg_start, cng_g_arg_end;
unsigned long cng_g_env_start, cng_g_env_end;

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

    unsigned long region = GUEST_STACK_GUARD + GUEST_STACK_SIZE;
    void *stk = sys_mmap(0, region, CNG_PROT_READ | CNG_PROT_WRITE,
                         CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (stk == CNG_MAP_FAILED || cng_is_err((long)stk))
        cng_die("guest stack mmap", (long)stk);
    long gr = sys_mprotect(stk, GUEST_STACK_GUARD, CNG_PROT_NONE);
    if (gr < 0)
        cng_die("guest stack guard mprotect", gr);
    /* The region, not the sp inside it: an emulated execve gives the previous
     * program's back (see cng_exec_generation), and it is by far the largest
     * thing it can give back. Published only once everything below has
     * succeeded — the one failure path here unmaps it again. */
    cng_g_stack_lo = 0;
    cng_g_stack_len = 0;
    cng_g_arg_start = cng_g_arg_end = cng_g_env_start = cng_g_env_end = 0;
    unsigned long bottom = (unsigned long)stk + GUEST_STACK_GUARD;
    unsigned long top = bottom + GUEST_STACK_SIZE;

    /* Where the address of each pushed string is collected until the vector
     * region's base is known. These were VLAs, so they were argc*8 bytes of the
     * *caller's* stack — and the caller here is the emulated execve, which the
     * SIGSYS handler runs on a 256 KiB scratch stack (sigsys.c) while accepting
     * a quarter of RLIMIT_STACK worth of arguments: megabytes. `rm *` in a
     * directory of fifty thousand files is an exec the kernel takes and this
     * overflowed the handler's stack on, which inside the handler (every signal
     * but SIGSYS masked) is the death of the guest rather than a fault.
     *
     * They live at the bottom of the stack just mapped instead — 64 MiB below
     * where the stack is built, and further below than any guest reaches
     * (just above the guard, which is the one part of the region that cannot
     * hold them). */
    unsigned long *argv_addr = (unsigned long *)bottom;
    unsigned long *env_addr = argv_addr + argc;

    const char *execfn_str = execfn ? execfn : (argc > 0 ? argv[0] : "");

    /* ...and with them inside the mapping, whether all of this fits is a
     * question with an answer. The caller bounds argv+envp to a quarter of this
     * size (exec_arg_max), so exceeding it means a caller that did not — the
     * pushes below would run off the end of the mapping. Answering 0 lets the
     * caller report -E2BIG, which is what the kernel says to the same input. */
    unsigned long areabytes = strlen(execfn_str) + 1;
    for (int i = 0; i < argc; i++)
        areabytes += strlen(argv[i]) + 1;
    for (int i = 0; i < envc; i++)
        areabytes += strlen(envp[i]) + 1;
    unsigned long strbytes = 8 + areabytes + sizeof "aarch64" + 16;
    unsigned long need = 2 * ((unsigned long)argc + (unsigned long)envc) * 8 +
                         strbytes + (3 + 64 * 2) * 8 + 64 /* auxv + alignment */;
    if (need > GUEST_STACK_SIZE) {
        sys_munmap(stk, region);
        return 0;
    }

    /* The strings, in the order and the shape the kernel leaves them: one
     * contiguous run, argv[0] lowest, every argv string followed by the next,
     * the environment straight after the last of them, and the exec'd path
     * last, under a zero word at the very top (fs/exec.c copies them down from
     * there in reverse, which comes out ascending). Programs depend on that
     * shape and not only on the pointers: setproctitle-style code reuses the
     * argv strings as one buffer. postgres, nginx and perl's $0 check that the
     * strings are adjacent and settle for less when they are not; libuv's
     * uv_setup_args, which every node process runs, does not check, and takes
     * argv[argc-1] + its length - argv[0] as the room it may overwrite. These
     * used to be pushed down one at a time in argv order, which left argv
     * descending — that sum came out negative as soon as a program had three
     * arguments, and libuv's memset over the "remaining" title room ran off
     * through the address space: `npm -v` was a SIGSEGV on its first
     * process.title assignment.
     *
     * The lengths are the ones measured above: argv and envp are the caller's
     * own copies (the emulated execve takes them before anything is mapped),
     * so the second strlen reads the same bytes. */
    unsigned long sp_str = top - 8 - areabytes;
    unsigned long put = sp_str;
#define PUT_STR(s)                                                             \
    ({                                                                         \
        const char *_s = (s);                                                  \
        size_t _n = strlen(_s) + 1;                                            \
        unsigned long _at = put;                                               \
        memcpy((void *)_at, _s, _n);                                           \
        put += _n;                                                             \
        _at;                                                                   \
    })

    unsigned long arg_start = put;
    for (int i = 0; i < argc; i++)
        argv_addr[i] = PUT_STR(argv[i]);
    unsigned long arg_end = put;
    for (int i = 0; i < envc; i++)
        env_addr[i] = PUT_STR(envp[i]);
    unsigned long env_end = put;
    unsigned long execfn_addr = PUT_STR(execfn_str);
    *(unsigned long *)put = 0; /* fresh anonymous memory, but say it */

    /* Below the run, as create_elf_tables puts them: the platform string, then
     * the AT_RANDOM bytes, then the vectors. */
    sp_str -= sizeof "aarch64";
    memcpy((void *)sp_str, "aarch64", sizeof "aarch64");
    unsigned long platform_addr = sp_str;

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
        const struct cng_cred *c;
        do {
            unsigned s = cng_cred_read_begin(&c);
            a_uid = c->ruid;
            a_euid = c->euid;
            a_gid = c->rgid;
            a_egid = c->egid;
            if (!cng_cred_read_retry(s))
                break;
        } while (1);
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

    cng_g_stack_lo = (unsigned long)stk;
    cng_g_stack_len = region;
    cng_g_arg_start = arg_start;
    cng_g_arg_end = cng_g_env_start = arg_end;
    cng_g_env_end = env_end;
    return sp;
}
