/* Build and install the seccomp-BPF filter.
 *
 * Logic: if arch != AArch64 -> KILL; else if the syscall's instruction pointer
 * is inside our gate [__cng_gate_start, __cng_gate_end) -> ALLOW (this is how
 * the SIGSYS handler re-issues translated syscalls without re-trapping); else
 * if the syscall is one of the path-bearing set -> TRAP (SIGSYS); else ALLOW.
 */
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/seccomp.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

/* Must match the set handled in dispatch.c. */
static const int path_syscalls[] = {
    __NR_openat,
#ifdef __NR_openat2
    __NR_openat2,
#endif
    __NR_newfstatat, __NR_statx,   __NR_faccessat,
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
    __NR_readlinkat, __NR_mkdirat, __NR_mknodat,   __NR_unlinkat,
    __NR_fchownat,   __NR_fchmodat, __NR_utimensat, __NR_symlinkat,
    __NR_linkat,     __NR_renameat, __NR_renameat2, __NR_truncate,
    __NR_statfs,     __NR_chdir,    __NR_fchdir,    __NR_getcwd,
    __NR_chroot,
    /* signal control: keep SIGSYS unblocked / our handler in place */
    __NR_rt_sigprocmask, __NR_rt_sigaction,
    __NR_execve,
#ifdef __NR_execveat
    __NR_execveat,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
};

#define NPATH ((int)(sizeof(path_syscalls) / sizeof(path_syscalls[0])))

/* Credential syscalls: trapped only when -0 credential faking is active
 * (see cng_g_fake_id), so we don't slow down getuid/etc otherwise. */
static const int id_syscalls[] = {
    __NR_getuid,    __NR_geteuid,   __NR_getgid,    __NR_getegid,
    __NR_getresuid, __NR_getresgid, __NR_setuid,    __NR_setgid,
    __NR_setresuid, __NR_setresgid, __NR_setreuid,  __NR_setregid,
    __NR_setgroups, __NR_setfsuid,  __NR_setfsgid,
};
#define NID ((int)(sizeof(id_syscalls) / sizeof(id_syscalls[0])))

int cng_install_seccomp(void) {
    unsigned long gs = (unsigned long)__cng_gate_start;
    unsigned long ge = (unsigned long)__cng_gate_end;
    uint32_t gate_hi = (uint32_t)(gs >> 32);
    uint32_t gate_lo = (uint32_t)gs;
    uint32_t gate_end_lo = (uint32_t)ge;

    /* Build the trapped syscall list (path set, plus id set when faking). */
    int nr[NPATH + NID];
    int nsys = 0;
    for (int i = 0; i < NPATH; i++)
        nr[nsys++] = path_syscalls[i];
    if (cng_g_fake_id)
        for (int i = 0; i < NID; i++)
            nr[nsys++] = id_syscalls[i];

    /* Prologue (indices 0..8) + LD nr (9) + nsys checks + 2 RETs. */
    struct sock_filter f[12 + NPATH + NID];
    int n = 0;

    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARCH); /* 0 */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_AUDIT_ARCH_AARCH64, 1,
        0); /* 1: match->3, else->2 */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_KILL_THREAD); /*2*/
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP + 4); /* 3: ip high */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, gate_hi, 0,
        4); /* 4: match->5, else->nr(9) */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP); /* 5: ip low */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, gate_lo, 0,
        2); /* 6: >=lo ->7, else->nr(9) */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, gate_end_lo, 1,
        0); /* 7: >=end ->nr(9), else->8 */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW); /* 8: in-gate allow */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* 9: A = nr */

    /* nsys checks at indices 10..10+nsys-1; TRAP at 10+nsys+1. */
    for (int i = 0; i < nsys; i++)
        f[n++] = (struct sock_filter)CNG_BPF_JUMP(
            CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)nr[i],
            (uint8_t)(nsys - i), 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_ALLOW); /* dflt */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);

    struct sock_fprog prog = {.len = (uint16_t)n, .filter = f};

    if (sys_prctl(CNG_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    /* prctl path is 3.5+ (the seccomp() syscall is only 3.17+). */
    long r = sys_prctl(CNG_PR_SET_SECCOMP, CNG_SECCOMP_MODE_FILTER,
                       (unsigned long)&prog, 0, 0);
    return (int)r;
}
