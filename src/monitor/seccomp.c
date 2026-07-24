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
    __NR_statfs,     __NR_chdir,    __NR_getcwd,    __NR_chroot,
    __NR_execve,
#ifdef __NR_execveat
    __NR_execveat,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
};

#define NSYS ((int)(sizeof(path_syscalls) / sizeof(path_syscalls[0])))

int cng_install_seccomp(void) {
    unsigned long gs = (unsigned long)__cng_gate_start;
    unsigned long ge = (unsigned long)__cng_gate_end;
    uint32_t gate_hi = (uint32_t)(gs >> 32);
    uint32_t gate_lo = (uint32_t)gs;
    uint32_t gate_end_lo = (uint32_t)ge;

    /* Prologue (indices 0..8) + LD nr (9) + NSYS checks + 2 RETs. */
    struct sock_filter f[12 + NSYS];
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

    /* NSYS checks at indices 10..10+NSYS-1; TRAP at 10+NSYS+1. */
    for (int i = 0; i < NSYS; i++)
        f[n++] = (struct sock_filter)CNG_BPF_JUMP(
            CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)path_syscalls[i],
            (uint8_t)(NSYS - i), 0);
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
