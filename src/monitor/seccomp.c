/* Build and install the seccomp-BPF filter.
 *
 * Logic: if arch != AArch64 -> KILL; else if the syscall's instruction pointer
 * is inside our gate [__cng_gate_start, __cng_gate_end) -> ALLOW (this is how
 * the SIGSYS handler re-issues translated syscalls without re-trapping); else
 * if the syscall is one of the path-bearing set -> TRAP (SIGSYS); else ALLOW.
 */
#include "cng/l2s.h"
#include "cng/monitor.h"
#include "cng/procfs.h"
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
    /* Extended attributes. Eight path-bearing forms, all with the path in a0
     * and no dirfd; the f* variants act on an fd and need no translation. The
     * getters leak host state and answer existence questions about it; the
     * setters and removers *write* the host filesystem. */
    __NR_setxattr,    __NR_lsetxattr,    __NR_getxattr,    __NR_lgetxattr,
    __NR_listxattr,   __NR_llistxattr,   __NR_removexattr, __NR_lremovexattr,
    /* AF_UNIX addresses. A pathname socket carries a filesystem path in
     * sun_path, so it needs the same containment as any other path: without
     * these a guest bind("/run/foo.sock") created the inode on the HOST and
     * connect() reached host daemons. The readback calls are here to strip the
     * rootfs prefix back off, so the guest never sees where its rootfs lives. */
    __NR_bind,        __NR_connect,      __NR_sendto,      __NR_sendmsg,
    __NR_getsockname, __NR_getpeername,  __NR_accept,      __NR_accept4,
    __NR_recvfrom,    __NR_recvmsg,
};

#define NPATH ((int)(sizeof(path_syscalls) / sizeof(path_syscalls[0])))

/* Credential syscalls: trapped only when --fake-id credential faking is active
 * (see cng_g_fake_id), so we don't slow down getuid/etc otherwise. Must match
 * the set emulated in cred.c / dispatch.c. */
static const int id_syscalls[] = {
    __NR_getuid,    __NR_geteuid,   __NR_getgid,    __NR_getegid,
    __NR_getresuid, __NR_getresgid, __NR_getgroups, __NR_setuid,
    __NR_setgid,    __NR_setresuid, __NR_setresgid, __NR_setreuid,
    __NR_setregid,  __NR_setgroups, __NR_setfsuid,  __NR_setfsgid,
    __NR_fchown,    __NR_capget,    __NR_capset,
    /* SO_PEERCRED reports the real invoking uid, and ps/tmux/polkit-style peer
     * checks compare it against getuid() — which under --fake-id is the fake id.
     * A guest daemon would reject its own client on the mismatch. */
    __NR_getsockopt,
};
#define NID ((int)(sizeof(id_syscalls) / sizeof(id_syscalls[0])))

/* System V shared memory: always trapped, always emulated (shm.c). Android
 * denies all four, and trapping them everywhere keeps one guest namespace
 * whatever the host would have allowed — the same choice arm64chroot makes. */
static const int ipc_syscalls[] = {
#ifdef __NR_shmget
    __NR_shmget,
#endif
#ifdef __NR_shmat
    __NR_shmat,
#endif
#ifdef __NR_shmdt
    __NR_shmdt,
#endif
#ifdef __NR_shmctl
    __NR_shmctl,
#endif
};
#define NIPC ((int)(sizeof(ipc_syscalls) / sizeof(ipc_syscalls[0])))

/* File syscalls trapped only when -l/--link2symlink is active: fstat must
 * report the emulated st_nlink, getdents64 must hide the backing files. Must
 * match the l2s hooks in dispatch.c. (getdents64 is also trapped for the /proc
 * hidden-process view — see below — so it is listed once, conditionally.) */
static const int l2s_syscalls[] = {
    __NR_fstat,
};
#define NL2S ((int)(sizeof(l2s_syscalls) / sizeof(l2s_syscalls[0])))

/* The designed-ENOSYS set — arm64chroot's `quiet_enosys`, and the one piece of
 * policy chroot-ng needs that is not translation. These are syscalls a guest
 * probes and falls back from, which we must refuse rather than let through:
 * every one of them reaches the filesystem by a route the path traps cannot see,
 * so allowing it would silently bypass the rootfs.
 *
 * io_uring is the whole reason this list exists. Its operations are submitted by
 * writing SQEs into a shared ring, not by a syscall per operation, so
 * IORING_OP_OPENAT / STATX / RENAMEAT / UNLINKAT / LINKAT / MKDIRAT never
 * execute an `svc` and can never be trapped or translated. A guest linked
 * against liburing would address the host filesystem directly. There is nothing
 * to intercept, so the ring must not be created at all; liburing and every
 * runtime that uses it (recent Node, Tokio, fio) has a documented non-ring
 * fallback for exactly this answer.
 *
 * Answered with SECCOMP_RET_ERRNO, so the kernel refuses them itself — no
 * signal, no handler, and it holds even where nested SIGSYS delivery does not.
 * cng_denied_syscall() covers the -R trampoline tier, which has no filter. */
static const int enosys_syscalls[] = {
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
    __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
    __NR_io_uring_register,
#endif
    /* clone3. Its flags live in a `struct clone_args` behind args[0], so BPF —
     * which can only read scalars out of seccomp_data — cannot tell a thread
     * from a vfork here, and the CLONE_VFORK conversion below is exactly what
     * keeps an emulated execve from loading the new program over its parent.
     * glibc >= 2.34 reaches clone3 first from posix_spawn and pthread_create and
     * falls back to clone on ENOSYS, which we do handle, so refusing it puts
     * every spawn back on the path that has the conversion. Cheaper and far more
     * predictable than reimplementing that delicate child-stack handling for a
     * second entry point; it is also what the oracle does.
     *
     * We never issue clone3 ourselves (sys_fork uses __NR_clone), so refusing it
     * ahead of the gate allowlist costs nothing. */
#ifdef __NR_clone3
    __NR_clone3,
#endif
};
#define NENOSYS ((int)(sizeof(enosys_syscalls) / sizeof(enosys_syscalls[0])))

int cng_denied_syscall(long nr) {
    for (int i = 0; i < NENOSYS; i++)
        if (nr == enosys_syscalls[i])
            return 1;
    return 0;
}

int cng_build_seccomp(struct sock_filter *f, int cap) {
    unsigned long gs = (unsigned long)__cng_gate_start;
    unsigned long ge = (unsigned long)__cng_gate_end;
    uint32_t gate_hi = (uint32_t)(gs >> 32);
    uint32_t gate_lo = (uint32_t)gs;
    uint32_t gate_end_lo = (uint32_t)ge;

    /* Build the trapped syscall list (path set + SysV IPC set, plus the id set
     * when faking, plus the l2s set when hardlink emulation is on). */
    int nr[NPATH + NIPC + NID + NL2S + 1]; /* +1: the conditional getdents64 */
    int nsys = 0;
    for (int i = 0; i < NPATH; i++)
        nr[nsys++] = path_syscalls[i];
    for (int i = 0; i < NIPC; i++)
        nr[nsys++] = ipc_syscalls[i];
    if (cng_g_fake_id)
        for (int i = 0; i < NID; i++)
            nr[nsys++] = id_syscalls[i];
    if (cng_g_l2s)
        for (int i = 0; i < NL2S; i++)
            nr[nsys++] = l2s_syscalls[i];
    /* getdents64: hides the l2s backing files, and — the reason it is trapped
     * by default — filters host processes out of a /proc listing, which is
     * what `ls /proc` and `ps` actually read. Listed once for either. */
    if (cng_g_l2s || !cng_g_no_proc)
        nr[nsys++] = __NR_getdents64;

    if (cap < CNG_SECCOMP_MAX_INSNS)
        return -1;
    int n = 0;

    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARCH); /* 0 */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_AUDIT_ARCH_AARCH64, 1,
        0); /* 1: match->3, else->2 */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_KILL_THREAD);

    /* Designed-ENOSYS set (see enosys_syscalls), refused by the kernel itself.
     * Deliberately ahead of the gate allowlist: the gate exists so our own
     * re-issued syscalls are not re-trapped, but we never issue any of these, so
     * exempting them by instruction pointer would only leave a hole. The last
     * check's jf skips the RET; earlier ones fall through to the next check. */
    if (NENOSYS > 0) {
        f[n++] = (struct sock_filter)CNG_BPF_STMT(
            CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* A = nr */
        for (int i = 0; i < NENOSYS; i++)
            f[n++] = (struct sock_filter)CNG_BPF_JUMP(
                CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K,
                (uint32_t)enosys_syscalls[i], (uint8_t)(NENOSYS - 1 - i),
                (uint8_t)(i == NENOSYS - 1 ? 1 : 0));
        f[n++] = (struct sock_filter)CNG_BPF_STMT(
            CNG_BPF_RET | CNG_BPF_K,
            CNG_SECCOMP_RET_ERRNO | (ENOSYS & CNG_SECCOMP_RET_DATA));
    }

    /* Gate allowlist: a syscall issued from inside our own gate is a re-issue
     * from the handler and must not trap again. Offsets below are relative, so
     * "-> nr" means the A = nr load that follows this block. */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP + 4); /* ip high */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, gate_hi, 0, 4); /* else -> nr */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP); /* ip low */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, gate_lo, 0,
        2); /* >=lo ? -> next : nr */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, gate_end_lo, 1,
        0); /* >=end ? -> nr : in-gate */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW); /* in-gate allow */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* A = nr */

    /* clone: trap process creation, let thread creation run natively.
     *  - without CLONE_VM the clone makes a new process, and the parent must
     *    publish it into the PID registry (procreg) for the /proc view;
     *  - with CLONE_VFORK (Go's os/exec, posix_spawn) the child shares our
     *    address space and suspends us until its execve — but our execve is
     *    emulated in-process, so a shared VM would corrupt the parent; dispatch
     *    converts it to a real fork.
     * A thread (CLONE_VM, no CLONE_VFORK) is neither, and runs untrapped.
     * clone flags are in args[0] (low 32 bits). */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)__NR_clone, 0,
        8); /* 10: nr==clone? no->19 (reload nr) */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS); /* 11: A=flags lo */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_ALU | CNG_BPF_AND | CNG_BPF_K, CNG_CLONE_VM); /* 12 */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, 0, 3,
        0); /* 13: (flags&VM)==0? yes->17 trap (new process), no->14 */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS); /* 14: reload flags */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_ALU | CNG_BPF_AND | CNG_BPF_K, CNG_CLONE_VFORK); /* 15 */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, 0, 1,
        0); /* 16: (flags&VFORK)==0? yes->18 allow (thread), no->17 trap */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP); /* 17 */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW); /* 18: plain thread */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* 19: reload A=nr */

    /* Synthesized-file refresh: a read on one of the high fds reserved for the
     * time-varying /proc files (loadavg, uptime, stat) must reach the
     * dispatcher, which regenerates the content when the read starts at offset
     * 0 — otherwise top and vmstat, which lseek(0)+reread a held fd, would show
     * frozen numbers. The whole read family is covered (read, readv, pread64,
     * preadv, preadv2), matching the refresh hooks arm64chroot applies.
     * Filtering on "fd >= base" keeps every ordinary read untrapped; a guest
     * fd that happens to land in the range is simply re-issued. The kernel
     * truncates the fd argument to 32 bits, so the low word is exactly what it
     * will use. */
    if (cng_g_synth_fd_base > 0) {
        static const int read_family[] = {
            __NR_read, __NR_pread64, __NR_readv, __NR_preadv,
#ifdef __NR_preadv2
            __NR_preadv2,
#endif
        };
        int nrf = (int)(sizeof read_family / sizeof read_family[0]);
        for (int i = 0; i < nrf; i++)
            f[n++] = (struct sock_filter)CNG_BPF_JUMP(
                CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K,
                (uint32_t)read_family[i], (uint8_t)(nrf - 1 - i),
                /* last check: no-> skip fd test, trap, allow -> reload */
                (uint8_t)(i == nrf - 1 ? 4 : 0));
        f[n++] = (struct sock_filter)CNG_BPF_STMT(
            CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS); /* A=fd lo */
        f[n++] = (struct sock_filter)CNG_BPF_JUMP(
            CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K,
            (uint32_t)cng_g_synth_fd_base, 0, 1); /* fd>=base? yes->trap */
        f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                                  CNG_SECCOMP_RET_TRAP);
        f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                                  CNG_SECCOMP_RET_ALLOW);
        f[n++] = (struct sock_filter)CNG_BPF_STMT(
            CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* reload A=nr */
    }

    /* nsys checks; TRAP at the tail. */
    for (int i = 0; i < nsys; i++)
        f[n++] = (struct sock_filter)CNG_BPF_JUMP(
            CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)nr[i],
            (uint8_t)(nsys - i), 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_ALLOW); /* dflt */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);

    return n;
}

int cng_install_seccomp(void) {
    struct sock_filter f[CNG_SECCOMP_MAX_INSNS];
    int n = cng_build_seccomp(f, (int)(sizeof f / sizeof f[0]));
    if (n < 0)
        return -1;
    struct sock_fprog prog = {.len = (uint16_t)n, .filter = f};

    if (sys_prctl(CNG_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    /* prctl path is 3.5+ (the seccomp() syscall is only 3.17+). */
    long r = sys_prctl(CNG_PR_SET_SECCOMP, CNG_SECCOMP_MODE_FILTER,
                       (unsigned long)&prog, 0, 0);
    return (int)r;
}
