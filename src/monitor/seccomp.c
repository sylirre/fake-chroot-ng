/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
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
    /* inotify_add_watch: the last path-bearing syscall with no dirfd form, and
     * the only one whose a0 is not one. Left native it armed the watch on the
     * HOST's copy of the name while the rootfs's own answered ENOENT — the
     * whole containment inverted, for every file-watching runtime there is. */
    __NR_inotify_add_watch,
    /* AF_UNIX addresses. A pathname socket carries a filesystem path in
     * sun_path, so it needs the same containment as any other path: without
     * these a guest bind("/run/foo.sock") created the inode on the HOST and
     * connect() reached host daemons. The readback calls are here to strip the
     * rootfs prefix back off, so the guest never sees where its rootfs lives. */
    __NR_bind,        __NR_connect,      __NR_sendto,      __NR_sendmsg,
    __NR_getsockname, __NR_getpeername,  __NR_accept,      __NR_accept4,
    __NR_recvfrom,    __NR_recvmsg,
    /* The array forms carry one address per message. Left native, a pathname
     * sun_path passed through sendmmsg went untranslated and one returned by
     * recvmmsg went unstripped — the same hole, one loop further in. */
    __NR_sendmmsg,    __NR_recvmmsg,
    /* fchmodat2 (6.6+) is what glibc >= 2.39 reaches for first, and the only
     * way to chmod a symlink itself. Translated rather than refused, so the
     * guest keeps the capability. */
#ifdef __NR_fchmodat2
    __NR_fchmodat2,
#endif
    /* socket(): substitutes an emulated NETLINK_ROUTE socket where the host
     * denies app domains rtnetlink (netlink.c). Everything else runs native. */
    __NR_socket,
    /* POSIX timers: not a path syscall, but one whose result the emulated
     * execve has to undo. A real exec deletes every timer with the address
     * space; ours keeps the address space, and nothing enumerates a process's
     * timers, so the id has to be caught as it is handed out (dispatch.c). */
    __NR_timer_create, __NR_timer_delete,
    /* uname: the host's release describes the device, not the rootfs, and on
     * Android carries vendor suffixes that identify it. Faked to a fixed
     * identity that /proc/version repeats verbatim (procfs.c). */
    __NR_uname,
    /* ptrace: emulated in full (ptrace.c). It has to be trapped from the start
     * — PTRACE_TRACEME is the first ptrace call in a session and the tracer has
     * made none at all yet — but nothing else pays for it: no ordinary program
     * calls ptrace, and everything the emulation additionally needs (wait4,
     * kill, the tracee's whole syscall stream) is trapped by a second filter
     * stacked on demand, only on the tasks that trace or are traced. */
    __NR_ptrace,
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
    /* fchown/fchmod act on an fd, so there is no path to translate — they are
     * here for the fake-root fail-soft: the guest believes it is root, and a
     * real chown/chmod it is not allowed to perform must not surface as EPERM
     * (apk chowns every extracted file). */
    __NR_fchown,    __NR_fchmod,    __NR_capget,    __NR_capset,
    /* SO_PEERCRED reports the real invoking uid, and ps/tmux/polkit-style peer
     * checks compare it against getuid() — which under --fake-id is the fake id.
     * A guest daemon would reject its own client on the mismatch. */
    __NR_getsockopt,
};
#define NID ((int)(sizeof(id_syscalls) / sizeof(id_syscalls[0])))

/* System V IPC: always trapped, always emulated (shm.c, sysvipc.c). Android
 * denies the whole family, and trapping them everywhere keeps one guest
 * namespace whatever the host would have allowed — the same choice arm64chroot
 * makes, and the reason a guest cannot reach a host semaphore or have its
 * queues turn up in the host's `ipcs`. */
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
    __NR_semget,      __NR_semop,       __NR_semctl,      __NR_semtimedop,
    __NR_msgget,      __NR_msgsnd,      __NR_msgrcv,      __NR_msgctl,
};
#define NIPC ((int)(sizeof(ipc_syscalls) / sizeof(ipc_syscalls[0])))

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
    /* The mount family. Each takes one or two paths, and none of them was
     * trapped or refused, so the guest's own untranslated spelling went to the
     * host kernel to be judged. In the target environment that judgement is
     * EPERM and nothing happens — but it is EPERM for the wrong reason, and on
     * a host where chroot-ng does hold the privilege (running as root, or an
     * identity rootfs) the path would have been acted on where it named.
     *
     * Refusing rather than translating, because a mount is not something this
     * design can carry out even in principle: the path layer would not know
     * about the new mount, and the synthesized /proc/self/mounts — which is
     * what the guest reads back — is built from the rootfs and its binds. A
     * mount that succeeded would be invisible to everything that had to see
     * it. ENOSYS says so; EPERM implies it might have worked with privilege.
     * `mount --bind` inside a guest is what -b exists for. */
    __NR_mount,
    __NR_umount2,
    __NR_pivot_root,
#ifdef __NR_mount_setattr
    __NR_mount_setattr,
#endif
    /* Process accounting names a file by path and is the same story — the last
     * path-bearing syscall in the table that was neither trapped nor refused.
     * It is also the one that cannot be translated even in principle: what it
     * turns on is a machine-wide kernel setting with one file behind it, not
     * something a rootfs can hold a private copy of, so re-rooting the name
     * would merely put the *host's* accounting records inside the guest. */
    __NR_acct,
    /* Quotas and swap name a block device by path and are the same story. */
    __NR_quotactl,
#ifdef __NR_quotactl_fd
    __NR_quotactl_fd,
#endif
    __NR_swapon,
    __NR_swapoff,
    /* Path-bearing syscalls we do not model. Each takes a path or names a mount
     * and would otherwise reach the host filesystem untranslated; all are
     * privileged in practice, so an unprivileged guest saw EPERM rather than an
     * escape — but ENOSYS is the honest answer and the oracle's. */
#ifdef __NR_open_tree
    __NR_open_tree, /* unprivileged without OPEN_TREE_CLONE: a path->fd lookup */
#endif
#ifdef __NR_move_mount
    __NR_move_mount,
#endif
#ifdef __NR_fsopen
    __NR_fsopen,
#endif
#ifdef __NR_fsconfig
    __NR_fsconfig,
#endif
#ifdef __NR_fsmount
    __NR_fsmount,
#endif
#ifdef __NR_fspick
    __NR_fspick,
#endif
#ifdef __NR_open_by_handle_at
    __NR_open_by_handle_at, /* name_to_handle_at is trapped; keep the pair even */
#endif
#ifdef __NR_fanotify_mark
    __NR_fanotify_mark,
#endif
    /* statmount/listmount would hand the guest the HOST mount tree, defeating
     * the synthesized /proc/self/mounts entirely. */
#ifdef __NR_statmount
    __NR_statmount,
#endif
#ifdef __NR_listmount
    __NR_listmount,
#endif
    /* seccomp(2). A guest filter is layered on top of ours by the kernel and
     * applies to every thread it is installed on — including the syscalls the
     * SIGSYS handler re-issues through the gate, which the guest's filter knows
     * nothing about. A guest that refuses openat, or kills on an unlisted
     * syscall, would therefore take the monitor down with it. There is no way to
     * honor a second filter here, so the capability is refused rather than
     * half-granted; the prctl spelling is answered in the dispatcher (it shares
     * its syscall number with ops we must keep working). We never issue
     * seccomp(2) ourselves — the filter goes in via prctl — so refusing it ahead
     * of the gate allowlist costs nothing. */
#ifdef __NR_seccomp
    __NR_seccomp,
#endif
    /* POSIX message queues — the same escape as the System V family's, in the
     * one namespace the emulation cannot take over. An mq name is not a
     * filesystem path: it names an entry in the per-IPC-namespace mqueue mount,
     * which an unprivileged process cannot be given one of, so there is nothing
     * for the path traps to translate and nothing the rootfs prefix can scope.
     * Left native, a guest mq_open("/x") created the queue in the HOST's
     * namespace, where it is visible to every process on the machine (and to
     * `ls /dev/mqueue`) and charged against the host's RLIMIT_MSGQUEUE. Android
     * denies all six outright — they predate the app allow-list and Bionic never
     * issues them — so refusing is also what the guest already sees there, and it
     * is the oracle's answer (arm64chroot has no handler at all). The
     * descriptor-taking four are listed with the two name-taking ones: without a
     * queue there is nothing to send on, and a bare mq_getsetattr on some other
     * fd must not half-work. */
#ifdef __NR_mq_open
    __NR_mq_open,
#endif
#ifdef __NR_mq_unlink
    __NR_mq_unlink,
#endif
#ifdef __NR_mq_timedsend
    __NR_mq_timedsend,
#endif
#ifdef __NR_mq_timedreceive
    __NR_mq_timedreceive,
#endif
#ifdef __NR_mq_notify
    __NR_mq_notify,
#endif
#ifdef __NR_mq_getsetattr
    __NR_mq_getsetattr,
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
     * when faking, plus the two conditional entries below). */
    int nr[NPATH + NIPC + NID + 2];
    int nsys = 0;
    for (int i = 0; i < NPATH; i++)
        nr[nsys++] = path_syscalls[i];
    for (int i = 0; i < NIPC; i++)
        nr[nsys++] = ipc_syscalls[i];
    if (cng_g_fake_id)
        for (int i = 0; i < NID; i++)
            nr[nsys++] = id_syscalls[i];
    /* fstat: under -l it must report the emulated st_nlink; under --fake-id it
     * needs the same ownership remap stat() gets, or stat("f") and
     * fstat(open("f")) disagree about who owns the very same file — which is
     * exactly the comparison an installer makes before deciding to chown.
     * Listed once for either. */
    if (cng_g_l2s || cng_g_fake_id)
        nr[nsys++] = __NR_fstat;
    /* getdents64 does three jobs, and it has to be trapped for any one of them:
     * it hides the l2s backing files, it filters host processes out of a /proc
     * listing (what `ls /proc` and `ps` actually read), and it splices in the
     * entries that exist only as resolution overlays — the -b mount points and
     * the /dev nodes, which have no dirent of their own. Gating on the first two
     * alone meant `--no-proc` silently took the third away with it: `ls /` no
     * longer showed a bind destination and `ls /dev` came back empty, on a real
     * device, while both still opened by name. Listed once for whichever
     * applies. */
    if (cng_g_l2s || !cng_g_no_proc || !cng_g_no_dev ||
        (cng_g_fs && cng_g_fs->nbinds > 0))
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

    /* prctl: four ops are ours, the rest of the syscall is not.
     *
     *  - PR_SET_SECCOMP would stack a guest filter over ours (see the note on
     *    seccomp(2) above), so it has to be refused;
     *  - PR_GET_SECCOMP would answer 2 — the mode WE installed — and a program
     *    that checks whether it is already confined would believe it is;
     *  - the NO_NEW_PRIVS pair reports our own bit, which the guest never asked
     *    for, and which tells it setuid-on-exec is dead when our emulated execve
     *    still honors it.
     *
     * Everything else prctl does (PR_SET_NAME, PR_SET_VMA, PR_SET_PDEATHSIG, the
     * capability bounding set) is real process state that works natively and must
     * not pay for a trap — bionic's allocator calls PR_SET_VMA on every mapping.
     * The op is a scalar in args[0], so BPF can tell them apart. */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)__NR_prctl, 0,
        7); /* not prctl -> reload nr */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS); /* A = op */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_PR_GET_SECCOMP, 4, 0);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_PR_SET_SECCOMP, 3, 0);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_PR_SET_NO_NEW_PRIVS, 2, 0);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_PR_GET_NO_NEW_PRIVS, 1, 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW); /* not ours */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* reload A=nr */

    /* ioctl, for the interface-query band only. SIOCGIF* answers the same
     * questions the netlink dumps do and has to agree with them, but the
     * requests arrive on an ordinary AF_INET socket — there is no fd range to
     * key on, the way the synthesized /proc files have. Trapping ioctl wholesale
     * would put every terminal TCGETS and every driver call through the handler,
     * so the request itself is tested instead: 0x8910..0x8970 is the SIOCxIF
     * band, which is small enough to trap whole (the setters land in the
     * dispatcher and are passed straight through). */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)__NR_ioctl, 0,
        5); /* not ioctl -> reload nr */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS + 8); /* A = request */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, 0x8910, 0, 2); /* below -> allow */
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGT | CNG_BPF_K, 0x8970, 1, 0); /* above -> allow */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_RET | CNG_BPF_K, CNG_SECCOMP_RET_ALLOW); /* not the band */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR); /* reload A=nr */

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

/* The prologue every filter starts with: kill a non-AArch64 caller, allow
 * anything issued from inside our gate (that is our own re-issue, and it must
 * never trap again), and leave A holding the syscall number. Returns the
 * instruction count; `f` must hold at least 10. */
static int emit_prologue(struct sock_filter *f) {
    unsigned long gs = (unsigned long)__cng_gate_start;
    unsigned long ge = (unsigned long)__cng_gate_end;
    int n = 0;
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARCH);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, CNG_AUDIT_ARCH_AARCH64, 1, 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_KILL_THREAD);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP + 4);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)(gs >> 32), 0, 4);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_IP);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, (uint32_t)gs, 0, 2);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K, (uint32_t)ge, 1, 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_NR);
    return n;
}

static int install_filter(const struct sock_filter *f, int n) {
    struct sock_fprog prog = {.len = (uint16_t)n, .filter = (struct sock_filter *)f};
    return (int)sys_prctl(CNG_PR_SET_SECCOMP, CNG_SECCOMP_MODE_FILTER,
                          (unsigned long)&prog, 0, 0);
}

/* The filter a task stacks when it becomes a ptrace tracee: trap *everything*,
 * because a tracee must stop on every syscall and the base filter only traps
 * the path-bearing set. Three exceptions, each mandatory rather than an
 * optimization:
 *
 *  - our gate (the prologue), or the handler's own re-issue would trap;
 *  - rt_sigreturn, which must execute with sp still pointing at the kernel's
 *    signal frame. We can only "execute" a trapped syscall by re-issuing it
 *    from the gate, where sp is the handler's — so trapping it would restore a
 *    garbage context. It carries nothing a tracer needs, and the -R rewriter
 *    skips its site for the same reason;
 *  - a thread-creating clone (CLONE_VM without CLONE_VFORK). A re-issued clone
 *    returns into the handler on the new thread's stack, with no frame to
 *    sigreturn through; the base filter lets threads run natively for exactly
 *    that reason. The cost is that a tracer does not see thread creation
 *    (process creation, which is what strace -f follows, traps normally).
 *
 * Stacked filters compose by most-restrictive-action-wins, so this also
 * converts the base filter's RET_ERRNO answers into traps; the dispatcher
 * turns those back into -ENOSYS (see cng_denied_syscall). */
int cng_build_seccomp_traceall(struct sock_filter *f, int cap) {
    if (cap < CNG_SECCOMP_TRACEALL_INSNS)
        return -1;
    int n = emit_prologue(f);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)__NR_rt_sigreturn, 7, 0);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)__NR_clone, 0, 7);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_ALU | CNG_BPF_AND | CNG_BPF_K, CNG_CLONE_VM);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, 0, 4, 0); /* no VM -> trap */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS, CNG_SD_ARGS);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(
        CNG_BPF_ALU | CNG_BPF_AND | CNG_BPF_K, CNG_CLONE_VFORK);
    f[n++] = (struct sock_filter)CNG_BPF_JUMP(
        CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, 0, 0, 1); /* thread -> allow */
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);
    return n;
}

int cng_install_seccomp_traceall(void) {
    struct sock_filter f[CNG_SECCOMP_TRACEALL_INSNS];
    int n = cng_build_seccomp_traceall(f, (int)(sizeof f / sizeof f[0]));
    return n < 0 ? -1 : install_filter(f, n);
}

/* The filter a task stacks when it becomes a ptrace tracer. Far narrower than
 * the tracee's: only the calls whose answer has to account for emulated stops.
 * wait4/waitid are the reason this is on-demand rather than in the base filter
 * — trapping them for every guest would put every shell's blocking wait inside
 * the SIGSYS handler, where all signals are masked. */
int cng_build_seccomp_tracer(struct sock_filter *f, int cap) {
    static const int nrs[] = {
        __NR_wait4, __NR_waitid,
        /* Stop signals aimed at a tracee become cooperative group-stops: a real
         * SIGSTOP would freeze it inside its service loop and deadlock the
         * tracer's next request (strace sends exactly that on ^C). */
        __NR_kill, __NR_tkill, __NR_tgkill,
        /* strace reads tracee memory with these first; served from the mailbox
         * when the peer is one of our stopped tracees, since the host may
         * refuse the real thing (Yama, SELinux) for a process it does not see
         * as ptrace-attached. */
        __NR_process_vm_readv, __NR_process_vm_writev,
    };
    const int k = (int)(sizeof nrs / sizeof nrs[0]);
    if (cap < CNG_SECCOMP_TRACER_INSNS)
        return -1;
    int n = emit_prologue(f);
    for (int i = 0; i < k; i++)
        f[n++] = (struct sock_filter)CNG_BPF_JUMP(
            CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K, (uint32_t)nrs[i],
            (uint8_t)(k - i), 0);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_ALLOW);
    f[n++] = (struct sock_filter)CNG_BPF_STMT(CNG_BPF_RET | CNG_BPF_K,
                                              CNG_SECCOMP_RET_TRAP);
    return n;
}

int cng_install_seccomp_tracer(void) {
    struct sock_filter f[CNG_SECCOMP_TRACER_INSNS];
    int n = cng_build_seccomp_tracer(f, (int)(sizeof f / sizeof f[0]));
    return n < 0 ? -1 : install_filter(f, n);
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
