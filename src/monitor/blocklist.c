/* Startup probe of the ambient (Android zygote) seccomp filter.
 *
 * We can re-issue a translated path syscall through the gate, but if Android
 * blocks that syscall (e.g. fchownat, mknodat) the re-issue traps to SIGSYS —
 * and on kernels that don't honor nested delivery, a re-issue from inside our
 * handler force-kills the process. Rather than guess the block-list or rely on
 * the gate-net, we measure it: fork a child that (with only Android's filter
 * active) invokes each candidate syscall with harmless NULL args and records
 * which ones trap. dispatch then emulates the blocked ones as ENOSYS instead of
 * re-issuing. Off Android nothing is blocked, so everything re-issues normally.
 */
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

#include <asm/unistd.h>

unsigned char cng_blocked[CNG_NR_MAX];

/* Candidate syscalls: the set dispatch may re-issue to the real kernel. */
static const int probe_set[] = {
    __NR_openat,
#ifdef __NR_openat2
    __NR_openat2,
#endif
    __NR_newfstatat, __NR_statx,     __NR_faccessat,
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
    __NR_readlinkat, __NR_mkdirat,   __NR_mknodat,    __NR_unlinkat,
    __NR_fchownat,   __NR_fchmodat,  __NR_utimensat,  __NR_symlinkat,
    __NR_linkat,     __NR_renameat,  __NR_renameat2,  __NR_truncate,
    __NR_statfs,     __NR_chdir,     __NR_fchown,     __NR_fchmod,
    __NR_fstat,
    __NR_getdents64,
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
    __NR_setxattr,   __NR_lsetxattr,  __NR_getxattr,   __NR_lgetxattr,
    __NR_listxattr,  __NR_llistxattr, __NR_removexattr, __NR_lremovexattr,
#ifdef __NR_fchmodat2
    __NR_fchmodat2,
#endif
    __NR_bind,       __NR_connect,    __NR_sendto,     __NR_sendmsg,
    __NR_getsockname, __NR_getpeername, __NR_accept,   __NR_accept4,
    __NR_recvfrom,   __NR_recvmsg,    __NR_sendmmsg,   __NR_recvmmsg,
};
#define NPROBE ((int)(sizeof probe_set / sizeof probe_set[0]))

static unsigned char *g_probe_map; /* MAP_SHARED page: child marks, parent reads */

static void probe_sigsys(int sig, cng_siginfo_t *si, void *ucv) {
    (void)sig;
    int nr = si->_u._sigsys.syscall;
    if (si->si_code == CNG_SYS_SECCOMP && nr >= 0 && nr < CNG_NR_MAX &&
        g_probe_map)
        g_probe_map[nr] = 1;
    /* Skip the trapped syscall: seccomp already advanced pc past the svc. */
    ((struct cng_ucontext *)ucv)->uc_mcontext.regs[0] = 0;
}

void cng_probe_blocked(void) {
    g_probe_map = sys_mmap(0, 4096, CNG_PROT_READ | CNG_PROT_WRITE,
                           CNG_MAP_SHARED | CNG_MAP_ANONYMOUS, -1, 0);
    if (g_probe_map == CNG_MAP_FAILED || cng_is_err((long)g_probe_map)) {
        g_probe_map = 0;
        return; /* no probe -> nothing blocked; gate-net remains the backstop */
    }
    memset(g_probe_map, 0, CNG_NR_MAX);

    long child = sys_fork();
    if (child == 0) {
        cng_sig_install(CNG_SIGSYS, probe_sigsys);
        for (int i = 0; i < NPROBE; i++)
            /* arg0 = -1: a seccomp filter matches on the syscall number before
             * the kernel reads any argument, so a blocked call still traps —
             * while an allowed one dies on EBADF/EFAULT instantly. Zeros here
             * made arg0 name fd 0, and the probes really ran against stdin:
             * utimensat(0, NULL, ...) is futimens and STAMPED it, fchown hit
             * it, and recvfrom(0, NULL, 0, 0) blocked startup forever when
             * stdin was a silent datagram socket (ssh/CI harnesses). */
            cng_syscall6(-1, 0, 0, 0, 0, 0, probe_set[i]);
        sys_exit_group(0);
    }
    if (child > 0) {
        int st = 0;
        sys_wait4((int)child, &st, 0, 0);
        memcpy(cng_blocked, g_probe_map, CNG_NR_MAX);
    }
    sys_munmap(g_probe_map, 4096);
    g_probe_map = 0;
}
