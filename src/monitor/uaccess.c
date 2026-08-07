/* Validated access to guest memory.
 *
 * The dispatcher runs inside the SIGSYS handler, where every signal but SIGSYS
 * is masked (see cng_sig_install) — so a SIGSEGV raised there is unblockable and
 * force-kills the process. That makes every direct dereference of a guest
 * pointer a way to turn what a real kernel answers with -EFAULT into the death
 * of the guest: `shmctl(id, IPC_SET, garbage)`, `capget(hdr, garbage)`,
 * `rt_sigaction(sig, garbage, 0)` and friends all reach the pointer behind
 * nothing more than a NULL check.
 *
 * So ask the kernel whether a range is accessible instead of finding out by
 * faulting — the same move dbg_str makes for the debug log, generalized from a
 * C string to a byte range. Two ways to ask, and the first one that works wins:
 *
 *   process_vm_readv/writev against our own pid. One syscall, no descriptor,
 *   and nothing that can go stale — the kernel copies exactly [p,p+n) and
 *   reports what it managed. Self-access needs no ptrace permission (the mm is
 *   already ours, so mm_access never reaches the check).
 *
 *   a copy through a scratch memfd, for a kernel — or an emulator — without the
 *   pair:
 *     readable  pwrite64(fd, p, n, SCRATCH)  — copy_from_user of exactly [p,p+n)
 *     writable  pread64 (fd, p, n, ZERO)     — copy_to_user of exactly [p,p+n)
 *   This one holds a descriptor, and we do not trap close(2), so the guest can
 *   close ours and have the number handed straight back for a file of its own —
 *   after which a probe would write into a guest file. Hence the inode check on
 *   every use, which is the second syscall the pair above does not need.
 *
 * Both report -EFAULT (or a short count, where the fault is partway in) for an
 * inaccessible range and touch nothing else. The write probe's source region is
 * never written, so it always delivers zeros; callers use it immediately before
 * filling the buffer, so the zeroing is not observable. The read probe's
 * scratch region is written and never read back, so concurrent probes on
 * different threads cannot disturb each other and no lock is needed.
 *
 * When neither can be had the probes answer "accessible" and the caller
 * dereferences as it did before: no regression, just no protection.
 */
#include "cng/broker.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

#define UA_ZERO_OFF    0    /* [0,4096): never written — the write probe reads it */
#define UA_SCRATCH_OFF 4096 /* [4096,8192): where the read probe lands */
#define UA_CHUNK       4096

#define STAT_INO_OFF 8

/* -1 = not created yet, -2 = another thread is creating it, -3 = unavailable. */
static int g_fd = -1;
static unsigned long g_ino;

static unsigned long fd_ino(int fd) {
    char st[128]; /* AArch64 struct stat */
    if (sys_fstat(fd, st) != 0)
        return 0;
    return *(unsigned long *)(st + STAT_INO_OFF);
}

/* The scratch descriptor, or -1 when there is none to be had right now.
 *
 * We do not trap close(2), so the guest can close ours and the kernel will hand
 * the number straight back out for a file of its own — after which a probe would
 * write into a guest file. The inode is recorded at creation and checked on every
 * use, which is the same staleness discipline procfs.c applies to its
 * synthesized fds. A stale number is abandoned, never closed: by then it belongs
 * to the guest. */
static int scratch_fd(void) {
    int fd = __atomic_load_n(&g_fd, __ATOMIC_ACQUIRE);
    if (fd == -3 || fd == -2)
        return -1; /* unavailable, or another thread is mid-creation */
    if (fd >= 0 && fd_ino(fd) == g_ino)
        return fd;

    int expect = fd;
    if (!__atomic_compare_exchange_n(&g_fd, &expect, -2, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED))
        return -1; /* lost the race: skip validation this once */

    long nfd = sys_memfd_create("cng-uaccess", CNG_MFD_CLOEXEC);
    if (nfd >= 0 &&
        sys_ftruncate((int)nfd, UA_SCRATCH_OFF + UA_CHUNK) == 0) {
        unsigned long ino = fd_ino((int)nfd);
        if (ino) {
            g_ino = ino;
            __atomic_store_n(&g_fd, (int)nfd, __ATOMIC_RELEASE);
            return (int)nfd;
        }
    }
    if (nfd >= 0)
        sys_close((int)nfd);
    __atomic_store_n(&g_fd, -3, __ATOMIC_RELEASE);
    return -1;
}

/* Did a probe of `n` bytes come back saying the range is inaccessible? A fault
 * at the very first byte is -EFAULT; one partway in stops the copy and reports
 * the bytes that made it. Any other error is about the memfd, not the guest's
 * memory, so it is not held against the caller. */
static int probe_faulted(long r, unsigned long n) {
    return r == -EFAULT || (r >= 0 && (unsigned long)r < n);
}

/* Our end of a process_vm_* probe. The read probe's landing area is written and
 * never read back; the write probe's source is read and never written, so it
 * stays the zeros the guest's buffer is filled with. Neither needs a lock for
 * the same reason the memfd regions do not. */
static char g_land[UA_CHUNK];
static char g_zero[UA_CHUNK];

/* One process_vm_readv/writev of [user, user+n) against our own address space.
 * `write` picks the direction: readv copies the guest's bytes into g_land,
 * writev copies our zeros over them. */
static long pvm(const void *user, unsigned long n, int write) {
    struct cng_iovec local = {write ? (void *)g_zero : (void *)g_land, n};
    struct cng_iovec remote = {(void *)user, n};
    return CNG_SYS(write ? __NR_process_vm_writev : __NR_process_vm_readv,
                   sys_getpid(), &local, 1, &remote, 1, 0);
}

/* -1 undecided, 1 the pair works here, 0 it does not. */
static int g_pvm = -1;

int cng_uaccess_probe_setup(void) {
    int v = __atomic_load_n(&g_pvm, __ATOMIC_ACQUIRE);
    if (v >= 0)
        return v;
    /* CNG_UACCESS_MEMFD=1 forces the fallback, so the descriptor path can be
     * exercised on a host that does have the pair — otherwise it would only
     * ever run under an emulator, which is where it is least worth trusting. */
    if (cng_broker_env("CNG_UACCESS_MEMFD")) {
        __atomic_store_n(&g_pvm, 0, __ATOMIC_RELEASE);
        return 0;
    }
    /* Android denies plenty; the block-list has measured which syscalls before
     * any filter of ours exists, so asking it here cannot trap — which matters,
     * because deciding this from inside the SIGSYS handler would need nested
     * delivery, the one thing the design refuses to depend on. */
    if (cng_blocked[__NR_process_vm_readv] ||
        cng_blocked[__NR_process_vm_writev]) {
        v = 0;
    } else {
        /* Only the address of `here` is under test; the byte read out of it is
         * thrown away. It is initialized anyway, so that reading it is not the
         * undefined behaviour the compiler warns it would otherwise be. */
        char here = 0;
        v = pvm(&here, sizeof here, 0) == (long)sizeof here;
    }
    __atomic_store_n(&g_pvm, v, __ATOMIC_RELEASE);
    return v;
}

static int probe(const void *p, unsigned long n, int nr, long off, int write) {
    if (!p)
        return 0;
    if (!n)
        return 1;
    const char *q = (const char *)p;
    if (cng_uaccess_probe_setup()) {
        while (n) {
            unsigned long k = n > UA_CHUNK ? UA_CHUNK : n;
            if (probe_faulted(pvm(q, k, write), k))
                return 0;
            q += k;
            n -= k;
        }
        return 1;
    }
    int fd = scratch_fd();
    if (fd < 0)
        return 1; /* cannot ask: dereference as we did before */
    while (n) {
        unsigned long k = n > UA_CHUNK ? UA_CHUNK : n;
        if (probe_faulted(CNG_SYS(nr, fd, q, k, off, 0, 0), k))
            return 0;
        q += k;
        n -= k;
    }
    return 1;
}

int cng_user_readable(const void *p, unsigned long n) {
    return probe(p, n, __NR_pwrite64, UA_SCRATCH_OFF, 0);
}

int cng_user_writable(void *p, unsigned long n) {
    return probe(p, n, __NR_pread64, UA_ZERO_OFF, 1);
}

/* A string and a pointer vector are read a piece at a time, so they cannot be
 * probed in one go — their length is what we are trying to find out. Both walk
 * up to the next 4 KiB boundary and never across one, which makes each probe
 * exact whatever the page size is: a range inside a single page is readable
 * exactly when that page is. That is also what keeps the cost down — one probe
 * per page, not per element. */
#define UA_GRAIN 4096

long cng_user_strlen(const char *s, unsigned long max) {
    if (!s)
        return -EFAULT;
    unsigned long done = 0;
    while (done < max) {
        unsigned long k = UA_GRAIN - ((unsigned long)(s + done) & (UA_GRAIN - 1));
        if (k > max - done)
            k = max - done;
        if (!cng_user_readable(s + done, k))
            return -EFAULT;
        for (unsigned long i = 0; i < k; i++)
            if (!s[done + i])
                return (long)(done + i);
        done += k;
    }
    return -E2BIG;
}

long cng_user_veclen(char *const *v, unsigned long max) {
    if (!v)
        return 0; /* a NULL argv/envp is an empty one, as the kernel takes it */
    unsigned long n = 0;
    while (n < max) {
        const char *base = (const char *)(v + n);
        unsigned long k = (UA_GRAIN - ((unsigned long)base & (UA_GRAIN - 1))) /
                          sizeof *v;
        if (k == 0)
            k = 1; /* a misaligned vector: this slot straddles the boundary, and
                    * probing all 8 bytes covers both pages anyway */
        if (k > max - n)
            k = max - n;
        if (!cng_user_readable(base, k * sizeof *v))
            return -EFAULT;
        for (unsigned long i = 0; i < k; i++)
            if (!v[n + i])
                return (long)(n + i);
        n += k;
    }
    return -E2BIG;
}
