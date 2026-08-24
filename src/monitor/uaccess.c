/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
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
 *
 * Probing is not the whole answer, though, and never was. "Is this readable?"
 * followed by a memcpy is two acts with a gap, and the guest owns its own
 * address space throughout: another thread is free to unmap the range inside
 * that gap, and the memcpy then takes exactly the fault the probe was there to
 * prevent — or, worse, the bytes change and what is acted on is not what was
 * validated. So the primitives that matter are the copies, not the probes:
 * cng_user_copyin/copyout move the bytes with the kernel doing the touching, so
 * the check and the copy are one act. Both mechanisms have that form —
 * process_vm_readv/writev directly, and the descriptor by staging one chunk
 * through a slot of its own (pwrite copies the source in, pread copies it back
 * out; whichever end is the guest's, the kernel is the one that touches it).
 * The probes remain for the callers that only need to know, and for the last
 * fallback where neither mechanism exists.
 */
#include "cng/broker.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

#define UA_CHUNK       4096
#define UA_ZERO_OFF    0    /* [0,4096): never written — the write probe reads it */
#define UA_SCRATCH_OFF 4096 /* [4096,8192): where the read probe lands */
#define UA_SLOT_OFF    8192 /* [8192,...): one staging slot per concurrent copy */
#define UA_SLOTS       64
#define UA_FD_SIZE     (UA_SLOT_OFF + (long)UA_SLOTS * UA_CHUNK)

#define STAT_INO_OFF 8

/* -1 = not created yet, -2 = another thread is creating it, -3 = unavailable. */
static int g_fd = -1;
static unsigned long g_ino;
static long g_pid;

static unsigned long fd_ino(int fd) {
    char st[128]; /* AArch64 struct stat */
    if (sys_fstat(fd, st) != 0)
        return 0;
    return *(unsigned long *)(st + STAT_INO_OFF);
}

/* A staging slot of the descriptor, held for the length of one copy.
 *
 * The probe regions above are shared by every thread on purpose — the write
 * probe's source is never written and the read probe's landing area is never
 * read back, so nothing a concurrent probe does can be observed. A copy is the
 * opposite: what is staged there IS read back, so two threads staging into the
 * same bytes would hand each other's data to their callers. One slot each,
 * claimed for the two syscalls it takes and released straight after.
 *
 * The ring is walked from a rotating start so threads spread out over it, and
 * the claim is a CAS rather than a lock: a slot is only ever held across two
 * memfd syscalls, so contention is already vanishingly unlikely at 64 of them.
 * Failing to claim one is not fatal either — the caller falls back to
 * probe-then-copy, which is what every caller did before this existed. That is
 * deliberately not a spin: a thread job-stopped between claim and release would
 * hang every other one forever, and answering a shade less safely beats not
 * answering at all. */
static unsigned g_slot_busy[UA_SLOTS];
static unsigned g_slot_rr;

static int slot_claim(void) {
    unsigned start = __atomic_fetch_add(&g_slot_rr, 1, __ATOMIC_RELAXED);
    for (unsigned i = 0; i < UA_SLOTS; i++) {
        unsigned s = (start + i) % UA_SLOTS;
        unsigned free_slot = 0;
        if (__atomic_compare_exchange_n(&g_slot_busy[s], &free_slot, 1u, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return (int)s;
    }
    return -1;
}

static void slot_release(int s) {
    __atomic_store_n(&g_slot_busy[s], 0u, __ATOMIC_RELEASE);
}

/* The scratch descriptor, or -1 when there is none to be had right now.
 *
 * We do not trap close(2), so the guest can close ours and the kernel will hand
 * the number straight back out for a file of its own — after which a probe would
 * write into a guest file. The inode is recorded at creation and checked on every
 * use, which is the same staleness discipline procfs.c applies to its
 * synthesized fds. A stale number is abandoned, never closed: by then it belongs
 * to the guest.
 *
 * The pid is recorded and checked for a different reason: fork. A descriptor
 * comes across with the address space, and so does the file behind it, so
 * parent and child would go on staging copies into the same bytes of the same
 * memfd — each reading back whatever the other put there. (The probes are
 * indifferent to that, which is why this only became a question once the
 * descriptor started carrying data: the write probe's source is never written
 * and the read probe's landing area is never read back.) Threads keep sharing
 * one descriptor, which is the point; a new process gets its own. A child that
 * shares the address space but not the pid would break the sharing rule this
 * rests on — which is exactly why dispatch converts CLONE_VM without
 * CLONE_THREAD into a plain fork. */
static int scratch_fd(void) {
    int fd = __atomic_load_n(&g_fd, __ATOMIC_ACQUIRE);
    if (fd == -3 || fd == -2)
        return -1; /* unavailable, or another thread is mid-creation */
    long pid = sys_getpid();
    int ours = fd >= 0 && fd_ino(fd) == g_ino;
    if (ours && g_pid == pid)
        return fd;

    int expect = fd;
    if (!__atomic_compare_exchange_n(&g_fd, &expect, -2, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED))
        return -1; /* lost the race: skip validation this once */
    if (ours) {
        /* Inherited across a fork: still our file, and this copy of the
         * descriptor is ours to close. The claim flags came across too, and
         * any that were held belonged to threads this process does not have —
         * fork brings one thread with it — so the ring starts clean. */
        sys_close(fd);
        for (unsigned i = 0; i < UA_SLOTS; i++)
            __atomic_store_n(&g_slot_busy[i], 0u, __ATOMIC_RELAXED);
    }

    long nfd = sys_memfd_create("cng-uaccess", CNG_MFD_CLOEXEC);
    if (nfd >= 0 && sys_ftruncate((int)nfd, UA_FD_SIZE) == 0) {
        unsigned long ino = fd_ino((int)nfd);
        if (ino) {
            g_ino = ino;
            g_pid = pid;
            __atomic_store_n(&g_fd, (int)nfd, __ATOMIC_RELEASE);
            return (int)nfd;
        }
    }
    if (nfd >= 0)
        sys_close((int)nfd);
    __atomic_store_n(&g_fd, -3, __ATOMIC_RELEASE);
    return -1;
}

/* Test aid: the inode of this process's staging descriptor, created if there is
 * none yet, or 0 where none can be had. Nothing in the monitor asks. It exists
 * so a test can assert the one property that identity carries — that a forked
 * child does not go on staging through its parent's descriptor. */
unsigned long cng_uaccess_scratch_ino(void) {
    return scratch_fd() >= 0 ? g_ino : 0;
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

/* Move `n` bytes between guest memory and our own through the descriptor, in
 * the same shape the probes use: pwrite copies the source in with
 * copy_from_user, pread copies it back out with copy_to_user. Whichever end is
 * the guest's, the kernel is the one touching it, so a range that goes away
 * mid-copy is a short count and never a fault — and the bytes are read exactly
 * once, which is what makes the check and the copy one act here too.
 *
 * Returns 0, -EFAULT for a range that would not come across whole, or -EAGAIN
 * when there is no descriptor or no free slot and the caller has to fall back.
 * An error that is about the memfd rather than the memory (a full tmpfs, say)
 * is -EAGAIN for the same reason the probes do not hold one against the caller:
 * it says nothing about the guest's pointer. */
static long fd_copy(void *dst, const void *src, unsigned long n) {
    int fd = scratch_fd();
    if (fd < 0)
        return -EAGAIN;
    int slot = slot_claim();
    if (slot < 0)
        return -EAGAIN;
    long off = UA_SLOT_OFF + (long)slot * UA_CHUNK;
    long r = 0;
    for (unsigned long done = 0; done < n;) {
        unsigned long k = n - done > UA_CHUNK ? UA_CHUNK : n - done;
        long w = CNG_SYS(__NR_pwrite64, fd, (long)((const char *)src + done),
                         (long)k, off, 0, 0);
        if (w < 0 && w != -EFAULT) {
            r = -EAGAIN;
            break;
        }
        if (w != (long)k) {
            r = -EFAULT;
            break;
        }
        long q = CNG_SYS(__NR_pread64, fd, (long)((char *)dst + done), (long)k,
                         off, 0, 0);
        if (q < 0 && q != -EFAULT) {
            r = -EAGAIN;
            break;
        }
        if (q != (long)k) {
            r = -EFAULT;
            break;
        }
        done += k;
    }
    slot_release(slot);
    return r;
}

/* Copy a guest range into our own memory, answering -EFAULT rather than
 * faulting on it.
 *
 * cng_user_readable followed by memcpy is two acts with a gap between them, and
 * a guest is free to use that gap: another thread of the process calling execve
 * can munmap the argv it just had validated, and the memcpy then faults inside
 * the handler — the death the probes exist to prevent, arrived at through them.
 * Both mechanisms have a form with no gap: process_vm_readv does the copy in
 * the kernel and reports the fault instead of raising it, and the descriptor
 * stages the bytes through a slot of its own (fd_copy). Only when neither can
 * be had does this stay probe-then-copy, which is what every caller did before.
 * Returns 0, or -EFAULT for a range that would not come across whole. */
long cng_user_copyin(void *dst, const void *src, unsigned long n) {
    if (!n)
        return 0;
    if (!src)
        return -EFAULT;
    if (cng_uaccess_probe_setup()) {
        struct cng_iovec local = {dst, n};
        struct cng_iovec remote = {(void *)src, n};
        long r = CNG_SYS(__NR_process_vm_readv, sys_getpid(), &local, 1, &remote,
                         1, 0);
        return r == (long)n ? 0 : -EFAULT;
    }
    long r = fd_copy(dst, src, n);
    if (r != -EAGAIN)
        return r;
    if (!cng_user_readable(src, n))
        return -EFAULT;
    memcpy(dst, src, n);
    return 0;
}

/* The same act in the other direction: our bytes into a guest buffer.
 *
 * cng_user_writable followed by a store has the identical gap, and the store is
 * the half that cannot be taken back — a thread unmapping the buffer between
 * the two turns a -EFAULT into a fault inside the handler. Note that the write
 * probe validates by zeroing, so a caller that reaches the fallback still hands
 * over a range of zeros before the real bytes land; that is unchanged, and
 * unobservable for the same reason it always was (the buffer is filled
 * immediately). Returns 0, or -EFAULT. */
long cng_user_copyout(void *dst, const void *src, unsigned long n) {
    if (!n)
        return 0;
    if (!dst)
        return -EFAULT;
    if (cng_uaccess_probe_setup()) {
        struct cng_iovec local = {(void *)src, n};
        struct cng_iovec remote = {dst, n};
        long r = CNG_SYS(__NR_process_vm_writev, sys_getpid(), &local, 1,
                         &remote, 1, 0);
        return r == (long)n ? 0 : -EFAULT;
    }
    long r = fd_copy(dst, src, n);
    if (r != -EAGAIN)
        return r;
    if (!cng_user_writable(dst, n))
        return -EFAULT;
    memcpy(dst, src, n);
    return 0;
}

/* A string and a pointer vector are read a piece at a time, so they cannot be
 * taken in one go — their length is what we are trying to find out. Both walk
 * up to the next 4 KiB boundary and never across one, which keeps the cost to
 * one copy per page rather than one per element, whatever the page size is.
 *
 * Each grain is copied in and then searched *in our copy*. Searching the
 * guest's own bytes is what a probe followed by a walk amounts to, and it has
 * both of the faults this file exists to remove: the walk can be racing a
 * munmap that the probe already blessed, and the terminator it finds need not
 * still be there when the string is taken. Measuring a copy answers about
 * bytes nobody else can touch. */
#define UA_GRAIN 4096

long cng_user_strlen(const char *s, unsigned long max) {
    if (!s)
        return -EFAULT;
    char win[UA_GRAIN];
    unsigned long done = 0;
    while (done < max) {
        unsigned long k = UA_GRAIN - ((unsigned long)(s + done) & (UA_GRAIN - 1));
        if (k > max - done)
            k = max - done;
        if (cng_user_copyin(win, s + done, k) < 0)
            return -EFAULT;
        for (unsigned long i = 0; i < k; i++)
            if (!win[i])
                return (long)(done + i);
        done += k;
    }
    return -E2BIG;
}

/* A guest string, measured and taken in the same act: each grain is copied in
 * and then searched for the terminator *in our copy*, so what is delivered is
 * what was measured. Walking the guest's bytes to find the NUL and copying them
 * afterwards reads them twice, and between the two reads they can change — the
 * string that fit the budget when it was measured is not the one memcpy then
 * takes. Returns the length excluding the terminator, -E2BIG when `cap` bytes
 * pass without one (cap counts the terminator), or -EFAULT. */
long cng_user_strcopyin(char *dst, const char *src, unsigned long cap) {
    if (!src)
        return -EFAULT;
    unsigned long done = 0;
    while (done < cap) {
        unsigned long k = UA_GRAIN - ((unsigned long)(src + done) & (UA_GRAIN - 1));
        if (k > cap - done)
            k = cap - done;
        long r = cng_user_copyin(dst + done, src + done, k);
        if (r < 0)
            return r;
        for (unsigned long i = 0; i < k; i++)
            if (!dst[done + i])
                return (long)(done + i);
        done += k;
    }
    return -E2BIG;
}

long cng_user_veclen(char *const *v, unsigned long max) {
    if (!v)
        return 0; /* a NULL argv/envp is an empty one, as the kernel takes it */
    char *win[UA_GRAIN / sizeof *v];
    unsigned long n = 0;
    while (n < max) {
        const char *base = (const char *)(v + n);
        unsigned long k = (UA_GRAIN - ((unsigned long)base & (UA_GRAIN - 1))) /
                          sizeof *v;
        if (k == 0)
            k = 1; /* a misaligned vector: this slot straddles the boundary, and
                    * copying all 8 bytes covers both pages anyway */
        if (k > max - n)
            k = max - n;
        if (cng_user_copyin(win, base, k * sizeof *v) < 0)
            return -EFAULT;
        for (unsigned long i = 0; i < k; i++)
            if (!win[i])
                return (long)(n + i);
        n += k;
    }
    return -E2BIG;
}
