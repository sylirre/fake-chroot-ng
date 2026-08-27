/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* System V shared memory, emulated in-process (see include/cng/shm.h).
 *
 * Ported from arm64chroot's src/sys_ipc.c. The broker daemon (broker.c) is the
 * authoritative registry and owns each segment's backing fd; this file is the
 * client that drives it and does the mapping. Because chroot-ng runs the guest
 * in its own address space, an attach is an ordinary MAP_SHARED mmap of the fd
 * the broker hands over, and the fd is closed immediately afterwards — a
 * process holds a segment only as a mapping, never as a descriptor the guest
 * could see or close.
 *
 * The per-process attach list lets shmdt(addr) resolve the shmid and length,
 * and lets fork/execve keep the broker's nattch honest. It is thread-shared, so
 * slots are claimed by CAS rather than under a lock: every path here can run
 * inside the SIGSYS handler, where a sleeping lock could deadlock against the
 * thread it interrupted.
 */
#include "cng/broker.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

/* IPC_64: callers OR this into the shmctl command on every arch whose libc
 * uses the 64-bit ipc structs, which on arm64 is the only layout there is. */
#define IPC_64 0x100

/* Attachments this process holds. va == 0 is a free entry; ATT_CLAIMING
 * reserves one while the payload is written, so a scan never sees a half-filled
 * one.
 *
 * A fixed table was the wrong shape for it. Linux enforces no per-process attach
 * limit — shminfo's SHMSEG is reported and never applied — so an attachment past
 * the end of one was recorded nowhere, and the two things this table exists for
 * both went wrong for it: shmdt(addr) answered EINVAL for an address the kernel
 * would have detached, and an exec left it attached with its count on the
 * broker's nattch. Measured against the host kernel, 200 attaches of one
 * segment: 200 detached there, 128 here.
 *
 * So it grows instead, one page-sized block at a time, chained and never freed.
 * The first block is ordinary .bss, which keeps the common case allocation-free,
 * and every later one is private anonymous memory of this process — so a fork
 * child inherits the whole chain at the same addresses, exactly as it inherited
 * the first block alone. */
#define ATT_BLK      128 /* entries per block */
#define ATT_CLAIMING (~(u64)0)

struct att_ent {
    u64 va;
    u64 size;
    s32 shmid;
};

struct att_blk {
    struct att_blk *next;
    struct att_ent e[ATT_BLK];
};

static struct att_blk g_att0;

/* Every entry of every block. `next` is published with a release store and read
 * with an acquire load, so a block is either not seen at all or seen with its
 * entries (all zero, i.e. free) already visible. */
#define ATT_FOR(e)                                                             \
    for (struct att_blk *_b = &g_att0; _b;                                     \
         _b = __atomic_load_n(&_b->next, __ATOMIC_ACQUIRE))                    \
        for (struct att_ent *e = _b->e; e < _b->e + ATT_BLK; e++)

/* ---- broker calls ------------------------------------------------------- */

static s32 shm_get(s32 key, u64 size, s32 shmflg) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SHMGET;
    q.key = key;
    q.size = size;
    q.arg = shmflg;
    struct cng_bresp r;
    if (cng_broker_rpc(&q, &r, 0) < 0)
        return -ENOSPC; /* no broker reachable: fail loud */
    return r.ret;
}

/* Ask for a mappable fd and count the attach. Returns the fd (>= 0) or -errno;
 * *size_out gets the segment's requested size. */
static int shm_at(s32 shmid, int readonly, int exec, u64 *size_out) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SHMAT;
    q.id = shmid;
    q.arg = (readonly ? CNG_SHMAT_RDONLY : 0) | (exec ? CNG_SHMAT_EXEC : 0);
    struct cng_bresp r;
    int fd = -1;
    if (cng_broker_rpc(&q, &r, &fd) < 0)
        return -EINVAL;
    if (r.ret < 0) {
        if (fd >= 0)
            sys_close(fd);
        return r.ret;
    }
    if (fd < 0)
        return -EINVAL; /* success but no fd: treat as a bad id */
    *size_out = r.size;
    return fd;
}

static void shm_dt(s32 shmid) {
    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SHMDT;
    q.id = shmid;
    struct cng_bresp r;
    cng_broker_rpc(&q, &r, 0); /* best effort: the daemon reclaims on death */
}

/* ---- the attach list ---------------------------------------------------- */

/* Append a block after `tail`. 1 when the chain has grown — by this call or by
 * another thread that got there first, which serves just as well — 0 when the
 * host would not give us the page. */
static int att_grow(struct att_blk *tail) {
    unsigned long sz = cng_page_up(sizeof(struct att_blk));
    void *p = sys_mmap(0, sz, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    struct att_blk *none = 0;
    if (!__atomic_compare_exchange_n(&tail->next, &none, (struct att_blk *)p, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        sys_munmap(p, sz); /* lost the append: theirs is the block we scan */
    return 1;
}

/* Record an attachment already mapped at `va`. Returns 0 only when no memory
 * for another block could be had at all, in which case the attach is untracked:
 * shmdt of it answers EINVAL and execve will not detach it, and the broker
 * reclaims the leaked nattch when this process dies. Refusing the attach
 * outright would be the worse lie — a real shmat has no such limit. */
static int att_add(s32 shmid, u64 va, u64 size) {
    /* Each round either takes an entry or lengthens the chain, so the bound is
     * only there to keep a pathological interleave from spinning for ever. */
    for (int round = 0; round < 64; round++) {
        struct att_blk *tail = &g_att0;
        for (struct att_blk *b = &g_att0; b;
             b = __atomic_load_n(&b->next, __ATOMIC_ACQUIRE)) {
            tail = b;
            for (int i = 0; i < ATT_BLK; i++) {
                u64 expect = 0;
                if (!__atomic_compare_exchange_n(&b->e[i].va, &expect,
                                                 ATT_CLAIMING, 0,
                                                 __ATOMIC_ACQ_REL,
                                                 __ATOMIC_RELAXED))
                    continue;
                b->e[i].shmid = shmid;
                b->e[i].size = size;
                __atomic_store_n(&b->e[i].va, va, __ATOMIC_RELEASE); /* findable */
                return 1;
            }
        }
        if (!att_grow(tail))
            return 0;
    }
    return 0;
}

/* A MAP_FIXED attach replaces whatever was mapped at its address, so an
 * attachment it covered is simply gone and the table has to say so. Left in,
 * the stale entry is what shmdt() resolves the address to: it unmaps that
 * entry's length instead of the new mapping's — punching a hole in a live
 * attachment — and detaches the wrong segment, whose nattch then never reaches
 * zero and whose backing is held until the daemon's death reclaim.
 *
 * The kernel takes this from the VMA it destroys, and the two cases are not the
 * same event. Measured: remapping a 64 KiB segment over a 4 KiB attachment
 * closes the old VMA, so the old segment's nattch drops to 0 at remap time and
 * the later shmdt detaches the new one. Remapping one page over the front of a
 * 16-page attachment *splits* the VMA instead — the old segment keeps its
 * nattch, the address now resolves to the new mapping, and the orphaned tail
 * can never be detached again. So a fully covered entry is retired and
 * detached; one whose start alone is covered is retired without the detach,
 * which says exactly that. No munmap either way: the new mapping already
 * replaced those pages.
 *
 * An entry the range covers only at its *tail* is left alone, as the kernel
 * leaves its nattch and its address: the split it models is not one this table
 * can express. */
static void att_retire_covered(u64 p, u64 len) {
    ATT_FOR(e) {
        u64 va = __atomic_load_n(&e->va, __ATOMIC_ACQUIRE);
        if (!va || va == ATT_CLAIMING || va < p || va >= p + len)
            continue;
        s32 shmid = e->shmid; /* before the CAS: see do_shmdt */
        u64 size = e->size;
        u64 expect = va;
        if (!__atomic_compare_exchange_n(&e->va, &expect, 0, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        if (va + size <= p + len)
            shm_dt(shmid);
    }
}

/* ---- the syscalls ------------------------------------------------------- */

static long do_shmget(s32 key, u64 size, s32 shmflg) {
    return shm_get(key, size, shmflg);
}

static long do_shmat(s32 shmid, u64 shmaddr, s32 shmflg) {
    int readonly = (shmflg & CNG_SHM_RDONLY) ? 1 : 0;
    /* SHM_EXEC is a permission request, not just a mapping flag: it needs
     * execute permission on the segment the way SHM_RDONLY needs read and a
     * plain attach needs write. The broker applies the triad. */
    u64 size = 0;
    int fd = shm_at(shmid, readonly, (shmflg & CNG_SHM_EXEC) ? 1 : 0, &size);
    if (fd < 0)
        return fd;

    /* A size whose page round-up wraps has no mapping that can represent it.
     * Quietly substituting one page — which is what this did — handed the guest
     * a mapping far shorter than the segment it asked for, and left every later
     * shmdt and detach-on-exec computing a length from a record that never
     * matched. The broker refuses such a size at shmget now; this is the belt,
     * and it answers rather than guesses. */
    u64 len = cng_page_up(size);
    int prot = CNG_PROT_READ | (readonly ? 0 : CNG_PROT_WRITE) |
               ((shmflg & CNG_SHM_EXEC) ? CNG_PROT_EXEC : 0);

    /* SHMLBA is the page size on arm64, and the guest runs on our pages, so
     * SHM_RND rounds to cng_page_size. */
    u64 addr = shmaddr;
    long err = len ? 0 : -EINVAL;
    if (!err && addr) {
        if (shmflg & CNG_SHM_RND)
            addr = cng_page_down(addr);
        if (addr & (cng_page_size - 1))
            err = -EINVAL;
        /* SHM_REMAP is MAP_FIXED, and the monitor lives in the guest's own
         * address space: an attach placed over chroot-ng's image would replace
         * the code that is running the attach. The kernel has no such range to
         * protect, so there is no errno to copy — EINVAL is what shmat already
         * answers for an address it will not honor, and it is what a plain
         * (non-REMAP) attach here produces anyway, since the range is taken. */
        else if (cng_hits_image(addr, len))
            err = -EINVAL;
    }

    void *p = CNG_MAP_FAILED;
    if (!err) {
        int flags = CNG_MAP_SHARED;
        if (addr)
            flags |= (shmflg & CNG_SHM_REMAP) ? CNG_MAP_FIXED
                                              : CNG_MAP_FIXED_NOREPLACE;
        p = sys_mmap((void *)addr, len, prot, flags, fd, 0);
        if (cng_is_err((long)p)) {
            err = (long)p;
            /* An occupied range is EINVAL from shmat, not EEXIST from mmap. */
            if (err == -EEXIST)
                err = -EINVAL;
            p = CNG_MAP_FAILED;
        } else if (addr && (u64)p != addr) {
            /* Pre-4.17 kernels do not know MAP_FIXED_NOREPLACE and treat the
             * address as a hint, so a collision lands us elsewhere instead of
             * failing. Undo it and answer as shmat would. */
            sys_munmap(p, len);
            err = -EINVAL;
            p = CNG_MAP_FAILED;
        }
    }
    sys_close(fd); /* the mapping backs it now; hold no descriptor */
    if (err) {
        shm_dt(shmid); /* undo the attach the broker already counted */
        return err;
    }
    if (addr && (shmflg & CNG_SHM_REMAP))
        att_retire_covered((u64)p, len); /* the only path that maps FIXED */
    att_add(shmid, (u64)p, len);
    return (long)p;
}

static long do_shmdt(u64 addr) {
    if (!addr)
        return -EINVAL;
    ATT_FOR(e) {
        if (__atomic_load_n(&e->va, __ATOMIC_ACQUIRE) != addr)
            continue;
        s32 shmid = e->shmid;
        u64 len = e->size;
        /* Release the entry before unmapping so a concurrent shmdt of the same
         * address cannot double-count the detach; the loser sees no entry and
         * answers EINVAL, exactly as a second shmdt should. */
        u64 expect = addr;
        if (!__atomic_compare_exchange_n(&e->va, &expect, 0, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return -EINVAL;
        sys_munmap((void *)addr, len);
        shm_dt(shmid);
        return 0;
    }
    return -EINVAL;
}

/* Fill a guest shmid64_ds from a broker reply. */
static void fill_ds(struct cng_shmid64_ds *ds, const struct cng_bresp *r) {
    memset(ds, 0, sizeof *ds);
    ds->shm_perm.key = r->key;
    ds->shm_perm.uid = r->uid;
    ds->shm_perm.gid = r->gid;
    ds->shm_perm.cuid = r->cuid;
    ds->shm_perm.cgid = r->cgid;
    ds->shm_perm.mode = r->mode;
    ds->shm_segsz = r->size;
    ds->shm_atime = r->atime;
    ds->shm_dtime = r->dtime;
    ds->shm_ctime = r->ctime;
    ds->shm_cpid = r->cpid;
    ds->shm_lpid = r->lpid;
    ds->shm_nattch = r->nattch;
}

static long do_shmctl(s32 shmid, int cmd, void *buf) {
    cmd &= ~IPC_64; /* arm64 always uses the 64-bit ds */

    struct cng_breq q;
    memset(&q, 0, sizeof q);
    q.op = CNG_REQ_SHMCTL;
    q.id = shmid; /* a segment id, or an array index for SHM_STAT */
    q.arg = cmd;
    if (cmd == CNG_IPC_SET) {
        /* `buf` is guest memory and this runs with SIGSEGV masked, so a bad
         * pointer has to be reported, not dereferenced — and taken as a copy,
         * so the fields applied are the ones that were validated
         * (see uaccess.c). */
        struct cng_shmid64_ds in;
        if (cng_user_copyin(&in, buf, sizeof in) < 0)
            return -EFAULT;
        q.set_mode = in.shm_perm.mode;
        q.set_uid = in.shm_perm.uid;
        q.set_gid = in.shm_perm.gid;
    }

    struct cng_bresp r;
    if (cng_broker_rpc(&q, &r, 0) < 0)
        return -EINVAL;

    /* The ipcs enumeration commands deliver a struct and return a max index or
     * a shmid; SHM_INFO/IPC_INFO return -1 (no segments) without that being an
     * error, so they write their struct before the sign check below — and clamp
     * that -1 to 0, which is what the kernel hands the user (`err < 0 ? 0 : err`
     * over ipc_get_maxidx, in both shmctl_shm_info and shmctl_ipc_info). Passed
     * through raw it reaches the guest as a failed syscall with errno EPERM, so
     * `ipcs -m` on a namespace with no segments yet reported an error instead of
     * an empty list. The sem/msg siblings clamp the same way. */
    if (cmd == CNG_SHM_INFO) {
        struct cng_shm_info si;
        memset(&si, 0, sizeof si);
        si.used_ids = r.info_used;
        si.shm_tot = r.info_tot;
        si.shm_rss = r.info_tot; /* no separate RSS accounting: report total */
        if (cng_user_copyout(buf, &si, sizeof si) < 0)
            return -EFAULT;
        return r.ret < 0 ? 0 : r.ret;
    }
    if (cmd == CNG_IPC_INFO) {
        struct cng_shminfo64 li;
        memset(&li, 0, sizeof li);
        li.shmmax = 0x7fffffffffffffffULL; /* effectively host-RAM bounded */
        li.shmmin = 1;
        li.shmmni = li.shmseg = 1024;      /* the broker's segment table */
        li.shmall = 0x7fffffffffffffffULL >> 12;
        if (cng_user_copyout(buf, &li, sizeof li) < 0)
            return -EFAULT;
        return r.ret < 0 ? 0 : r.ret;
    }

    if (r.ret < 0)
        return r.ret;

    if (cmd == CNG_IPC_STAT || cmd == CNG_SHM_STAT || cmd == CNG_SHM_STAT_ANY) {
        struct cng_shmid64_ds ds;
        fill_ds(&ds, &r);
        if (cng_user_copyout(buf, &ds, sizeof ds) < 0)
            return -EFAULT;
    }
    return r.ret;
}

long cng_shm_handle(long nr, long a0, long a1, long a2) {
    switch (nr) {
#ifdef __NR_shmget
    case __NR_shmget:
        return do_shmget((s32)a0, (u64)a1, (s32)a2);
#endif
#ifdef __NR_shmat
    case __NR_shmat:
        return do_shmat((s32)a0, (u64)a1, (s32)a2);
#endif
#ifdef __NR_shmdt
    case __NR_shmdt:
        return do_shmdt((u64)a0);
#endif
#ifdef __NR_shmctl
    case __NR_shmctl:
        return do_shmctl((s32)a0, (int)a1, (void *)a2);
#endif
    default:
        return -ENOSYS;
    }
}

/* ---- fork / execve bookkeeping ------------------------------------------ */

void cng_shm_fork_child(void) {
    ATT_FOR(e) {
        u64 va = __atomic_load_n(&e->va, __ATOMIC_ACQUIRE);
        if (!va || va == ATT_CLAIMING)
            continue;
        struct cng_breq q;
        memset(&q, 0, sizeof q);
        q.op = CNG_REQ_SHMFORK; /* stamped with our pid: the child's */
        q.id = e->shmid;
        struct cng_bresp r;
        cng_broker_rpc(&q, &r, 0);
    }
}

void cng_shm_detach_all(void) {
    ATT_FOR(e) {
        u64 va = __atomic_load_n(&e->va, __ATOMIC_ACQUIRE);
        if (!va || va == ATT_CLAIMING)
            continue;
        /* Copied out before the CAS, as do_shmdt does and for the same reason:
         * zeroing `va` releases the slot, and from that instant a concurrent
         * shmat on another thread may claim it and write its own segment in.
         * Read afterwards, the length belonged to that segment and this
         * unmapped the old address for the new one's size, then charged the
         * detach against the wrong shmid. */
        s32 shmid = e->shmid;
        u64 len = e->size;
        u64 expect = va;
        if (!__atomic_compare_exchange_n(&e->va, &expect, 0, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        sys_munmap((void *)va, len);
        shm_dt(shmid);
    }
}
