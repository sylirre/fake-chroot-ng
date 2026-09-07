/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* mmap(PROT_EXEC) of a file the host refuses to map executable — see
 * include/cng/execmap.h for why this exists at all. */
#include "cng/execmap.h"
#include "cng/elf.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

int cng_g_execmap_force = 0;

/* MAP_TYPE: the low bits that say SHARED / PRIVATE / SHARED_VALIDATE. */
#define MAP_TYPE_MASK 0x0f

/* pread the whole of [off, off+len) that the file actually has. Returns the
 * byte count (a short answer is EOF, which is normal: the mapping a linker
 * asks for spans the object's bss too) or a negative errno. */
static long fill_from_file(int fd, char *dst, unsigned long len,
                           unsigned long off) {
    unsigned long done = 0;
    while (done < len) {
        long r = sys_pread64(fd, dst + done, len - done, (long)(off + done));
        if (r < 0) {
            if (r == -EINTR)
                continue;
            return r;
        }
        if (r == 0)
            break; /* EOF */
        done += (unsigned long)r;
    }
    return (long)done;
}

/* One program header, read straight from the file rather than from the mapping
 * (which may begin past them). Returns 0/-1. */
static int read_phdr(int fd, const Elf64_Ehdr *eh, int i, Elf64_Phdr *ph) {
    unsigned long at = eh->e_phoff + (unsigned long)i * sizeof *ph;
    return fill_from_file(fd, (char *)ph, sizeof *ph, at) == (long)sizeof *ph
               ? 0
               : -1;
}

/* Take CNG_TRAMP_POOL bytes at exactly `want`, or nothing. MAP_FIXED_NOREPLACE
 * so an occupied range is refused rather than replaced; on a kernel that
 * predates the flag it degrades to a hint, which answers a collision by placing
 * the mapping somewhere else — so the address is checked either way and a miss
 * is handed straight back. */
static unsigned long pool_at(unsigned long want) {
    if (!want || cng_hits_image(want, CNG_TRAMP_POOL))
        return 0;
    void *p = sys_mmap((void *)want, CNG_TRAMP_POOL,
                       CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS |
                           CNG_MAP_FIXED_NOREPLACE,
                       -1, 0);
    if (cng_is_err((long)p))
        return 0;
    if ((unsigned long)p != want) {
        sys_munmap(p, CNG_TRAMP_POOL);
        return 0;
    }
    return want;
}

/* Rewrite the `svc` sites of this mapping, but only where the object says its
 * code is. The M8 scan matches a bare 0xD4000001 word, and a PF_X PT_LOAD is
 * not a code segment: a musl link puts the whole read-only image in it, and
 * every link leaves the unwind tables there, where LSDA bytes really do equal
 * `svc #0` (see cng_code_ranges). So the segments say which bytes this mapping
 * carries and the section headers say which of them are instructions.
 *
 * The trampoline pool has to be within a `b`'s reach of the code. The loader
 * gets that by over-allocating its own reservation; here the mapping belongs to
 * the guest's linker, which has already reserved the object's whole span and
 * MAP_FIXEDs the remaining segments into it, so the pool goes immediately
 * outside that span instead — computed from the same headers. Both candidates
 * are taken with MAP_FIXED_NOREPLACE, so a busy neighbourhood costs the
 * rewriting and nothing else.
 *
 * Anything unexpected — not an ELF, a mapping matching no segment, nowhere to
 * put the pool — simply means no rewriting: the SIGSYS floor still covers those
 * sites and the mapping itself is already correct. Returns the number of sites
 * rewritten. */
static int rewrite_text(int fd, unsigned long map, unsigned long off,
                        unsigned long got) {
    Elf64_Ehdr eh;
    if (fill_from_file(fd, (char *)&eh, sizeof eh, 0) != (long)sizeof eh)
        return 0;
    if (eh.e_ident[0] != ELF_MAG0 || eh.e_ident[1] != ELF_MAG1 ||
        eh.e_ident[2] != ELF_MAG2 || eh.e_ident[3] != ELF_MAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_AARCH64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum > CNG_MAX_PHDR)
        return 0;

    /* Pass one: the object's own load span, and the bias this mapping implies.
     * A linker maps a segment at bias + page_down(p_vaddr) from file offset
     * page_down(p_offset) — glibc and musl both — so the segment whose rounded
     * offset is this mapping's names the bias. */
    unsigned long vlo = ~0UL, vhi = 0, bias = 0;
    int have_bias = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_phdr(fd, &eh, i, &ph) != 0)
            return 0;
        if (ph.p_type != PT_LOAD)
            continue;
        if (ph.p_vaddr + ph.p_memsz < ph.p_vaddr)
            return 0; /* a header that wraps describes nothing */
        unsigned long s = cng_page_down(ph.p_vaddr);
        unsigned long e = cng_page_up(ph.p_vaddr + ph.p_memsz);
        if (e < s)
            return 0;
        if (s < vlo)
            vlo = s;
        if (e > vhi)
            vhi = e;
        if (!have_bias && cng_page_down(ph.p_offset) == off) {
            bias = map - s;
            have_bias = 1;
        }
    }
    if (!have_bias || vhi <= vlo)
        return 0;

    /* Immediately above the object, then immediately below it, then wherever
     * the kernel cares to put one: a library sits in a crowded neighbourhood
     * (its neighbours were allocated from the same arena), so the two exact
     * spots are often taken. The kernel's own choice comes out of that same
     * arena and is normally within reach as well — and when it is not,
     * cng_rewrite_seg rewrites nothing and the pool is handed straight back. */
    unsigned long pool = pool_at(bias + vhi);
    if (!pool && bias + vlo >= CNG_TRAMP_POOL)
        pool = pool_at(bias + vlo - CNG_TRAMP_POOL);
    if (!pool) {
        void *any = sys_mmap(0, CNG_TRAMP_POOL,
                             CNG_PROT_READ | CNG_PROT_WRITE,
                             CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
        if (!cng_is_err((long)any))
            pool = (unsigned long)any;
    }
    if (!pool)
        return 0;

    /* Pass two: the executable segments, clipped to the bytes this mapping
     * actually carries, and to the object's own code map. */
    struct cng_code_ranges cr;
    cng_code_ranges(fd, &cr);
    unsigned long used = 0;
    int sites = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_phdr(fd, &eh, i, &ph) != 0)
            break;
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X) || !ph.p_filesz)
            continue;
        unsigned long slo = ph.p_offset, shi = ph.p_offset + ph.p_filesz;
        if (shi < slo)
            continue;
        if (slo < off)
            slo = off;
        if (shi > off + got)
            shi = off + got;
        if (shi <= slo)
            continue;
        sites += cng_rewrite_seg(map + (slo - off), map + (shi - off), slo,
                                 &cr, pool, CNG_TRAMP_POOL, &used);
    }
    if (!used) {
        sys_munmap((void *)pool, CNG_TRAMP_POOL); /* nothing was reachable */
        return 0;
    }
    sys_mprotect((void *)pool, cng_page_up(used),
                 CNG_PROT_READ | CNG_PROT_EXEC);
    cng_flush_icache((void *)pool, (void *)(pool + used));
    return sites;
}

long cng_execmap(unsigned long addr, unsigned long len, long prot, long flags,
                 long fd, unsigned long off) {
    int mfd = (int)fd; /* int arg: the x-register's top half may be dirty */
    long native = -EPERM;

    /* Ask the kernel first: on an exec-permitted mount the real file mapping is
     * strictly better than a copy, and it is what everything reading
     * /proc/self/maps expects to find. Only the two refusals a noexec mount (or
     * an SELinux file-execute denial) produces are worth answering. */
    if (!cng_g_execmap_force) {
        void *p = sys_mmap((void *)addr, len, (int)prot, (int)flags, mfd,
                           (long)off);
        if (!cng_is_err((long)p))
            return (long)p;
        native = (long)p;
        if (native != -EPERM && native != -EACCES)
            return native;
    }

    /* A copy has private semantics whatever the file says, so MAP_SHARED must
     * keep the kernel's refusal: quietly handing back memory no other attacher
     * would ever see is worse than the error. */
    if ((flags & MAP_TYPE_MASK) != CNG_MAP_PRIVATE || mfd < 0)
        return native;
    unsigned long mlen = cng_page_up(len);
    if (!len || mlen < len || (off & (cng_page_size - 1)))
        return native;
    /* The one address that is never ours to take (see the threat-model note in
     * docs/DESIGN.md): mapping over the monitor would replace the code serving
     * the mapping. Only MAP_FIXED can reach it — a hint is a hint. */
    if ((flags & CNG_MAP_FIXED) && cng_hits_image(addr, mlen))
        return native;

    void *p = sys_mmap((void *)addr, mlen, CNG_PROT_READ | CNG_PROT_WRITE,
                       (int)flags | CNG_MAP_ANONYMOUS, -1, 0);
    if (cng_is_err((long)p))
        return native;

    /* Fill it. Past end-of-file this leaves zeroes where a real file mapping
     * would fault SIGBUS — the more forgiving of the two, and the same thing
     * the loader's anonymous strategy does with a segment's bss tail. */
    long got = fill_from_file(mfd, (char *)p, mlen, off);
    if (got < 0) {
        sys_munmap(p, mlen);
        return native;
    }

    int sites = 0;
    if (cng_g_rewrite && (prot & CNG_PROT_EXEC))
        sites = rewrite_text(mfd, (unsigned long)p, off, (unsigned long)got);

    if (sys_mprotect(p, mlen, (int)prot) < 0) {
        /* execmem denied as well: there is no in-process way to run this code,
         * and the guest is owed the kernel's own answer for its request. */
        sys_munmap(p, mlen);
        return native;
    }
    if (prot & CNG_PROT_EXEC)
        cng_flush_icache(p, (char *)p + mlen);
    if (cng_g_debug)
        cng_dprintf(2,
                    "[cng] execmap fd=%d off=%lu len=%lu prot=%ld -> %p"
                    " (anon copy of %ld bytes, %d svc sites)\n",
                    mfd, off, mlen, prot, p, got, sites);
    return (long)p;
}
