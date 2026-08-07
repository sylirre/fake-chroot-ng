/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* ul_exec core: map an ELF64 guest into our address space from a read-only fd.
 *
 * Reading the file as data (never execve, never file-backed PROT_EXEC) is what
 * lets us run guests off a true noexec mount: segments land in anonymous memory
 * mapped RW, filled by pread(), then flipped to their final protections
 * (RX for code — the ART-JIT-style W^X flow, gated by SELinux execmem).
 */
#include "cng/elf.h"
#include "cng/loader.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#define MAX_PHDR CNG_MAX_PHDR

static long read_exact(int fd, void *buf, size_t n, long off) {
    size_t done = 0;
    while (done < n) {
        long r = sys_pread64(fd, (char *)buf + done, n - done, off + (long)done);
        if (r < 0) {
            if (r == -EINTR)
                continue;
            return r;
        }
        if (r == 0)
            break; /* short read / EOF */
        done += (size_t)r;
    }
    return (long)done;
}

static int prot_of(uint32_t pf) {
    int p = 0;
    if (pf & PF_R)
        p |= CNG_PROT_READ;
    if (pf & PF_W)
        p |= CNG_PROT_WRITE;
    if (pf & PF_X)
        p |= CNG_PROT_EXEC;
    return p;
}

int cng_g_loader_file = 0;

void cng_loader_check_execmem(void) {
    void *t = sys_mmap(0, 4096, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (t == CNG_MAP_FAILED || cng_is_err((long)t))
        return;
    if (sys_mprotect(t, 4096, CNG_PROT_READ | CNG_PROT_EXEC) < 0)
        cng_g_loader_file = 1; /* execmem revoked (e.g. by NO_NEW_PRIVS) */
    sys_munmap(t, 4096);
}

/* Strategy A — anonymous: reserve the span RW, pread segment contents, then
 * mprotect each to its final perms. Defeats a true noexec mount but needs
 * execmem (anon PROT_EXEC). Returns CNG_LOAD_EEXEC if mprotect(RX) is denied so
 * the caller can retry file-backed. Supports M8 svc rewriting. */
static int map_anon(int fd, const Elf64_Ehdr *eh, const Elf64_Phdr *ph,
                    int is_dyn, unsigned long lo, unsigned long span,
                    unsigned long base_hint, unsigned long *bias_out) {
    unsigned long pool_extra = cng_g_rewrite ? CNG_TRAMP_POOL : 0;
    int mflags = CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS;
    void *want = is_dyn ? (void *)base_hint : (void *)lo;
    if (!is_dyn)
        mflags |= CNG_MAP_FIXED;
    void *seg = sys_mmap(want, span + pool_extra, CNG_PROT_READ | CNG_PROT_WRITE,
                         mflags, -1, 0);
    if (seg == CNG_MAP_FAILED || cng_is_err((long)seg))
        return CNG_LOAD_EMAP;
    unsigned long bias = is_dyn ? ((unsigned long)seg - lo) : 0;

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || !ph[i].p_filesz)
            continue;
        if (read_exact(fd, (void *)(bias + ph[i].p_vaddr), ph[i].p_filesz,
                       (long)ph[i].p_offset) != (long)ph[i].p_filesz) {
            sys_munmap(seg, span + pool_extra);
            return CNG_LOAD_EIO;
        }
    }

    if (cng_g_rewrite) {
        unsigned long pool = (unsigned long)seg + span, used = 0;
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X))
                cng_rewrite_seg(bias + ph[i].p_vaddr,
                                bias + ph[i].p_vaddr + ph[i].p_filesz, pool,
                                CNG_TRAMP_POOL, &used);
        if (used) {
            sys_mprotect((void *)pool, cng_page_up(used),
                         CNG_PROT_READ | CNG_PROT_EXEC);
            cng_flush_icache((void *)pool, (void *)(pool + used));
        }
    }

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        unsigned long ps = cng_page_down(bias + ph[i].p_vaddr);
        unsigned long pe = cng_page_up(bias + ph[i].p_vaddr + ph[i].p_memsz);
        long mr = sys_mprotect((void *)ps, pe - ps, prot_of(ph[i].p_flags));
        if (mr < 0) {
            sys_munmap(seg, span + pool_extra);
            if (mr == -EACCES && (ph[i].p_flags & PF_X))
                return CNG_LOAD_EEXEC; /* execmem denied */
            cng_dprintf(2, "chroot-ng: load: mprotect(%lx len=%lu prot=%d)"
                           " errno=%d\n",
                        ps, (unsigned long)(pe - ps), prot_of(ph[i].p_flags),
                        (int)-mr);
            return CNG_LOAD_EMAP;
        }
        if (ph[i].p_flags & PF_X)
            cng_flush_icache((void *)ps, (void *)pe);
    }
    *bias_out = bias;
    return CNG_LOAD_OK;
}

/* Strategy B — file-backed: reserve the span PROT_NONE, then MAP_FIXED each
 * segment's file portion (with its final perms, PROT_EXEC included) directly
 * from the file, plus anon BSS. No execmem needed; needs an exec-permitted
 * mount. No M8 rewriting (code pages aren't writable). */
static int map_file(int fd, const Elf64_Ehdr *eh, const Elf64_Phdr *ph,
                    int is_dyn, unsigned long lo, unsigned long span,
                    unsigned long base_hint, unsigned long *bias_out) {
    int rflags = CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS;
    void *want = is_dyn ? (void *)base_hint : (void *)lo;
    if (!is_dyn)
        rflags |= CNG_MAP_FIXED;
    void *base = sys_mmap(want, span, CNG_PROT_NONE, rflags, -1, 0);
    if (base == CNG_MAP_FAILED || cng_is_err((long)base))
        return CNG_LOAD_EMAP;
    unsigned long bias = is_dyn ? ((unsigned long)base - lo) : 0;

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        int prot = prot_of(ph[i].p_flags);
        unsigned long vstart = bias + ph[i].p_vaddr;
        unsigned long vpage = cng_page_down(vstart);
        unsigned long fileend = vstart + ph[i].p_filesz;

        if (ph[i].p_filesz) {
            unsigned long map_len = cng_page_up(fileend) - vpage;
            void *m = sys_mmap((void *)vpage, map_len, prot,
                               CNG_MAP_PRIVATE | CNG_MAP_FIXED, fd,
                               (long)cng_page_down(ph[i].p_offset));
            if (m == CNG_MAP_FAILED || cng_is_err((long)m)) {
                cng_dprintf(2, "chroot-ng: load: file mmap(%lx len=%lu prot=%d)"
                               " errno=%d\n",
                            vpage, (unsigned long)map_len, prot,
                            cng_errno((long)m));
                sys_munmap(base, span);
                return CNG_LOAD_EMAP;
            }
            /* Zero the BSS bytes sharing the last file page (writable segs). */
            unsigned long pend = cng_page_up(fileend);
            if (ph[i].p_memsz > ph[i].p_filesz && (prot & CNG_PROT_WRITE) &&
                pend > fileend)
                memset((void *)fileend, 0, pend - fileend);
        }

        /* Full BSS pages beyond the file-backed part (or the whole segment when
         * p_filesz == 0). */
        unsigned long bss_lo =
            ph[i].p_filesz ? cng_page_up(fileend) : cng_page_down(vstart);
        unsigned long bss_hi = cng_page_up(vstart + ph[i].p_memsz);
        if (bss_hi > bss_lo) {
            void *b = sys_mmap((void *)bss_lo, bss_hi - bss_lo, prot,
                               CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS |
                                   CNG_MAP_FIXED,
                               -1, 0);
            if (b == CNG_MAP_FAILED || cng_is_err((long)b)) {
                sys_munmap(base, span);
                return CNG_LOAD_EMAP;
            }
        }
        if (ph[i].p_flags & PF_X)
            cng_flush_icache((void *)vpage, (void *)cng_page_up(fileend));
    }
    *bias_out = bias;
    return CNG_LOAD_OK;
}

/* ---- the header pass: read and validate, map nothing ------------------- */

static int elf_read_headers(int fd, struct cng_elf_plan *plan,
                            struct cng_loaded *out) {
    Elf64_Ehdr *eh = &plan->eh;
    if (read_exact(fd, eh, sizeof *eh, 0) != (long)sizeof *eh)
        return CNG_LOAD_EIO;
    if (eh->e_ident[0] != ELF_MAG0 || eh->e_ident[1] != ELF_MAG1 ||
        eh->e_ident[2] != ELF_MAG2 || eh->e_ident[3] != ELF_MAG3 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB || eh->e_machine != EM_AARCH64 ||
        (eh->e_type != ET_DYN && eh->e_type != ET_EXEC))
        return CNG_LOAD_EFORMAT;
    if (eh->e_phnum == 0 || eh->e_phnum > MAX_PHDR ||
        eh->e_phentsize != sizeof(Elf64_Phdr))
        return CNG_LOAD_ETOOBIG;

    Elf64_Phdr *ph = plan->ph;
    size_t phsz = (size_t)eh->e_phnum * sizeof(Elf64_Phdr);
    if (read_exact(fd, ph, phsz, (long)eh->e_phoff) != (long)phsz)
        return CNG_LOAD_EIO;

    /* Span over all PT_LOAD; capture PT_INTERP path along the way. */
    unsigned long lo = ~0UL, hi = 0;
    int nload = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP && ph[i].p_filesz > 0 &&
            ph[i].p_filesz < sizeof out->interp) {
            if (read_exact(fd, out->interp, ph[i].p_filesz,
                           (long)ph[i].p_offset) == (long)ph[i].p_filesz) {
                out->interp[ph[i].p_filesz] = '\0';
                out->has_interp = 1;
            }
        }
        if (ph[i].p_type != PT_LOAD)
            continue;
        nload++;
        /* The span has to cover every byte that gets written into it, and what
         * is written is p_filesz — the kernel maps each segment on its own, so
         * a p_filesz past p_memsz costs it nothing, while here it is the one
         * reserve everything lands in. Sized from p_memsz alone, a header
         * claiming filesz=2 MiB and memsz=4 KiB reserved a page and then had
         * read_exact pread 2 MiB of file into it, straight through whatever the
         * kernel had placed after. Take the larger of the two: no real object
         * has filesz above memsz (0 of 16515 in a Debian + Alpine tree), so
         * this refuses nothing that ever loaded, and a malformed one is now
         * merely wrong rather than out of bounds.
         *
         * Overflow is the same question one step out: p_vaddr and the sizes are
         * attacker-chosen 64-bit values, and a sum that wraps yields an `e`
         * below `lo` and a span that is not the range we then write into. */
        unsigned long fill = ph[i].p_filesz > ph[i].p_memsz ? ph[i].p_filesz
                                                            : ph[i].p_memsz;
        if (ph[i].p_vaddr + fill < ph[i].p_vaddr)
            return CNG_LOAD_EFORMAT;
        unsigned long s = cng_page_down(ph[i].p_vaddr);
        unsigned long e = cng_page_up(ph[i].p_vaddr + fill);
        if (e < s) /* cng_page_up wrapped at the top of the address space */
            return CNG_LOAD_EFORMAT;
        if (s < lo)
            lo = s;
        if (e > hi)
            hi = e;
    }
    if (nload == 0)
        return CNG_LOAD_EFORMAT;

    plan->lo = lo;
    plan->hi = hi;
    plan->is_dyn = (eh->e_type == ET_DYN);
    return CNG_LOAD_OK;
}

/* The two checks open_exec makes before an ELF header is ever looked at, and
 * the reason a directory and a mode-0644 file both fail an exec with EACCES
 * rather than with something about their contents. The execute bit is required
 * even of root: CAP_DAC_OVERRIDE only covers a file with at least one of the
 * three set. Measured on the host, program and interpreter alike. */
static int elf_check_execable(int fd) {
    char st[128];
    if (CNG_SYS(__NR_newfstatat, fd, (long)"", (long)st, CNG_AT_EMPTY_PATH, 0,
                0) != 0)
        return CNG_LOAD_EACCES;
    unsigned mode = *(unsigned *)(st + 16);
    if ((mode & 0170000) != 0100000 || !(mode & 0111))
        return CNG_LOAD_EACCES;
    return CNG_LOAD_OK;
}

int cng_elf_plan_fd(int fd, struct cng_elf_plan *plan, struct cng_loaded *out) {
    memset(out, 0, sizeof *out);
    plan->fd = fd; /* borrowed: the caller owns it, so never own_fd */
    plan->own_fd = 0;
    plan->err = 0;
    int rc = elf_check_execable(fd);
    if (rc == CNG_LOAD_OK)
        rc = elf_read_headers(fd, plan, out);
    if (rc != CNG_LOAD_OK)
        plan->fd = -1;
    return rc;
}

int cng_elf_plan(const char *path, struct cng_elf_plan *plan,
                 struct cng_loaded *out) {
    memset(out, 0, sizeof *out);
    plan->fd = -1;
    plan->own_fd = 0;
    plan->err = 0;
    long fd = sys_openat(CNG_AT_FDCWD, path, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0) {
        plan->err = (int)fd; /* ENOENT, EACCES, ENOTDIR, ELOOP: the caller's */
        return CNG_LOAD_EOPEN;
    }
    plan->fd = (int)fd;
    plan->own_fd = 1;
    int rc = elf_check_execable((int)fd);
    if (rc == CNG_LOAD_OK)
        rc = elf_read_headers((int)fd, plan, out);
    if (rc != CNG_LOAD_OK)
        cng_elf_plan_release(plan);
    return rc;
}

void cng_elf_plan_release(struct cng_elf_plan *plan) {
    if (plan->own_fd && plan->fd >= 0)
        sys_close(plan->fd);
    plan->fd = -1;
    plan->own_fd = 0;
}

/* ---- the map pass: from here the address space is being rewritten ------ */

int cng_elf_map(const struct cng_elf_plan *plan, unsigned long base_hint,
                struct cng_loaded *out) {
    const Elf64_Ehdr *eh = &plan->eh;
    const Elf64_Phdr *ph = plan->ph;
    unsigned long lo = plan->lo, hi = plan->hi, span = hi - lo, bias = 0;

    int rc = cng_g_loader_file ? map_file(plan->fd, eh, ph, plan->is_dyn, lo,
                                          span, base_hint, &bias)
                               : map_anon(plan->fd, eh, ph, plan->is_dyn, lo,
                                          span, base_hint, &bias);
    if (rc == CNG_LOAD_EEXEC) {
        /* Anonymous executable memory was denied (e.g. NO_NEW_PRIVS revoking
         * execmem on Android). Fall back to file-backed exec mapping, which
         * works on an exec-permitted mount, and remember it for next time. */
        cng_g_loader_file = 1;
        rc = map_file(plan->fd, eh, ph, plan->is_dyn, lo, span, base_hint,
                      &bias);
    }
    if (rc != CNG_LOAD_OK)
        return rc;

    /* Address of the program headers in memory (within the PT_LOAD covering
     * e_phoff). */
    unsigned long phdr_addr = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && eh->e_phoff >= ph[i].p_offset &&
            eh->e_phoff < ph[i].p_offset + ph[i].p_filesz) {
            phdr_addr = bias + ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
            break;
        }
    }

    out->entry = bias + eh->e_entry;
    out->phdr = phdr_addr ? phdr_addr : (bias + lo + eh->e_phoff);
    out->phent = eh->e_phentsize;
    out->phnum = eh->e_phnum;
    out->base = bias;
    out->load_lo = bias + lo;
    out->load_hi = bias + hi;
    out->is_dyn = plan->is_dyn;
    return CNG_LOAD_OK;
}

/* ---- both passes, for the callers that have nothing to validate against
 * (the initial program, and the debug ops) ------------------------------- */

int cng_load_elf_fd(int fd, unsigned long base_hint, struct cng_loaded *out) {
    struct cng_elf_plan plan;
    int rc = cng_elf_plan_fd(fd, &plan, out);
    if (rc == CNG_LOAD_OK)
        rc = cng_elf_map(&plan, base_hint, out);
    cng_elf_plan_release(&plan);
    return rc;
}

int cng_load_elf(const char *path, unsigned long base_hint,
                 struct cng_loaded *out) {
    struct cng_elf_plan plan;
    int rc = cng_elf_plan(path, &plan, out);
    if (rc == CNG_LOAD_OK)
        rc = cng_elf_map(&plan, base_hint, out);
    cng_elf_plan_release(&plan);
    return rc;
}
