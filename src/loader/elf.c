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

#define MAX_PHDR 64

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

int cng_load_elf(const char *path, unsigned long base_hint,
                 struct cng_loaded *out) {
    memset(out, 0, sizeof *out);

    long fd = sys_openat(CNG_AT_FDCWD, path, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return CNG_LOAD_EOPEN;

    int rc = CNG_LOAD_OK;
    Elf64_Ehdr eh;
    if (read_exact((int)fd, &eh, sizeof eh, 0) != (long)sizeof eh) {
        rc = CNG_LOAD_EIO;
        goto out;
    }
    if (eh.e_ident[0] != ELF_MAG0 || eh.e_ident[1] != ELF_MAG1 ||
        eh.e_ident[2] != ELF_MAG2 || eh.e_ident[3] != ELF_MAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_machine != EM_AARCH64 ||
        (eh.e_type != ET_DYN && eh.e_type != ET_EXEC)) {
        rc = CNG_LOAD_EFORMAT;
        goto out;
    }
    if (eh.e_phnum == 0 || eh.e_phnum > MAX_PHDR ||
        eh.e_phentsize != sizeof(Elf64_Phdr)) {
        rc = CNG_LOAD_ETOOBIG;
        goto out;
    }

    Elf64_Phdr ph[MAX_PHDR];
    size_t phsz = (size_t)eh.e_phnum * sizeof(Elf64_Phdr);
    if (read_exact((int)fd, ph, phsz, (long)eh.e_phoff) != (long)phsz) {
        rc = CNG_LOAD_EIO;
        goto out;
    }

    /* Span over all PT_LOAD; capture PT_INTERP path along the way. */
    unsigned long lo = ~0UL, hi = 0;
    int nload = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP && ph[i].p_filesz > 0 &&
            ph[i].p_filesz < sizeof out->interp) {
            if (read_exact((int)fd, out->interp, ph[i].p_filesz,
                           (long)ph[i].p_offset) == (long)ph[i].p_filesz) {
                out->interp[ph[i].p_filesz] = '\0';
                out->has_interp = 1;
            }
        }
        if (ph[i].p_type != PT_LOAD)
            continue;
        nload++;
        unsigned long s = cng_page_down(ph[i].p_vaddr);
        unsigned long e = cng_page_up(ph[i].p_vaddr + ph[i].p_memsz);
        if (s < lo)
            lo = s;
        if (e > hi)
            hi = e;
    }
    if (nload == 0) {
        rc = CNG_LOAD_EFORMAT;
        goto out;
    }

    unsigned long span = hi - lo;
    int is_dyn = (eh.e_type == ET_DYN);
    /* When rewriting, reserve a trampoline pool contiguously after the guest so
     * every site is within a `b`'s ±128 MiB reach (mmap hints aren't reliable,
     * especially under qemu). */
    unsigned long pool_extra = cng_g_rewrite ? CNG_TRAMP_POOL : 0;
    int mflags = CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS;
    void *want = 0;
    if (is_dyn) {
        want = (void *)base_hint; /* 0 => kernel chooses a free area */
    } else {
        want = (void *)lo;
        mflags |= CNG_MAP_FIXED; /* ET_EXEC: fixed vaddrs (collision caveat) */
    }
    void *seg = sys_mmap(want, span + pool_extra, CNG_PROT_READ | CNG_PROT_WRITE,
                         mflags, -1, 0);
    if (seg == CNG_MAP_FAILED || cng_is_err((long)seg)) {
        rc = CNG_LOAD_EMAP;
        goto out;
    }
    unsigned long bias = is_dyn ? ((unsigned long)seg - lo) : 0;

    /* Fill segment contents; BSS (memsz > filesz) stays zero from anon. */
    unsigned long phdr_addr = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        unsigned long dst = bias + ph[i].p_vaddr;
        if (ph[i].p_filesz &&
            read_exact((int)fd, (void *)dst, ph[i].p_filesz,
                       (long)ph[i].p_offset) != (long)ph[i].p_filesz) {
            rc = CNG_LOAD_EIO;
            goto out;
        }
        if (eh.e_phoff >= ph[i].p_offset &&
            eh.e_phoff < ph[i].p_offset + ph[i].p_filesz)
            phdr_addr = bias + ph[i].p_vaddr + (eh.e_phoff - ph[i].p_offset);
    }

    /* M8: rewrite svc sites while the executable segments are still writable
     * (before the RX flip below), into the pool reserved just past the guest. */
    if (cng_g_rewrite) {
        unsigned long pool = (unsigned long)seg + span;
        unsigned long used = 0;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X))
                continue;
            unsigned long s = bias + ph[i].p_vaddr;
            cng_rewrite_seg(s, s + ph[i].p_filesz, pool, CNG_TRAMP_POOL, &used);
        }
        if (used) {
            sys_mprotect((void *)pool, cng_page_up(used),
                         CNG_PROT_READ | CNG_PROT_EXEC);
            cng_flush_icache((void *)pool, (void *)(pool + used));
        }
    }

    /* Apply final protections + make code coherent.
     * Caveat: page-granular per-segment; assumes segments don't share a page
     * (true for normal max-page-size-aligned AArch64 ELFs). */
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        unsigned long ps = cng_page_down(bias + ph[i].p_vaddr);
        unsigned long pe = cng_page_up(bias + ph[i].p_vaddr + ph[i].p_memsz);
        if (sys_mprotect((void *)ps, pe - ps, prot_of(ph[i].p_flags)) < 0) {
            rc = CNG_LOAD_EMAP;
            goto out;
        }
        if (ph[i].p_flags & PF_X)
            cng_flush_icache((void *)ps, (void *)pe);
    }

    out->entry = bias + eh.e_entry;
    out->phdr = phdr_addr ? phdr_addr : (bias + lo + eh.e_phoff);
    out->phent = eh.e_phentsize;
    out->phnum = eh.e_phnum;
    out->base = bias;
    out->load_lo = bias + lo;
    out->load_hi = bias + hi;
    out->is_dyn = is_dyn;
    rc = CNG_LOAD_OK;

out:
    sys_close((int)fd);
    return rc;
}
