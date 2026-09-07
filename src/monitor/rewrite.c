/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
#include "cng/rewrite.h"
#include "cng/elf.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"

#include <stdint.h>

int cng_g_rewrite = 0;

/* Trampoline template (src/monitor/tramp.S). */
extern char cng_svc_tramp_tpl[];
extern char cng_svc_tramp_tpl_end[];
extern char cng_svc_tramp_disp[];
extern char cng_svc_tramp_ret[];
extern char cng_svc_tramp_back[];

#define SVC0_INSN    0xD4000001u /* `svc #0` */
#define B_OPCODE     0x14000000u /* unconditional branch */
#define BRANCH_REACH (1L << 27)  /* +-128 MiB */
#define MOVZ_X8_MASK 0xFFE0001Fu /* movz x8, #imm16 (hw=0) */
#define MOVZ_X8      0xD2800008u
#define NR_RT_SIGRETURN 139u

/* Section headers we are willing to walk, and how many at a time (a page's
 * worth would be 64; the biggest object in a Debian/Alpine aarch64 rootfs has
 * 61 sections in total, so the loop runs twice for the worst of them). */
#define MAX_SHDR   1024
#define SHDR_CHUNK 8

/* How far back a candidate's syscall number may have been set, in
 * instructions. Measured over ~1800 real `svc` sites in Alpine/Debian aarch64
 * rootfs images: 97.1% set x8 within 8 instructions, and every data word that
 * collided with the encoding had nothing resembling one. */
#define X8_LOOKBACK 8

unsigned long cng_tramp_size(void) {
    return (unsigned long)(cng_svc_tramp_tpl_end - cng_svc_tramp_tpl);
}

/* Encode `b <target>` at `at`; 0 if the target is out of a branch's reach. */
static uint32_t b_insn(unsigned long at, unsigned long target) {
    long delta = (long)target - (long)at;
    if (delta < -BRANCH_REACH || delta >= BRANCH_REACH || (delta & 3))
        return 0;
    return B_OPCODE | (uint32_t)(((unsigned long)delta >> 2) & 0x03FFFFFFu);
}

/* Copy a trampoline into pool+*used, patch its two literals and its return
 * branch, advance *used. The branch is what lets the common exit put the guest
 * back at S+4 without spending a register on the address — which is how x16/x17
 * survive (see tramp.S). */
static char *emit(unsigned long pool, unsigned long cap, unsigned long *used,
                  unsigned long ret_site) {
    unsigned long tsz = cng_tramp_size();
    if (*used + tsz > cap)
        return 0;
    char *slot = (char *)(pool + *used);
    size_t back_off = (size_t)(cng_svc_tramp_back - cng_svc_tramp_tpl);
    uint32_t back = b_insn((unsigned long)slot + back_off, ret_site);
    if (!back)
        return 0; /* the site is reachable but the way back is not */
    memcpy(slot, cng_svc_tramp_tpl, tsz);
    size_t disp_off = (size_t)(cng_svc_tramp_disp - cng_svc_tramp_tpl);
    size_t ret_off = (size_t)(cng_svc_tramp_ret - cng_svc_tramp_tpl);
    *(unsigned long *)(slot + disp_off) = (unsigned long)&cng_tramp_dispatch;
    *(unsigned long *)(slot + ret_off) = ret_site;
    *(uint32_t *)(slot + back_off) = back;
    *used += tsz;
    return slot;
}

/* pread exactly n bytes at off, or fail. */
static int pread_all(int fd, void *buf, unsigned long n, unsigned long off) {
    unsigned long done = 0;
    while (done < n) {
        long r = sys_pread64(fd, (char *)buf + done, n - done,
                             (long)(off + done));
        if (r < 0) {
            if (r == -EINTR)
                continue;
            return 0;
        }
        if (r == 0)
            return 0; /* short of what was asked for: not the file we expect */
        done += (unsigned long)r;
    }
    return 1;
}

/* Where an object says its code is.
 *
 * A `PF_X PT_LOAD` is not a code segment: a musl/Alpine link puts the whole
 * read-only image — .rela.dyn, .dynstr, .rodata, .eh_frame, .gcc_except_table —
 * into the one R+E segment, and even a `-z separate-code` link leaves .rodata
 * and the unwind tables in there. Measured over 1717 aarch64 objects, 58% of
 * the bytes inside PF_X segments are not instructions at all, and ten data
 * words in stock Alpine/Debian rootfs images (libstdc++, libapt-pkg, libicuuc,
 * sqv, libgo, libgphobos — every one of them in .gcc_except_table, whose
 * uleb128 call-site records produce the byte string `01 00 00 d4` at a rate
 * some 10^5 times chance) equal `svc #0` exactly. Rewriting one corrupts an
 * LSDA the C++ personality routine later reads; nothing on the path from the
 * store to the wrong landing pad reports anything.
 *
 * The section headers separate the two exactly — all 1837 real `svc` words in
 * that corpus are inside SHF_EXECINSTR sections and all ten data words are
 * outside — and they survive `strip` (not one of those objects was without
 * them). They are guest-controlled input, but they can only ever narrow what
 * the caller scans, so nonsense here costs rewriting and never correctness. */
int cng_code_ranges(int fd, struct cng_code_ranges *cr) {
    cr->n = 0;
    if (fd < 0)
        return 0;

    Elf64_Ehdr eh;
    if (!pread_all(fd, &eh, sizeof eh, 0))
        return 0;
    if (eh.e_ident[0] != ELF_MAG0 || eh.e_ident[1] != ELF_MAG1 ||
        eh.e_ident[2] != ELF_MAG2 || eh.e_ident[3] != ELF_MAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_machine != EM_AARCH64)
        return 0;
    if (!eh.e_shoff || !eh.e_shnum || eh.e_shnum > MAX_SHDR ||
        eh.e_shentsize != sizeof(Elf64_Shdr))
        return 0; /* incl. e_shnum == 0's extended numbering: not worth a case */

    Elf64_Shdr sh[SHDR_CHUNK];
    for (unsigned i = 0; i < eh.e_shnum; i += SHDR_CHUNK) {
        unsigned k = (unsigned)eh.e_shnum - i;
        if (k > SHDR_CHUNK)
            k = SHDR_CHUNK;
        if (!pread_all(fd, sh, (unsigned long)k * sizeof *sh,
                       eh.e_shoff + (unsigned long)i * sizeof *sh))
            goto give_up;
        for (unsigned j = 0; j < k; j++) {
            if (sh[j].sh_type == SHT_NOBITS || !sh[j].sh_size)
                continue;
            if ((sh[j].sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
                (SHF_ALLOC | SHF_EXECINSTR))
                continue;
            unsigned long lo = sh[j].sh_offset, hi = lo + sh[j].sh_size;
            if (hi < lo)
                goto give_up; /* a header that wraps describes nothing */
            /* .init/.plt/.text/.fini are laid out end to end, so the four
             * become one range and the table never fills on a real object. */
            if (cr->n && cr->hi[cr->n - 1] == lo) {
                cr->hi[cr->n - 1] = hi;
                continue;
            }
            if (cr->n == CNG_CODE_RANGES_MAX)
                goto give_up;
            cr->lo[cr->n] = lo;
            cr->hi[cr->n] = hi;
            cr->n++;
        }
    }
    return cr->n;

give_up:
    cr->n = 0;
    return 0;
}

/* Does this instruction write x8, the register a syscall number arrives in?
 * Deliberately broad — a false accept only means the filter did not fire —
 * covering the forms a syscall stub actually uses: `movz/movk x8, #nr`, `mov
 * x8, xN` (an orr), `add/sub x8, ...`, and a load into x8. */
static int writes_x8(uint32_t w) {
    if ((w & 0x1Fu) != 8u)
        return 0; /* Rd/Rt is not x8 */
    uint32_t g = w & 0x7F800000u;
    if (g == 0x52800000u || g == 0x72800000u)
        return 1; /* movz / movk, both widths */
    if (g == 0x11000000u || g == 0x51000000u)
        return 1; /* add / sub immediate */
    g = w & 0x7FC00000u;
    if (g == 0x0A000000u || g == 0x2A000000u || g == 0x4A000000u)
        return 1; /* and / orr / eor shifted register — `mov x8, xN` is an orr */
    g = w & 0x3B000000u;
    if (g == 0x39000000u || g == 0x18000000u)
        return 1; /* load/store unsigned offset, or a literal load */
    return 0;
}

/* Scan [lo,hi) for sites, never reading below `floor` for context. `verify`
 * asks for the syscall-context filter, which the caller sets when it has no
 * code map to trust. */
static int scan(unsigned long lo, unsigned long hi, unsigned long floor,
                int verify, unsigned long pool, unsigned long cap,
                unsigned long *used) {
    int count = 0;
    /* Round the start up, never down: with a code map, `lo` is a section's
     * start, and rounding down would read the word before it. */
    for (unsigned long a = (lo + 3) & ~3UL; a + 4 <= hi; a += 4) {
        if (*(uint32_t *)a != SVC0_INSN)
            continue;

        /* Never rewrite a signal-return site (`mov x8,#139; svc 0` — the
         * sa_restorer every handler returns through): rt_sigreturn must
         * execute with sp still at the kernel's signal frame, which a
         * trampoline call abandons — the kernel then restores a garbage
         * context (SIGSEGV on the first signal, e.g. a shell's SIGCHLD).
         * It carries no path anyway; leave it for the kernel. */
        if (a >= floor + 4) {
            uint32_t prev = *(uint32_t *)(a - 4);
            if ((prev & MOVZ_X8_MASK) == MOVZ_X8 &&
                ((prev >> 5) & 0xFFFFu) == NR_RT_SIGRETURN)
                continue;
        }

        /* No code map: the word is a syscall only if something nearby put a
         * number in x8. Costs the ~3% of real sites that load it from further
         * away (they keep the SIGSYS floor) and rejects data that collides
         * with the encoding, which is the trade this direction is worth. */
        if (verify) {
            int seen = 0;
            for (int k = 1; k <= X8_LOOKBACK; k++) {
                if (a < floor + 4UL * (unsigned long)k)
                    break;
                if (writes_x8(*(uint32_t *)(a - 4UL * (unsigned long)k))) {
                    seen = 1;
                    break;
                }
            }
            if (!seen)
                continue;
        }

        /* Reachability of the next slot from this site via a `b`. The way back
         * is checked inside emit(), against the same limit from a few dozen
         * bytes further along, so a site right at the edge of reach is left to
         * the SIGSYS floor rather than half-rewritten. */
        uint32_t br = b_insn(a, pool + *used);
        if (!br)
            continue; /* leave for the SIGSYS floor */
        if (*used + cng_tramp_size() > cap)
            break; /* pool exhausted: so is every site after this one */
        if (!emit(pool, cap, used, a + 4))
            continue; /* the way back is out of reach; the way out was not */

        *(uint32_t *)a = br;
        count++;
    }
    return count;
}

int cng_rewrite_seg(unsigned long lo, unsigned long hi, unsigned long foff,
                    const struct cng_code_ranges *cr, unsigned long pool,
                    unsigned long cap, unsigned long *used) {
    if (!cng_g_rewrite || hi <= lo)
        return 0;

    if (!cr || !cr->n)
        return scan(lo, hi, lo, /*verify=*/1, pool, cap, used);

    int count = 0;
    for (int i = 0; i < cr->n; i++) {
        /* The code map is in file offsets and the caller holds a mapping of
         * [foff, foff + (hi - lo)); clip each range to the part it has. */
        unsigned long clo = cr->lo[i], chi = cr->hi[i];
        if (clo < foff)
            clo = foff;
        if (chi > foff + (hi - lo))
            chi = foff + (hi - lo);
        if (chi <= clo)
            continue;
        /* `floor` stays at the mapping's own start: the word before a code
         * section is mapped and readable, and the sigreturn guard wants it. */
        count += scan(lo + (clo - foff), lo + (chi - foff), lo, /*verify=*/0,
                      pool, cap, used);
    }
    return count;
}
