/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
#include "cng/rewrite.h"
#include "cng/elf.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

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

/* ---- lazy rewriting: the site the CPU just trapped from ------------------
 *
 * Everything above has to decide what is code before any of it runs, which is
 * why it needs the section headers and a filter behind them. A SIGSYS trap
 * needs neither: `si_call_addr - 4` is a word the CPU fetched and executed as
 * `svc #0`, so patching it cannot be wrong about what it is. What it cannot do
 * is find a site nothing has run yet, and where the filter never traps at all
 * (qemu-user, a pre-3.5 kernel) it finds nothing — so this runs alongside the
 * ahead-of-time pass rather than instead of it, and picks up exactly what that
 * pass could not reach: a library the kernel mapped natively (there is no copy
 * for the rewriter to walk), code a guest JIT wrote itself, and any site left
 * behind by an exhausted pool, a branch out of reach, or an object whose
 * headers named no code.
 *
 * Replacing `svc` with `b` is also the one edit that needs no stopping of the
 * world: both are in the set the architecture allows to be modified while
 * another PE is executing them (B, BL, BRK, HVC, ISB, NOP, SMC, SVC), so a
 * thread in that instruction sees the old word or the new one, and the old one
 * simply traps again. */

#define LAZY_REGIONS 32
#define LAZY_POOL    0x20000UL /* 128 KiB: ~800 trampolines per mapping */

struct lazy_region {
    unsigned long lo, hi;  /* the mapping, as /proc/self/maps had it */
    unsigned long pool;    /* 0: this mapping is not one we can patch */
    unsigned long used;
    int prot;              /* what the page goes back to after the store */
};

static struct lazy_region g_lazy[LAZY_REGIONS];
static int g_lazy_n;
static int g_lazy_nomaps; /* no /proc to read: stop asking */
/* Not a lock to wait on: a thread that finds the table busy leaves this site to
 * the floor, which is what would have answered it anyway. That also keeps a
 * nested trap (one of our own syscalls refused by Android, answered by the
 * gate-net) from ever meeting a table it is already inside. */
static volatile int g_lazy_busy;

unsigned long cng_pool_at(unsigned long want, unsigned long size) {
    if (!want || cng_hits_image(want, size))
        return 0;
    void *p = sys_mmap((void *)want, size, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS |
                           CNG_MAP_FIXED_NOREPLACE,
                       -1, 0);
    if (cng_is_err((long)p))
        return 0;
    if ((unsigned long)p != want) {
        sys_munmap(p, size); /* a kernel without the flag placed it elsewhere */
        return 0;
    }
    return want;
}

static unsigned long hex_at(char **p) {
    unsigned long v = 0;
    for (;; (*p)++) {
        char c = **p;
        int d = (c >= '0' && c <= '9')   ? c - '0'
                : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                                         : -1;
        if (d < 0)
            return v;
        v = v * 16 + (unsigned long)d;
    }
}

/* One read of /proc/self/maps answers two questions at once, which is why it is
 * one function: what the mapping holding `addr` is — bounds, protection, and
 * whether it is private, since a store into a shared file mapping would not
 * patch our copy but edit the file on disk — and where the nearest hole big
 * enough to hold a pool is. The hole matters as much as the mapping: a pool has
 * to be within a branch's reach of the sites that use it, and the addresses
 * around a loaded library are exactly the ones the linker has already taken.
 * Returns 0 if there is no line covering `addr` to find. */
static int lazy_vma(unsigned long addr, unsigned long *lo_out,
                    unsigned long *hi_out, int *prot_out, int *shared_out,
                    unsigned long *hole_out) {
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/maps",
                         CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0) {
        g_lazy_nomaps = 1;
        return 0;
    }
    /* Small on purpose: this can run on a guest thread's own stack. A line
     * split across two reads is carried over at the front of the next. */
    char buf[1024];
    long n, keep = 0;
    int found = 0;
    unsigned long prev_end = 0, best = 0, best_d = ~0UL;
    while ((n = sys_read((int)fd, buf + keep, sizeof buf - 1 - (size_t)keep)) >
           0) {
        n += keep;
        buf[n] = 0;
        char *p = buf, *nl;
        while ((nl = strchr(p, '\n'))) {
            *nl = 0;
            char *q = p;
            unsigned long lo = hex_at(&q); /* "lo-hi perms ..." */
            p = nl + 1;
            if (*q != '-')
                continue;
            q++;
            unsigned long hi = hex_at(&q);
            if (*q != ' ')
                continue;
            if (prev_end && lo - prev_end >= LAZY_POOL) {
                /* Distance from the hole to the site, both ways, kept as the
                 * unsigned magnitude so the nearest one wins. */
                unsigned long d = prev_end > addr ? prev_end - addr
                                                  : addr - prev_end;
                if (d < best_d) {
                    best_d = d;
                    best = prev_end;
                }
            }
            prev_end = hi;
            if (!found && addr >= lo && addr < hi) {
                *lo_out = lo;
                *hi_out = hi;
                *prot_out = (q[1] == 'r' ? CNG_PROT_READ : 0) |
                            (q[2] == 'w' ? CNG_PROT_WRITE : 0) |
                            (q[3] == 'x' ? CNG_PROT_EXEC : 0);
                *shared_out = (q[4] == 's');
                found = 1;
            }
        }
        keep = (long)strlen(p);
        if (keep >= (long)sizeof buf - 1)
            keep = 0; /* pathological line: drop it */
        else
            memmove(buf, p, (size_t)keep);
    }
    sys_close((int)fd);
    *hole_out = best;
    return found;
}

/* A pool the whole mapping can reach with a `b`: the hole the maps survey found
 * first, then immediately above the mapping and immediately below it (both
 * usually taken — a library's segments abut each other), then wherever the
 * kernel cares to put one. The pool is executable from the start: a trampoline
 * that is already live cannot be made unexecutable to write its neighbour, so
 * what happens per trampoline is the far smaller window of adding W to a page
 * that keeps X throughout. */
static unsigned long lazy_pool(unsigned long lo, unsigned long hi,
                               unsigned long hole) {
    unsigned long p = cng_pool_at(hole, LAZY_POOL);
    if (!p)
        p = cng_pool_at(hi, LAZY_POOL);
    if (!p && lo >= LAZY_POOL)
        p = cng_pool_at(lo - LAZY_POOL, LAZY_POOL);
    if (!p) {
        void *any = sys_mmap(0, LAZY_POOL, CNG_PROT_READ | CNG_PROT_WRITE,
                             CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
        if (!cng_is_err((long)any))
            p = (unsigned long)any;
    }
    if (!p)
        return 0;
    /* Every site in the mapping has to be able to branch into it — the two
     * extremes bound the rest — because a pool out of reach is worse than no
     * pool at all: the table would keep the mapping alive and every trap out of
     * it would go looking for a slot it can never use. Measured on the device
     * before this check existed, where the kernel's own choice of address
     * landed outside ±128 MiB: `ls -lR` took 3.9 s against 2.0 s, all of it
     * /proc/self/maps read once per trapped syscall.
     *
     * Where anonymous executable memory is denied outright (Android's execmem,
     * revoked by NO_NEW_PRIVS) there is no lazy tier to have at all; that is
     * found out here, once per mapping, rather than once per site. */
    if (!b_insn(lo, p + LAZY_POOL) || !b_insn(hi - 4, p) ||
        sys_mprotect((void *)p, LAZY_POOL, CNG_PROT_READ | CNG_PROT_EXEC) < 0) {
        sys_munmap((void *)p, LAZY_POOL);
        return 0;
    }
    return p;
}

/* The table entry for the mapping holding `site`, or nothing. An entry with no
 * pool is a mapping we know we cannot patch, kept precisely so the next trap
 * out of it costs nothing — not even the read of /proc/self/maps, which is the
 * whole reason the table exists. */
static struct lazy_region *lazy_known(unsigned long site) {
    for (int i = 0; i < g_lazy_n; i++)
        if (site >= g_lazy[i].lo && site < g_lazy[i].hi)
            return &g_lazy[i];
    return 0;
}

/* Remember a mapping the first time a site in it traps, with the pool its sites
 * will branch into — or with none, when the mapping is one we must not write,
 * which is remembered just as carefully so the next trap out of it is answered
 * from this table and costs nothing. */
static struct lazy_region *lazy_add(unsigned long lo, unsigned long hi, int prot,
                                    int usable, unsigned long hole) {
    if (g_lazy_n == LAZY_REGIONS)
        return 0;
    struct lazy_region *r = &g_lazy[g_lazy_n++];
    r->lo = lo;
    r->hi = hi;
    r->prot = prot;
    r->used = 0;
    r->pool = usable ? lazy_pool(lo, hi, hole) : 0;
    return r;
}

/* One trampoline, into a pool that stays executable while it is written. */
static char *lazy_emit(struct lazy_region *r, unsigned long site) {
    unsigned long tsz = cng_tramp_size();
    if (r->used + tsz > LAZY_POOL)
        return 0;
    unsigned long slot = r->pool + r->used;
    if (!b_insn(site, slot))
        return 0; /* out of a branch's reach: leave the site to the floor */
    unsigned long p0 = cng_page_down(slot), p1 = cng_page_up(slot + tsz);
    if (sys_mprotect((void *)p0, p1 - p0,
                     CNG_PROT_READ | CNG_PROT_WRITE | CNG_PROT_EXEC) < 0)
        return 0;
    unsigned long used = r->used;
    char *got = emit(r->pool, LAZY_POOL, &used, site + 4);
    if (got) {
        cng_flush_icache(got, got + tsz);
        r->used = used;
    }
    sys_mprotect((void *)p0, p1 - p0, CNG_PROT_READ | CNG_PROT_EXEC);
    return got;
}

int cng_rewrite_site(unsigned long site) {
    if (!cng_g_rewrite || (site & 3) || g_lazy_nomaps)
        return 0;
    int idle = 0;
    if (!__atomic_compare_exchange_n(&g_lazy_busy, &idle, 1, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;

    int done = 0;
    struct lazy_region *r = lazy_known(site);
    if (!r) {
        /* The first site to trap out of a mapping is the only one that pays for
         * reading /proc/self/maps. What that answers is whether the word may be
         * loaded at all — an execute-only mapping would fault on the load, in a
         * handler running with SIGSEGV masked — whether the store would land in
         * our copy or in a file on disk (a shared mapping is not ours to
         * write), and what to put the page back to afterwards.
         *
         * That last one is remembered rather than re-read, so a guest that
         * changes its own text protections after a site there is patched gets
         * back what the mapping had when we first saw it. The alternative costs
         * a read of /proc per trap, which is what this tier exists to avoid. */
        unsigned long lo, hi, hole;
        int prot, shared;
        if (!lazy_vma(site, &lo, &hi, &prot, &shared, &hole))
            goto out;
        int usable = !shared && (prot & (CNG_PROT_READ | CNG_PROT_EXEC)) ==
                                    (CNG_PROT_READ | CNG_PROT_EXEC);
        r = lazy_add(lo, hi, prot, usable, hole);
    }
    if (!r || !r->pool)
        goto out; /* known to be none of ours: answered without a syscall */

    /* Not a `svc` any more is the ordinary outcome of two threads trapping the
     * same site at once: the first patched it, and this one is finishing the
     * syscall it was already in the middle of. */
    if (*(uint32_t *)site != SVC0_INSN)
        goto out;

    char *slot = lazy_emit(r, site);
    uint32_t br = slot ? b_insn(site, (unsigned long)slot) : 0;
    if (!br)
        goto retire; /* the pool is full: this mapping has had its share */

    unsigned long p0 = cng_page_down(site), p1 = cng_page_up(site + 4);
    int add_w = !(r->prot & CNG_PROT_WRITE);
    if (add_w && sys_mprotect((void *)p0, p1 - p0, r->prot | CNG_PROT_WRITE) < 0)
        goto retire; /* the mapping cannot be written at all: stop asking */
    /* X is held throughout, so a thread executing this page while the store
     * lands neither faults nor has to be stopped — and `svc` to `b` is one of
     * the substitutions the architecture allows under exactly that condition. */
    *(uint32_t *)site = br;
    cng_flush_icache((void *)site, (void *)(site + 4));
    if (add_w)
        sys_mprotect((void *)p0, p1 - p0, r->prot);
    done = 1;
    goto out;

retire:
    /* Whatever stopped this site stops every other site in the mapping too, so
     * the pool goes back and the entry stays as the record that it did. */
    sys_munmap((void *)r->pool, LAZY_POOL);
    r->pool = 0;
out:
    __atomic_store_n(&g_lazy_busy, 0, __ATOMIC_RELEASE);
    if (done && cng_g_debug)
        cng_dprintf(2, "[cng] lazy: patched the svc site at %lx\n", site);
    return done;
}

void cng_rewrite_lazy_reset(void) {
    /* An emulated execve is the one place the mappings these describe go away,
     * and it happens single-threaded (a real execve kills the other threads and
     * ours cannot, so the loader refuses to run with any) — there is nothing
     * left running in a pool to take the lock against. Handing the address
     * space back is the point: an exec chain must not accumulate pools the way
     * M32 stopped it accumulating images. */
    for (int i = 0; i < g_lazy_n; i++)
        if (g_lazy[i].pool)
            sys_munmap((void *)g_lazy[i].pool, LAZY_POOL);
    g_lazy_n = 0;
}
