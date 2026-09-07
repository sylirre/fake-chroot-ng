/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* M8: ahead-of-time rewriting of `svc #0` sites to per-site trampolines that
 * call the dispatcher directly — skipping the kernel seccomp+SIGSYS round trip.
 *
 * This is an optimization layer on top of the SIGSYS correctness floor: sites
 * we can't reach or don't find are left for the filter to trap. Because a
 * rewritten site needs no seccomp at all, this path also works where seccomp is
 * unavailable (very old kernels, qemu-user).
 *
 * The trampoline pool MUST sit within ±128 MiB of the code (a `b` reaches it),
 * so the caller (the loader) allocates it contiguously with the guest mapping
 * and passes it in — mmap hints are not reliably honored (notably under qemu).
 *
 * What may be scanned is decided by the object's own section headers, never by
 * the segment bounds: a `PF_X PT_LOAD` is not a code segment (see
 * cng_code_ranges), and a data word that happens to equal `svc #0` must not be
 * rewritten — nothing would report the corruption it causes.
 */
#ifndef CNG_REWRITE_H
#define CNG_REWRITE_H

/* Trampoline pool reserved per loaded object (bytes). ~3200 sites at ~160 B. */
#define CNG_TRAMP_POOL 0x80000

/* Executable ranges of one object, as file offsets. Four is what a real ELF
 * has (.init/.plt/.text/.fini, three after contiguous ones are merged); the
 * slack is for objects that scatter more .text.* sections than a linker
 * normally emits, and anything past it falls back (see cng_code_ranges). */
#define CNG_CODE_RANGES_MAX 16

struct cng_code_ranges {
    int n; /* 0: nothing usable — the caller's scan falls back to the filter */
    unsigned long lo[CNG_CODE_RANGES_MAX];
    unsigned long hi[CNG_CODE_RANGES_MAX];
};

/* Enable rewriting (set by `run -R`). */
extern int cng_g_rewrite;

/* Bytes one trampoline occupies (to size/advance a pool). */
unsigned long cng_tramp_size(void);

/* Collect the SHF_EXECINSTR ranges of the ELF on `fd` into *cr, as file
 * offsets, merging contiguous ones. Returns cr->n, which is 0 for anything
 * unreadable, malformed, or too fragmented to hold — every such answer means
 * "no code map", not "no code". */
int cng_code_ranges(int fd, struct cng_code_ranges *cr);

/* Rewrite `svc #0` sites in the executable, still-writable range [lo,hi) into
 * the caller's pool [pool, pool+cap); *used tracks consumption across calls.
 * `foff` is the file offset the byte at `lo` was read from, which is what ties
 * the mapping to `cr`, the object's code map: only the parts of [lo,hi) that
 * `cr` calls code are scanned. Where the map is empty (`cr` NULL or `cr->n`
 * 0 — a stripped-to-the-bone object) the whole range is scanned instead, and
 * every candidate must additionally pass the syscall-context filter.
 * Returns the number of sites rewritten. No-op unless cng_g_rewrite is set. */
int cng_rewrite_seg(unsigned long lo, unsigned long hi, unsigned long foff,
                    const struct cng_code_ranges *cr, unsigned long pool,
                    unsigned long cap, unsigned long *used);

/* Take `size` bytes at exactly `want`, or nothing. MAP_FIXED_NOREPLACE so an
 * occupied range is refused rather than replaced; on a kernel that predates the
 * flag it degrades to a hint, so the address is checked either way. */
unsigned long cng_pool_at(unsigned long want, unsigned long size);

/* Rewrite one site the SIGSYS floor just trapped from — `si_call_addr - 4`,
 * a word the CPU executed as `svc #0`, which is the one thing a scan of the
 * bytes cannot establish. Everything about it is best-effort: an unreadable
 * mapping, a shared one, no pool in reach, a denied mprotect all mean the site
 * keeps trapping, which is what it did before. Returns 1 if the site is now a
 * branch. No-op unless cng_g_rewrite is set. */
int cng_rewrite_site(unsigned long site);

/* Hand back the lazy pools. For the emulated execve, whose images (and the
 * sites in them) are gone. */
void cng_rewrite_lazy_reset(void);

#endif /* CNG_REWRITE_H */
