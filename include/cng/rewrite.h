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
 */
#ifndef CNG_REWRITE_H
#define CNG_REWRITE_H

/* Trampoline pool reserved per loaded object (bytes). ~3200 sites at ~160 B. */
#define CNG_TRAMP_POOL 0x80000

/* Enable rewriting (set by `run -R`). */
extern int cng_g_rewrite;

/* Bytes one trampoline occupies (to size/advance a pool). */
unsigned long cng_tramp_size(void);

/* Rewrite `svc #0` sites in the executable, still-writable range [lo,hi) into
 * the caller's pool [pool, pool+cap); *used tracks consumption across calls.
 * Returns the number of sites rewritten. No-op unless cng_g_rewrite is set. */
int cng_rewrite_seg(unsigned long lo, unsigned long hi, unsigned long pool,
                    unsigned long cap, unsigned long *used);

#endif /* CNG_REWRITE_H */
