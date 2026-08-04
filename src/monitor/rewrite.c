#include "cng/rewrite.h"
#include "cng/monitor.h"
#include "cng/rt.h"

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

int cng_rewrite_seg(unsigned long lo, unsigned long hi, unsigned long pool,
                    unsigned long cap, unsigned long *used) {
    if (!cng_g_rewrite)
        return 0;

    int count = 0;
    for (unsigned long a = lo & ~3UL; a + 4 <= hi; a += 4) {
        if (*(uint32_t *)a != SVC0_INSN)
            continue;

        /* Never rewrite a signal-return site (`mov x8,#139; svc 0` — the
         * sa_restorer every handler returns through): rt_sigreturn must
         * execute with sp still at the kernel's signal frame, which a
         * trampoline call abandons — the kernel then restores a garbage
         * context (SIGSEGV on the first signal, e.g. a shell's SIGCHLD).
         * It carries no path anyway; leave it for the kernel. */
        if (a >= lo + 4) {
            uint32_t prev = *(uint32_t *)(a - 4);
            if ((prev & MOVZ_X8_MASK) == MOVZ_X8 &&
                ((prev >> 5) & 0xFFFFu) == NR_RT_SIGRETURN)
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
