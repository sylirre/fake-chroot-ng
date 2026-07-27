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

#define SVC0_INSN    0xD4000001u /* `svc #0` */
#define B_OPCODE     0x14000000u /* unconditional branch */
#define BRANCH_REACH (1L << 27)  /* +-128 MiB */
#define MOVZ_X8_MASK 0xFFE0001Fu /* movz x8, #imm16 (hw=0) */
#define MOVZ_X8      0xD2800008u
#define NR_RT_SIGRETURN 139u

unsigned long cng_tramp_size(void) {
    return (unsigned long)(cng_svc_tramp_tpl_end - cng_svc_tramp_tpl);
}

/* Copy a trampoline into pool+*used, patch its two literals, advance *used. */
static char *emit(unsigned long pool, unsigned long cap, unsigned long *used,
                  unsigned long ret_site) {
    unsigned long tsz = cng_tramp_size();
    if (*used + tsz > cap)
        return 0;
    char *slot = (char *)(pool + *used);
    memcpy(slot, cng_svc_tramp_tpl, tsz);
    size_t disp_off = (size_t)(cng_svc_tramp_disp - cng_svc_tramp_tpl);
    size_t ret_off = (size_t)(cng_svc_tramp_ret - cng_svc_tramp_tpl);
    *(unsigned long *)(slot + disp_off) = (unsigned long)&cng_tramp_dispatch;
    *(unsigned long *)(slot + ret_off) = ret_site;
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

        /* Reachability of the next slot from this site via a `b`. */
        long delta = (long)(pool + *used) - (long)a;
        if (delta < -BRANCH_REACH || delta >= BRANCH_REACH)
            continue; /* leave for the SIGSYS floor */

        if (!emit(pool, cap, used, a + 4))
            break; /* pool exhausted */

        uint32_t br = B_OPCODE |
                      (uint32_t)(((unsigned long)delta >> 2) & 0x03FFFFFFu);
        *(uint32_t *)a = br;
        count++;
    }
    return count;
}
