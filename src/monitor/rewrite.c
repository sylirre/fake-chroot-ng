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
    *(unsigned long *)(slot + disp_off) = (unsigned long)&cng_dispatch;
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
