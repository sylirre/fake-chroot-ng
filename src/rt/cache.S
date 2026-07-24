/* cng_flush_icache(void *start, void *end)
 *
 * Make freshly-written code visible to the instruction stream on AArch64:
 * clean the D-cache to Point-of-Unification, then invalidate the I-cache,
 * using the line sizes reported by CTR_EL0.  Required before executing any
 * code we copy into anonymous RW->RX memory (execmem probe, ELF loader,
 * svc-rewriting).  Under qemu-user these ops are handled/harmless.
 */
    .text
    .global cng_flush_icache
    .type cng_flush_icache, %function
cng_flush_icache:
    mrs     x3, ctr_el0
    /* D-cache line size = 4 << CTR_EL0.DminLine[19:16] */
    ubfx    x4, x3, #16, #4
    mov     x2, #4
    lsl     x2, x2, x4
    sub     x4, x2, #1
    bic     x4, x0, x4              /* line-aligned start */
1:  dc      cvau, x4
    add     x4, x4, x2
    cmp     x4, x1
    b.lo    1b
    dsb     ish

    /* I-cache line size = 4 << CTR_EL0.IminLine[3:0] */
    and     x3, x3, #0xf
    mov     x2, #4
    lsl     x2, x2, x3
    sub     x4, x2, #1
    bic     x4, x0, x4
2:  ic      ivau, x4
    add     x4, x4, x2
    cmp     x4, x1
    b.lo    2b
    dsb     ish
    isb
    ret
    .size cng_flush_icache, . - cng_flush_icache
