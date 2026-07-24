/* Process entry for the freestanding, statically-linked chroot-ng binary.
 *
 * On entry the kernel places the stack pointer at the base of the initial
 * process stack: [argc][argv...][NULL][envp...][NULL][auxv...].  We hand that
 * raw pointer to cng_bootstrap(), which never returns.
 */
    .text
    .global _start
    .type _start, %function
_start:
    mov     x29, xzr            /* mark bottom of frame chain */
    mov     x30, xzr
    mov     x0, sp              /* arg0 = pointer to argc */
    and     sp, x0, #~15        /* ensure 16-byte alignment */
    bl      cng_bootstrap
0:  b       0b                  /* unreachable: bootstrap exits */
    .size _start, . - _start
