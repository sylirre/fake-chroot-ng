/* Per-site syscall trampoline template + a self-test function (M8).
 *
 * A rewritten `svc #0` at site S becomes `b tramp`. `b` (not `bl`) preserves
 * x30, which is live across the ubiquitous libc `svc; ret` wrapper. The
 * trampoline saves the syscall-preserved registers (x0..x18 and x30 — x18 is
 * Android's shadow-call-stack register, x19..x29 are preserved by the AAPCS
 * callee cng_dispatch), marshals the trapped args, calls the dispatcher, writes
 * the result to x0, restores the rest, and branches back to S+4. The two 64-bit
 * literals (dispatcher address, return address) are patched per copy; the
 * PC-relative LDRs survive verbatim copying.
 */
    .text

    .global cng_svc_tramp_tpl
    .global cng_svc_tramp_tpl_end
    .global cng_svc_tramp_disp
    .global cng_svc_tramp_ret
    .balign 8
cng_svc_tramp_tpl:
    sub     sp, sp, #176
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x30, [sp, #144]
    /* cng_dispatch(nr=x8, a0=x0..a5=x5, trapped=0) — trampoline path, so an
     * unhandled syscall is re-issued rather than turned into ENOSYS. */
    mov     x6, x5
    mov     x5, x4
    mov     x4, x3
    mov     x3, x2
    mov     x2, x1
    mov     x1, x0
    mov     x0, x8
    mov     x7, xzr             /* trapped = 0 */
    ldr     x16, cng_svc_tramp_disp
    blr     x16
    str     x0, [sp, #160]          /* result */
    ldr     x1, [sp, #8]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldr     x18, [sp, #144]
    ldr     x30, [sp, #152]
    ldr     x0,  [sp, #160]         /* x0 = result */
    add     sp, sp, #176
    ldr     x16, cng_svc_tramp_ret
    br      x16
    .balign 8
cng_svc_tramp_disp:
    .quad   0                       /* patched: &cng_dispatch */
cng_svc_tramp_ret:
    .quad   0                       /* patched: return site S+4 */
cng_svc_tramp_tpl_end:
    .size cng_svc_tramp_tpl, . - cng_svc_tramp_tpl

/* Self-test function (M8 _rwtest): set sentinels in x1..x7, do a getpid via
 * `svc #0` (the site to rewrite), then verify the sentinels survived (the
 * kernel — and our trampoline — must preserve them). Returns the pid if all
 * preserved, else -1. Self-contained (local branches, no literals) so it can be
 * copied to an anonymous buffer and rewritten.
 */
    .global cng_rwtest_fn
    .global cng_rwtest_fn_end
    .balign 4
cng_rwtest_fn:
    mov     x1, #0x101
    mov     x2, #0x202
    mov     x3, #0x303
    mov     x4, #0x404
    mov     x5, #0x505
    mov     x6, #0x606
    mov     x7, #0x707
    mov     x8, #172                /* __NR_getpid */
    svc     #0                      /* <-- rewritten by the test */
    mov     x9, x0                  /* save pid */
    cmp     x1, #0x101
    b.ne    1f
    cmp     x2, #0x202
    b.ne    1f
    cmp     x3, #0x303
    b.ne    1f
    cmp     x4, #0x404
    b.ne    1f
    cmp     x5, #0x505
    b.ne    1f
    cmp     x6, #0x606
    b.ne    1f
    cmp     x7, #0x707
    b.ne    1f
    mov     x0, x9                  /* all preserved: return pid */
    ret
1:  mov     x0, #-1                 /* a sentinel was clobbered */
    ret
cng_rwtest_fn_end:
    .size cng_rwtest_fn, . - cng_rwtest_fn
