/* Per-site syscall trampoline template + a self-test function (M8).
 *
 * A rewritten `svc #0` at site S becomes `b tramp`. `b` (not `bl`) preserves
 * x30, which is live across the ubiquitous libc `svc; ret` wrapper. The
 * trampoline builds a full `struct cng_uregs` (x0..x30, sp, pc, pstate) on its
 * own stack, hands it to cng_tramp_dispatch, and then restores every register
 * from that frame — including sp and pc.
 *
 * It saves and restores far more than a syscall clobbers because the frame is
 * also the register file a ptrace tracer reads and writes at a syscall stop on
 * this tier (PTRACE_GETREGSET/SETREGSET); restoring pc and sp from it is what
 * makes a tracer's edits take effect. x16/x17 (IP0/IP1) are the exception:
 * they are this trampoline's own scratch, as they are any veneer's.
 *
 * pc is recorded as S+4 — where the kernel reports a syscall stop, the
 * instruction after the svc — and pstate carries NZCV only, which is what the
 * flags-dependent parts (single-step's condition evaluation) need.
 *
 * The two 64-bit literals (dispatcher address, return address) are patched per
 * copy; the PC-relative LDRs survive verbatim copying.
 */
    .text

    .global cng_svc_tramp_tpl
    .global cng_svc_tramp_tpl_end
    .global cng_svc_tramp_disp
    .global cng_svc_tramp_ret
    .balign 8
cng_svc_tramp_tpl:
    sub     sp, sp, #288
    stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]
    add     x16, sp, #288           /* sp as the guest had it at the site */
    str     x16,      [sp, #248]
    ldr     x16, cng_svc_tramp_ret  /* pc = S+4 */
    str     x16,      [sp, #256]
    mrs     x16, nzcv
    str     x16,      [sp, #264]
    mov     x0, sp                  /* cng_tramp_dispatch(&frame) */
    ldr     x16, cng_svc_tramp_disp
    blr     x16
    ldr     x16,      [sp, #264]
    msr     nzcv, x16
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    ldr     x17,      [sp, #248]    /* sp and pc last: both are ours to use */
    ldr     x16,      [sp, #256]
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    mov     sp, x17
    br      x16
    .balign 8
cng_svc_tramp_disp:
    .quad   0                       /* patched: &cng_tramp_dispatch */
cng_svc_tramp_ret:
    .quad   0                       /* patched: return site S+4 */
cng_svc_tramp_tpl_end:
    .size cng_svc_tramp_tpl, . - cng_svc_tramp_tpl

/* Self-test function (M8 _rwtest): set sentinels in x1..x7, the FP registers and
 * FPCR, run two `svc #0` sites, then check that they survived. A syscall
 * preserves every register but x0 — the kernel saves the lot into pt_regs and
 * never touches the FP state — so a rewritten site owes the guest exactly the
 * same.
 *
 * Two sites, because what the dispatcher does behind them differs: getpid is
 * answered almost immediately, while the openat runs the path translator and
 * whatever synthesis the path selects, which is where the C code that might
 * spend a register the guest still owns actually lives.
 *
 * x1..x7 are answered here (return -1); the rest are written to the caller's
 * buffer in x0 so the failure can be named. Returns the pid when the register
 * file is intact, else -1. Self-contained (local branches, no literals) so it
 * can be copied to an anonymous buffer and rewritten.
 *
 * Buffer layout, 8 bytes each: d0, d1, d8, d16, d31, fpcr, then the openat
 * result.
 */
    .global cng_rwtest_fn
    .global cng_rwtest_fn_end
    .balign 4
cng_rwtest_fn:                      /* (void *results, const char *path) */
    mov     x10, x0                 /* result buffer; x0 is about to be a fd */
    mov     x12, x1                 /* path, likewise for x1 */
    movz    x11, #0xfd00            /* an FP value live across a syscall is */
    fmov    d0, x11                 /* ordinary code: gcc -O2 keeps doubles in */
    movz    x11, #0xfd01            /* d0..d7 across an inline svc, since the */
    fmov    d1, x11                 /* asm clobbers only "memory" and "cc" */
    movz    x11, #0xfd08
    fmov    d8, x11
    movz    x11, #0xfd10
    fmov    d16, x11
    movz    x11, #0xfd1f
    fmov    d31, x11
    mov     x11, #0x400000          /* FPCR.RMode = 01 (toward +inf) */
    msr     fpcr, x11
    mov     x0, #-100               /* AT_FDCWD */
    mov     x1, x12
    mov     x2, #0                  /* O_RDONLY */
    mov     x8, #56                 /* __NR_openat */
    svc     #0                      /* <-- rewritten by the test */
    mov     x13, x0                 /* fd, or -errno */
    mov     x1, #0x101              /* the x1..x7 sentinels: after the openat, */
    mov     x2, #0x202              /* whose arguments live in x0..x2 */
    mov     x3, #0x303
    mov     x4, #0x404
    mov     x5, #0x505
    mov     x6, #0x606
    mov     x7, #0x707
    mov     x8, #172                /* __NR_getpid */
    svc     #0                      /* <-- rewritten by the test */
    mov     x9, x0                  /* save pid */
    fmov    x11, d0
    str     x11, [x10, #0]
    fmov    x11, d1
    str     x11, [x10, #8]
    fmov    x11, d8
    str     x11, [x10, #16]
    fmov    x11, d16
    str     x11, [x10, #24]
    fmov    x11, d31
    str     x11, [x10, #32]
    mrs     x11, fpcr
    str     x11, [x10, #40]
    str     x13, [x10, #48]
    msr     fpcr, xzr               /* leave the caller's rounding mode alone */
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
