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
 * makes a tracer's edits take effect.
 *
 * pc is recorded as S+4 — where the kernel reports a syscall stop, the
 * instruction after the svc — and pstate carries NZCV only, which is what the
 * flags-dependent parts (single-step's condition evaluation) need.
 *
 * Two exits, because of x16/x17. The last instruction has to be `br xN`, which
 * spends a register on the target and leaves it wrong — and IP0/IP1 are the two
 * this uses, on the reasoning that they are any veneer's scratch. But a veneer
 * stands at a *call*, where the ABI gives them up; the guest wrote an `svc`,
 * across which the kernel preserves them, and gcc -O2 does hold live values
 * there (measured: `ldp x16, x15, [x4, 48]` before the syscall, `add x0, x0,
 * x16` after). So when the dispatcher left pc and sp alone — everything except
 * a tracer that moved them — the exit reproduces both without a register: `add
 * sp, sp, #288` and a `b` back to S+4, patched per copy like the literals. That
 * frees x16/x17 to be restored with the rest. The register exit below is kept
 * for the case where a tracer really did move pc or sp, where there is nowhere
 * else to hold them.
 *
 * The two 64-bit literals (dispatcher address, return address) and that `b` are
 * patched per copy; the PC-relative LDRs survive verbatim copying.
 */
    .text

    .global cng_svc_tramp_tpl
    .global cng_svc_tramp_tpl_end
    .global cng_svc_tramp_disp
    .global cng_svc_tramp_ret
    .global cng_svc_tramp_back
    .balign 8
cng_svc_tramp_tpl:
    sub     sp, sp, #288
    /* x16/x17 and the flags go in first, because the test below spends them and
     * every one of the three belongs to the guest.
     *
     * A thread's clone must not reach the dispatcher. The child returns from
     * that call with SP pointing at the stack the guest just allocated for it,
     * where none of these frames exist — it would restore its register file
     * from an empty stack. The seccomp tier never has this problem because the
     * filter lets a thread clone run untrapped (it tests exactly these two
     * flags); -R rewrites every site it can reach, so the same rule has to be
     * applied here, where the filter cannot. What is left — a clone making a
     * process, or a vfork-style one the dispatcher converts — is what the
     * filter does trap, and goes on below.
     *
     * Before the fix the dispatcher took it and stripped CLONE_VM, which with
     * CLONE_THREAD is what the kernel answers EINVAL to: pthread_create did not
     * work under -R at all. */
    stp     x16, x17, [sp, #128]
    mrs     x16, nzcv
    str     x16,      [sp, #264]
    cmp     w8, #220                /* __NR_clone (w8: the kernel reads it as an
                                     * int, and so does the filter) */
    b.ne    2f
    tst     x0, #0x100              /* CLONE_VM: a thread, or a vfork */
    b.eq    2f
    tst     x0, #0x4000             /* CLONE_VFORK: the dispatcher converts it */
    b.ne    2f
    ldr     x16,      [sp, #264]
    msr     nzcv, x16
    ldp     x16, x17, [sp, #128]
    add     sp, sp, #288
    svc     #0                      /* exactly what an unrewritten site does */
    b       cng_svc_tramp_back      /* patched: b S+4 — the child arrives here
                                     * with the kernel's SP and returns to the
                                     * guest without touching a frame of ours */
2:  stp     x0, x1,   [sp, #0]
    stp     x2, x3,   [sp, #16]
    stp     x4, x5,   [sp, #32]
    stp     x6, x7,   [sp, #48]
    stp     x8, x9,   [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
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
    mov     x0, sp                  /* cng_tramp_dispatch(&frame) */
    ldr     x16, cng_svc_tramp_disp
    blr     x16
    ldp     x0, x1,   [sp, #0]
    ldp     x2, x3,   [sp, #16]
    ldp     x4, x5,   [sp, #32]
    ldp     x6, x7,   [sp, #48]
    ldp     x8, x9,   [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    /* Did anything move pc or sp? Only a tracer's SETREGSET can have. The
     * comparison spends the flags, so NZCV is restored after it, in both arms. */
    ldr     x16,      [sp, #256]
    ldr     x17, cng_svc_tramp_ret
    cmp     x16, x17
    ldr     x16,      [sp, #248]
    add     x17, sp, #288
    ccmp    x16, x17, #0, eq
    b.ne    1f
    ldr     x16,      [sp, #264]
    msr     nzcv, x16
    ldp     x16, x17, [sp, #128]    /* the guest's own IP0/IP1, last of all */
    add     sp, sp, #288
cng_svc_tramp_back:
    brk     #0                      /* patched: b S+4 (loud if it ever is not) */
1:  ldr     x16,      [sp, #264]
    msr     nzcv, x16
    ldr     x17,      [sp, #248]    /* sp and pc last: both are ours to use */
    ldr     x16,      [sp, #256]
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
 * Buffer layout, 8 bytes each: d0, d1, d8, d16, d31, fpcr, x16, x17, then the
 * openat result.
 *
 * This is the one place in the monitor allowed to name an FP register, so it
 * has to re-enable them for itself. The build passes -mgeneral-regs-only, which
 * gcc treats as a codegen flag and never forwards to the assembler, but clang
 * (Termux/NDK, where cc *is* the assembler) turns into a target feature and
 * rejects `fmov`/`msr fpcr` outright. `.arch_extension fp` opens exactly this
 * function and `nofp` below shuts it again, so the ban still holds over the
 * trampoline template — where an accidental FP instruction would be a real bug,
 * since it runs on the guest's own register file.
 */
    .global cng_rwtest_fn
    .global cng_rwtest_fn_end
    .arch_extension fp
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
    movz    x16, #0xdead, lsl #16   /* IP0/IP1: the trampoline's own scratch, */
    movk    x16, #0x1616            /* but a compiler holds live values here */
    movz    x17, #0xbeef, lsl #16   /* across an svc all the same (measured) */
    movk    x17, #0x1717
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
    str     x16, [x10, #48]
    str     x17, [x10, #56]
    str     x13, [x10, #64]         /* the openat result, after the registers */
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
    .arch_extension nofp

/* Second self-test function: the trampoline's *general* exit, the one taken
 * when the dispatcher hands back a pc or sp the guest did not arrive with —
 * which on this tier means a tracer's PTRACE_SETREGSET at a syscall stop, and
 * nothing else. The harness forces it by pointing this copy's dispatcher
 * literal at a stand-in that moves pc on by 4, so the `mov x14, #0` below is
 * skipped exactly when the exit honoured the move.
 *
 * x16/x17 are deliberately not checked here: that exit needs two scratch
 * registers for sp and pc and has nowhere else to keep them, so it is the one
 * place they are still spent. x12 stands for everything else, which it owes.
 *
 * Buffer layout, 8 bytes each: pid, the marker, x12.
 */
    .global cng_rwtest_gen_fn
    .global cng_rwtest_gen_fn_end
    .balign 4
cng_rwtest_gen_fn:                  /* (void *results) */
    mov     x10, x0
    mov     x14, #0x9a9a            /* cleared iff the move was not honoured */
    mov     x12, #0x0c0c
    mov     x8, #172                /* __NR_getpid */
    svc     #0                      /* <-- rewritten by the test */
    mov     x14, #0                 /* skipped when pc moved past it */
    mov     x9, x0
    str     x9,  [x10, #0]
    str     x14, [x10, #8]
    str     x12, [x10, #16]
    ret
cng_rwtest_gen_fn_end:
    .size cng_rwtest_gen_fn, . - cng_rwtest_gen_fn
