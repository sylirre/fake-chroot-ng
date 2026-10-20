/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* The syscall gate: the ONLY `svc #0` in chroot-ng.
 *
 * long cng_syscall6(long a0,a1,a2,a3,a4,a5, long nr)
 *   AAPCS64: a0..a5 arrive in x0..x5, nr in x6, result returned in x0.
 *
 * The seccomp filter installed later (SIGSYS milestone) allows any syscall
 * whose instruction pointer lies in [__cng_gate_start, __cng_gate_end); that
 * is how the SIGSYS handler re-issues translated syscalls without trapping
 * itself.  Keep this region tiny and self-contained.
 *
 * The instruction pointer the filter sees is the one AFTER the svc, so a svc
 * is in the gate only if the instruction that follows it is too: __cng_gate_end
 * must never directly follow a svc that is meant to be allowed.
 */
    .section .text.gate,"ax",%progbits
    .balign 64
    .global __cng_gate_start
    .hidden __cng_gate_start
__cng_gate_start:

    .global cng_syscall6
    .type cng_syscall6, %function
cng_syscall6:
    mov     x8, x6
    svc     #0
    ret
    .size cng_syscall6, . - cng_syscall6

/* The kickable wait (ptrace.c, cng_pt_wait_native): an -R guest's blocking
 * wait4 or waitid, made as the guest issued it — unless a ptrace kick has been
 * taken since the caller read *kicks as `seen`.
 *
 * long cng_wait_unless(long a0, a1, a2, a3, a4, long nr,
 *                      const unsigned *kicks, unsigned seen)
 *   a0..a4 in x0..x4, nr in x5 (the svc's sixth argument, which neither call
 *   reads), kicks in x6, seen in w7.
 *
 * The compare covers a kick taken before it; one taken from the compare up to
 * and including the svc — where the value read is already stale, or a restart
 * of the svc is pending — has its handler resume here at the bail instead
 * (cng_pt_kick_taken); and one that interrupts the svc has its -EINTR replaced
 * the same way. The bail's -512 is CNG_WAIT_KICKED: ERESTARTSYS, which no wait
 * ever returns to user space. */
    .global cng_wait_unless
    .type cng_wait_unless, %function
cng_wait_unless:
    mov     x8, x5
    .global cng_wait_unless_check
cng_wait_unless_check:
    ldr     w9, [x6]
    cmp     w9, w7
    b.ne    cng_wait_unless_bail
    .global cng_wait_unless_svc
cng_wait_unless_svc:
    svc     #0
    ret
    .global cng_wait_unless_bail
cng_wait_unless_bail:
    mov     x0, #-512
    ret
    .size cng_wait_unless, . - cng_wait_unless

/* The bounce (sigsys.c): a syscall the SIGSYS handler must not run itself —
 * a wait that installs a signal mask of its own for its duration — is run from
 * here instead, in the guest's own context, with the guest's own registers.
 * The handler rewrites the trap frame so that sigreturn resumes at
 * cng_bounce_wait with x0..x5 and x8 as the guest issued them (a mask pointer
 * redirected to a copy with SIGSYS taken out); the svc is inside the gate, and
 * so is the mov after it, where the filter sees its instruction pointer, so
 * the filter allows it. The svc after __cng_gate_end is outside the gate and
 * traps: that is the completion, which the handler recognizes by its address
 * (cng_bounce_svc_end) and answers by putting the guest's registers back and
 * resuming it after its own svc with the wait's result. The number in x8 there
 * only has to be one every filter of ours traps; uname is. Nothing runs past
 * the completion, hence the brk. */
    .global cng_bounce_wait
    .type cng_bounce_wait, %function
cng_bounce_wait:
    svc     #0
    mov     x8, #160                /* __NR_uname */

    .global __cng_gate_end
    .hidden __cng_gate_end
__cng_gate_end:
    svc     #0
    .global cng_bounce_svc_end
cng_bounce_svc_end:
    brk     #0
    .size cng_bounce_wait, . - cng_bounce_wait
