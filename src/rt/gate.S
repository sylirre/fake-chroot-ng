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

/* The bounce (sigsys.c): a syscall the SIGSYS handler must not run itself —
 * a wait that installs a signal mask of its own for its duration — is run from
 * here instead, in the guest's own context, with the guest's own registers.
 * The handler rewrites the trap frame so that sigreturn resumes at
 * cng_bounce_wait with x0..x5 and x8 as the guest issued them (a mask pointer
 * redirected to a copy with SIGSYS taken out); the svc is inside the gate, so
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

    .global __cng_gate_end
    .hidden __cng_gate_end
__cng_gate_end:
    mov     x8, #160                /* __NR_uname */
    svc     #0
    .global cng_bounce_svc_end
cng_bounce_svc_end:
    brk     #0
    .size cng_bounce_wait, . - cng_bounce_wait
