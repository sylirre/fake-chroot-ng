/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Signal-return trampoline. The kernel resumes here when a handler returns; it
 * must invoke rt_sigreturn to restore the interrupted context. We supply our
 * own (via SA_RESTORER) so we don't depend on a vDSO. rt_sigreturn is not in
 * the trapped set, so the seccomp filter allows this svc.
 */
    .text
    .global cng_sigrestore
    .type cng_sigrestore, %function
cng_sigrestore:
    mov     x8, #139            /* __NR_rt_sigreturn */
    svc     #0
    .size cng_sigrestore, . - cng_sigrestore

/* The filter probe (sigsys.c, cng_sig_filter_stacked):
 *   long cng_probe_svc(long a0, long nr)
 * one call made outside the gate, where our filters see it as the guest's,
 * with x1..x4 zero. The handler recognizes a trap of this svc by the address
 * after it (cng_probe_ret) and answers it without dispatching anything. */
    .global cng_probe_svc
    .type cng_probe_svc, %function
cng_probe_svc:
    mov     x8, x1
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    svc     #0
    .global cng_probe_ret
cng_probe_ret:
    ret
    .size cng_probe_svc, . - cng_probe_svc
