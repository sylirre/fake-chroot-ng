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
