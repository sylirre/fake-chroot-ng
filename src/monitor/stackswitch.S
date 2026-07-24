/* long cng_run_on_stack(void *newsp, void *fn, void *a0, void *a1)
 *
 * Switch SP to `newsp`, call fn(a0, a1), then restore SP and return fn's
 * result. Used by the SIGSYS handler to run the (stack-hungry) path dispatcher
 * on a large dedicated stack instead of the interrupted thread's own stack —
 * Go goroutine stacks are only ~8 KiB and the dispatcher's PATH_MAX buffers
 * need far more, so without this the handler smashes the guest's stack.
 *
 * The signal ucontext lives on the original stack; we only pass its pointer
 * down, so switching the working stack under the dispatcher is safe. x9/x10 are
 * AAPCS temporaries; the callee saves x19..x29 and we save x30 on the new stack.
 */
    .section .text
    .balign 16
    .global cng_run_on_stack
    .type cng_run_on_stack, %function
cng_run_on_stack:
    mov     x9, x1              /* fn */
    mov     x10, sp             /* caller SP */
    mov     sp, x0              /* switch to the scratch stack */
    stp     x10, x30, [sp, #-16]!   /* stash caller SP + return address */
    mov     x0, x2              /* a0 */
    mov     x1, x3              /* a1 */
    blr     x9                  /* fn(a0, a1) -> x0 (kept as our result) */
    ldp     x10, x30, [sp], #16
    mov     sp, x10             /* restore caller SP */
    ret
    .size cng_run_on_stack, .-cng_run_on_stack

    .section .note.GNU-stack,"",%progbits
