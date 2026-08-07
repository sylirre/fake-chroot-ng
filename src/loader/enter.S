/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* cng_enter(unsigned long sp, unsigned long entry) -> never returns
 *
 * Emulate the kernel's execve register state: set the stack pointer to our
 * hand-built argc block and clear the general registers (the kernel zeroes them
 * at process start; glibc/musl _start read argc/argv from sp and expect x0 == 0
 * for the static case). Then branch to the guest entry point.
 */
    .text
    .global cng_enter
    .type cng_enter, %function
cng_enter:
    mov     x9, x1              /* stash entry (x9 is not one we clear) */
    mov     sp, x0
    mov     x0,  xzr
    mov     x1,  xzr
    mov     x2,  xzr
    mov     x3,  xzr
    mov     x4,  xzr
    mov     x5,  xzr
    mov     x6,  xzr
    mov     x7,  xzr
    mov     x8,  xzr
    mov     x10, xzr
    mov     x11, xzr
    mov     x12, xzr
    mov     x13, xzr
    mov     x14, xzr
    mov     x15, xzr
    mov     x16, xzr
    mov     x17, xzr
    mov     x18, xzr
    mov     x19, xzr
    mov     x20, xzr
    mov     x21, xzr
    mov     x22, xzr
    mov     x23, xzr
    mov     x24, xzr
    mov     x25, xzr
    mov     x26, xzr
    mov     x27, xzr
    mov     x28, xzr
    mov     x29, xzr
    mov     x30, xzr
    br      x9
    .size cng_enter, . - cng_enter
