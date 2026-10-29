/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Classic-BPF structures and helpers for seccomp filters.
 *
 * Used by the capability probe (M2) and the SIGSYS monitor (M5).  seccomp_data
 * is the buffer the kernel presents to the filter:
 *   offset 0  : u32 nr        (syscall number)
 *   offset 4  : u32 arch      (AUDIT_ARCH_*)
 *   offset 8  : u64 instruction_pointer
 *   offset 16 : u64 args[6]
 */
#ifndef CNG_SECCOMP_H
#define CNG_SECCOMP_H

#include <stdint.h>

struct sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct sock_fprog {
    uint16_t len;
    struct sock_filter *filter;
};

/* BPF opcode fragments we need. */
#define CNG_BPF_LD  0x00
#define CNG_BPF_W   0x00
#define CNG_BPF_ABS 0x20
#define CNG_BPF_JMP 0x05
#define CNG_BPF_JEQ 0x10
#define CNG_BPF_JGE 0x30
#define CNG_BPF_JGT 0x20
#define CNG_BPF_K   0x00
#define CNG_BPF_RET 0x06
#define CNG_BPF_ALU 0x04
#define CNG_BPF_AND 0x50

#define CNG_BPF_STMT(code, k)                                                  \
    { (uint16_t)(code), 0, 0, (uint32_t)(k) }
#define CNG_BPF_JUMP(code, k, jt, jf)                                          \
    { (uint16_t)(code), (uint8_t)(jt), (uint8_t)(jf), (uint32_t)(k) }

/* seccomp_data field offsets */
#define CNG_SD_NR   0
#define CNG_SD_ARCH 4
#define CNG_SD_IP   8
#define CNG_SD_ARGS 16

/* Run classic-BPF program `f` (n instructions) over a 64-byte seccomp_data
 * image, the subset our filters use (LD W ABS, JEQ/JGE/JGT K, ALU AND K, RET
 * K). Returns the action; *bad is set for anything outside that subset, or a
 * program that runs off its end, as the kernel would have refused it. */
uint32_t cng_bpf_run(const struct sock_filter *f, int n, const uint32_t *data,
                     int *bad);

/* Would the calling task's filters trap syscall `nr` with arguments `a`,
 * made from the svc whose next instruction is `ip`? Our base filter as it was
 * installed, the tracee's and the tracer's when `traceall`/`tracer` say they
 * are stacked on this task, and an ambient one by the syscalls it was measured
 * to refuse (cng_blocked). 0 before any filter of ours is installed. */
int cng_seccomp_traps(long nr, const uint64_t *a, unsigned long ip,
                      int traceall, int tracer);

#endif /* CNG_SECCOMP_H */
