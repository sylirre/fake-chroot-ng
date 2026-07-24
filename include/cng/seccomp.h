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

#endif /* CNG_SECCOMP_H */
