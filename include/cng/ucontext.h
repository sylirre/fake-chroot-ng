/* AArch64 signal-frame structures, matching the kernel UAPI so the SIGSYS
 * handler can read the trapped syscall's registers and write its return value.
 * Layout is part of the stable arch ABI; we mirror it rather than pull in libc.
 */
#ifndef CNG_UCONTEXT_H
#define CNG_UCONTEXT_H

typedef struct {
    unsigned long sig[1]; /* kernel sigset_t: 64 signals = 8 bytes */
} cng_sigset_t;

typedef struct {
    void *ss_sp;
    int ss_flags;
    unsigned long ss_size;
} cng_stack_t;

struct cng_sigcontext {
    unsigned long long fault_address;
    unsigned long long regs[31]; /* x0..x30 */
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
    /* fpsimd + extension records; aligned(16) fixes uc_mcontext's offset. */
    unsigned char __reserved[4096] __attribute__((aligned(16)));
};

struct cng_ucontext {
    unsigned long uc_flags;
    struct cng_ucontext *uc_link;
    cng_stack_t uc_stack;
    cng_sigset_t uc_sigmask;
    /* glibc reserves a 1024-bit sigset; the kernel skips this padding to reach
     * uc_mcontext. Match the reserved gap exactly. */
    unsigned char __glibc_reserved[1024 / 8 - sizeof(cng_sigset_t)];
    struct cng_sigcontext uc_mcontext;
};

typedef struct {
    int si_signo;
    int si_errno;
    int si_code;
    unsigned int __pad0;
    union {
        unsigned long _pad[14];
        struct {
            void *call_addr; /* svc site */
            int syscall;     /* trapped syscall number */
            unsigned int arch;
        } _sigsys;
    } _u;
} cng_siginfo_t;

/* Signal-handler prototype we use everywhere. */
typedef void (*cng_sighandler_t)(int, cng_siginfo_t *, void *);

#define CNG_SIGUSR1 10
#define CNG_SIGSYS  31

/* sa_flags */
#define CNG_SA_SIGINFO  0x00000004u
#define CNG_SA_RESTART  0x10000000u
#define CNG_SA_RESTORER 0x04000000u

#endif /* CNG_UCONTEXT_H */
