/* Raw syscall layer for AArch64.
 *
 * Every syscall chroot-ng issues goes through the single out-of-line gate
 * cng_syscall6() (see src/rt/gate.S).  The gate is the ONLY place in the
 * program that contains an `svc #0` instruction.  This matters for the
 * seccomp/SIGSYS milestone: the BPF filter allows any syscall whose
 * instruction pointer falls inside [__cng_gate_start, __cng_gate_end) so the
 * SIGSYS handler can re-issue translated syscalls without re-trapping itself.
 */
#ifndef CNG_SYSCALL_H
#define CNG_SYSCALL_H

#include <asm/unistd.h>
#include <asm-generic/errno.h>
#include <stddef.h>
#include <stdint.h>

/* Defined in src/rt/gate.S. Arguments in AAPCS64 order: a0..a5 then nr. */
long cng_syscall6(long a0, long a1, long a2, long a3, long a4, long a5,
                  long nr);

/* Linker-provided bounds of the gate (see gate.S). */
extern char __cng_gate_start[];
extern char __cng_gate_end[];

#define CNG_SYS(nr, a, b, c, d, e, f)                                          \
    cng_syscall6((long)(a), (long)(b), (long)(c), (long)(d), (long)(e),        \
                 (long)(f), (nr))

/* Kernel returns -errno in [-4095, -1] on error. */
static inline int cng_is_err(long r) { return r < 0 && r >= -4095; }
static inline int cng_errno(long r) { return cng_is_err(r) ? (int)-r : 0; }

static inline long sys_read(int fd, void *b, size_t n) {
    return CNG_SYS(__NR_read, fd, b, n, 0, 0, 0);
}
static inline long sys_write(int fd, const void *b, size_t n) {
    return CNG_SYS(__NR_write, fd, b, n, 0, 0, 0);
}
static inline long sys_ioctl(int fd, unsigned long req, void *arg) {
    return CNG_SYS(__NR_ioctl, fd, req, arg, 0, 0, 0);
}
static inline long sys_openat(int dfd, const char *p, int fl, int mode) {
    return CNG_SYS(__NR_openat, dfd, p, fl, mode, 0, 0);
}
static inline long sys_close(int fd) {
    return CNG_SYS(__NR_close, fd, 0, 0, 0, 0, 0);
}
static inline long sys_lseek(int fd, long off, int whence) {
    return CNG_SYS(__NR_lseek, fd, off, whence, 0, 0, 0);
}
static inline long sys_pread64(int fd, void *b, size_t n, long off) {
    return CNG_SYS(__NR_pread64, fd, b, n, off, 0, 0);
}
static inline void *sys_mmap(void *a, size_t l, int prot, int fl, int fd,
                             long off) {
    return (void *)CNG_SYS(__NR_mmap, a, l, prot, fl, fd, off);
}
static inline long sys_mprotect(void *a, size_t l, int prot) {
    return CNG_SYS(__NR_mprotect, a, l, prot, 0, 0, 0);
}
static inline long sys_munmap(void *a, size_t l) {
    return CNG_SYS(__NR_munmap, a, l, 0, 0, 0, 0);
}
static inline long sys_getpid(void) {
    return CNG_SYS(__NR_getpid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_getcwd(char *buf, unsigned long size) {
    return CNG_SYS(__NR_getcwd, buf, size, 0, 0, 0, 0);
}
static inline long sys_chdir(const char *path) {
    return CNG_SYS(__NR_chdir, path, 0, 0, 0, 0, 0);
}
static inline long sys_gettid(void) {
    return CNG_SYS(__NR_gettid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_readlinkat(int dfd, const char *p, char *b, size_t n) {
    return CNG_SYS(__NR_readlinkat, dfd, p, b, n, 0, 0);
}
static inline long sys_statx(int dfd, const char *p, int fl, unsigned mask,
                             void *buf) {
    return CNG_SYS(__NR_statx, dfd, p, fl, mask, buf, 0);
}
static inline long sys_statfs(const char *p, void *buf) {
    return CNG_SYS(__NR_statfs, p, buf, 0, 0, 0, 0);
}
static inline long sys_uname(void *buf) {
    return CNG_SYS(__NR_uname, buf, 0, 0, 0, 0, 0);
}
static inline long sys_prctl(int op, unsigned long a, unsigned long b,
                             unsigned long c, unsigned long d) {
    return CNG_SYS(__NR_prctl, op, a, b, c, d, 0);
}
static inline long sys_seccomp(unsigned op, unsigned flags, void *args) {
    return CNG_SYS(__NR_seccomp, op, flags, args, 0, 0, 0);
}
static inline long sys_memfd_create(const char *name, unsigned flags) {
    return CNG_SYS(__NR_memfd_create, name, flags, 0, 0, 0, 0);
}
static inline long sys_fcntl(int fd, int op, long arg) {
    return CNG_SYS(__NR_fcntl, fd, op, arg, 0, 0, 0);
}
static inline long sys_fstat(int fd, void *buf) {
    return CNG_SYS(__NR_fstat, fd, buf, 0, 0, 0, 0);
}
static inline long sys_ftruncate(int fd, long len) {
    return CNG_SYS(__NR_ftruncate, fd, len, 0, 0, 0, 0);
}

/* Kernel 64-bit layout of struct sysinfo (uapi/linux/sysinfo.h). Only uptime,
 * loads and procs are consumed; the rest is here to size the buffer right. */
struct cng_sysinfo {
    long uptime;
    unsigned long loads[3];
    unsigned long totalram, freeram, sharedram, bufferram;
    unsigned long totalswap, freeswap;
    unsigned short procs, pad;
    unsigned long totalhigh, freehigh;
    unsigned mem_unit;
    char _f[20 - 2 * sizeof(unsigned long) - sizeof(unsigned)];
};
static inline long sys_sysinfo(struct cng_sysinfo *si) {
    return CNG_SYS(__NR_sysinfo, si, 0, 0, 0, 0, 0);
}

struct cng_timespec {
    long tv_sec, tv_nsec;
};
static inline long sys_clock_gettime(int clk, struct cng_timespec *ts) {
    return CNG_SYS(__NR_clock_gettime, clk, ts, 0, 0, 0, 0);
}

struct cng_rlimit {
    unsigned long cur, max;
};
static inline long sys_prlimit64(int pid, int res, const struct cng_rlimit *new_,
                                 struct cng_rlimit *old) {
    return CNG_SYS(__NR_prlimit64, pid, res, new_, old, 0, 0);
}
static inline long sys_getrandom(void *buf, unsigned long n, unsigned flags) {
    return CNG_SYS(__NR_getrandom, buf, n, flags, 0, 0, 0);
}
static inline long sys_getuid(void) {
    return CNG_SYS(__NR_getuid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_geteuid(void) {
    return CNG_SYS(__NR_geteuid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_getgid(void) {
    return CNG_SYS(__NR_getgid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_getegid(void) {
    return CNG_SYS(__NR_getegid, 0, 0, 0, 0, 0, 0);
}
static inline long sys_wait4(int pid, int *wstatus, int options, void *rusage) {
    return CNG_SYS(__NR_wait4, pid, wstatus, options, rusage, 0, 0);
}
/* fork() via raw clone: newsp=0 gives copy-on-write of the parent stack.
 * AArch64 clone order: (flags, newsp, ptid, ctid, tls). SIGCHLD = 17. */
static inline long sys_fork(void) {
    return CNG_SYS(__NR_clone, 17 /*SIGCHLD*/, 0, 0, 0, 0, 0);
}
static inline _Noreturn void sys_exit_group(int code) {
    CNG_SYS(__NR_exit_group, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

#endif /* CNG_SYSCALL_H */
