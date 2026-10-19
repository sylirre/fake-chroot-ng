/* Run a program under the filter an Android app runs under, as far as the uid
 * and gid setters go (M84): it traps setuid, setgid, setreuid, setregid,
 * setresgid, setfsuid, setfsgid and setgroups (bionic's
 * SECCOMP_BLOCKLIST_APP.TXT) and allows the rest, setresuid included. Started
 * outside chroot-ng, so the monitor finds the filter already in place, as it
 * does on a device, and has to measure it.
 *
 * Where no filter can be installed (qemu-user) it says SKIP instead. */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TRAP_IF(nr)                                                            \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1),                           \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        TRAP_IF(__NR_setuid),
        TRAP_IF(__NR_setgid),
        TRAP_IF(__NR_setreuid),
        TRAP_IF(__NR_setregid),
        TRAP_IF(__NR_setresgid),
        TRAP_IF(__NR_setfsuid),
        TRAP_IF(__NR_setfsgid),
        TRAP_IF(__NR_setgroups),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = {(unsigned short)(sizeof f / sizeof f[0]), f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p) != 0) {
        printf("SKIP: no seccomp filter can be installed here\n");
        return 0;
    }
    execv(argv[1], argv + 1);
    perror("execv");
    return 127;
}
