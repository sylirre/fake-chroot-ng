/* Directory descriptors the guest has no name for, and the names resolved
 * against them.
 *
 * A dirfd is a place to resolve names from, and the kernel resolves them with
 * no rootfs in the way. Every descriptor the guest can hold must therefore be
 * on a directory inside its view — the rootfs, a bind, the /proc and /dev
 * zones — or the relative names it walks from there lead straight out:
 * "../etc/passwd" against a dirfd on /proc read the HOST's, and so did a name
 * through /proc/self/fd/<dirfd>/..., which the resolver handed to the kernel
 * with the trailing components untouched. The launcher's own descriptors are
 * how such a dirfd used to arrive: leaked across the exec that started
 * chroot-ng, and inherited by the guest as they were.
 *
 * The last section is the same view by pid rather than by path: a process
 * /proc hides is ESRCH to process_vm_readv and pidfd_open as well, while a
 * guest process (a forked child) is reachable by both.
 *
 * Run with fd 7 open on a host directory outside the rootfs and fd 8 on a host
 * file outside it, plus a rootfs holding /etc/marker (guest content), /sub
 * (a directory) with /sub/lnk -> /etc/marker, and a /dev directory. Each
 * line is "<what>=<answer>"; the harness asserts on the answers. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void content(const char *what, int fd) {
    char buf[64];
    if (fd < 0) {
        printf("%s=%s\n", what, strerror(errno));
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n < 0)
        n = 0;
    buf[n] = 0;
    for (char *c = buf; *c; c++)
        if (*c == '\n')
            *c = ' ';
    printf("%s=ok(%s)\n", what, buf);
    close(fd);
}

static void rc(const char *what, long r) {
    if (r >= 0)
        printf("%s=ok\n", what);
    else
        printf("%s=%s\n", what, strerror(errno));
}

/* Pass `fd` over a socketpair to ourselves and report on the copy we get. */
static void scm_self(const char *what, int fd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("%s=socketpair:%s\n", what, strerror(errno));
        return;
    }
    char data = 'x';
    struct iovec io = {&data, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof u);
    struct msghdr mh = {0};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    mh.msg_control = u.buf;
    mh.msg_controllen = sizeof u.buf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    if (sendmsg(sv[0], &mh, 0) < 0) {
        printf("%s=sendmsg:%s\n", what, strerror(errno));
        return;
    }
    memset(&u, 0, sizeof u);
    mh.msg_controllen = sizeof u.buf;
    if (recvmsg(sv[1], &mh, 0) < 0) {
        printf("%s=recvmsg:%s\n", what, strerror(errno));
        return;
    }
    int got = -1;
    c = CMSG_FIRSTHDR(&mh);
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
        memcpy(&got, CMSG_DATA(c), sizeof got);
    struct stat st;
    printf("%s=%s\n", what,
           got < 0 ? "no-fd" : fstat(got, &st) == 0 ? "usable" : strerror(errno));
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    char p[256];
    struct stat st;

    /* The launcher's leaks: the directory is gone, the file is still there
     * for the I/O it carries. And what stdin is: a directory there is
     * replaced by /dev/null rather than left closed. */
    rc("inherited-dirfd", fcntl(7, F_GETFD));
    content("inherited-file", dup(8));
    if (fstat(0, &st) == 0 && S_ISCHR(st.st_mode) && readlink("/proc/self/fd/0", p, sizeof p - 1) > 0 &&
        !strncmp(p, "/dev/null", 9))
        printf("stdin=/dev/null\n");
    else
        printf("stdin=%s\n", fstat(0, &st) == 0 ? "other" : strerror(errno));

    /* Relative names against the zones' directories. */
    int pr = open("/proc", O_RDONLY | O_DIRECTORY);
    content("proc-dotdot", openat(pr, "../etc/marker", O_RDONLY));
    int ps = open("/proc/self", O_RDONLY | O_DIRECTORY);
    content("procself-dotdot", openat(ps, "../../etc/marker", O_RDONLY));
    int pts = open("/dev/pts", O_RDONLY | O_DIRECTORY);
    content("devpts-dotdot", openat(pts, "../../etc/marker", O_RDONLY));

    /* Through a directory fd's magic link. */
    int sub = open("/sub", O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "/proc/self/fd/%d/../../../../../../../../etc/marker",
             sub);
    content("magic-dotdot", open(p, O_RDONLY));
    snprintf(p, sizeof p, "/proc/self/fd/%d/lnk", sub);
    content("magic-symlink", open(p, O_RDONLY));
    snprintf(p, sizeof p, "/dev/fd/%d/lnk", sub);
    content("devfd-symlink", open(p, O_RDONLY));
    /* ...and the plain reopen of a directory of the view still works. */
    snprintf(p, sizeof p, "/proc/self/fd/%d", sub);
    rc("magic-reopen-dir", open(p, O_RDONLY | O_DIRECTORY));

    /* fchdir into a zone: the cwd follows, and relative names resolve there. */
    rc("fchdir-proc", fchdir(pr));
    printf("getcwd=%s\n", getcwd(p, sizeof p) ? p : strerror(errno));
    rc("rel-self-status", open("self/status", O_RDONLY));
    rc("chdir-back", chdir("/"));

    /* A directory of the view survives a trip over a socket; so does a file. */
    scm_self("scm-view-dir", sub);
    int f = open("/etc/marker", O_RDONLY);
    scm_self("scm-view-file", f);
    (void)st;
    fflush(stdout);

    /* By pid. Pid 1 is the host's init, which the guest's /proc does not
     * show; the child is a guest process, and its parent may read it under
     * any ptrace policy (Yama's scope 1 allows descendants). The child parks
     * on a pipe so its memory is there to read. */
    int pp[2];
    if (pipe(pp) < 0)
        return 0;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        char c;
        close(pp[1]);
        if (read(pp[0], &c, 1) < 0)
            _exit(1);
        _exit(0);
    }
    close(pp[0]);
    char local[8], remote_probe = 0;
    struct iovec lio = {local, sizeof local};
    struct iovec rio = {&remote_probe, 1};
    rc("pvm-read-hidden", syscall(SYS_process_vm_readv, 1, &lio, 1, &rio, 1, 0));
    rc("pvm-read-guest",
       syscall(SYS_process_vm_readv, child, &lio, 1, &rio, 1, 0));
    rc("pidfd-open-hidden", syscall(SYS_pidfd_open, 1, 0));
    long pf = syscall(SYS_pidfd_open, child, 0);
    rc("pidfd-open-guest", pf);
    if (pf >= 0)
        close(pf);
    if (write(pp[1], "x", 1) < 0)
        kill(child, SIGKILL);
    close(pp[1]);
    waitpid(child, NULL, 0);
    fflush(stdout);
    return 0;
}
