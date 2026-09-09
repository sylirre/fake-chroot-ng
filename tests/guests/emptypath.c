/* AT_EMPTY_PATH: the descriptor is the file, and there is no name to resolve.
 *
 * `openat(..., O_PATH|O_NOFOLLOW)` followed by `*at(fd, "", ..., AT_EMPTY_PATH)`
 * is the race-free way to ask about a symlink itself — systemd and util-linux
 * use it everywhere — and it must describe the LINK, not what the link points
 * at. Under the emulation the empty name was walked like any other relative
 * one: the probe that decides whether a name needs the guest-side walk ends in
 * a readlinkat, which for an empty name reports on the dirfd, so a symlink fd
 * answered "this is a link, walk it". The walk then joined the empty name onto
 * the fd's own guest path and resolved it dereferencing the final component,
 * and the reissued call named the target with the dirfd ignored altogether.
 *
 * Three consequences, all printed here: stat described the target; a dangling
 * link — which the kernel stats happily, since it never looks at the target —
 * came back ENOENT; and fchownat would have changed the target's group and left
 * the link alone (asserted through the stat, since the test user may own only
 * its own files).
 *
 * linkat is the other half of the flag, and the half that WRITES: the source is
 * named by descriptor alone, which is how an O_TMPFILE file is published under
 * a name. The number it is given has to BE a descriptor before it can be
 * treated as one — see the link_* lines below.
 *
 * execveat takes the same flag and asks the same question of the number, with
 * one answer of its own: AT_FDCWD is not a descriptor there either, and the
 * kernel opens the working directory for execution rather than refusing the
 * number — which is EACCES, not EBADF. See the exec_* lines.
 *
 * And the descriptor it is given may be an O_PATH one, which is the documented
 * shape of fexecve: it refers to the file without opening it, so it needs no
 * read permission and has no readable side at all. The kernel runs it by
 * opening what it names with its own exec flags. An emulation that loads the
 * image by reading the descriptor cannot — pread and mmap answer EBADF on an
 * O_PATH fd — and has to reopen the file by name instead, which is a different
 * act in exactly one place: a descriptor may hold a SYMLINK, where opening for
 * execution is ELOOP and reopening by name follows it. See the exec_opath*
 * lines.
 *
 * Output is protocol only, so the same source built for the host is the oracle.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* argv[1] is a directory prefix, so the host build can be pointed at a scratch
 * tree while the guest build uses the rootfs it is given. */
static const char *base = "";

static void probe(const char *tag, const char *name) {
    char p[512];
    snprintf(p, sizeof p, "%s%s", base, name);
    int fd = openat(AT_FDCWD, p, O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        printf("%s=openfail\n", tag);
        return;
    }
    struct stat st;
    int r = fstatat(fd, "", &st, AT_EMPTY_PATH);
    printf("%s=%s\n", tag,
           r < 0             ? "error"
           : S_ISLNK(st.st_mode) ? "link"
           : S_ISREG(st.st_mode) ? "regular"
                                 : "other");
    close(fd);
}

/* The errno of one linkat, or 0 — the whole answer, since a hardlink either
 * happens or does not. The destination is removed on both sides of the call, so
 * one run cannot answer EEXIST for the previous one's leftovers. */
static void linkprobe(const char *tag, int fd, const char *name) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, name);
    unlink(p);
    errno = 0;
    int r = linkat(fd, "", AT_FDCWD, p, AT_EMPTY_PATH);
    printf("%s=%d\n", tag, r < 0 ? errno : 0);
    unlink(p);
}

/* The errno of one execveat that cannot succeed. argv and envp are real, so
 * nothing here depends on how a null vector is counted: the kernel opens the
 * file before it counts them, and every case below fails at the open. */
static void execprobe(const char *tag, int fd, int flags) {
    char *av[] = {(char *)"x", 0};
    char *ev[] = {0};
    errno = 0;
    long r = syscall(SYS_execveat, fd, "", av, ev, flags);
    printf("%s=%d\n", tag, r < 0 ? errno : 0);
}

int main(int argc, char **argv) {
    /* The image the last probe below re-executes through an O_PATH descriptor.
     * It prints one line and leaves, so the exec is observable as output rather
     * than as an exit status. */
    if (argc > 2 && !strcmp(argv[2], "child")) {
        printf("exec_opath=ok\n");
        return 0;
    }
    if (argc > 1)
        base = argv[1];
    probe("symlink_fd", "/l");   /* -> f, a regular file */
    probe("dangling_fd", "/dang"); /* -> nowhere */
    probe("regular_fd", "/f");
    /* A non-empty name against the same fd is an ordinary relative lookup and
     * must keep working: this is the control that the change above did not
     * simply stop translating dirfd-relative names. */
    int d = openat(AT_FDCWD, base[0] ? base : "/", O_RDONLY | O_DIRECTORY);
    if (d >= 0) {
        struct stat st;
        int r = fstatat(d, "l", &st, AT_SYMLINK_NOFOLLOW);
        printf("named_lookup=%s\n",
               r < 0 ? "error" : S_ISLNK(st.st_mode) ? "link" : "other");
        close(d);
    } else {
        printf("named_lookup=openfail\n");
    }

    /* linkat(AT_EMPTY_PATH). The working directory is moved to the base first
     * so that both builds link within one filesystem: on the host the source
     * and the destination would otherwise straddle a mount point and answer
     * EXDEV before any of what is under test is reached.
     *
     *  - a real descriptor IS the file, and the link is made;
     *  - AT_FDCWD is not a descriptor. The kernel resolves the empty name
     *    against the working directory and answers about that directory, which
     *    is EPERM: there is no hardlink to a directory. Spelling it as one
     *    ("/proc/self/fd/" and the digits of -100, sign dropped) named fd 0 —
     *    so the guest's own stdin was linked into the filesystem instead;
     *  - every other negative number, and every number that is not open, is
     *    EBADF, where a /proc/self/fd name that happens not to exist is
     *    ENOENT. */
    char src[512];
    snprintf(src, sizeof src, "%s/f", base);
    if (chdir(base[0] ? base : "/") != 0) {
        printf("link_chdir=failed\n");
        return 0;
    }
    int lf = open(src, O_RDONLY);
    if (lf < 0) {
        printf("link_open=failed\n");
        return 0;
    }
    linkprobe("link_byfd", lf, "lk_ok");
    linkprobe("link_cwd", AT_FDCWD, "lk_cwd");
    linkprobe("link_negfd", -5, "lk_neg");
    close(lf);
    linkprobe("link_closedfd", lf, "lk_closed");

    /* execveat(AT_EMPTY_PATH), which reads the number the same way and then
     * has to open what it names for execution. None of these can succeed, so
     * the process is still here to print the next line:
     *
     *  - AT_FDCWD names the working directory, and a directory is EACCES to
     *    open for execution (may_open's MAY_EXEC arm) — where treating the
     *    number as a descriptor and asking about it answered EBADF;
     *  - a real directory descriptor is the same refusal by another route;
     *  - a regular file that is merely not executable is EACCES too, which is
     *    what tells that answer apart from "there is no such descriptor";
     *  - a negative number and a closed one are EBADF;
     *  - and without the flag an empty name is ENOENT, whatever the fd is. */
    int df = open(base[0] ? base : "/", O_RDONLY | O_DIRECTORY);
    int rf = open(src, O_RDONLY); /* mode 0644: readable, not executable */
    execprobe("exec_cwd", AT_FDCWD, AT_EMPTY_PATH);
    execprobe("exec_dirfd", df, AT_EMPTY_PATH);
    execprobe("exec_regular", rf, AT_EMPTY_PATH);
    execprobe("exec_negfd", -5, AT_EMPTY_PATH);
    execprobe("exec_noflag", rf, 0);
    close(df);
    close(rf);
    execprobe("exec_closedfd", rf, AT_EMPTY_PATH);

    /* An O_PATH descriptor refers to a file without opening it, which is
     * exactly what a caller holding one to execute later wants — it is the
     * documented shape of fexecve, and needs no read permission. The kernel
     * executes it: with AT_EMPTY_PATH it opens the file the descriptor names
     * with its own exec flags. An emulation that reads the image out of the
     * descriptor cannot, since pread and mmap answer EBADF on one, so what it
     * must do instead is reopen the file by name.
     *
     * The refusals come first, because they leave the process here to print:
     *  - a regular file that is not executable is EACCES, the same answer its
     *    readable descriptor gets, so this says the reopen did not quietly
     *    become the permission check;
     *  - a directory is EACCES;
     *  - a SYMLINK is the one thing only an O_PATH|O_NOFOLLOW descriptor can
     *    hold, and opening it for execution is ELOOP — where the same file
     *    named as "/proc/self/fd/N" would have followed the link and run its
     *    target. */
    int of = openat(AT_FDCWD, src, O_PATH);
    execprobe("exec_opath_regular", of, AT_EMPTY_PATH);
    close(of);
    char lp[512];
    snprintf(lp, sizeof lp, "%s/l", base);
    of = openat(AT_FDCWD, lp, O_PATH | O_NOFOLLOW);
    execprobe("exec_opath_link", of, AT_EMPTY_PATH);
    close(of);
    of = openat(AT_FDCWD, base[0] ? base : "/", O_PATH);
    execprobe("exec_opath_dir", of, AT_EMPTY_PATH);
    close(of);

    /* ...and the one that succeeds, last, since it replaces this program: our
     * own image through an O_PATH descriptor. The line comes from the new
     * image on success and from here on failure, so either way there is
     * exactly one — and the buffer is flushed first, because a successful
     * exec drops everything not yet written. */
    of = openat(AT_FDCWD, argv[0], O_PATH);
    if (of < 0) {
        printf("exec_opath=openfail\n");
        return 0;
    }
    char *av[] = {(char *)"x", (char *)base, (char *)"child", 0};
    char *ev[] = {0};
    fflush(stdout);
    errno = 0;
    syscall(SYS_execveat, of, "", av, ev, AT_EMPTY_PATH);
    printf("exec_opath=%d\n", errno);
    return 0;
}
