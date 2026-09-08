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
 * Output is protocol only, so the same source built for the host is the oracle.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
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

int main(int argc, char **argv) {
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
    return 0;
}
