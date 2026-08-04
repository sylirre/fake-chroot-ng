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
 * Output is protocol only, so the same source built for the host is the oracle.
 */
#define _GNU_SOURCE
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
    return 0;
}
