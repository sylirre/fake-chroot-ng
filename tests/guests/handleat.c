/* name_to_handle_at's flag runs the other way round.
 *
 * Every other *at() call follows a final symlink unless told not to; this one
 * does NOT follow unless AT_SYMLINK_FOLLOW is given. Taken as a follower during
 * path translation, it encoded the target instead of the link — so a handle
 * meant to identify a symlink identified whatever it pointed at, and a dangling
 * link, which the kernel encodes happily because it never looks at the target,
 * came back ENOENT.
 *
 * argv[1] is a directory prefix so the host build can be pointed at a scratch
 * tree while the guest build uses its rootfs. Protocol only: the handle bytes
 * are filesystem-specific and are never printed, only whether the call
 * succeeded and what it refused with.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

struct fh {
    unsigned handle_bytes;
    int handle_type;
    unsigned char f_handle[128];
};

static void probe(const char *tag, const char *base, const char *name,
                  int flags) {
    char p[512];
    snprintf(p, sizeof p, "%s%s", base, name);
    struct fh h;
    h.handle_bytes = sizeof h.f_handle;
    int mid = 0;
    errno = 0;
    int r = name_to_handle_at(AT_FDCWD, p, (struct file_handle *)&h, &mid,
                              flags);
    printf("%s=%s\n", tag,
           r == 0                ? "ok"
           : errno == ENOENT     ? "ENOENT"
           : errno == ENOTSUP    ? "ENOTSUP"
           : errno == EOPNOTSUPP ? "ENOTSUP"
           : errno == EPERM      ? "EPERM"
                                 : "other");
}

int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "";
    probe("file", base, "/f", 0);
    /* The link itself, which is the default, and its target on request. */
    probe("link_default", base, "/l", 0);
    probe("link_follow", base, "/l", AT_SYMLINK_FOLLOW);
    /* The discriminating pair: a dangling link is encodable when the link is
     * what is being named, and ENOENT when the target is. */
    probe("dangling_default", base, "/dang", 0);
    probe("dangling_follow", base, "/dang", AT_SYMLINK_FOLLOW);
    return 0;
}
