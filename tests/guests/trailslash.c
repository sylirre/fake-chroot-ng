/* A trailing slash is a statement about the FILE, not about the name.
 *
 * "f/" does not name f. It says "f had better be a directory", and Linux
 * answers ENOTDIR when it is not — for every call that takes a path, whether it
 * reads, writes, creates or removes. It says it loudly enough to override the
 * caller: a final symlink is followed even under O_NOFOLLOW or
 * AT_SYMLINK_NOFOLLOW (so lstat("l2d/") describes the DIRECTORY the link points
 * at, and lstat("l2f/") is ENOTDIR), and an O_CREAT that would otherwise make a
 * file answers EISDIR instead. A trailing "/." says the identical thing.
 *
 * The emulation canonicalizes a guest path before mapping it into the rootfs,
 * and canonicalization drops trailing slashes — that is what makes a name a
 * name. So the statement was lost on the way to the kernel and every one of
 * these answered about f itself: `stat` described the file, `open` opened it,
 * and `unlink("f/")` deleted it.
 *
 * Everything here is inside the guest view and none of it depends on where the
 * rootfs lives, so the same source built for the host is the oracle. The tree
 * these expect is made by the harness: f (a regular file), d and d2
 * (directories), l2f -> f, l2d -> d, dang -> nowhere.
 *
 * The mutating probes are all supposed to fail, so they leave the tree as they
 * found it; the two that are supposed to succeed (rmdir d2, mkdir new) put it
 * back, since the oracle and the guest run against the same tree in turn.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *base = "";

/* One probe: its errno, or 0. The tag is the whole protocol. */
static void say(const char *tag, int r) {
    printf("%s=%d\n", tag, r < 0 ? errno : 0);
}

/* base + name, so the host build can be pointed at a scratch tree while the
 * guest build names the same paths inside its rootfs.
 *
 * A ring of buffers, because rename() and link() take two of these in one call
 * and C does not say which argument is evaluated first: one buffer made both
 * operands the same string, and the two builds disagreed about which — a
 * difference in the probe reported as a difference in the emulation. */
static const char *P(const char *name) {
    static char buf[4][512];
    static int i;
    char *b = buf[i++ & 3];
    snprintf(b, sizeof buf[0], "%s%s", base, name);
    return b;
}

int main(int argc, char **argv) {
    if (argc > 1)
        base = argv[1];
    struct stat st;
    char lb[64];

    /* Containment, and the one question the oracle cannot be asked: the same
     * tree on the host has no rootfs to be inside of.
     *
     * A trailing slash makes the kernel follow the final symlink whatever
     * O_NOFOLLOW said. If the walk leaves that link for the kernel, the kernel
     * follows it in the HOST namespace, and an absolute target then resolves
     * from the host root — out of the rootfs entirely. So the walk has to
     * follow it itself, where an absolute target is re-rooted. "labs" points at
     * "/d", which the guest must reach as <rootfs>/d, marker and all. */
    if (argc > 2 && !strcmp(argv[2], "contain")) {
        int fd = open("/labs/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        printf("contain=%s\n", fd < 0                            ? "openfail"
                               : fstatat(fd, "mark", &st, 0) == 0 ? "rootfs"
                                                                  : "escaped");
        if (fd >= 0)
            close(fd);
        return 0;
    }

    /* --- the plain question, asked of every kind of final component ------- */
    say("stat_file_slash", stat(P("/f/"), &st));
    say("stat_file", stat(P("/f"), &st)); /* control: no slash, no change */
    say("stat_dir_slash", stat(P("/d/"), &st));
    say("stat_dir_slashslash", stat(P("/d//"), &st));
    say("stat_missing_slash", stat(P("/nope/"), &st));
    say("stat_dang_slash", stat(P("/dang/"), &st));
    /* "/." is the same statement spelled differently. */
    say("stat_file_dot", stat(P("/f/."), &st));
    say("stat_dir_dot", stat(P("/d/."), &st));

    /* --- and it overrides "do not follow the last link" ------------------- */
    say("lstat_l2f_slash", lstat(P("/l2f/"), &st));
    say("lstat_l2d_slash", lstat(P("/l2d/"), &st));
    say("lstat_l2f", lstat(P("/l2f"), &st)); /* control */
    say("lstat_dang_slash", lstat(P("/dang/"), &st));
    /* ...and describes what the link points at, not the link. */
    printf("lstat_l2d_slash_isdir=%d\n",
           lstat(P("/l2d/"), &st) == 0 && S_ISDIR(st.st_mode));

    /* --- opens, including the one that would have created --------------- */
    say("open_file_slash", open(P("/f/"), O_RDONLY));
    say("open_dir_slash", open(P("/d/"), O_RDONLY | O_DIRECTORY));
    say("open_l2d_slash_nofollow", open(P("/l2d/"), O_RDONLY | O_NOFOLLOW));
    say("open_l2f_slash_nofollow", open(P("/l2f/"), O_RDONLY | O_NOFOLLOW));
    say("creat_new_slash", open(P("/new/"), O_WRONLY | O_CREAT, 0644));
    say("creat_file_slash", open(P("/f/"), O_WRONLY | O_CREAT, 0644));

    /* --- the mutating calls, which is where losing it did damage --------- */
    say("unlink_file_slash", unlink(P("/f/")));
    say("unlink_l2f_slash", unlink(P("/l2f/")));
    say("truncate_file_slash", truncate(P("/f/"), 0));
    say("chmod_file_slash", chmod(P("/f/"), 0644));
    say("access_file_slash", access(P("/f/"), R_OK));
    say("readlink_l2f_slash", (int)readlink(P("/l2f/"), lb, sizeof lb));
    say("rename_src_slash", rename(P("/f/"), P("/moved")));
    say("rename_dst_slash", rename(P("/f"), P("/moved/")));
    say("link_src_slash", link(P("/f/"), P("/lk")));
    say("link_dst_slash", link(P("/f"), P("/lk/")));
    say("symlink_dst_slash", symlink("f", P("/sl/")));
    say("mkdir_over_file_slash", mkdir(P("/f/"), 0755));
    say("rmdir_file_slash", rmdir(P("/f/")));

    /* ...and the two that must still work, put back afterwards. */
    say("rmdir_dir_slash", rmdir(P("/d2/")));
    say("mkdir_new_slash", mkdir(P("/new2/"), 0755));
    mkdir(P("/d2"), 0755);
    rmdir(P("/new2"));

    /* --- through a dirfd, where the name is relative --------------------- */
    int d = open(base[0] ? base : "/", O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        printf("dirfd=openfail\n");
        return 0;
    }
    printf("dirfd=ok\n");
    say("at_stat_file_slash", fstatat(d, "f/", &st, 0));
    say("at_lstat_l2f_slash", fstatat(d, "l2f/", &st, AT_SYMLINK_NOFOLLOW));
    say("at_lstat_l2d_slash", fstatat(d, "l2d/", &st, AT_SYMLINK_NOFOLLOW));
    say("at_open_file_slash", openat(d, "f/", O_RDONLY));
    say("at_open_dir_slash", openat(d, "d/", O_RDONLY | O_DIRECTORY));
    say("at_unlink_file_slash", unlinkat(d, "f/", 0));
    close(d);

    /* --- and the zones that exist only inside the emulation -------------- */
    say("dev_null_slash", stat("/dev/null/", &st));
    say("proc_cmdline_slash", stat("/proc/self/cmdline/", &st));
    say("proc_fd_slash", stat("/proc/self/fd/", &st));

    /* The tree is as it was: everything above either failed or was undone. */
    printf("intact=%d\n", stat(P("/f"), &st) == 0 && S_ISREG(st.st_mode) &&
                              stat(P("/d"), &st) == 0 && S_ISDIR(st.st_mode) &&
                              stat(P("/d2"), &st) == 0 &&
                              lstat(P("/l2f"), &st) == 0);
    return 0;
}
