/* Reaches the entries that exist only as path-resolution overlays — a /dev
 * whitelist node and a -b mount point — through a *dirfd* rather than by
 * absolute path.
 *
 * They have no directory entry behind them, so the kernel cannot find one
 * relative to a dirfd however plain the name looks: only the guest-side walk
 * can, and it has to be taken for such a name even though nothing about it
 * looks like it could redirect. `ls -l` asks exactly this (fstatat against the
 * fd it is listing), which is how an entry that `ls` had just shown came back
 * "No such file or directory".
 *
 * Each line is "<what>=ok" or "<what>=<errno-name>", so the harness asserts on
 * the answer rather than on this program's exit status.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void say(const char *what, int rc) {
    if (rc >= 0)
        printf("%s=ok\n", what);
    else
        printf("%s=%s\n", what, errno == ENOENT ? "ENOENT" : strerror(errno));
}

int main(int argc, char **argv) {
    const char *bind = argc > 1 ? argv[1] : "hostdir";
    struct stat st;

    int d = open("/dev", O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        printf("devdir=%s\n", strerror(errno));
    } else {
        printf("devdir=ok\n");
        int f = openat(d, "zero", O_RDONLY);
        say("dev-openat", f);
        if (f >= 0)
            close(f);
        say("dev-fstatat", fstatat(d, "urandom", &st, AT_SYMLINK_NOFOLLOW));
        say("dev-faccessat", faccessat(d, "null", R_OK, 0));
        close(d);
    }

    int r = open("/", O_RDONLY | O_DIRECTORY);
    if (r < 0) {
        printf("rootdir=%s\n", strerror(errno));
    } else {
        printf("rootdir=ok\n");
        say("bind-fstatat", fstatat(r, bind, &st, AT_SYMLINK_NOFOLLOW));
        int f = openat(r, bind, O_RDONLY | O_DIRECTORY);
        say("bind-openat", f);
        if (f >= 0)
            close(f);
        close(r);
    }

    fflush(stdout);
    return 0;
}
