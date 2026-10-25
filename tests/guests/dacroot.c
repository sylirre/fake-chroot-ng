/* Root's DAC bypass, one line of outcome per case.
 *
 * Root creates and removes names in a directory whose mode forbids writing it,
 * opens a file for an access its mode refuses, and searches a directory with
 * no x bit. A fake root (-u) is the real uid underneath, so chroot-ng lends
 * the owner bits for the one call the host refused and puts them back. Run as
 * real root, this program prints what the kernel lets root do; under -u it
 * must print the same, mode for mode, which includes the modes being back
 * where they were once each call is done. Everything is made under the
 * directory named in argv[1], and only errnos and modes are printed, so the
 * two runs describe the same tree wherever it lives.
 *
 * usage: dacroot <dir>   (<dir> must exist and be writable)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

static char base[512];

static const char *at(const char *rel) {
    static char buf[4][1024];
    static int i;
    char *b = buf[i++ & 3];
    snprintf(b, sizeof buf[0], "%s/%s", base, rel);
    return b;
}

static void report(const char *tag, long r) {
    printf("%s=%d\n", tag, r < 0 ? errno : 0);
}
#define E(tag, call)                                                           \
    do {                                                                       \
        errno = 0;                                                             \
        long r_ = (long)(call);                                                \
        report(tag, r_);                                                       \
    } while (0)

/* An open, closed again at once: only whether it was let through counts. */
static long op(const char *rel, int flags, int mode) {
    int fd = open(at(rel), flags, mode);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

static void put(const char *rel, const char *s, int mode) {
    int fd = open(at(rel), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        if (write(fd, s, strlen(s)) < 0)
            perror("write");
        close(fd);
    }
    chmod(at(rel), mode);
}

/* What a file holds, as the next line of output: "<tag>=<bytes>" or the
 * errno the open or the read drew. */
static void show(const char *tag, const char *rel) {
    char b[64];
    int fd = open(at(rel), O_RDONLY);
    long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
    if (n < 0) {
        printf("%s=err%d\n", tag, errno);
    } else {
        b[n] = '\0';
        printf("%s=%s\n", tag, b);
    }
    if (fd >= 0)
        close(fd);
}

static unsigned mode_of(const char *rel) {
    struct stat st;
    return lstat(at(rel), &st) == 0 ? st.st_mode & 07777 : 07777;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    snprintf(base, sizeof base, "%s/dac", argv[1]);
    umask(022);
    if (mkdir(base, 0755) != 0) {
        perror("mkdir");
        return 1;
    }

    /* Names made and removed in a directory root may not write: tar's case.
     * It makes each directory with the owner bits it will end up with. */
    E("mkdir_ro", mkdir(at("ro"), 0500));
    E("create_in_ro", op("ro/f", O_CREAT | O_EXCL | O_WRONLY, 0600));
    E("mkdir_in_ro", mkdir(at("ro/sub"), 0700));
    E("mkdir2_in_ro", mkdir(at("ro/sub2"), 0700));
    E("mknod_in_ro", mknod(at("ro/p"), S_IFIFO | 0600, 0));
    E("symlink_in_ro", symlink("f", at("ro/l")));
    E("link_in_ro", link(at("ro/f"), at("ro/h")));
    E("rename_in_ro", rename(at("ro/f"), at("ro/g")));
    /* Moved to another parent, a directory has its ".." rewritten, which
     * takes write on the directory itself. */
    chmod(at("ro/sub"), 0500);
    E("rename_dir_out", rename(at("ro/sub"), at("sub")));
    E("rmdir_in_ro", rmdir(at("ro/sub2")));
    E("unlink_in_ro", unlink(at("ro/g")));
    E("unlink_link_in_ro", unlink(at("ro/h")));
    E("unlink_sym_in_ro", unlink(at("ro/l")));
    E("unlink_fifo_in_ro", unlink(at("ro/p")));
    {
        /* The unnamed file is made in the directory the name is. A
         * filesystem that cannot make one at all answers root the same, and
         * says nothing about the bypass. */
        int fd = open(at("ro"), O_TMPFILE | O_WRONLY, 0600);
        int e = fd < 0 ? errno : 0;
        if (fd >= 0)
            close(fd);
        if (e == EOPNOTSUPP || e == EISDIR)
            e = 0;
        printf("tmpfile_in_ro=%d\n", e);
    }
    /* Relative to a descriptor on the directory, as tar names its members. */
    {
        int d = open(at("ro"), O_PATH | O_DIRECTORY);
        errno = 0;
        int fd = openat(d, "m", O_CREAT | O_EXCL | O_WRONLY, 0600);
        printf("create_at_dirfd=%d\n", fd < 0 ? errno : 0);
        if (fd >= 0)
            close(fd);
        E("unlink_at_dirfd", unlinkat(d, "m", 0));
        close(d);
    }

    /* Files opened for what their mode refuses. */
    E("mkdir_rw", mkdir(at("rw"), 0700));
    put("rw/z", "zero", 0000);
    put("rw/w", "ro", 0400);
    put("rw/t", "trunc", 0444);
    put("rw/t2", "trunc2", 0444);
    show("read_0000", "rw/z");
    E("append_0400", op("rw/w", O_WRONLY | O_APPEND, 0));
    E("trunc_0444", op("rw/t", O_RDWR | O_TRUNC, 0));
    show("after_trunc", "rw/t");
    E("truncate_0444", truncate(at("rw/t2"), 2));
    show("after_truncate", "rw/t2");
    E("mkdir_nr", mkdir(at("nr"), 0700));
    put("nr/e", "e", 0600);
    chmod(at("nr"), 0300);
    E("readdir_0300", op("nr", O_RDONLY | O_DIRECTORY, 0));
    /* Not a permission question, and not one root gets past either. */
    E("write_a_dir", op("rw", O_WRONLY, 0));
    E("exec_no_x", execl(at("rw/w"), "w", (char *)0));

    /* Through a directory that may not be searched: a name in it, a symlink
     * in it (which only a walk that may search finds), and one more such
     * directory below it. */
    E("mkdir_nx", mkdir(at("nx"), 0700));
    put("nx/f", "nxf", 0600);
    E("symlink_nx", symlink("f", at("nx/lnk")));
    E("mkdir_deep", mkdir(at("nx/deep"), 0700));
    put("nx/deep/h", "deep", 0600);
    chmod(at("nx/deep"), 0600);
    chmod(at("nx"), 0600);
    {
        struct stat st;
        E("stat_through", stat(at("nx/f"), &st));
    }
    show("open_through", "nx/f");
    show("link_through", "nx/lnk");
    show("deep_through", "nx/deep/h");
    E("access_through", access(at("nx/f"), R_OK | W_OK));
    E("create_through", op("nx/new", O_CREAT | O_WRONLY, 0640));
    E("chmod_through", chmod(at("nx/f"), 0640));
    printf("mode_after_chmod=%o\n", mode_of("nx/f"));
    {
        int here = open(".", O_PATH | O_DIRECTORY);
        E("chdir_nx", chdir(at("nx")));
        /* ...and a name relative to it, which is searched from there. */
        char b[16];
        int fd = open("f", O_RDONLY);
        long n = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
        if (n < 0) {
            printf("read_in_nx=err%d\n", errno);
        } else {
            b[n] = '\0';
            printf("read_in_nx=%s\n", b);
        }
        if (fd >= 0)
            close(fd);
        if (here >= 0) {
            if (fchdir(here) != 0)
                perror("fchdir");
            close(here);
        }
    }

    /* Several processes lending the one directory at once: every name made,
     * and the mode back where it was once they are all done. */
    E("mkdir_race", mkdir(at("race"), 0500));
    for (int c = 0; c < 4; c++) {
        if (fork() == 0) {
            int bad = 0;
            for (int i = 0; i < 25; i++) {
                char n[64];
                snprintf(n, sizeof n, "race/c%d_%d", c, i);
                bad += op(n, O_CREAT | O_EXCL | O_WRONLY, 0600) != 0;
            }
            _exit(bad ? 1 : 0);
        }
    }
    int failed = 0;
    for (int c = 0; c < 4; c++) {
        int st;
        if (wait(&st) < 0 || !WIFEXITED(st) || WEXITSTATUS(st))
            failed++;
    }
    int made = 0;
    for (int c = 0; c < 4; c++)
        for (int i = 0; i < 25; i++) {
            char n[64];
            struct stat st;
            snprintf(n, sizeof n, "race/c%d_%d", c, i);
            made += lstat(at(n), &st) == 0;
        }
    printf("race failed=%d made=%d\n", failed, made);

    /* Every mode lent along the way given back. */
    printf("modes ro=%o sub=%o nr=%o nx=%o deep=%o race=%o z=%o w=%o\n",
           mode_of("ro"), mode_of("sub"), mode_of("nr"), mode_of("nx"),
           mode_of("nx/deep"), mode_of("race"), mode_of("rw/z"),
           mode_of("rw/w"));
    return 0;
}
