/* openat2(2)'s open_how.resolve, one line of outcome per case.
 *
 * Built as a differential: the same program run with no emulation at all gets
 * the host kernel's own answers, and under chroot-ng it must print the same
 * ones. Everything is created relative to the directory named in argv[1], so
 * the two runs describe the same tree even though it lives at different
 * absolute paths; nothing is printed that could differ between them (no fds,
 * no paths) — only "ok" or the negative errno.
 *
 * usage: openat2 <dir>   (<dir> must exist and be writable)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif

#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_IN_ROOT       0x10
#endif

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

struct how {
    unsigned long long flags, mode, resolve;
};

/* An ambient filter that refuses the number (Android's) traps it rather than
 * failing it, and the run that is meant to ask the kernel would die of the
 * SIGSYS: the handler turns that into the ENOSYS a kernel without the call
 * gives, which is the same "nothing to compare against" here. */
static volatile sig_atomic_t trapped;

static void on_sigsys(int sig) {
    (void)sig;
    trapped = 1;
}

/* The raw syscall: every user builds the struct itself, which is the whole
 * reason the flag set is worth testing. */
static long o2(int dfd, const char *path, struct how *h, unsigned long size) {
    trapped = 0;
    long r = syscall(__NR_openat2, dfd, path, h, size);
    if (trapped)
        return -ENOSYS;
    return r < 0 ? -errno : r;
}

/* Run one case and print its outcome. A successful open is closed and reported
 * as "ok", so no descriptor number ever reaches the output. */
static void one_m(const char *name, int dfd, const char *path,
                  unsigned long long flags, unsigned long long mode,
                  unsigned long long resolve, unsigned long size) {
    struct how h = {flags, mode, resolve};
    long r = o2(dfd, path, &h, size ? size : sizeof h);
    if (r >= 0) {
        close((int)r);
        printf("%s=ok\n", name);
    } else {
        printf("%s=%ld\n", name, r);
    }
}

static void one(const char *name, int dfd, const char *path,
                unsigned long long flags, unsigned long long resolve,
                unsigned long size) {
    one_m(name, dfd, path, flags, 0, resolve, size);
}

static int mkfile(int dfd, const char *name) {
    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, "X", 1);
    close(fd);
    return n == 1 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: openat2 <dir>\n");
        return 2;
    }
    int d = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        fprintf(stderr, "openat2: open %s: %s\n", argv[1], strerror(errno));
        return 3;
    }
    signal(SIGSYS, on_sigsys);

    /* Is openat2 here at all? Every host below 5.6 (and qemu-user builds that
     * do not implement it) answers ENOSYS, an Android filter traps it, and
     * there is nothing to compare. Under chroot-ng every one of those is
     * emulated, so the run it is compared with always gets past here. */
    struct how probe = {O_RDONLY, 0, 0};
    if (o2(d, "..", &probe, sizeof probe) == -ENOSYS) {
        printf("openat2=unsupported\n");
        return 0;
    }
    close((int)o2(d, "..", &probe, sizeof probe));

    /* The tree. Names are deliberately dull; the interesting part is the shape:
     *   file, sub/file            ordinary
     *   link -> sub/file          a relative symlink
     *   abslink -> /ROOTNAME      an absolute one, whose target exists under
     *                             this directory and (by construction) not at
     *                             the real root — so RESOLVE_IN_ROOT's
     *                             re-rooting is visible as a success and its
     *                             absence as an ENOENT
     *   maglink -> /proc/self/fd/0   an ordinary link onto a magic one */
    const char *ROOTNAME = "cng-openat2-rooted";
    mkdirat(d, "sub", 0755);
    if (mkfile(d, "file") || mkfile(d, "sub/file") || mkfile(d, ROOTNAME)) {
        fprintf(stderr, "openat2: cannot populate %s\n", argv[1]);
        return 3;
    }
    unlinkat(d, "link", 0);
    unlinkat(d, "abslink", 0);
    unlinkat(d, "maglink", 0);
    char abs[256];
    snprintf(abs, sizeof abs, "/%s", ROOTNAME);
    if (symlinkat("sub/file", d, "link") || symlinkat(abs, d, "abslink") ||
        symlinkat("/proc/self/fd/0", d, "maglink")) {
        fprintf(stderr, "openat2: cannot create links in %s\n", argv[1]);
        return 3;
    }

    /* Unconstrained: the baseline every constrained case is judged against. */
    one("plain", d, "file", O_RDONLY, 0, 0);
    one("symlink", d, "link", O_RDONLY, 0, 0);

    /* NO_SYMLINKS refuses any link, and only a link. */
    one("nosym_link", d, "link", O_RDONLY, RESOLVE_NO_SYMLINKS, 0);
    one("nosym_plain", d, "sub/file", O_RDONLY, RESOLVE_NO_SYMLINKS, 0);
    one("nosym_magic", d, "maglink", O_RDONLY, RESOLVE_NO_SYMLINKS, 0);

    /* NO_MAGICLINKS refuses the /proc kind and leaves ordinary links alone. */
    one("nomagic_magic", d, "maglink", O_RDONLY, RESOLVE_NO_MAGICLINKS, 0);
    one("nomagic_link", d, "link", O_RDONLY, RESOLVE_NO_MAGICLINKS, 0);

    /* BENEATH: an absolute pathname, an escaping "..", and an absolute symlink
     * are each EXDEV; a name that stays under the directory opens. */
    one("beneath_abs", d, abs, O_RDONLY, RESOLVE_BENEATH, 0);
    one("beneath_dotdot", d, "../file", O_RDONLY, RESOLVE_BENEATH, 0);
    one("beneath_abslink", d, "abslink", O_RDONLY, RESOLVE_BENEATH, 0);
    one("beneath_ok", d, "sub/file", O_RDONLY, RESOLVE_BENEATH, 0);
    one("beneath_link", d, "link", O_RDONLY, RESOLVE_BENEATH, 0);

    /* IN_ROOT: the directory IS the root, so an absolute pathname and an
     * absolute symlink are both re-rooted onto it, and ".." at the top stays
     * there instead of climbing out. */
    one("inroot_abs", d, abs, O_RDONLY, RESOLVE_IN_ROOT, 0);
    one("inroot_abslink", d, "abslink", O_RDONLY, RESOLVE_IN_ROOT, 0);
    one("inroot_dotdot", d, "../../file", O_RDONLY, RESOLVE_IN_ROOT, 0);
    one("inroot_missing", d, "/nope", O_RDONLY, RESOLVE_IN_ROOT, 0);

    /* build_open_flags() runs before any resolution, so a how the kernel
     * refuses is EINVAL whatever the path would have said — including when a
     * constraint we answer ourselves would have fired first. */
    one("badbit", d, "link", O_RDONLY, RESOLVE_NO_SYMLINKS | 0x1000, 0);
    one("both_scopes", d, "file", O_RDONLY,
        RESOLVE_BENEATH | RESOLVE_IN_ROOT, 0);

    /* The size half of the ABI: below the struct is EINVAL, above it the tail
     * must be zero, and a zero tail makes the call identical to a sized one. */
    one("size_small", d, "file", O_RDONLY, RESOLVE_NO_SYMLINKS, 8);
    {
        struct {
            struct how h;
            unsigned long long tail;
        } big = {{O_RDONLY, 0, RESOLVE_NO_SYMLINKS}, 0};
        long r = o2(d, "file", (struct how *)&big, sizeof big);
        if (r >= 0) {
            close((int)r);
            printf("size_big_zero=ok\n");
        } else {
            printf("size_big_zero=%ld\n", r);
        }
        big.tail = 1;
        r = o2(d, "file", (struct how *)&big, sizeof big);
        if (r >= 0) {
            close((int)r);
            printf("size_big_tail=ok\n");
        } else {
            printf("size_big_tail=%ld\n", r);
        }
    }

    /* What openat2 refuses that openat strips or ignores: a mode where nothing
     * is created, a mode outside 07777, O_PATH with anything but its
     * companions, a flag bit no kernel defines; and O_TMPFILE's own rules,
     * which the two calls share. Where the host cannot issue openat2 these are
     * chroot-ng's to judge, with no kernel to ask. */
    one_m("mode_nocreat", d, "file", O_RDONLY, 0644, 0, 0);
    one_m("mode_toobig", d, "newf", O_WRONLY | O_CREAT, 010644, 0, 0);
    one("path_extra", d, "file", O_PATH | O_APPEND, 0, 0);
    one("flag_high", d, "file", O_RDONLY | (1ULL << 40), 0, 0);
    one("tmpfile_rdonly", d, ".", O_TMPFILE | O_RDONLY, 0, 0);
    one_m("tmpfile_creat", d, ".", O_TMPFILE | O_CREAT | O_RDWR, 0600, 0, 0);

    /* The scope's own errors, in path_init()'s order: an absolute name under
     * BENEATH is EXDEV before the descriptor is looked at; then a number that
     * is no descriptor is EBADF, and one on a file ENOTDIR. IN_ROOT takes the
     * absolute name as relative to the descriptor, so it gets the EBADF. */
    {
        int f = openat(d, "file", O_RDONLY);
        int bad = dup(d); /* a number that was a descriptor a moment ago */
        close(bad);
        one("scope_badfd", bad, "file", O_RDONLY, RESOLVE_BENEATH, 0);
        one("scope_badfd_abs", bad, "/file", O_RDONLY, RESOLVE_BENEATH, 0);
        one("scope_badfd_inroot", bad, "/file", O_RDONLY, RESOLVE_IN_ROOT, 0);
        one("scope_notdir", f, "x", O_RDONLY, RESOLVE_BENEATH, 0);
        if (f >= 0)
            close(f);
    }

    /* What tar (1.35 with the CVE-2025-45582 backport, through glibc 2.43's
     * openat2) does for every member: the parent directory, opened O_PATH
     * under BENEATH with a trailing slash; then files created and directories
     * reached through it. A symlink the archive planted on the way is refused
     * — absolute, or climbing out with "..". O_NOFOLLOW still refuses a final
     * link (ELOOP), and O_PATH|O_NOFOLLOW opens the link itself. */
    {
        unlinkat(d, "uplink", 0);
        unlinkat(d, "sub/new", 0);
        if (symlinkat("../escaped", d, "uplink")) {
            fprintf(stderr, "openat2: cannot create uplink\n");
            return 3;
        }
        const unsigned long long dirf =
            O_RDONLY | O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        one("tar_parent", d, "sub/", dirf, RESOLVE_BENEATH, 0);
        one("tar_parent_link", d, "abslink/", dirf, RESOLVE_BENEATH, 0);
        one("tar_parent_up", d, "uplink/", dirf, RESOLVE_BENEATH, 0);
        one_m("tar_create", d, "sub/new",
              O_WRONLY | O_CREAT | O_EXCL | O_NOCTTY | O_NONBLOCK | O_CLOEXEC,
              0600, RESOLVE_BENEATH, 0);
        one_m("tar_create_again", d, "sub/new", O_WRONLY | O_CREAT | O_EXCL,
              0600, RESOLVE_BENEATH, 0);
        one_m("tar_create_up", d, "uplink/new", O_WRONLY | O_CREAT, 0600,
              RESOLVE_BENEATH, 0);
        one("beneath_inside_dotdot", d, "sub/../file", O_RDONLY,
            RESOLVE_BENEATH, 0);
        one("beneath_nofollow", d, "link", O_RDONLY | O_NOFOLLOW,
            RESOLVE_BENEATH, 0);
        one("beneath_pathlink", d, "link", O_PATH | O_NOFOLLOW,
            RESOLVE_BENEATH, 0);
        one("beneath_missing", d, "sub/nope", O_RDONLY, RESOLVE_BENEATH, 0);
        one("beneath_notdir", d, "file/", O_RDONLY, RESOLVE_BENEATH, 0);
        unlinkat(d, "sub/new", 0);
        unlinkat(d, "uplink", 0);
    }

    close(d);
    return 0;
}
