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

struct how {
    unsigned long long flags, mode, resolve;
};

/* The raw syscall: glibc has no wrapper, which is the whole reason the flag set
 * is worth testing — every user builds the struct itself. */
static long o2(int dfd, const char *path, struct how *h, unsigned long size) {
    long r = syscall(__NR_openat2, dfd, path, h, size);
    return r < 0 ? -errno : r;
}

/* Run one case and print its outcome. A successful open is closed and reported
 * as "ok", so no descriptor number ever reaches the output. */
static void one(const char *name, int dfd, const char *path,
                unsigned long long flags, unsigned long long resolve,
                unsigned long size) {
    struct how h = {flags, 0, resolve};
    long r = o2(dfd, path, &h, size ? size : sizeof h);
    if (r >= 0) {
        close((int)r);
        printf("%s=ok\n", name);
    } else {
        printf("%s=%ld\n", name, r);
    }
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

    /* Is openat2 here at all? Every host below 5.6 (and qemu-user builds that
     * do not implement it) answers ENOSYS, and there is nothing to compare. */
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

    close(d);
    return 0;
}
