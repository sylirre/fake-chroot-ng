/* What stat and access say about the /proc files chroot-ng synthesizes.
 *
 * Android's SELinux policy refuses an app the getattr and the read access check
 * of /proc/version, loadavg, uptime and stat, so the monitor serves their
 * content from memory — and `cat /proc/version` worked while `stat
 * /proc/version` and `test -r /proc/version` failed with EACCES on the very same
 * name. Every way of asking is put to each file here, and what comes back has
 * to be what any /proc regular file is (0444, one link, no size, root's; the
 * sysctls under sys/kernel are 0644), the same from every form, with one inode number the path, the descriptor and the
 * O_PATH descriptor all agree on:
 *
 *   stat, lstat, statx, fstatat against a /proc dirfd, fstat of an O_PATH fd,
 *   fstat of the file opened for reading, access(R_OK), access(X_OK).
 *
 * Prints one line per file, "<name>: ok" or the first thing that was wrong.
 * It asserts nothing about the host: the same output is right where the host
 * answers every one of these itself and where it refuses them all. A host
 * with no statx at all (a kernel before 4.11, or a filter that predates it) is
 * the exception, since nothing can answer what nobody can ask: the statx
 * forms are left out there, and a last line says so.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

/* The statx buffer is 256 bytes; these are the offsets of what is read. */
struct sx {
    unsigned char b[256];
};
static unsigned sx_u32(const struct sx *s, int o) {
    unsigned v;
    memcpy(&v, s->b + o, sizeof v);
    return v;
}
static unsigned long long sx_u64(const struct sx *s, int o) {
    unsigned long long v;
    memcpy(&v, s->b + o, sizeof v);
    return v;
}

static char why[160];

/* statx answered ENOSYS: there is none to ask on this host. */
static int no_statx;

/* statx, or 1 with no_statx set where there is none. */
static int statx_of(int dfd, const char *name, int flags, struct sx *sx) {
    memset(sx, 0, sizeof *sx);
    if (no_statx)
        return 1;
    if (syscall(__NR_statx, dfd, name, flags, 0x7ffu /* STATX_BASIC_STATS */,
                sx->b) == 0)
        return 0;
    if (errno != ENOSYS)
        return -1;
    no_statx = 1;
    return 1;
}

static int bad(const char *what, const char *fmt, long a, long b) {
    int n = snprintf(why, sizeof why, "%s: ", what);
    snprintf(why + n, sizeof why - (size_t)n, fmt, a, b);
    return 1;
}

static int fail_errno(const char *what) {
    snprintf(why, sizeof why, "%s: errno %d", what, errno);
    return 1;
}

/* The permission bits of the file under test: 0444 for a /proc file, 0644 for
 * a sysctl. */
static mode_t want_perm;

/* A /proc regular file: 0444 (see want_perm), one link, empty, root's. */
static int shape(const char *what, mode_t mode, unsigned long nlink, long size,
                 unsigned uid, unsigned gid) {
    if (mode != (S_IFREG | want_perm))
        return bad(what, "mode %lo, want %lo", (long)mode,
                   (long)(S_IFREG | want_perm));
    if (nlink != 1)
        return bad(what, "nlink %ld, want %ld", (long)nlink, 1);
    if (size != 0)
        return bad(what, "size %ld, want %ld", size, 0);
    if (uid != 0 || gid != 0)
        return bad(what, "owner %ld:%ld, want 0:0", (long)uid, (long)gid);
    return 0;
}

static int check_st(const char *what, const struct stat *s, const struct stat *ref) {
    if (shape(what, s->st_mode, s->st_nlink, s->st_size, s->st_uid, s->st_gid))
        return 1;
    if (ref && (s->st_ino != ref->st_ino || s->st_dev != ref->st_dev))
        return bad(what, "identity %ld, want %ld", (long)s->st_ino,
                   (long)ref->st_ino);
    return 0;
}

static int one(const char *name, int procfd) {
    struct stat st, ls, as, ps, fs;
    struct sx sx;
    /* The name under the /proc directory the dirfd forms are given. */
    const char *leaf = name + strlen("/proc/");

    want_perm = strstr(name, "/overflow") ? 0644 : 0444;

    if (stat(name, &st))
        return fail_errno("stat");
    if (check_st("stat", &st, 0))
        return 1;
    if (lstat(name, &ls))
        return fail_errno("lstat");
    if (check_st("lstat", &ls, &st))
        return 1;

    int r = statx_of(AT_FDCWD, name, 0, &sx);
    if (r < 0)
        return fail_errno("statx");
    if (r == 0 &&
        shape("statx", sx_u32(&sx, 28) & 0xffff, sx_u32(&sx, 16),
              (long)sx_u64(&sx, 40), sx_u32(&sx, 20), sx_u32(&sx, 24)))
        return 1;
    if (r == 0 && (sx_u64(&sx, 32) != st.st_ino ||
                   makedev(sx_u32(&sx, 136), sx_u32(&sx, 140)) != st.st_dev))
        return bad("statx", "identity %ld, want %ld", (long)sx_u64(&sx, 32),
                   (long)st.st_ino);

    if (fstatat(procfd, leaf, &as, 0))
        return fail_errno("fstatat(/proc)");
    if (check_st("fstatat(/proc)", &as, &st))
        return 1;

    int pfd = open(name, O_PATH | O_CLOEXEC);
    if (pfd < 0)
        return fail_errno("open O_PATH");
    if (fstat(pfd, &ps))
        return fail_errno("fstat O_PATH");
    if (check_st("fstat O_PATH", &ps, &st))
        return 1;
    r = statx_of(pfd, "", AT_EMPTY_PATH, &sx);
    if (r < 0)
        return fail_errno("statx O_PATH");
    if (r == 0 && sx_u64(&sx, 32) != st.st_ino)
        return bad("statx O_PATH", "identity %ld, want %ld",
                   (long)sx_u64(&sx, 32), (long)st.st_ino);
    close(pfd);

    int rfd = open(name, O_RDONLY | O_CLOEXEC);
    if (rfd < 0)
        return fail_errno("open");
    if (fstat(rfd, &fs))
        return fail_errno("fstat");
    if (check_st("fstat", &fs, &st))
        return 1;
    close(rfd);

    /* ...and opened against the /proc directory, which is how procps and
     * bubblewrap's neighbours reach them: the same file, the same identity. */
    int dfd = openat(procfd, leaf, O_RDONLY | O_CLOEXEC);
    if (dfd < 0)
        return fail_errno("openat(/proc)");
    if (fstat(dfd, &fs))
        return fail_errno("fstat openat(/proc)");
    if (check_st("fstat openat(/proc)", &fs, &st))
        return 1;
    close(dfd);

    if (access(name, R_OK))
        return fail_errno("access R_OK");
    if (faccessat(procfd, leaf, R_OK, 0))
        return fail_errno("faccessat(/proc) R_OK");
    if (!access(name, X_OK) || errno != EACCES)
        return fail_errno("access X_OK");
    /* The write check is root's to pass: a real root gets W_OK on a 0444 file,
     * and on a 0644 one only root has the write bit at all. */
    if (geteuid() != 0 && (!access(name, W_OK) || errno != EACCES))
        return fail_errno("access W_OK");
    return 0;
}

int main(void) {
    static const char *const names[] = {"/proc/version", "/proc/loadavg",
                                        "/proc/uptime", "/proc/stat",
                                        "/proc/sys/kernel/overflowuid",
                                        "/proc/sys/kernel/overflowgid"};
    int procfd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (procfd < 0) {
        printf("open /proc: errno=%d\n", errno);
        return 1;
    }
    int rc = 0;
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
        why[0] = '\0';
        if (one(names[i], procfd)) {
            printf("%s: %s\n", names[i], why);
            rc = 1;
        } else {
            printf("%s: ok\n", names[i]);
        }
        fflush(stdout);
    }
    if (no_statx)
        printf("statx: none on this host\n");
    return rc;
}
