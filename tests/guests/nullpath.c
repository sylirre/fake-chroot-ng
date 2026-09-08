/* A NULL pathname is -EFAULT, and it is the kernel's job to say so.
 *
 * Every path-bearing syscall copies its name in before it looks at anything
 * else — getname() faults on a NULL pointer, ahead of the dirfd, the flags and
 * every permission check — so the answer is EFAULT and never ENOENT. The
 * emulation gets that for free almost everywhere by handing the NULL to the
 * kernel and re-issuing: the translator passes a null name straight through
 * (xlate_lim), which is also what keeps the two spellings where a NULL name is
 * legitimate rather than an error — utimensat against a real dirfd, and statx
 * with AT_EMPTY_PATH — answering as the host answers rather than as a table of
 * ours claims. linkat was the one call that resolved both ends itself, never
 * reached a re-issue, and turned NULL into the ENOENT it gives an unresolvable
 * name.
 *
 * Output is protocol only, so the same source built for the host is the oracle.
 * A number this host does not implement, or refuses outright, says nothing
 * about pathnames — ENOSYS and EPERM print as "unavailable" so that a kernel
 * without fchmodat2, or an Android policy that denies openat2, compares equal
 * on both sides instead of asserting an errno that was never about the name.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *base = "";
static int dfd = -1;

static void report(const char *tag, long r) {
    int e = r < 0 ? errno : 0;
    if (e == ENOSYS || e == EPERM)
        printf("%s=unavailable\n", tag);
    else
        printf("%s=%d\n", tag, e);
}
#define P(tag, call)                                                           \
    do {                                                                       \
        errno = 0;                                                             \
        long r_ = (call);                                                      \
        report(tag, r_);                                                       \
    } while (0)

int main(int argc, char **argv) {
    char dir[256], newp[256], st[512];
    if (argc > 1)
        base = argv[1];
    snprintf(dir, sizeof dir, "%s/", base[0] ? base : "/");
    snprintf(newp, sizeof newp, "%s/nullpath_new", base);
    dfd = (int)syscall(SYS_openat, AT_FDCWD, dir, O_RDONLY | O_DIRECTORY, 0);
    printf("dirfd_ok=%d\n", dfd >= 0);

    P("openat", syscall(SYS_openat, AT_FDCWD, NULL, O_RDONLY, 0));
    P("openat_dirfd", syscall(SYS_openat, dfd, NULL, O_RDONLY, 0));
#ifdef SYS_openat2
    {
        struct {
            unsigned long long flags, mode, resolve;
        } how = {O_RDONLY, 0, 0};
        P("openat2", syscall(SYS_openat2, AT_FDCWD, NULL, &how, sizeof how));
    }
#endif
    P("mkdirat", syscall(SYS_mkdirat, AT_FDCWD, NULL, 0700));
    P("mknodat", syscall(SYS_mknodat, AT_FDCWD, NULL, S_IFREG | 0600, 0));
    P("unlinkat", syscall(SYS_unlinkat, AT_FDCWD, NULL, 0));
    P("newfstatat", syscall(SYS_newfstatat, AT_FDCWD, NULL, st, 0));
    P("statx", syscall(SYS_statx, AT_FDCWD, NULL, 0, 0, st));
    P("fchownat", syscall(SYS_fchownat, AT_FDCWD, NULL, -1, -1, 0));
    P("fchmodat", syscall(SYS_fchmodat, AT_FDCWD, NULL, 0600, 0));
#ifdef SYS_fchmodat2
    P("fchmodat2", syscall(SYS_fchmodat2, AT_FDCWD, NULL, 0600, 0));
#endif
    P("faccessat", syscall(SYS_faccessat, AT_FDCWD, NULL, F_OK, 0));
#ifdef SYS_faccessat2
    P("faccessat2", syscall(SYS_faccessat2, AT_FDCWD, NULL, F_OK, 0));
#endif
    P("readlinkat", syscall(SYS_readlinkat, AT_FDCWD, NULL, st, sizeof st));
    P("utimensat", syscall(SYS_utimensat, AT_FDCWD, NULL, NULL, 0));
    P("name_to_handle_at",
      syscall(SYS_name_to_handle_at, AT_FDCWD, NULL, st, st + 256, 0));
    P("symlinkat_target", syscall(SYS_symlinkat, NULL, AT_FDCWD, newp));
    P("symlinkat_link", syscall(SYS_symlinkat, "target", AT_FDCWD, NULL));
    P("linkat_src", syscall(SYS_linkat, AT_FDCWD, NULL, AT_FDCWD, newp, 0));
    P("linkat_dst",
      syscall(SYS_linkat, AT_FDCWD, dir, AT_FDCWD, NULL, 0));
    P("linkat_src_empty_flag",
      syscall(SYS_linkat, AT_FDCWD, NULL, AT_FDCWD, newp, AT_EMPTY_PATH));
    P("renameat_src", syscall(SYS_renameat, AT_FDCWD, NULL, AT_FDCWD, newp));
    P("renameat_dst", syscall(SYS_renameat, AT_FDCWD, dir, AT_FDCWD, NULL));
#ifdef SYS_renameat2
    P("renameat2_src",
      syscall(SYS_renameat2, AT_FDCWD, NULL, AT_FDCWD, newp, 0));
#endif
    P("inotify_add_watch",
      syscall(SYS_inotify_add_watch, (int)syscall(SYS_inotify_init1, 0), NULL,
              1));
    P("truncate", syscall(SYS_truncate, NULL, 0));
    P("statfs", syscall(SYS_statfs, NULL, st));
    P("chdir", syscall(SYS_chdir, NULL));
    P("chroot", syscall(SYS_chroot, NULL));
    P("getxattr", syscall(SYS_getxattr, NULL, "user.x", st, sizeof st));
    P("lgetxattr", syscall(SYS_lgetxattr, NULL, "user.x", st, sizeof st));
    P("setxattr", syscall(SYS_setxattr, NULL, "user.x", "v", 1, 0));
    P("listxattr", syscall(SYS_listxattr, NULL, st, sizeof st));
    P("removexattr", syscall(SYS_removexattr, NULL, "user.x"));
    P("execve", syscall(SYS_execve, NULL, NULL, NULL));
#ifdef SYS_execveat
    P("execveat", syscall(SYS_execveat, AT_FDCWD, NULL, NULL, NULL, 0));
    P("execveat_empty_flag",
      syscall(SYS_execveat, AT_FDCWD, NULL, NULL, NULL, AT_EMPTY_PATH));
#endif
    /* The two spellings where a NULL name is not an error but a way of naming
     * the descriptor. Both must keep working, and both are the host's answer
     * rather than ours: statx grew this only in 6.11, so an older kernel says
     * EFAULT here and the oracle says it too. */
    P("utimensat_dirfd", syscall(SYS_utimensat, dfd, NULL, NULL, 0));
    P("statx_dirfd_empty",
      syscall(SYS_statx, dfd, NULL, AT_EMPTY_PATH, 0, st));
    return 0;
}
