/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] [-c CHROOT] PATH...
 * prints guest->host path translations (-c first emulates a chroot to CHROOT).
 * Used by the M5 unit tests (the path core is pure logic, fully exercisable
 * under qemu).
 */
#include "cng/broker.h"
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/procfs.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/rewrite.h"
#include "cng/seccomp.h"
#include "cng/shm.h"
#include "cng/sysvipc.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

#include <asm/unistd.h>

/* aarch64 struct stat accessors (for _l2stest). */
#define ST_INO(b)   (*(unsigned long long *)((char *)(b) + 8))
#define ST_MODE(b)  (*(unsigned *)((char *)(b) + 16))
#define ST_NLINK(b) (*(unsigned *)((char *)(b) + 20))
#define ST_MTIME(b) (*(long long *)((char *)(b) + 88))
#define ST_ISREG(b) ((ST_MODE(b) & 0170000) == 0100000)
/* struct statx accessors. */
#define STX_MASK(b)  (*(unsigned *)(char *)(b))
#define STX_NLINK(b) (*(unsigned *)((char *)(b) + 16))

int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;

    const char *rootfs = "/";
    const char *cwd = 0;
    const char *chroot_to = 0;
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int bind_ro[CNG_MAX_BINDS];
    int nb = 0;
    const char *paths[256];
    int np = 0, resolve = 0, deref_final = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
            /* SRC:DST[:ro] — host first, same order as the -b CLI option. */
            char *spec = argv[++i];
            char *c = strchr(spec, ':');
            if (c && nb < CNG_MAX_BINDS) {
                *c = '\0';
                char *dst = c + 1;
                int ro = 0;
                unsigned long dl = strlen(dst);
                if (dl >= 3 && !strcmp(dst + dl - 3, ":ro")) {
                    ro = 1;
                    dst[dl - 3] = '\0';
                }
                bind_g[nb] = dst;
                bind_h[nb] = spec;
                bind_ro[nb] = ro;
                nb++;
            }
        } else if (!strcmp(argv[i], "-C") && i + 1 < argc) {
            cwd = argv[++i];
        } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            chroot_to = argv[++i];
        } else if (!strcmp(argv[i], "-R")) {
            resolve = 1; /* the real resolver: symlinks, physical ".." */
        } else if (!strcmp(argv[i], "-n")) {
            resolve = 1;
            deref_final = 0;
        } else if (np < 256) {
            paths[np++] = argv[i];
        }
    }

    struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    for (int i = 0; i < nb; i++)
        cng_fs_add_bind(&fs, bind_g[i], bind_h[i], bind_ro[i]);
    if (cwd)
        cng_fs_set_cwd(&fs, cwd);
    if (chroot_to) { /* what cng_dispatch does for chroot(2), minus the stat */
        char canon[CNG_PATH_MAX], hp[CNG_PATH_MAX];
        if (cng_fs_abscanon(&fs, chroot_to, canon, sizeof canon) == 0 &&
            cng_fs_translate(&fs, canon, hp, sizeof hp) == 0)
            cng_fs_chroot(&fs, canon, hp);
    }

    char out[CNG_PATH_MAX];
    for (int i = 0; i < np; i++) {
        if (resolve) {
            /* cng_resolve reads the real filesystem (it readlinks each
             * component), so this leg needs the tree to exist. */
            cng_g_fs = &fs;
            long r = cng_resolve(paths[i], deref_final, out, sizeof out);
            if (r == 0)
                cng_dprintf(1, "%s -> %s\n", paths[i], out);
            else
                cng_dprintf(1, "%s -> <errno %d>\n", paths[i], (int)-r);
            continue;
        }
        if (cng_fs_translate(&fs, paths[i], out, sizeof out) == 0)
            cng_dprintf(1, "%s -> %s\n", paths[i], out);
        else
            cng_dprintf(1, "%s -> <overflow>\n", paths[i]);
    }
    return 0;
}

/* _dtest -r ROOT (open|access) GUESTPATH
 * Drives cng_dispatch directly (no seccomp) to verify translate+reissue: the
 * real syscall must hit ROOT/GUESTPATH. Exercised under qemu. */
int cng_cmd_dtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = "/";
    const char *op = 0, *gpath = 0, *bind_spec = 0, *relpath = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc)
            rootfs = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc)
            bind_spec = argv[++i];
        else if (!op)
            op = argv[i];
        else if (!gpath)
            gpath = argv[i];
        else if (!relpath)
            relpath = argv[i];
    }
    if (!op || !gpath) {
        cng_dprintf(2, "usage: _dtest -r ROOT [-b SRC:DST[:ro]] "
                       "(open|access|dbgpath|robind) GUESTPATH\n"
                       "       _dtest -r ROOT atrel GUESTDIR RELPATH\n");
        return 2;
    }

    static struct cng_fs fs; /* referenced by dispatcher via cng_g_fs */
    cng_fs_init(&fs, rootfs);
    if (bind_spec) { /* SRC:DST[:ro] — host first, as the CLI spells it */
        static char spec[512];
        cng_strlcpy(spec, bind_spec, sizeof spec);
        char *c = strchr(spec, ':');
        if (c) {
            *c = '\0';
            char *dst = c + 1;
            int ro = 0;
            unsigned long dl = strlen(dst);
            if (dl >= 3 && !strcmp(dst + dl - 3, ":ro")) {
                ro = 1;
                dst[dl - 3] = '\0';
            }
            cng_fs_add_bind(&fs, dst, spec, ro);
        }
    }
    cng_g_fs = &fs;

    if (!strcmp(op, "open")) {
        long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)gpath,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
        if (fd < 0) {
            cng_dprintf(1, "open: errno %d\n", (int)-fd);
            return 1;
        }
        char buf[128];
        long n = sys_read((int)fd, buf, sizeof buf - 1);
        sys_close((int)fd);
        if (n < 0) {
            cng_dprintf(1, "read: errno %d\n", (int)-n);
            return 1;
        }
        buf[n] = '\0';
        cng_dprintf(1, "read: %s\n", buf);
        return 0;
    }
    /* CNG_DEBUG error logging must never dereference a syscall arg that is a
     * scalar rather than a path: truncate's length here is large enough to look
     * like a pointer, and reading it killed the guest (SIGSEGV in the handler,
     * with SIGSEGV masked). The dispatch must survive and report EISDIR. */
    if (!strcmp(op, "dbgpath")) {
        int save = cng_g_debug;
        cng_g_debug = 1;
        long r = cng_dispatch(__NR_truncate, (long)gpath, 0x7ffffff0, 0, 0, 0, 0,
                              /*trapped=*/0);
        cng_g_debug = save;
        cng_dprintf(1, "dbgpath: survived rc=%d -> %s\n", (int)r,
                    r == -EISDIR ? "OK" : "FAIL");
        return r == -EISDIR ? 0 : 1;
    }
    /* A name resolved relative to a real dirfd must be contained exactly like an
     * absolute one. It used to be handed to the kernel untouched, and the kernel
     * has no rootfs: a ".." run climbed out of it and an absolute symlink target
     * came from the HOST root. Opens GUESTDIR through the dispatcher, then reads
     * RELPATH relative to that fd. */
    if (!strcmp(op, "atrel") && relpath) {
        long dfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)gpath,
                                CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
        if (dfd < 0) {
            cng_dprintf(1, "atrel: dir errno %d\n", (int)-dfd);
            return 1;
        }
        long fd = cng_dispatch(__NR_openat, dfd, (long)relpath, CNG_O_RDONLY, 0,
                               0, 0, 0);
        if (fd < 0) {
            cng_dprintf(1, "atrel: errno %d\n", (int)-fd);
            sys_close((int)dfd);
            return 1;
        }
        char buf[128];
        long n = sys_read((int)fd, buf, sizeof buf - 1);
        sys_close((int)fd);
        sys_close((int)dfd);
        if (n < 0) {
            cng_dprintf(1, "atrel: read errno %d\n", (int)-n);
            return 1;
        }
        buf[n] = '\0';
        cng_dprintf(1, "atrel: %s\n", buf);
        return 0;
    }
    /* The xattr family was never trapped, so a guest's absolute path went to the
     * HOST filesystem: getxattr answered existence questions about it and
     * setxattr wrote it. Translation shows up as the errno: a name that exists
     * inside the rootfs answers ENODATA/EOPNOTSUPP ("no such attribute"), while
     * an untranslated path lands on a host name that is not there -> ENOENT. */
    if (!strcmp(op, "getxa")) {
        char val[64];
        long r = cng_dispatch(__NR_getxattr, (long)gpath, (long)"user.cng.probe",
                              (long)val, sizeof val, 0, 0, 0);
        cng_dprintf(1, "getxa: errno %d\n", r < 0 ? (int)-r : 0);
        return 0;
    }
    /* inotify_add_watch was never trapped either, and its a0 is the inotify
     * instance rather than a dirfd, so the guest's absolute path went to the
     * HOST — the containment exactly inverted: a name inside the rootfs
     * answered ENOENT while a host-only one armed the watch. The errno says
     * which file the kernel found. */
    /* The hidden-process view keys on the resolved HOST path, and a /proc dirfd
     * has no guest path to resolve against — so a relative name under it went
     * to the kernel untouched and `openat(dirfd("/proc"), "1/status")` read the
     * host's init while "/proc/1/status" answered ENOENT. Both spellings of a
     * foreign pid must be hidden, and both spellings of our own must not be. */
    if (!strcmp(op, "prochide")) {
        long d = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/proc",
                              CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
        if (d < 0) {
            cng_dprintf(1, "prochide: /proc errno %d\n", (int)-d);
            return 1;
        }
        char own[64];
        cng_snprintf(own, sizeof own, "%ld/status", sys_getpid());
        long a_for = cng_dispatch(__NR_openat, CNG_AT_FDCWD,
                                  (long)"/proc/1/status", CNG_O_RDONLY, 0, 0, 0,
                                  0);
        long r_for = cng_dispatch(__NR_openat, d, (long)"1/status",
                                  CNG_O_RDONLY, 0, 0, 0, 0);
        long r_bare = cng_dispatch(__NR_newfstatat, d, (long)"1",
                                   (long)(char[144]){0}, 0, 0, 0, 0);
        long r_own = cng_dispatch(__NR_openat, d, (long)own, CNG_O_RDONLY, 0, 0,
                                  0, 0);
        long r_self = cng_dispatch(__NR_openat, d, (long)"self/status",
                                   CNG_O_RDONLY, 0, 0, 0, 0);
        if (a_for >= 0)
            sys_close((int)a_for);
        if (r_for >= 0)
            sys_close((int)r_for);
        if (r_own >= 0)
            sys_close((int)r_own);
        if (r_self >= 0)
            sys_close((int)r_self);
        sys_close((int)d);
        int ok = a_for < 0 && r_for < 0 && r_bare < 0 && r_own >= 0 &&
                 r_self >= 0;
        cng_dprintf(1,
                    "prochide: abs=%d rel=%d bare=%d own=%d self=%d -> %s\n",
                    (int)a_for, (int)r_for, (int)r_bare, r_own >= 0,
                    r_self >= 0, ok ? "OK" : "FAIL");
        return ok ? 0 : 1;
    }
    if (!strcmp(op, "inotify")) {
        long ifd = CNG_SYS(__NR_inotify_init1, 0, 0, 0, 0, 0, 0);
        if (ifd < 0) {
            cng_dprintf(1, "inotify: init errno %d\n", (int)-ifd);
            return 1;
        }
        long w = cng_dispatch(__NR_inotify_add_watch, ifd, (long)gpath,
                              2 /*IN_MODIFY*/, 0, 0, 0, /*trapped=*/0);
        cng_dprintf(1, "inotify: errno %d\n", w < 0 ? (int)-w : 0);
        sys_close((int)ifd);
        return 0;
    }
    /* The -R trampoline tier runs with no seccomp filter at all, so the
     * designed-ENOSYS refusals cannot come from the kernel there: the dispatcher
     * has to answer them itself. bpftest covers the filter; this covers the
     * other tier, and it is the only one testable under qemu-user. */
    if (!strcmp(op, "denied")) {
        struct {
            const char *name;
            long nr;
        } d[] = {
#ifdef __NR_io_uring_setup
            {"io_uring_setup", __NR_io_uring_setup},
#endif
#ifdef __NR_io_uring_enter
            {"io_uring_enter", __NR_io_uring_enter},
#endif
#ifdef __NR_io_uring_register
            {"io_uring_register", __NR_io_uring_register},
#endif
#ifdef __NR_clone3
            {"clone3", __NR_clone3},
#endif
#ifdef __NR_statmount
            {"statmount", __NR_statmount},
#endif
#ifdef __NR_open_tree
            {"open_tree", __NR_open_tree},
#endif
#ifdef __NR_mq_open
            {"mq_open", __NR_mq_open},
#endif
#ifdef __NR_mq_timedsend
            {"mq_timedsend", __NR_mq_timedsend},
#endif
        };
        int fails = 0;
        for (unsigned i = 0; i < sizeof d / sizeof *d; i++) {
            /* trapped=0: exactly how an -R trampoline calls in. */
            long r = cng_dispatch(d[i].nr, 0, 0, 0, 0, 0, 0, 0);
            int ok = (r == -ENOSYS);
            cng_dprintf(1, "denied %s: rc=%d -> %s\n", d[i].name, (int)r,
                        ok ? "OK" : "FAIL");
            fails += !ok;
        }
        /* Control: an ordinary untranslated syscall still runs on this tier. */
        long g = cng_dispatch(__NR_getpid, 0, 0, 0, 0, 0, 0, 0);
        int ok = g > 0;
        cng_dprintf(1, "denied control getpid: rc=%d -> %s\n", (int)g,
                    ok ? "OK" : "FAIL");
        fails += !ok;
        cng_dprintf(1, "denied: %d failures\n", fails);
        return fails ? 1 : 0;
    }
    /* uname must report a fixed kernel identity, and /proc/version must repeat
     * it word for word — while nodename stays the host's, which is what names
     * the machine the guest is really on. */
    if (!strcmp(op, "uname")) {
        char host[390], guest[390];
        memset(host, 0, sizeof host);
        memset(guest, 0, sizeof guest);
        sys_uname(host);
        long r = cng_dispatch(__NR_uname, (long)guest, 0, 0, 0, 0, 0, 0);
        /* A faked field is 65 bytes, and the kernel NUL-pads its own. Writing a
         * shorter identity over a longer one left the host's tail readable past
         * the terminator — which for release and version is the vendor string
         * the fake exists to withhold. Every byte after it must be zero. */
        int dirty = 0;
        for (int f = 0; f < 5; f++) {
            if (f == 1)
                continue; /* nodename is deliberately the host's */
            const char *p = guest + f * 65;
            for (unsigned k = strlen(p) + 1; k < 65; k++)
                dirty += p[k] != '\0';
        }
        cng_dprintf(1,
                    "uname: rc=%d sys=%s rel=%s ver=%s mach=%s node_kept=%d "
                    "tail_dirty=%d\n",
                    (int)r, guest, guest + 2 * 65, guest + 3 * 65, guest + 4 * 65,
                    !strcmp(host + 65, guest + 65), dirty);
        return r == 0 ? 0 : 1;
    }
    /* chroot(2) is privileged: without CAP_SYS_CHROOT — for us, a fake identity
     * whose effective uid is 0 — the kernel refuses it. Both answers in one run,
     * since the gate is the whole point. */
    if (!strcmp(op, "chroot")) {
        cng_g_fake_id = 0;
        long unpriv = cng_dispatch(__NR_chroot, (long)gpath, 0, 0, 0, 0, 0, 0);
        cng_g_fake_id = 1;
        cng_g_fake_uid = cng_g_fake_gid = 0;
        cng_cred_seed();
        long priv = cng_dispatch(__NR_chroot, (long)gpath, 0, 0, 0, 0, 0, 0);
        cng_dprintf(1, "chroot: unpriv=%d root=%d cwd=%s\n", (int)unpriv,
                    (int)priv, cng_g_fs->cwd);
        cng_g_fake_id = 0;
        return 0;
    }
    if (!strcmp(op, "access")) {
        long r = cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)gpath, 0, 0, 0,
                              0, /*trapped=*/0);
        cng_dprintf(1, "access: %s\n", r == 0 ? "ok" : "no");
        return r == 0 ? 0 : 1;
    }
#ifdef __NR_faccessat2
    /* faccessat2's AT_SYMLINK_NOFOLLOW asks about the link itself, so a
     * dangling one exists (F_OK) where following it is ENOENT. Resolving the
     * final component during translation answered for the target instead. */
    if (!strcmp(op, "accessnf")) {
        long f = cng_dispatch(__NR_faccessat2, CNG_AT_FDCWD, (long)gpath, 0,
                              CNG_AT_SYMLINK_NOFOLLOW, 0, 0, /*trapped=*/0);
        long d = cng_dispatch(__NR_faccessat2, CNG_AT_FDCWD, (long)gpath, 0, 0,
                              0, 0, /*trapped=*/0);
        cng_dprintf(1, "accessnf: nofollow=%d follow=%d\n", (int)f, (int)d);
        return 0;
    }
#endif
    /* A ":ro" bind must answer -EROFS for every mutating path syscall while
     * still serving reads, the way a real read-only mount does. GUESTPATH names
     * an existing file inside the bind. Without ":ro" on the -b spec the same
     * calls must NOT report EROFS — that is the negative control the test
     * drives, so a blanket refusal cannot pass. */
    if (!strcmp(op, "robind")) {
        int ro = fs.nbinds > 0 && fs.binds[0].ro;
        char sib[CNG_PATH_MAX];
        size_t gl = cng_strlcpy(sib, gpath, sizeof sib);
        cng_strlcpy(sib + gl, ".x", sizeof sib - gl);
        int fails = 0;

        /* First, the same calls made *relative to a directory fd* inside the
         * bind, which is how rm -rf, find -delete, tar and git all work. The
         * refusal keys on the resolved HOST path, and a plain relative name used
         * to be handed to the kernel without ever acquiring one — so these went
         * straight through and the unlink really removed the file. Run before
         * the absolute set below, which in the rw control leg deletes it. */
        long rofd = cng_dispatch(__NR_openat, CNG_AT_FDCWD,
                                 (long)(fs.nbinds > 0 ? fs.binds[0].guest : "/"),
                                 CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
        const char *base = strrchr(gpath, '/');
        base = base ? base + 1 : gpath;
        /* The unlink leg gets a name of its own: in the rw control run it really
         * removes what it names, and the absolute set below still needs the
         * original. Creating it is itself one of the calls under test. */
        char atsib[128];
        size_t bl = cng_strlcpy(atsib, base, sizeof atsib);
        cng_strlcpy(atsib + bl, ".at", sizeof atsib - bl);
        struct {
            const char *name;
            long r;
        } at[] = {
            {"at-read", cng_dispatch(__NR_openat, rofd, (long)base,
                                     CNG_O_RDONLY, 0, 0, 0, 0)},
            {"at-open-w", cng_dispatch(__NR_openat, rofd, (long)base,
                                       CNG_O_WRONLY, 0, 0, 0, 0)},
            {"at-creat", cng_dispatch(__NR_openat, rofd, (long)atsib,
                                      CNG_O_WRONLY | CNG_O_CREAT, 0644, 0, 0,
                                      0)},
            {"at-unlink", cng_dispatch(__NR_unlinkat, rofd, (long)atsib, 0, 0, 0,
                                       0, 0)},
        };
        if (rofd >= 0)
            sys_close((int)rofd);
        for (unsigned i = 0; i < sizeof at / sizeof *at; i++) {
            int is_read = !strcmp(at[i].name, "at-read");
            int ok = is_read ? at[i].r >= 0
                             : (ro ? at[i].r == -EROFS : at[i].r != -EROFS);
            if (at[i].r >= 0 && strcmp(at[i].name, "at-unlink"))
                sys_close((int)at[i].r);
            cng_dprintf(1, "robind %s %s: rc=%d -> %s\n", ro ? "ro" : "rw",
                        at[i].name, (int)at[i].r, ok ? "OK" : "FAIL");
            fails += !ok;
        }

        struct {
            const char *name;
            long r;
        } t[] = {
            {"read", cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)gpath,
                                  CNG_O_RDONLY, 0, 0, 0, 0)},
            /* access(W_OK) reports a read-only mount, so `test -w` agrees with
             * what the write would actually do rather than with the host
             * file's own mode. R_OK on the same name must still succeed. */
            {"access-r", cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)gpath,
                                      4 /*R_OK*/, 0, 0, 0, 0)},
            {"access-w", cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)gpath,
                                      2 /*W_OK*/, 0, 0, 0, 0)},
            {"open-w", cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)gpath,
                                    CNG_O_WRONLY, 0, 0, 0, 0)},
            {"open-creat", cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)sib,
                                        CNG_O_RDONLY | CNG_O_CREAT, 0644, 0, 0,
                                        0)},
            {"mkdirat", cng_dispatch(__NR_mkdirat, CNG_AT_FDCWD, (long)sib, 0755,
                                     0, 0, 0, 0)},
            {"unlinkat", cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)gpath, 0,
                                      0, 0, 0, 0)},
            {"fchmodat", cng_dispatch(__NR_fchmodat, CNG_AT_FDCWD, (long)gpath,
                                      0600, 0, 0, 0, 0)},
            {"truncate",
             cng_dispatch(__NR_truncate, (long)gpath, 0, 0, 0, 0, 0, 0)},
            {"symlinkat", cng_dispatch(__NR_symlinkat, (long)"/t", CNG_AT_FDCWD,
                                       (long)sib, 0, 0, 0, 0)},
            {"renameat", cng_dispatch(__NR_renameat, CNG_AT_FDCWD, (long)gpath,
                                      CNG_AT_FDCWD, (long)sib, 0, 0, 0)},
            {"utimensat", cng_dispatch(__NR_utimensat, CNG_AT_FDCWD, (long)gpath,
                                       0, 0, 0, 0, 0)},
            {"fchownat", cng_dispatch(__NR_fchownat, CNG_AT_FDCWD, (long)gpath, 0,
                                      0, 0, 0, 0)},
        };
        for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
            int is_read = !strcmp(t[i].name, "read") ||
                          !strcmp(t[i].name, "access-r");
            /* reads always succeed; mutators are EROFS exactly when ro */
            int ok = is_read ? t[i].r >= 0
                             : (ro ? t[i].r == -EROFS : t[i].r != -EROFS);
            if (!strcmp(t[i].name, "read") && t[i].r >= 0)
                sys_close((int)t[i].r);
            cng_dprintf(1, "robind %s %s: rc=%d -> %s\n", ro ? "ro" : "rw",
                        t[i].name, (int)t[i].r, ok ? "OK" : "FAIL");
            fails += !ok;
        }
        cng_dprintf(1, "robind: %d failures\n", fails);
        return fails ? 1 : 0;
    }
    cng_dprintf(2, "_dtest: unknown op %s\n", op);
    return 2;
}

/* _sigtest — install a SIGUSR1 handler with our restorer, self-signal, and
 * confirm the handler ran and the AArch64 ucontext was readable (validates the
 * signal round-trip and sigcontext offsets that the SIGSYS path relies on). */
static volatile int g_sig_ran;
static volatile unsigned long g_sig_pc;

static void sigtest_handler(int s, cng_siginfo_t *si, void *ucv) {
    (void)s;
    (void)si;
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    g_sig_pc = (unsigned long)uc->uc_mcontext.pc;
    g_sig_ran = 1;
}

int cng_cmd_sigtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    if (cng_sig_install(CNG_SIGUSR1, sigtest_handler) < 0) {
        cng_dprintf(1, "sigtest: sigaction failed\n");
        return 1;
    }
    long pid = sys_getpid();
    long tid = sys_gettid();
    cng_syscall6(pid, tid, CNG_SIGUSR1, 0, 0, 0, __NR_tgkill);
    if (g_sig_ran && g_sig_pc > 0x1000) {
        cng_dprintf(1, "sigtest: handler ran, pc=0x%lx\n", g_sig_pc);
        return 0;
    }
    cng_dprintf(1, "sigtest: handler did not run cleanly\n");
    return 1;
}

/* _jmptest — validate the ucontext-redirect that M6's execve emulation relies
 * on: a handler rewrites uc->pc so sigreturn resumes at a different function.
 * If the redirect works we land in jmptest_landing and exit 7. */
static void jmptest_landing(void) {
    cng_dprintf(1, "jmptest: landed in redirected context\n");
    sys_exit_group(7);
}

static void jmptest_handler(int s, cng_siginfo_t *si, void *ucv) {
    (void)s;
    (void)si;
    struct cng_ucontext *uc = (struct cng_ucontext *)ucv;
    uc->uc_mcontext.pc = (unsigned long long)(unsigned long)(void *)jmptest_landing;
}

int cng_cmd_jmptest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    if (cng_sig_install(CNG_SIGUSR1, jmptest_handler) < 0) {
        cng_dprintf(1, "jmptest: sigaction failed\n");
        return 1;
    }
    cng_syscall6(sys_getpid(), sys_gettid(), CNG_SIGUSR1, 0, 0, 0,
                 __NR_tgkill);
    /* Reached only if the redirect did NOT take effect. */
    cng_dprintf(1, "jmptest: fell through (redirect failed)\n");
    return 1;
}

/* _faketest -r ROOT FILE — exercise the M7 fidelity fixups through the
 * dispatcher: credential faking, stat ownership rewrite, /proc/self/exe. */
int cng_cmd_faketest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = "/";
    const char *file = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc)
            rootfs = argv[++i];
        else if (!file)
            file = argv[i];
    }
    if (!file) {
        cng_dprintf(2, "usage: _faketest -r ROOT FILE\n");
        return 2;
    }

    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    cng_g_fake_id = 1;
    cng_g_fake_uid = 0;
    cng_g_fake_gid = 0;
    /* The remap source is the real owner of the test file (this process). */
    cng_g_host_uid = (unsigned)sys_getuid();
    cng_g_host_gid = (unsigned)sys_getgid();
    cng_cred_seed();
    cng_g_exe_guest = "/bin/sh";

    cng_dprintf(1, "getuid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 0));
    cng_dprintf(1, "geteuid=%d\n",
                (int)cng_dispatch(__NR_geteuid, 0, 0, 0, 0, 0, 0, 0));
    /* fchown a real fd (stdout) to root: the unprivileged host can't, so
     * fake-root must turn the denial into success. fchmod on the same fd is the
     * mirror image — a guest that opens a file and chmods the descriptor (tar,
     * cp -p, install) never goes near the fchmodat branch. */
    cng_dprintf(1, "fchown=%d\n",
                (int)cng_dispatch(__NR_fchown, 1, 0, 0, 0, 0, 0, 1));
    cng_dprintf(1, "fchmod=%d\n",
                (int)cng_dispatch(__NR_fchmod, 1, 0644, 0, 0, 0, 0, 1));

    /* stat and fstat must agree about who owns the same file: an installer
     * compares them before deciding to chown, and the remap used to be applied
     * only on the path form (fstat was trapped only under -l). */
    {
        char fs1[128], fs2[128];
        long pr = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)file,
                               (long)fs1, 0, 0, 0, /*trapped=*/0);
        long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)file,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
        long fr = fd < 0 ? -1
                         : cng_dispatch(__NR_fstat, fd, (long)fs2, 0, 0, 0, 0,
                                        /*trapped=*/0);
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "stat_vs_fstat stat=%u:%u fstat=%u:%u -> %s\n",
                    pr == 0 ? *(unsigned *)(fs1 + 24) : 0xffffffffu,
                    pr == 0 ? *(unsigned *)(fs1 + 28) : 0xffffffffu,
                    fr == 0 ? *(unsigned *)(fs2 + 24) : 0xffffffffu,
                    fr == 0 ? *(unsigned *)(fs2 + 28) : 0xffffffffu,
                    (pr == 0 && fr == 0 &&
                     *(unsigned *)(fs1 + 24) == *(unsigned *)(fs2 + 24) &&
                     *(unsigned *)(fs1 + 28) == *(unsigned *)(fs2 + 28))
                        ? "OK"
                        : "FAIL");
    }

    char sb[256];
    long r = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)file, (long)sb,
                          0, 0, 0, /*trapped=*/0);
    if (r == 0)
        cng_dprintf(1, "st_uid=%u st_gid=%u\n", *(unsigned *)(sb + 24),
                    *(unsigned *)(sb + 28));
    else
        cng_dprintf(1, "stat errno %d\n", (int)-r);

    char lb[256];
    long n = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD,
                          (long)"/proc/self/exe", (long)lb, sizeof lb, 0, 0,
                          /*trapped=*/0);
    if (n > 0) {
        lb[n] = '\0';
        cng_dprintf(1, "exe=%s\n", lb);
    }

    /* Fake-root reads what real root could. apk hands its package scripts to
     * the shebang interpreter as "/proc/self/fd/N", and their inode grants
     * execute but not read — real root reopens it anyway, we get EACCES. Take
     * the read bits off the test file and the reopen must still succeed, with
     * the file's mode put back exactly as it was. */
    {
        char hp[CNG_PATH_MAX], pfd[40];
        long ffd = -1, ofd = -1;
        int mode_kept = 0;
        if (cng_fs_translate(&fs, file, hp, sizeof hp) == 0)
            ffd = sys_openat(CNG_AT_FDCWD, hp, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
        if (ffd >= 0) {
            CNG_SYS(__NR_fchmod, (int)ffd, 0111, 0, 0, 0, 0);
            size_t k = cng_strlcpy(pfd, "/proc/self/fd/", sizeof pfd);
            char d[8];
            int di = 0;
            for (long v = ffd; di < 7; v /= 10) {
                d[di++] = (char)('0' + v % 10);
                if (v < 10)
                    break;
            }
            while (di > 0 && k + 1 < sizeof pfd)
                pfd[k++] = d[--di];
            pfd[k] = '\0';
            ofd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)pfd,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
            char st[128];
            mode_kept = (CNG_SYS(__NR_fstat, (int)ffd, st, 0, 0, 0, 0) == 0 &&
                         (ST_MODE(st) & 07777) == 0111);
            CNG_SYS(__NR_fchmod, (int)ffd, 0644, 0, 0, 0, 0);
            if (ofd >= 0)
                sys_close((int)ofd);
            sys_close((int)ffd);
        }
        cng_dprintf(1, "fakeroot_reopen: opened=%d mode_kept=%d -> %s\n",
                    ofd >= 0, mode_kept,
                    (ofd >= 0 && mode_kept) ? "OK" : "FAIL");
    }

    /* The other refusal kind, which no DAC change can fix: the inode grants
     * the access and the open is still denied (on Android, SELinux on the
     * tmpfs inode behind a memfd — where apk 3 keeps package scripts). The
     * refusal cannot be provoked on a devbox, so drive cng_fd_reopen directly
     * with a memfd and a simulated EACCES: it must hand back a usable
     * duplicate, rewound to the start even though ours sits at EOF. */
    {
        long mfd = sys_memfd_create("cng-fdreopen", 1 /*MFD_CLOEXEC*/);
        int dup_ok = 0, content = 0;
        if (mfd >= 0) {
            sys_write((int)mfd, "SCRIPT", 6); /* our offset is now at EOF */
            char pfd[40];
            size_t k = cng_strlcpy(pfd, "/proc/self/fd/", sizeof pfd);
            char d[8];
            int di = 0;
            for (long v = mfd; di < 7; v /= 10) {
                d[di++] = (char)('0' + v % 10);
                if (v < 10)
                    break;
            }
            while (di > 0 && k + 1 < sizeof pfd)
                pfd[k++] = d[--di];
            pfd[k] = '\0';
            long nfd = cng_fd_reopen(pfd, CNG_O_RDONLY, 0, -EACCES);
            if (nfd >= 0) {
                dup_ok = 1;
                char b[8];
                long n = sys_read((int)nfd, b, sizeof b);
                content = (n == 6 && b[0] == 'S' && b[5] == 'T');
                sys_close((int)nfd);
            }
            sys_close((int)mfd);
        }
        cng_dprintf(1, "fd_reopen: dup=%d content=%d -> %s\n", dup_ok, content,
                    (dup_ok && content) ? "OK" : "FAIL");
    }

    /* Full credential model. Supplementary groups start empty; capabilities are
     * the full set while fake-root (euid still 0 at this point). */
    cng_dprintf(1, "ngroups=%d\n",
                (int)cng_dispatch(__NR_getgroups, 0, 0, 0, 0, 0, 0, 1));
    unsigned caphdr[2] = { 0x20080522u, 0 };   /* _LINUX_CAPABILITY_VERSION_3 */
    unsigned capdata[6] = { 0 };               /* two {eff,perm,inh} blocks */
    cng_dispatch(__NR_capget, (long)caphdr, (long)capdata, 0, 0, 0, 0, 1);
    cng_dprintf(1, "cap_eff=%x\n", capdata[0]);
    /* The header version is negotiated, not assumed: an unrecognised one is
     * answered with the version the kernel does speak, and only a data-less
     * probe of it counts as a success. Calling it supported instead handed a v1
     * caller two blocks of data for its one-block buffer. */
    unsigned probe[2] = { 0, 0 };
    long cpn = cng_dispatch(__NR_capget, (long)probe, 0, 0, 0, 0, 0, 1);
    unsigned negotiated = probe[0];
    probe[0] = 0;
    long cbad = cng_dispatch(__NR_capget, (long)probe, (long)capdata, 0, 0, 0, 0,
                             1);
    unsigned v1hdr[2] = { 0x19980330u, 0 };    /* v1: one block, and only one */
    unsigned v1data[6];
    memset(v1data, 0xee, sizeof v1data);
    long cv1 = cng_dispatch(__NR_capget, (long)v1hdr, (long)v1data, 0, 0, 0, 0,
                            1);
    cng_dprintf(1, "cap_ver probe=%d got=%x bad=%d v1=%d v1_spill=%d\n",
                (int)cpn, negotiated, (int)cbad, (int)cv1,
                v1data[3] != 0xeeeeeeeeu);

    /* A privilege drop is real and, for the resulting non-root id, irreversible:
     * setuid(1000) succeeds, getuid then reports 1000, and setuid(0) is EPERM. */
    long su = cng_dispatch(__NR_setuid, 1000, 0, 0, 0, 0, 0, 1);
    long u2 = cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1);
    long re = cng_dispatch(__NR_setuid, 0, 0, 0, 0, 0, 0, 1);
    cng_dprintf(1, "setuid_drop rc=%d uid=%d regain=%d\n", (int)su, (int)u2,
                (int)re);

    /* --setuid-root / --setgid-root: as a non-root fake id (1000), a setuid+
     * setgid executable ("/suid", mode 6755) is shown as owned by root:root, and
     * exec of it elevates euid/egid to 0 while ruid stays 1000 — after which the
     * guest's own setuid(0) is privileged and sticks. This is the `su` chain. */
    cng_g_fake_uid = 1000;
    cng_g_fake_gid = 1000;
    cng_cred_seed();
    cng_g_setuid_root = 1;
    cng_g_setgid_root = 1;

    char sub[256];
    long sr = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/suid",
                           (long)sub, 0, 0, 0, /*trapped=*/0);
    if (sr == 0)
        cng_dprintf(1, "suid_stat st_uid=%u st_gid=%u\n",
                    *(unsigned *)(sub + 24), *(unsigned *)(sub + 28));
    else
        cng_dprintf(1, "suid_stat errno %d\n", (int)-sr);

    char suidhost[CNG_PATH_MAX];
    if (cng_fs_translate(&fs, "/suid", suidhost, sizeof suidhost) == 0)
        cng_cred_exec(suidhost);
    cng_dprintf(1, "suid_exec ruid=%d euid=%d egid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_geteuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getegid, 0, 0, 0, 0, 0, 0, 1));
    long root = cng_dispatch(__NR_setuid, 0, 0, 0, 0, 0, 0, 1);
    cng_dprintf(1, "su_to_root rc=%d uid=%d\n", (int)root,
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1));

    /* Identity resolution (cng_cred_setup): an id only implied by --setuid-root
     * (explicit=0) defaults to the real invoking id, so those flags alone don't
     * turn the guest into root; an explicit -u/--fake-id (explicit=1) wins. */
    cng_g_setuid_root = 0;
    cng_g_setgid_root = 0;
    cng_g_fake_id_explicit = 0;
    cng_g_fake_uid = 0;
    cng_g_fake_gid = 0; /* CLI defaults before the run seeds the identity */
    cng_cred_setup(4321, 8765);
    cng_dprintf(1, "implied_id uid=%d gid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getgid, 0, 0, 0, 0, 0, 0, 1));
    cng_g_fake_id_explicit = 1;
    cng_g_fake_uid = 1000;
    cng_g_fake_gid = 1000;
    cng_cred_setup(4321, 8765);
    cng_dprintf(1, "explicit_id uid=%d gid=%d\n",
                (int)cng_dispatch(__NR_getuid, 0, 0, 0, 0, 0, 0, 1),
                (int)cng_dispatch(__NR_getgid, 0, 0, 0, 0, 0, 0, 1));
    return 0;
}

/* _rwtest — copy a self-checking function containing an `svc #0`, rewrite the
 * svc to a trampoline, run it, and confirm it returns the real pid with all
 * caller registers preserved (validates M8's trampoline: x30/x18/args survive
 * the C dispatch call). No seccomp involved. */
extern char cng_rwtest_fn[];
extern char cng_rwtest_fn_end[];

int cng_cmd_rwtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;

    size_t fsz = (size_t)(cng_rwtest_fn_end - cng_rwtest_fn);
    /* One mapping: [code page | trampoline pool], so the pool is adjacent and
     * within a `b`'s reach (same reason the loader over-allocates). */
    unsigned long total = 4096 + CNG_TRAMP_POOL;
    void *region = sys_mmap(0, total, CNG_PROT_READ | CNG_PROT_WRITE,
                            CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (region == CNG_MAP_FAILED || cng_is_err((long)region)) {
        cng_dprintf(1, "rwtest: mmap failed\n");
        return 1;
    }
    void *buf = region;
    memcpy(buf, cng_rwtest_fn, fsz);
    unsigned long pool = (unsigned long)region + 4096;
    unsigned long used = 0;

    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    cng_g_rewrite = 1;

    int n = cng_rewrite_seg((unsigned long)buf, (unsigned long)buf + fsz, pool,
                            CNG_TRAMP_POOL, &used);
    sys_mprotect(region, total, CNG_PROT_READ | CNG_PROT_EXEC);
    cng_flush_icache(buf, (char *)buf + fsz);
    cng_flush_icache((void *)pool, (void *)(pool + used));

    long real = sys_getpid();
    long (*fn)(void) = (long (*)(void))buf;
    long got = fn();

    int ok = (n >= 1 && got == real);
    cng_dprintf(1, "rwtest: rewrote %d site(s); real_pid=%d fn_pid=%d -> %s\n",
                n, (int)real, (int)got, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _blocktest — validate that a syscall marked blocked (as cng_probe_blocked
 * would on Android) is emulated to ENOSYS by the dispatcher instead of being
 * re-issued, while an unblocked one still runs. */
int cng_cmd_blocktest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    int fails = 0;

    cng_blocked[__NR_fchownat] = 1; /* pretend Android blocks chown */
    long r = cng_dispatch(__NR_fchownat, CNG_AT_FDCWD, (long)"/x", 0, 0, 0, 0,
                          /*trapped=*/1);
    int ok1 = (r == -ENOSYS);
    cng_dprintf(1, "blocktest fchownat(blocked)=%d want=%d -> %s\n", (int)r,
                (int)-ENOSYS, ok1 ? "OK" : "FAIL");
    fails += !ok1;

    cng_blocked[__NR_faccessat] = 0; /* allowed -> still re-issued */
    long r2 = cng_dispatch(__NR_faccessat, CNG_AT_FDCWD, (long)"/", 0, 0, 0, 0,
                           /*trapped=*/1);
    int ok2 = (r2 == 0);
    cng_dprintf(1, "blocktest faccessat(allowed)=%d -> %s\n", (int)r2,
                ok2 ? "OK" : "FAIL");
    fails += !ok2;

    cng_blocked[__NR_fchownat] = 0; /* reset */
    return fails ? 1 : 0;
}

/* _faulttest — a guest pointer the handler dereferences itself must answer
 * -EFAULT, not kill the guest.
 *
 * These syscalls are emulated rather than re-issued, so the kernel never gets to
 * validate their pointers for us; and the handler runs with SIGSEGV masked, so a
 * fault there is unblockable and fatal. Every case below passes a wild (non-NULL,
 * unmapped) pointer through the dispatcher: a pass means the run survived AND the
 * errno is right, so the test failing to print at all is itself the diagnosis. */
int cng_cmd_faulttest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;

    void *bad = (void *)0x10; /* non-NULL, and no mapping starts that low */
    char *badv[2] = {(char *)0x10, 0}; /* a readable vector of unreadable strings */
    char good[128];
    int fails = 0;

    /* The probe needs a memfd; where it cannot be had the helpers answer
     * "accessible" and the dereferences below would really fault. */
    if (cng_user_readable(bad, 8) || cng_user_writable(bad, 8)) {
        cng_dprintf(1, "faulttest: memory probe unavailable here -> SKIP\n");
        return 0;
    }
    int okg = cng_user_readable(good, sizeof good) &&
              cng_user_writable(good, sizeof good);
    cng_dprintf(1, "faulttest probe good=%d bad=0 -> %s\n", okg,
                okg ? "OK" : "FAIL");
    fails += !okg;

    cng_g_fake_id = 1;
    cng_g_fake_uid = cng_g_fake_gid = 0;
    cng_cred_seed();

    struct {
        const char *name;
        long r;
    } t[] = {
        {"rt_sigaction",
         cng_dispatch(__NR_rt_sigaction, CNG_SIGUSR1, (long)bad, 0, 8, 0, 0, 1)},
        {"rt_sigprocmask",
         cng_dispatch(__NR_rt_sigprocmask, 0 /*SIG_BLOCK*/, (long)bad, 0, 8, 0,
                      0, 1)},
        {"getcwd", cng_dispatch(__NR_getcwd, (long)bad, 4096, 0, 0, 0, 0, 1)},
        {"getresuid",
         cng_dispatch(__NR_getresuid, (long)bad, (long)bad, (long)bad, 0, 0, 0,
                      1)},
        {"getresgid",
         cng_dispatch(__NR_getresgid, (long)bad, (long)bad, (long)bad, 0, 0, 0,
                      1)},
        {"setgroups", cng_dispatch(__NR_setgroups, 4, (long)bad, 0, 0, 0, 0, 1)},
        {"capget", cng_dispatch(__NR_capget, (long)bad, 0, 0, 0, 0, 0, 1)},
        {"shmctl",
         cng_dispatch(__NR_shmctl, 0, CNG_IPC_SET, (long)bad, 0, 0, 0, 1)},
        {"sendmsg", cng_dispatch(__NR_sendmsg, 0, (long)bad, 0, 0, 0, 0, 1)},
        /* A /proc magic link is answered from our own bookkeeping, so this
         * buffer is one the kernel never validates either. */
        {"readlinkat",
         cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/proc/self/cwd",
                      (long)bad, 4096, 0, 0, 1)},
        /* execve walks argv/envp itself — the kernel never sees them — so both
         * the vector and the strings it points at have to be validated. */
        {"execve path",
         cng_dispatch(__NR_execve, (long)bad, 0, 0, 0, 0, 0, 1)},
        {"execve argv",
         cng_dispatch(__NR_execve, (long)"/bin/sh", (long)bad, 0, 0, 0, 0, 1)},
        {"execve argv string",
         cng_dispatch(__NR_execve, (long)"/bin/sh", (long)badv, 0, 0, 0, 0, 1)},
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        int ok = (t[i].r == -EFAULT);
        cng_dprintf(1, "faulttest %s=%d want=%d -> %s\n", t[i].name, (int)t[i].r,
                    (int)-EFAULT, ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* getgroups writes only what it has: with no supplementary groups the bad
     * pointer is never touched, so seed one and ask again. */
    cng_g_cred.ngroups = 1;
    cng_g_cred.groups[0] = 42;
    long rg = cng_dispatch(__NR_getgroups, 4, (long)bad, 0, 0, 0, 0, 1);
    int okgg = (rg == -EFAULT);
    cng_dprintf(1, "faulttest getgroups=%d want=%d -> %s\n", (int)rg,
                (int)-EFAULT, okgg ? "OK" : "FAIL");
    fails += !okgg;

    /* Socket addresses are the other thing read ahead of the kernel: cng_sun_in
     * copies sun_path before any call that would have validated the pointer, and
     * the mmsg array forms walk a whole vector of guest msghdrs the same way. The
     * fd here is not a socket, so the kernel's own refusal arrives before it ever
     * looks at the address — which is the point. What is being asserted is that
     * an answer arrives at all, rather than the handler dying on the pointer; the
     * specific errno is the host's to choose. */
    long rb = cng_dispatch(__NR_bind, 0, (long)bad, 110, 0, 0, 0, 1);
    long rsm = cng_dispatch(__NR_sendmmsg, 0, (long)bad, 2, 0, 0, 0, 1);
    long rrm = cng_dispatch(__NR_recvmmsg, 0, (long)bad, 2, 0, 0, 0, 1);
    int oksa = (rb < 0 && rsm < 0 && rrm < 0);
    cng_dprintf(1,
                "faulttest socket-addr bind=%d sendmmsg=%d recvmmsg=%d -> %s\n",
                (int)rb, (int)rsm, (int)rrm, oksa ? "OK" : "FAIL");
    fails += !oksa;

    /* And the same calls with real memory still work. */
    long rr = cng_dispatch(__NR_getresuid, (long)good, (long)(good + 8),
                           (long)(good + 16), 0, 0, 0, 1);
    long rc = cng_dispatch(__NR_getcwd, (long)good, sizeof good, 0, 0, 0, 0, 1);
    int okv = (rr == 0 && rc > 0);
    cng_dprintf(1, "faulttest valid getresuid=%d getcwd=%d -> %s\n", (int)rr,
                (int)rc, okv ? "OK" : "FAIL");
    fails += !okv;

    /* readlinkat's bufsiz is an int, and the kernel refuses a non-positive one
     * outright. The magic links are answered from our bookkeeping, so the clamp
     * is ours to apply — and applying it to the raw register instead made a
     * negative bufsiz a buffer of ~2^64 bytes, i.e. no clamp at all. */
    long rn = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD,
                           (long)"/proc/self/cwd", (long)good, -1, 0, 0, 1);
    memset(good, '#', sizeof good);
    long rs = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD,
                           (long)"/proc/self/cwd", (long)good, 1, 0, 0, 1);
    int okrl = (rn == -EINVAL && rs == 1 && good[1] == '#');
    cng_dprintf(1, "faulttest readlink-bufsiz neg=%d short=%d -> %s\n", (int)rn,
                (int)rs, okrl ? "OK" : "FAIL");
    fails += !okrl;

    cng_g_fake_id = 0;
    return fails ? 1 : 0;
}

/* _prctltest — the confinement ops prctl must not answer honestly.
 *
 * We install a seccomp filter and set no_new_privs to do it, and both are
 * visible through prctl: PR_GET_SECCOMP would report mode 2 and
 * PR_GET_NO_NEW_PRIVS would report 1, neither of which the guest asked for. The
 * test sets the real bit first, so "the guest sees 0" is an assertion about the
 * virtualization rather than about an untouched process. */
int cng_cmd_prctltest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    int fails = 0;

    /* As cng_install_seccomp does, before the guest ever runs. */
    sys_prctl(CNG_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    long host_nnp = sys_prctl(CNG_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

    struct {
        const char *name;
        long r, want;
    } t[] = {
        {"GET_SECCOMP",
         cng_dispatch(__NR_prctl, CNG_PR_GET_SECCOMP, 0, 0, 0, 0, 0, 1), 0},
        {"GET_NO_NEW_PRIVS (host bit hidden)",
         cng_dispatch(__NR_prctl, CNG_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0, 1), 0},
        {"SET_SECCOMP refused",
         cng_dispatch(__NR_prctl, CNG_PR_SET_SECCOMP, CNG_SECCOMP_MODE_FILTER,
                      0, 0, 0, 0, 1),
         -EACCES},
        {"SET_NO_NEW_PRIVS 0 is EINVAL",
         cng_dispatch(__NR_prctl, CNG_PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0, 0, 1),
         -EINVAL},
        {"SET_NO_NEW_PRIVS 1",
         cng_dispatch(__NR_prctl, CNG_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0, 1), 0},
        {"GET_NO_NEW_PRIVS after the guest set it",
         cng_dispatch(__NR_prctl, CNG_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0, 1), 1},
        {"seccomp(2) refused",
         cng_dispatch(__NR_seccomp, CNG_SECCOMP_SET_MODE_FILTER, 0, 0, 0, 0, 0,
                      1),
         -ENOSYS},
    };
    cng_dprintf(1, "prctltest host no_new_privs=%d\n", (int)host_nnp);
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        int ok = (t[i].r == t[i].want);
        cng_dprintf(1, "prctltest %s=%d want=%d -> %s\n", t[i].name, (int)t[i].r,
                    (int)t[i].want, ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* An op we do not own still reaches the kernel. */
    char nm[16] = "cngprctl";
    long sr = cng_dispatch(__NR_prctl, CNG_PR_SET_NAME, (long)nm, 0, 0, 0, 0, 1);
    char back[16] = {0};
    sys_prctl(16 /*PR_GET_NAME*/, (unsigned long)back, 0, 0, 0);
    int okn = (sr == 0 && !strcmp(back, nm));
    cng_dprintf(1, "prctltest SET_NAME passthrough rc=%d comm=%s -> %s\n",
                (int)sr, back, okn ? "OK" : "FAIL");
    fails += !okn;

    cng_dprintf(1, "prctltest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

/* _selfproc — our own /proc/self/{cmdline,environ} must describe the GUEST.
 *
 * The registry is where another process's identity comes from, but for our own
 * it is a convenience: when it is unavailable (never mapped, or full) the old
 * fallback was the host file, which for a guest process is the chroot-ng
 * invocation that started it — `/proc/self/cmdline` read back "chroot-ng -u
 * /rootfs /bin/sh". Run with CNG_PROCREG_NONE=1 the registry is gone and the
 * answer must still be the guest's own argv, out of the live stack.
 *
 * The stack below is the layout cng_build_stack hands a guest: argc, argv,
 * NULL, envp, NULL, then auxv pairs terminated by AT_NULL. */
int cng_cmd_selfproc(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    cng_g_host_envp = envp;
    cng_g_exe_guest = "/bin/guestprog";

    static char *gargv[] = {"/bin/guestprog", "--flag", 0};
    static char *genvp[] = {"GUESTVAR=yes", 0};
    static unsigned long stk[16];
    int i = 0;
    stk[i++] = 2; /* argc */
    stk[i++] = (unsigned long)gargv[0];
    stk[i++] = (unsigned long)gargv[1];
    stk[i++] = 0;
    stk[i++] = (unsigned long)genvp[0];
    stk[i++] = 0;
    stk[i++] = 0; /* AT_NULL */
    stk[i++] = 0;

    cng_procfs_init();
    cng_procfs_publish_stack((unsigned long)stk);

    char buf[512];
    struct {
        const char *name, *want;
        int len;
    } t[] = {
        {"/proc/self/cmdline", "/bin/guestprog\0--flag", 22},
        {"/proc/self/environ", "GUESTVAR=yes", 13},
    };
    int fails = 0;
    for (unsigned k = 0; k < sizeof t / sizeof t[0]; k++) {
        long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)t[k].name,
                               CNG_O_RDONLY, 0, 0, 0, /*trapped=*/0);
        long n = fd < 0 ? -1 : sys_read((int)fd, buf, sizeof buf);
        if (fd >= 0)
            sys_close((int)fd);
        int ok = (n == t[k].len && !memcmp(buf, t[k].want, (size_t)n));
        cng_dprintf(1, "selfproc %s: %ld bytes [%s] -> %s\n", t[k].name, n,
                    n > 0 ? buf : "", ok ? "OK" : "FAIL");
        fails += !ok;
    }
    cng_dprintf(1, "selfproc registry=%d: %d failure(s)\n",
                cng_g_procreg_backing, fails);
    return fails ? 1 : 0;
}

/* _loadtwice PATH — load the same ELF twice into this address space (as execve
 * emulation does, without tearing down the first) to surface re-load failures. */
int cng_cmd_loadtwice(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    if (argc < 2) {
        cng_dprintf(2, "usage: _loadtwice PATH\n");
        return 2;
    }
    struct cng_loaded p1, p2;
    int rc1 = cng_load_elf(argv[1], 0, &p1);
    int rc2 = cng_load_elf(argv[1], 0, &p2);
    cng_dprintf(1, "load1 rc=%d base=%lx; load2 rc=%d base=%lx\n", rc1,
                p1.base, rc2, p2.base);
    return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}

/* _exectest -r ROOT [-b SRC:DST[:ro]]... [-D DIR] [-e] [-N] [-B] PROG [args]
 * — drive cng_emulate_execve (incl. shebang) and, on success, enter the loaded
 * program. Exercises execve emulation under qemu where neither the SIGSYS nor
 * trampoline route reaches it.
 *
 * The execveat form is reachable through the option flags, which is the only way
 * to test what its flags word means now that it is read at all:
 *   -D DIR  resolve PROG against an open fd for DIR (a real dirfd)
 *   -e      AT_EMPTY_PATH: open PROG and execute the fd, with an empty path
 *   -N      AT_SYMLINK_NOFOLLOW
 *   -B      set an undefined flag bit, which the kernel refuses with EINVAL
 *
 * The binds matter for a dynamically linked guest: its ELF interpreter is named
 * by an absolute guest path, and a synthetic rootfs holding only the test binary
 * has no interpreter of its own. On a host whose toolchain cannot link static
 * (Termux/bionic), the harness exposes the platform linker's directories here. */
int cng_cmd_exectest(int argc, char **argv, char **envp, unsigned long *auxv) {
    const char *rootfs = "/";
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int bind_ro[CNG_MAX_BINDS];
    const char *dirpath = 0;
    int nb = 0, xflags = 0, empty = 0, probe_reset = 0;
    int i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            rootfs = argv[i + 1];
            i += 2;
        } else if (!strcmp(argv[i], "-D") && i + 1 < argc) {
            dirpath = argv[i + 1];
            i += 2;
        } else if (!strcmp(argv[i], "-e")) {
            empty = 1;
            i++;
        } else if (!strcmp(argv[i], "-N")) {
            xflags |= CNG_AT_SYMLINK_NOFOLLOW;
            i++;
        } else if (!strcmp(argv[i], "-B")) {
            xflags |= CNG_AT_NO_AUTOMOUNT; /* not a valid execveat flag */
            i++;
        } else if (!strcmp(argv[i], "-R")) {
            probe_reset = 1;
            i++;
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
            /* SRC:DST[:ro] — host first, same order as the -b CLI option. Split
             * in place: argv is writable and outlives the fs view. */
            char *spec = argv[i + 1];
            char *c = strchr(spec, ':');
            if (c && nb < CNG_MAX_BINDS) {
                *c = '\0';
                char *dst = c + 1;
                int ro = 0;
                unsigned long dl = strlen(dst);
                if (dl >= 3 && !strcmp(dst + dl - 3, ":ro")) {
                    ro = 1;
                    dst[dl - 3] = '\0';
                }
                bind_g[nb] = dst;
                bind_h[nb] = spec;
                bind_ro[nb] = ro;
                nb++;
            }
            i += 2;
        } else {
            break;
        }
    }
    if (i >= argc) {
        cng_dprintf(2, "usage: _exectest -r ROOT [-b SRC:DST[:ro]]... "
                       "[-D DIR] [-e] [-N] [-B] PROG [args]\n");
        return 2;
    }
    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    for (int b = 0; b < nb; b++)
        cng_fs_add_bind(&fs, bind_g[b], bind_h[b], bind_ro[b]);
    cng_g_fs = &fs;
    cng_host_auxv = auxv;

    char **gargv = argv + i;
    const char *gpath = gargv[0];
    int dirfd = CNG_AT_FDCWD;
    /* Both fds are opened through the dispatcher, so they are the translated
     * ones a guest would have. */
    if (dirpath) {
        long d = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)dirpath,
                              CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 1);
        if (d < 0) {
            cng_dprintf(2, "exectest: open dir %s failed %ld\n", dirpath, d);
            return 1;
        }
        dirfd = (int)d;
    }
    if (empty) {
        long f = cng_dispatch(__NR_openat, dirfd, (long)gpath, CNG_O_RDONLY, 0,
                              0, 0, 1);
        if (f < 0) {
            cng_dprintf(2, "exectest: open %s failed %ld\n", gpath, f);
            return 1;
        }
        dirfd = (int)f;
        gpath = "";
        xflags |= CNG_AT_EMPTY_PATH;
    }
    /* -R: the state a real execve drops with the address space. Grow the heap
     * and arm a POSIX timer the way a running program would, then report
     * whether the emulation undid both — the reset happens at the commit point,
     * so it is only observable from here, before we enter the new program. */
    int tid = 0, have_timer = 0;
    if (probe_reset) {
        long b = CNG_SYS(__NR_brk, 0, 0, 0, 0, 0, 0);
        if (b > 0) {
            cng_g_brk0 = (unsigned long)b;
            CNG_SYS(__NR_brk, b + (1 << 20), 0, 0, 0, 0, 0);
        }
        /* Through the dispatcher, which is where the id gets recorded — a raw
         * syscall here would be a timer the emulation never saw. */
        have_timer = cng_dispatch(__NR_timer_create, 0 /*CLOCK_REALTIME*/, 0,
                                  (long)&tid, 0, 0, 0, 1) == 0;
    }

    static struct cng_ucontext uc;
    memset(&uc, 0, sizeof uc);
    cng_emulate_execve(&uc, dirfd, gpath, gargv, envp, xflags);
    if (probe_reset) {
        long b = CNG_SYS(__NR_brk, 0, 0, 0, 0, 0, 0);
        /* The timer is gone when deleting it again is refused. Counting
         * /proc/self/timers would answer a different question under an emulator,
         * which keeps its own timer table. */
        int gone = have_timer &&
                   CNG_SYS(__NR_timer_delete, tid, 0, 0, 0, 0, 0) < 0;
        int brk_back = ((unsigned long)b == cng_g_brk0);
        int ok = brk_back && (!have_timer || gone);
        cng_dprintf(1, "execreset: brk_back=%d timer_created=%d timer_gone=%d "
                       "-> %s\n",
                    brk_back, have_timer, gone, ok ? "OK" : "FAIL");
        return ok ? 0 : 1;
    }
    unsigned long entry = (unsigned long)uc.uc_mcontext.pc;
    unsigned long sp = (unsigned long)uc.uc_mcontext.sp;
    if (entry == 0) {
        cng_dprintf(2, "exectest: emulate_execve failed x0=%ld\n",
                    (long)uc.uc_mcontext.regs[0]);
        return 1;
    }
    /* /proc/self/exe fixup tracks the exec'd program (symlinks resolved). */
    cng_dprintf(2, "exectest: exe=%s\n", cng_g_exe_guest);
    cng_enter(sp, entry); /* never returns */
}

/* Host-path builder for the l2s store checks: "<a><b>" plus, when with_ino,
 * the decimal of `ino` appended. */
static void dbg_mkpath(char *out, size_t sz, const char *a, const char *b,
                       unsigned long long ino, int with_ino) {
    size_t n = cng_strlcpy(out, a, sz);
    if (b && n < sz)
        n += cng_strlcpy(out + n, b, sz - n);
    if (with_ino) {
        char tmp[24];
        int t = 0;
        do {
            tmp[t++] = (char)('0' + (ino % 10));
            ino /= 10;
        } while (ino);
        while (t > 0 && n + 1 < sz)
            out[n++] = tmp[--t];
        if (n < sz)
            out[n] = '\0';
    }
}

/* 1 if the host directory contains any ".l2s.*" entry, 0 if none, -1 on open
 * failure. Raw getdents64 walk (linux_dirent64: reclen @16, name @19). */
static int dbg_has_l2s(const char *dir) {
    long fd = sys_openat(CNG_AT_FDCWD, dir,
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int found = 0;
    long n;
    while (!found &&
           (n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0)) >
               0) {
        long o = 0;
        while (o + 19 <= n) {
            unsigned short rl;
            memcpy(&rl, buf + o + 16, 2);
            if (rl == 0 || o + rl > n)
                break;
            if (!strncmp(buf + o + 19, ".l2s.", 5)) {
                found = 1;
                break;
            }
            o += rl;
        }
    }
    sys_close((int)fd);
    return found;
}

/* _l2stest ROOT — exercise link2symlink (target must be a guest/relative path,
 * not a host path) and fchdir cwd tracking. ROOT must contain a dir "w". The
 * emulation is opt-in on the command line, so the test drives cng_g_l2s itself:
 * first off (the refusal must pass through), then on for the rest. */
int cng_cmd_l2stest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;
    const char *rootfs = argc > 1 ? argv[1] : "/";
    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    cng_g_fs = &fs;
    int fails = 0;

    /* link2symlink backing-file scheme. Force the fallback (tmpfs allows real
     * hardlinks) by marking linkat blocked. The emulated "hardlink" must present
     * as a regular file: shared inode, st_nlink counted, readlink refused. */
    cng_blocked[__NR_linkat] = 1;
    long fd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/a",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (fd >= 0) {
        sys_write((int)fd, "hi", 2);
        sys_close((int)fd);
    }

    /* The emulation is opt-in (-l/--link2symlink), so with the flag still off
     * the host's refusal must reach the guest verbatim and no name appear. */
    long loff = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                             CNG_AT_FDCWD, (long)"/w/z", 0, 0, 0);
    char sz[144];
    long rz = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/z",
                           (long)sz, 0, 0, 0, 0);
    int ok_off = (loff == -ENOSYS && rz == -ENOENT);
    cng_dprintf(1, "l2s-off: rc=%d created=%d -> %s\n", (int)loff, rz == 0,
                ok_off ? "OK" : "FAIL");
    fails += !ok_off;

    cng_g_l2s = 1; /* everything below exercises the enabled emulation */
    long lr = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a", CNG_AT_FDCWD,
                           (long)"/w/b", 0, 0, 0);
    /* linking onto an existing name must fail with EEXIST, like real link(2) */
    long lr2 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0);

    char sa[144], sb[144];
    long ra = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                           (long)sa, 0, 0, 0, 0);
    long rb = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)sb, 0, 0, 0, 0);
    int reg = (ra == 0 && rb == 0 && ST_ISREG(sa) && ST_ISREG(sb));
    int nlink = (reg && ST_NLINK(sa) == 2 && ST_NLINK(sb) == 2);
    int sameino = (reg && ST_INO(sa) == ST_INO(sb));

    char lb[256]; /* readlink must be transparent (EINVAL), never leak backing */
    long rl = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)lb, sizeof lb - 1, 0, 0, 0);
    int noleak = (rl == -EINVAL);

    char cbuf[8]; /* contents are shared through the backing file */
    long bf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/b",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    long rd = -1;
    if (bf >= 0) {
        rd = sys_read((int)bf, cbuf, sizeof cbuf);
        sys_close((int)bf);
    }
    int content = (rd == 2 && cbuf[0] == 'h' && cbuf[1] == 'i');

    int ok_l2s = (lr == 0 && lr2 == -EEXIST && reg && nlink && sameino &&
                  noleak && content);
    cng_dprintf(1,
                "l2s: rc=%d eexist=%d reg=%d nlink2=%d sameino=%d noleak=%d "
                "content=%d -> %s\n",
                (int)lr, lr2 == -EEXIST, reg, nlink, sameino, noleak, content,
                ok_l2s ? "OK" : "FAIL");
    fails += !ok_l2s;

    /* Central store: the backing pair lives in "<root>/.l2s" (data keeping the
     * original inode, marker at count 2), and nothing appears beside the
     * names in /w. */
    char hdata[CNG_PATH_MAX], hmark[CNG_PATH_MAX], hw[CNG_PATH_MAX];
    dbg_mkpath(hdata, sizeof hdata, rootfs, "/.l2s/.l2s.", ST_INO(sa), 1);
    dbg_mkpath(hmark, sizeof hmark, rootfs, "/.l2s/.l2s.", ST_INO(sa), 1);
    size_t hml = strlen(hmark);
    cng_strlcpy(hmark + hml, ".0002", sizeof hmark - hml);
    dbg_mkpath(hw, sizeof hw, rootfs, "/w", 0, 0);
    char sd[144];
    long rsd = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, hdata, sd,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    long rsm = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, hmark, sd,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    int store_ok = (rsd == 0 && rsm == 0);
    int user_clean = (dbg_has_l2s(hw) == 0);
    int ok_store = (store_ok && user_clean);
    cng_dprintf(1, "l2s-store: store=%d user_clean=%d -> %s\n", store_ok,
                user_clean, ok_store ? "OK" : "FAIL");
    fails += !ok_store;

    /* fd-based stat: fstat and the AT_EMPTY_PATH forms must report the
     * emulated st_nlink too (tar/rsync/coreutils stat open fds), and statx
     * must pass the guest's mask through while advertising STATX_NLINK. */
    int f_nlink = 0, ep_nlink = 0, epx = 0, xmask = 0;
    long bf2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/b",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    if (bf2 >= 0) {
        char sfd[144];
        long r1 = cng_dispatch(__NR_fstat, bf2, (long)sfd, 0, 0, 0, 0, 0);
        f_nlink = (r1 == 0 && ST_NLINK(sfd) == 2);
        long r2 = cng_dispatch(__NR_newfstatat, bf2, (long)"", (long)sfd,
                               CNG_AT_EMPTY_PATH, 0, 0, 0);
        ep_nlink = (r2 == 0 && ST_NLINK(sfd) == 2);
        char sxb[256];
        long r3 = cng_dispatch(__NR_statx, bf2, (long)"", CNG_AT_EMPTY_PATH,
                               CNG_STATX_BASIC_STATS, (long)sxb, 0, 0);
        epx = (r3 == 0 && STX_NLINK(sxb) == 2 &&
               (STX_MASK(sxb) & CNG_STATX_NLINK));
        sys_close((int)bf2);
    }
    char sxp[256];
    long rxp = cng_dispatch(__NR_statx, CNG_AT_FDCWD, (long)"/w/b", 0,
                            CNG_STATX_NLINK, (long)sxp, 0, 0);
    xmask = (rxp == 0 && STX_NLINK(sxp) == 2 &&
             (STX_MASK(sxp) & CNG_STATX_NLINK));
    int ok_fd = (f_nlink && ep_nlink && epx && xmask);
    cng_dprintf(1, "l2s-fstat: fd=%d empty=%d emptyx=%d mask=%d -> %s\n",
                f_nlink, ep_nlink, epx, xmask, ok_fd ? "OK" : "FAIL");
    fails += !ok_fd;

    /* readlink through a real dirfd must also refuse (the emulated link is a
     * regular file to the guest, wherever the name comes from). */
    int rlrel = 0;
    long wfd0 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    if (wfd0 >= 0) {
        char rb[64];
        long rr = cng_dispatch(__NR_readlinkat, wfd0, (long)"b", (long)rb,
                               sizeof rb, 0, 0, 0);
        rlrel = (rr == -EINVAL);
        sys_close((int)wfd0);
    }
    cng_dprintf(1, "l2s-dirfd-readlink: einval=%d -> %s\n", rlrel,
                rlrel ? "OK" : "FAIL");
    fails += !rlrel;

    /* mtime preserve (apk's scenario): set an explicit mtime on one name, read
     * it back through the other — must land on the shared backing file. */
    long times[4] = {0x11223344, 0, 0x11223344, 0}; /* atime, mtime = T */
    long um = cng_dispatch(__NR_utimensat, CNG_AT_FDCWD, (long)"/w/b",
                           (long)times, 0, 0, 0, 0);
    char sm[144];
    long rm = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                           (long)sm, 0, 0, 0, 0);
    int mtime_ok = (um == 0 && rm == 0 && ST_MTIME(sm) == 0x11223344);
    cng_dprintf(1, "l2s-mtime: set=%d mtime=%lld -> %s\n", (int)um,
                rm == 0 ? ST_MTIME(sm) : -1, mtime_ok ? "OK" : "FAIL");
    fails += !mtime_ok;

    /* dirfd-relative link (as apk does): open /w, linkat(fd,"d",fd,"e"). */
    long df = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/d",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (df >= 0) {
        sys_write((int)df, "x", 1);
        sys_close((int)df);
    }
    long wfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w", CNG_O_RDONLY,
                            0, 0, 0, 0);
    long lr3 = -1;
    int dreg = 0;
    if (wfd >= 0) {
        lr3 = cng_dispatch(__NR_linkat, wfd, (long)"d", wfd, (long)"e", 0, 0, 0);
        char se[144];
        long re = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/e",
                               (long)se, 0, 0, 0, 0);
        dreg = (re == 0 && ST_ISREG(se) && ST_NLINK(se) == 2);
        sys_close((int)wfd);
    }
    int ok_dirfd = (lr3 == 0 && dreg);
    cng_dprintf(1, "l2s-dirfd: rc=%d reg2=%d -> %s\n", (int)lr3, dreg,
                ok_dirfd ? "OK" : "FAIL");
    fails += !ok_dirfd;

    /* decref: removing one name drops st_nlink; removing the last reclaims the
     * backing file (the name then no longer exists). */
    long ub = cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0,
                           0, 0);
    char sa2[144];
    long ra2 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sa2, 0, 0, 0, 0);
    int after1 = (ub == 0 && ra2 == 0 && ST_NLINK(sa2) == 1);
    long ua = cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/a", 0, 0, 0,
                           0, 0);
    long ra3 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sa2, 0, 0, 0, 0);
    int gone = (ua == 0 && ra3 == -ENOENT);
    int ok_dec = (after1 && gone);
    cng_dprintf(1, "l2s-decref: nlink_after1=%d gone=%d -> %s\n", after1, gone,
                ok_dec ? "OK" : "FAIL");
    fails += !ok_dec;

    /* Cross-directory hardlink via the central store: shared inode and count,
     * content reachable both through the guest resolver (absolute path walks
     * the store target) and through the host kernel (dirfd-relative open
     * follows the absolute target natively). */
    long ff = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (ff >= 0) {
        sys_write((int)ff, "yo", 2);
        sys_close((int)ff);
    }
    cng_dispatch(__NR_mkdirat, CNG_AT_FDCWD, (long)"/w/sub", 0755, 0, 0, 0, 0);
    long xg = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_AT_FDCWD, (long)"/w/g", 0, 0, 0);
    long xr = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/f",
                           CNG_AT_FDCWD, (long)"/w/sub/x", 0, 0, 0);
    char sf[144], sx[144];
    long rf = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                           (long)sf, 0, 0, 0, 0);
    long rx = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/sub/x",
                           (long)sx, 0, 0, 0, 0);
    int x_ino = (rf == 0 && rx == 0 && ST_INO(sf) == ST_INO(sx));
    int x_nlink = (rf == 0 && rx == 0 && ST_NLINK(sf) == 3 &&
                   ST_NLINK(sx) == 3);
    char xb[8];
    long xrd = -1;
    long xf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/sub/x",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    if (xf >= 0) {
        xrd = sys_read((int)xf, xb, sizeof xb);
        sys_close((int)xf);
    }
    int x_abs = (xrd == 2 && xb[0] == 'y' && xb[1] == 'o');
    long wfd2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    int x_rel = 0;
    if (wfd2 >= 0) {
        long xf2 = cng_dispatch(__NR_openat, wfd2, (long)"sub/x", CNG_O_RDONLY,
                                0, 0, 0, 0);
        if (xf2 >= 0) {
            xrd = sys_read((int)xf2, xb, sizeof xb);
            x_rel = (xrd == 2 && xb[0] == 'y' && xb[1] == 'o');
            sys_close((int)xf2);
        }
        sys_close((int)wfd2);
    }
    int ok_xdir = (xg == 0 && xr == 0 && x_ino && x_nlink && x_abs && x_rel);
    cng_dprintf(1, "l2s-xdir: rc=%d ino=%d nlink3=%d abs=%d rel=%d -> %s\n",
                (int)xr, x_ino, x_nlink, x_abs, x_rel, ok_xdir ? "OK" : "FAIL");
    fails += !ok_xdir;

    /* Directory hiding: the ".l2s" store entry never shows in the root
     * listing (while real entries do). */
    int root_clean = 1, have_w = 0;
    long rfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/",
                            CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
    if (rfd >= 0) {
        char db[4096];
        long dn;
        while ((dn = cng_dispatch(__NR_getdents64, rfd, (long)db, sizeof db, 0,
                                  0, 0, 0)) > 0) {
            long o = 0;
            while (o + 19 <= dn) {
                unsigned short rl;
                memcpy(&rl, db + o + 16, 2);
                if (rl == 0 || o + rl > dn)
                    break;
                const char *nm = db + o + 19;
                if (!strncmp(nm, ".l2s", 4))
                    root_clean = 0;
                if (!strcmp(nm, "w"))
                    have_w = 1;
                o += rl;
            }
        }
        sys_close((int)rfd);
    }
    int ok_hide = (root_clean && have_w);
    cng_dprintf(1, "l2s-hide: root_clean=%d have_w=%d -> %s\n", root_clean,
                have_w, ok_hide ? "OK" : "FAIL");
    fails += !ok_hide;

    /* Handcraft a dir holding only legacy hidden files (raw host syscalls
     * bypass the guard), then list it through the dispatcher with a buffer so
     * small each batch holds one record: every batch filters away and the
     * listing must still terminate (the re-read loop, not a fake EOF). */
    char hh[CNG_PATH_MAX], hf1[CNG_PATH_MAX], hf2[CNG_PATH_MAX];
    dbg_mkpath(hh, sizeof hh, rootfs, "/w/h", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, hh, 0755, 0, 0, 0);
    dbg_mkpath(hf1, sizeof hf1, rootfs, "/w/h/.l2s.7", 0, 0);
    dbg_mkpath(hf2, sizeof hf2, rootfs, "/w/h/.l2s.7.0002", 0, 0);
    long tf = sys_openat(CNG_AT_FDCWD, hf1, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (tf >= 0)
        sys_close((int)tf);
    tf = sys_openat(CNG_AT_FDCWD, hf2, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (tf >= 0)
        sys_close((int)tf);
    int hb_clean = 1, hb_eof = 0;
    long hfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/h",
                            CNG_O_RDONLY | CNG_O_DIRECTORY, 0, 0, 0, 0);
    if (hfd >= 0) {
        char sb[48];
        for (int it = 0; it < 64; it++) {
            long dn = cng_dispatch(__NR_getdents64, hfd, (long)sb, sizeof sb,
                                   0, 0, 0, 0);
            if (dn == 0) {
                hb_eof = 1;
                break;
            }
            if (dn < 0)
                break;
            long o = 0;
            while (o + 19 <= dn) {
                unsigned short rl;
                memcpy(&rl, sb + o + 16, 2);
                if (rl == 0 || o + rl > dn)
                    break;
                const char *nm = sb + o + 19;
                if (strcmp(nm, ".") && strcmp(nm, ".."))
                    hb_clean = 0;
                o += rl;
            }
        }
        sys_close((int)hfd);
    }
    int ok_hb = (hb_clean && hb_eof);
    cng_dprintf(1, "l2s-hide-batch: clean=%d eof=%d -> %s\n", hb_clean, hb_eof,
                ok_hb ? "OK" : "FAIL");
    fails += !ok_hb;

    /* The machinery must appear nonexistent by name: creating a grammar-
     * matching file, statting the real data file, opening or chdir'ing into
     * the store — all ENOENT. */
    long dcr = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/.l2s.999",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    char gd[CNG_PATH_MAX];
    dbg_mkpath(gd, sizeof gd, "/.l2s/.l2s.", 0, ST_INO(sf), 1);
    char sdn[144];
    long dstt = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)gd,
                             (long)sdn, 0, 0, 0, 0);
    long dop = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/.l2s",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    long dch = cng_dispatch(__NR_chdir, (long)"/.l2s", 0, 0, 0, 0, 0, 0);
    int ok_deny = (dcr == -ENOENT && dstt == -ENOENT && dop == -ENOENT &&
                   dch == -ENOENT);
    cng_dprintf(1, "l2s-deny: create=%d data=%d store=%d chdir=%d -> %s\n",
                dcr == -ENOENT, dstt == -ENOENT, dop == -ENOENT,
                dch == -ENOENT, ok_deny ? "OK" : "FAIL");
    fails += !ok_deny;

    /* NOFOLLOW chown must land on the backing file: give the file setuid via
     * chmod (follows to the data), then chown with NOFOLLOW — the kernel
     * clears setuid on whichever inode it really chowned. */
    cng_dispatch(__NR_fchmodat, CNG_AT_FDCWD, (long)"/w/g", 04755, 0, 0, 0, 0);
    long cr = cng_dispatch(__NR_fchownat, CNG_AT_FDCWD, (long)"/w/g",
                           (long)sys_getuid(), (long)sys_getgid(),
                           CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    char sg[144];
    long rg = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/g",
                           (long)sg, 0, 0, 0, 0);
    int suid_cleared = (cr == 0 && rg == 0 && !(ST_MODE(sg) & 04000));
    cng_dprintf(1, "l2s-chown: suid_cleared=%d -> %s\n", suid_cleared,
                suid_cleared ? "OK" : "FAIL");
    fails += !suid_cleared;

    /* renameat2 flags: NOREPLACE refuses to clobber a link name (no decref);
     * EXCHANGE swaps the names without touching the count. */
    long pf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/p",
                           CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (pf >= 0) {
        sys_write((int)pf, "pp", 2);
        sys_close((int)pf);
    }
    long nrr = cng_dispatch(__NR_renameat2, CNG_AT_FDCWD, (long)"/w/p",
                            CNG_AT_FDCWD, (long)"/w/g", CNG_RENAME_NOREPLACE,
                            0, 0);
    char snr[144];
    long rnr = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                            (long)snr, 0, 0, 0, 0);
    int nr_ok = (nrr == -EEXIST && rnr == 0 && ST_NLINK(snr) == 3);
    cng_dprintf(1, "l2s-noreplace: eexist=%d nlink=%d -> %s\n", nrr == -EEXIST,
                rnr == 0 && ST_NLINK(snr) == 3, nr_ok ? "OK" : "FAIL");
    fails += !nr_ok;

    long exr = cng_dispatch(__NR_renameat2, CNG_AT_FDCWD, (long)"/w/p",
                            CNG_AT_FDCWD, (long)"/w/g", CNG_RENAME_EXCHANGE, 0,
                            0);
    char sp1[144], sf3[144];
    long rp1 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/p",
                            (long)sp1, 0, 0, 0, 0);
    long rf3 = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/f",
                            (long)sf3, 0, 0, 0, 0);
    int swapped = (rp1 == 0 && rf3 == 0 && ST_INO(sp1) == ST_INO(sf3));
    int ex_nlink = (rf3 == 0 && ST_NLINK(sf3) == 3);
    int ex_ok = (exr == 0 && swapped && ex_nlink);
    cng_dprintf(1, "l2s-exchange: rc=%d swapped=%d nlink3=%d -> %s\n",
                (int)exr, swapped, ex_nlink, ex_ok ? "OK" : "FAIL");
    fails += !ex_ok;

    /* Legacy (bare-basename) group: mv one name to another directory — the
     * dispatcher must repoint it at the unmoved data file. */
    char ofdir[CNG_PATH_MAX], od[CNG_PATH_MAX], om[CNG_PATH_MAX],
        ox[CNG_PATH_MAX], oy[CNG_PATH_MAX];
    dbg_mkpath(ofdir, sizeof ofdir, rootfs, "/w/of", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, ofdir, 0755, 0, 0, 0);
    dbg_mkpath(od, sizeof od, rootfs, "/w/of/.l2s.11", 0, 0);
    dbg_mkpath(om, sizeof om, rootfs, "/w/of/.l2s.11.0002", 0, 0);
    dbg_mkpath(ox, sizeof ox, rootfs, "/w/of/x", 0, 0);
    dbg_mkpath(oy, sizeof oy, rootfs, "/w/of/y", 0, 0);
    long odf = sys_openat(CNG_AT_FDCWD, od, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0) {
        sys_write((int)odf, "zz", 2);
        sys_close((int)odf);
    }
    odf = sys_openat(CNG_AT_FDCWD, om, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (odf >= 0)
        sys_close((int)odf);
    CNG_SYS(__NR_symlinkat, ".l2s.11", CNG_AT_FDCWD, ox, 0, 0, 0);
    CNG_SYS(__NR_symlinkat, ".l2s.11", CNG_AT_FDCWD, oy, 0, 0, 0);
    long mvr = cng_dispatch(__NR_renameat, CNG_AT_FDCWD, (long)"/w/of/x",
                            CNG_AT_FDCWD, (long)"/w/mvx", 0, 0, 0);
    char smx[144];
    long rmx = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/mvx",
                            (long)smx, 0, 0, 0, 0);
    int mv_reg = (mvr == 0 && rmx == 0 && ST_ISREG(smx));
    int mv_nlink = (rmx == 0 && ST_NLINK(smx) == 2);
    char mb[8];
    long mrd = -1;
    long mf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/mvx",
                           CNG_O_RDONLY, 0, 0, 0, 0);
    if (mf >= 0) {
        mrd = sys_read((int)mf, mb, sizeof mb);
        sys_close((int)mf);
    }
    int mv_content = (mrd == 2 && mb[0] == 'z' && mb[1] == 'z');
    int ok_mv = (mv_reg && mv_nlink && mv_content);
    cng_dprintf(1, "l2s-mvfix: reg=%d nlink2=%d content=%d -> %s\n", mv_reg,
                mv_nlink, mv_content, ok_mv ? "OK" : "FAIL");
    fails += !ok_mv;

    /* O_TMPFILE + linkat(fd, "", ..., AT_EMPTY_PATH): the anonymous file is
     * published (by content copy — nothing to symlink to). */
    long tmf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                            CNG_O_TMPFILE | CNG_O_RDWR, 0644, 0, 0, 0);
    long tlr = -1;
    int t_reg = 0, t_content = 0, t_mode = 0;
    if (tmf >= 0) {
        sys_write((int)tmf, "tt", 2);
        tlr = cng_dispatch(__NR_linkat, tmf, (long)"", CNG_AT_FDCWD,
                           (long)"/w/t", CNG_AT_EMPTY_PATH, 0, 0);
        sys_close((int)tmf);
        char stt[144];
        long rt = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/t",
                               (long)stt, 0, 0, 0, 0);
        t_reg = (rt == 0 && ST_ISREG(stt));
        /* a real link shares the inode's mode, so the copy must keep 0644 */
        t_mode = (rt == 0 && (ST_MODE(stt) & 07777) == 0644);
        char tb[8];
        long trd = -1;
        long tf2 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/t",
                                CNG_O_RDONLY, 0, 0, 0, 0);
        if (tf2 >= 0) {
            trd = sys_read((int)tf2, tb, sizeof tb);
            sys_close((int)tf2);
        }
        t_content = (trd == 2 && tb[0] == 't' && tb[1] == 't');
    }
    int ok_tmp = (tlr == 0 && t_reg && t_content && t_mode);
    cng_dprintf(1, "l2s-tmpfile: rc=%d reg=%d content=%d mode=%d -> %s\n",
                (int)tlr, t_reg, t_content, t_mode, ok_tmp ? "OK" : "FAIL");
    fails += !ok_tmp;

    /* linkat by fd on a live group member bumps that group. */
    long lff = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/f",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    long flr = -1;
    int fd_nl = 0;
    if (lff >= 0) {
        flr = cng_dispatch(__NR_linkat, lff, (long)"", CNG_AT_FDCWD,
                           (long)"/w/j", CNG_AT_EMPTY_PATH, 0, 0);
        sys_close((int)lff);
        char sj[144];
        long rj = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/j",
                               (long)sj, 0, 0, 0, 0);
        fd_nl = (rj == 0 && ST_NLINK(sj) == 4 && ST_INO(sj) == ST_INO(sf));
    }
    int ok_fdl = (flr == 0 && fd_nl);
    cng_dprintf(1, "l2s-fdlink: rc=%d nlink4=%d -> %s\n", (int)flr, fd_nl,
                ok_fdl ? "OK" : "FAIL");
    fails += !ok_fdl;

    /* O_NOFOLLOW: opening a link name through a dirfd succeeds on the backing
     * file, while a real guest symlink still draws ELOOP. */
    int nf_open = 0, nf_content = 0, nf_sym = 0;
    long wfd3 = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                             CNG_O_RDONLY, 0, 0, 0, 0);
    if (wfd3 >= 0) {
        long nff = cng_dispatch(__NR_openat, wfd3, (long)"f",
                                CNG_O_RDONLY | CNG_O_NOFOLLOW, 0, 0, 0, 0);
        if (nff >= 0) {
            nf_open = 1;
            char nb[8];
            long nrd = sys_read((int)nff, nb, sizeof nb);
            nf_content = (nrd == 2 && nb[0] == 'y' && nb[1] == 'o');
            sys_close((int)nff);
        }
        cng_dispatch(__NR_symlinkat, (long)"f", wfd3, (long)"sym", 0, 0, 0, 0);
        long nfs = cng_dispatch(__NR_openat, wfd3, (long)"sym",
                                CNG_O_RDONLY | CNG_O_NOFOLLOW, 0, 0, 0, 0);
        nf_sym = (nfs == -ELOOP);
        if (nfs >= 0)
            sys_close((int)nfs);
        sys_close((int)wfd3);
    }
    int ok_nf = (nf_open && nf_content && nf_sym);
    cng_dprintf(1, "l2s-nofollow: open=%d content=%d sym_eloop=%d -> %s\n",
                nf_open, nf_content, nf_sym, ok_nf ? "OK" : "FAIL");
    fails += !ok_nf;

    /* Legacy per-dir format end to end (what arm64chroot writes, and what a
     * pre-store chroot-ng left behind): stat, same-dir bump keeping the
     * legacy look, cross-dir join via absolute target, decref, readlink. */
    char ogdir[CNG_PATH_MAX], od2[CNG_PATH_MAX], om2[CNG_PATH_MAX],
        ou[CNG_PATH_MAX], ov[CNG_PATH_MAX], om3[CNG_PATH_MAX];
    dbg_mkpath(ogdir, sizeof ogdir, rootfs, "/w/og", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, ogdir, 0755, 0, 0, 0);
    dbg_mkpath(od2, sizeof od2, rootfs, "/w/og/.l2s.13", 0, 0);
    dbg_mkpath(om2, sizeof om2, rootfs, "/w/og/.l2s.13.0002", 0, 0);
    dbg_mkpath(om3, sizeof om3, rootfs, "/w/og/.l2s.13.0003", 0, 0);
    dbg_mkpath(ou, sizeof ou, rootfs, "/w/og/u", 0, 0);
    dbg_mkpath(ov, sizeof ov, rootfs, "/w/og/v", 0, 0);
    odf = sys_openat(CNG_AT_FDCWD, od2, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0) {
        sys_write((int)odf, "qq", 2);
        sys_close((int)odf);
    }
    odf = sys_openat(CNG_AT_FDCWD, om2, CNG_O_CREAT | CNG_O_WRONLY, 0600);
    if (odf >= 0)
        sys_close((int)odf);
    CNG_SYS(__NR_symlinkat, ".l2s.13", CNG_AT_FDCWD, ou, 0, 0, 0);
    CNG_SYS(__NR_symlinkat, ".l2s.13", CNG_AT_FDCWD, ov, 0, 0, 0);
    char sdn2[144], su[144];
    long rdn2 = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, od2, sdn2,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    long ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/u",
                           (long)su, 0, 0, 0, 0);
    int old_reg = (ru == 0 && ST_ISREG(su) && ST_NLINK(su) == 2);
    int old_same = (rdn2 == 0 && ru == 0 && ST_INO(su) == ST_INO(sdn2));
    long ol1 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            CNG_AT_FDCWD, (long)"/w/og/z", 0, 0, 0);
    char smk[144];
    long rm3 = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, om3, smk,
                       CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/z",
                      (long)su, 0, 0, 0, 0);
    int old_bump = (ol1 == 0 && rm3 == 0 && ru == 0 && ST_NLINK(su) == 3);
    long ol2 = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            CNG_AT_FDCWD, (long)"/w/z2", 0, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/z2", (long)su,
                      0, 0, 0, 0);
    int old_xdir = (ol2 == 0 && ru == 0 && ST_NLINK(su) == 4 &&
                    rdn2 == 0 && ST_INO(su) == ST_INO(sdn2));
    cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/z2", 0, 0, 0, 0, 0);
    cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/w/og/z", 0, 0, 0, 0, 0);
    ru = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/og/u",
                      (long)su, 0, 0, 0, 0);
    int old_back = (ru == 0 && ST_NLINK(su) == 2);
    char orb[64];
    long orl = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)"/w/og/u",
                            (long)orb, sizeof orb, 0, 0, 0);
    int old_einval = (orl == -EINVAL);
    int ok_old = (old_reg && old_same && old_bump && old_xdir && old_back &&
                  old_einval);
    cng_dprintf(1,
                "l2s-old: reg=%d same=%d bump3=%d xdir4=%d back2=%d "
                "einval=%d -> %s\n",
                old_reg, old_same, old_bump, old_xdir, old_back, old_einval,
                ok_old ? "OK" : "FAIL");
    fails += !ok_old;

    /* Store unusable (a plain file squats on "<root>/.l2s"): first links fall
     * back to the per-dir scheme beside the source. Exercised under a second
     * rootfs so the real store stays live. */
    char fbroot[CNG_PATH_MAX], fbsq[CNG_PATH_MAX], fbw[CNG_PATH_MAX];
    dbg_mkpath(fbroot, sizeof fbroot, rootfs, "/fb", 0, 0);
    dbg_mkpath(fbsq, sizeof fbsq, rootfs, "/fb/.l2s", 0, 0);
    dbg_mkpath(fbw, sizeof fbw, rootfs, "/fb/w", 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, fbroot, 0755, 0, 0, 0);
    CNG_SYS(__NR_mkdirat, CNG_AT_FDCWD, fbw, 0755, 0, 0, 0);
    odf = sys_openat(CNG_AT_FDCWD, fbsq, CNG_O_CREAT | CNG_O_WRONLY, 0644);
    if (odf >= 0)
        sys_close((int)odf);
    static struct cng_fs fs2;
    cng_fs_init(&fs2, fbroot);
    cng_g_fs = &fs2;
    long fbf = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (fbf >= 0) {
        sys_write((int)fbf, "ff", 2);
        sys_close((int)fbf);
    }
    long fbl = cng_dispatch(__NR_linkat, CNG_AT_FDCWD, (long)"/w/a",
                            CNG_AT_FDCWD, (long)"/w/b", 0, 0, 0);
    char sfa[144], sfb[144];
    long rfa = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/a",
                            (long)sfa, 0, 0, 0, 0);
    long rfb = cng_dispatch(__NR_newfstatat, CNG_AT_FDCWD, (long)"/w/b",
                            (long)sfb, 0, 0, 0, 0);
    int fb_reg = (fbl == 0 && rfa == 0 && rfb == 0 && ST_ISREG(sfa) &&
                  ST_NLINK(sfa) == 2 && ST_NLINK(sfb) == 2);
    int fb_same = (rfa == 0 && rfb == 0 && ST_INO(sfa) == ST_INO(sfb));
    int fb_beside = (dbg_has_l2s(fbw) == 1);
    cng_g_fs = &fs;
    int ok_fb = (fb_reg && fb_same && fb_beside);
    cng_dprintf(1, "l2s-storefail: rc=%d reg=%d sameino=%d beside=%d -> %s\n",
                (int)fbl, fb_reg, fb_same, fb_beside, ok_fb ? "OK" : "FAIL");
    fails += !ok_fb;

    /* glibc passes int args (dirfds) in w-registers and may leave the
     * x-register's top half dirty; the monitor must truncate before
     * comparing (Debian `ln a b` regression: AT_FDCWD arrived garbage-topped
     * and source resolution failed with ENOENT). */
    long dirty = (long)0xdeadbeef00000000ULL | (unsigned)CNG_AT_FDCWD;
    cng_dispatch(__NR_chdir, (long)"/w", 0, 0, 0, 0, 0, 0);
    long dcf = cng_dispatch(__NR_openat, dirty, (long)"da",
                            CNG_O_CREAT | CNG_O_WRONLY, 0644, 0, 0, 0);
    if (dcf >= 0) {
        sys_write((int)dcf, "dd", 2);
        sys_close((int)dcf);
    }
    long dlr = cng_dispatch(__NR_linkat, dirty, (long)"da", dirty, (long)"db",
                            0, 0, 0);
    char sdd[144];
    long drr = cng_dispatch(__NR_newfstatat, dirty, (long)"da", (long)sdd, 0,
                            0, 0, 0);
    int dirty_ok = (dlr == 0 && drr == 0 && ST_NLINK(sdd) == 2);
    cng_dprintf(1, "l2s-dirtyfd: rc=%d nlink2=%d -> %s\n", (int)dlr,
                drr == 0 && ST_NLINK(sdd) == 2, dirty_ok ? "OK" : "FAIL");
    fails += !dirty_ok;
    cng_dispatch(__NR_chdir, (long)"/", 0, 0, 0, 0, 0, 0);

    cng_blocked[__NR_linkat] = 0;
    cng_g_l2s = 0;

    /* fchdir cwd tracking. */
    long dfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/w",
                            CNG_O_RDONLY, 0, 0, 0, 0);
    if (dfd >= 0) {
        cng_dispatch(__NR_fchdir, dfd, 0, 0, 0, 0, 0, 0);
        sys_close((int)dfd);
    }
    int ok_cwd = (strcmp(cng_g_fs->cwd, "/w") == 0);
    cng_dprintf(1, "fchdir: cwd=%s -> %s\n", cng_g_fs->cwd,
                ok_cwd ? "OK" : "FAIL");
    fails += !ok_cwd;

    /* chdir through a symlink records where it LANDED, as the kernel's cwd is
     * the directory itself — so getcwd reports the symlink-free name and a
     * later ".." backs out of the real parent, not the link's. */
    cng_dispatch(__NR_symlinkat, (long)"/w", CNG_AT_FDCWD, (long)"/wlink", 0, 0,
                 0, 0);
    long lch = cng_dispatch(__NR_chdir, (long)"/wlink", 0, 0, 0, 0, 0, 0);
    int ok_link = (lch == 0 && strcmp(cng_g_fs->cwd, "/w") == 0);
    cng_dprintf(1, "chdir-symlink: rc=%d cwd=%s -> %s\n", (int)lch,
                cng_g_fs->cwd, ok_link ? "OK" : "FAIL");
    fails += !ok_link;
    cng_dispatch(__NR_chdir, (long)"/", 0, 0, 0, 0, 0, 0);
    cng_dispatch(__NR_unlinkat, CNG_AT_FDCWD, (long)"/wlink", 0, 0, 0, 0, 0);
    return fails ? 1 : 0;
}

/* _cloexectest — emulated execve must close FD_CLOEXEC fds like a real execve
 * (else fork/exec launchers' O_CLOEXEC notify pipes never close and the parent
 * hangs — the git-clone symptom). Open one CLOEXEC and one plain fd, run the
 * close pass, and check only the CLOEXEC one went away. */
int cng_cmd_cloexectest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    long ce = sys_openat(CNG_AT_FDCWD, "/dev/null",
                         CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    long pl = sys_openat(CNG_AT_FDCWD, "/dev/null", CNG_O_RDONLY, 0);
    cng_close_cloexec();
    long ce_fl = CNG_SYS(__NR_fcntl, (int)ce, 1 /*F_GETFD*/, 0, 0, 0, 0);
    long pl_fl = CNG_SYS(__NR_fcntl, (int)pl, 1 /*F_GETFD*/, 0, 0, 0, 0);
    int ok = (ce >= 0 && pl >= 0 && ce_fl == -EBADF && pl_fl >= 0);
    cng_dprintf(1, "cloexec: cloexec_closed=%d plain_open=%d -> %s\n",
                ce_fl == -EBADF, pl_fl >= 0, ok ? "OK" : "FAIL");
    if (pl >= 0)
        sys_close((int)pl);
    return ok ? 0 : 1;
}

/* _stackswtest — validate the handler's stack switch (cng_run_on_stack): the
 * callee must run on the scratch stack, its result must propagate, and the
 * caller's stack must be intact afterward. */
extern long cng_run_on_stack(void *newsp, void *fn, void *a0, void *a1);

static long sp_probe(void *lo, void *hi) {
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    /* return 1 iff we are running on the [lo,hi] scratch region */
    return (sp > (unsigned long)lo && sp <= (unsigned long)hi) ? 0xC0DE : sp;
}

int cng_cmd_stackswtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    unsigned long marker = 0xA5A5A5A5;
    void *base = sys_mmap(0, 256 * 1024, CNG_PROT_READ | CNG_PROT_WRITE,
                          CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    int mapped = !(base == CNG_MAP_FAILED || cng_is_err((long)base));
    unsigned long top = mapped ? (((unsigned long)base + 256 * 1024) & ~15UL) : 0;
    long r = mapped ? cng_run_on_stack((void *)top, (void *)sp_probe, base,
                                       (void *)top)
                    : -1;
    /* If SP was corrupted by the switch, `marker` on our frame would be clobbered
     * and subsequent use would crash; check it survived. */
    int ok = (mapped && r == 0xC0DE && marker == 0xA5A5A5A5);
    cng_dprintf(1, "stacksw: ran_on_scratch=%d ret=0x%lx caller_ok=%d -> %s\n",
                r == 0xC0DE, (unsigned long)r, marker == 0xA5A5A5A5,
                ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _clonetest — a CLONE_VFORK|CLONE_VM clone must be converted to a real (COW)
 * fork by the dispatcher, so the child gets a private address space (our
 * emulated execve would otherwise corrupt the shared parent). Verify the child
 * runs and exits, and that a write in the child is NOT visible in the parent. */
int cng_cmd_clonetest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    volatile long marker = 0;
    long pid = cng_dispatch(__NR_clone,
                            CNG_CLONE_VM | CNG_CLONE_VFORK | 17 /*SIGCHLD*/, 0, 0,
                            0, 0, 0, /*trapped=*/1);
    if (pid == 0) {        /* child */
        marker = 1;        /* if the VM were shared, the parent would see this */
        sys_exit_group(7);
    }
    int status = 0;
    sys_wait4((int)pid, &status, 0, 0);
    int exited7 = ((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 7);
    int private_vm = (marker == 0); /* real fork => parent's copy untouched */
    int ok = (pid > 0 && exited7 && private_vm);
    cng_dprintf(1, "clone: pid>0=%d child_exit7=%d private_vm=%d -> %s\n",
                pid > 0, exited7, private_vm, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _clonestktest — a vfork-style clone with a caller-provided child stack (as
 * musl's __clone/posix_spawn passes) must, after conversion, resume the child on
 * that stack. Drive cng_sigsys_body (the real SIGSYS path) with a synthetic
 * clone context and check it forks and sets the child's uc->sp to the child
 * stack while leaving the parent's untouched. */
int cng_cmd_clonestktest(int argc, char **argv, char **envp,
                         unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;

    void *cs = sys_mmap(0, 65536, CNG_PROT_READ | CNG_PROT_WRITE,
                        CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (cs == CNG_MAP_FAILED || cng_is_err((long)cs)) {
        cng_dprintf(1, "clonestk: mmap -> FAIL\n");
        return 1;
    }
    unsigned long cs_top = ((unsigned long)cs + 65536) & ~15UL;
    unsigned long sentinel = 0x5eed0d5eed0d0000UL;

    static struct cng_ucontext uc;
    memset(&uc, 0, sizeof uc);
    unsigned long long *r = uc.uc_mcontext.regs;
    r[8] = __NR_clone;
    r[0] = CNG_CLONE_VM | CNG_CLONE_VFORK | 17; /* SIGCHLD */
    r[1] = cs_top;                              /* caller-provided child stack */
    uc.uc_mcontext.sp = sentinel;               /* guest's original sp */

    cng_siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_code = CNG_SYS_SECCOMP;
    si._u._sigsys.call_addr = (void *)0x1000; /* not in gate -> guest syscall */
    si._u._sigsys.syscall = __NR_clone;

    cng_sigsys_body(&uc, &si); /* forks internally */

    if (uc.uc_mcontext.regs[0] == 0)           /* child */
        sys_exit_group(uc.uc_mcontext.sp == cs_top ? 7 : 8);

    long pid = (long)uc.uc_mcontext.regs[0];
    int status = 0;
    sys_wait4((int)pid, &status, 0, 0);
    int child_sp_ok = ((status & 0x7f) == 0 && ((status >> 8) & 0xff) == 7);
    int parent_sp_ok = (uc.uc_mcontext.sp == sentinel);
    int ok = (pid > 0 && child_sp_ok && parent_sp_ok);
    cng_dprintf(1,
                "clonestk: pid>0=%d child_sp=childstk=%d parent_sp=orig=%d "
                "-> %s\n",
                pid > 0, child_sp_ok, parent_sp_ok, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* _nettest — drive cng_sigsys_body with synthetic seccomp contexts to validate
 * the Android SIGSYS net branching (no real seccomp needed). */
int cng_cmd_nettest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    static struct cng_fs fs;
    cng_fs_init(&fs, "/");
    cng_g_fs = &fs;
    int fails = 0;

    /* 1) gate-net: a seccomp trap whose svc is our gate -> ENOSYS. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)__cng_gate_start;
        si._u._sigsys.syscall = 144; /* setgid */
        uc.uc_mcontext.regs[8] = 144;
        uc.uc_mcontext.regs[0] = 0x1234;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == -ENOSYS);
        cng_dprintf(1, "nettest gate-net: regs0=%d want=%d -> %s\n", (int)got,
                    (int)-ENOSYS, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2) non-gate seccomp trap of a translated path syscall -> dispatched and
     * re-issued (faccessat "/" with identity rootfs succeeds). */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        const char *root = "/";
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000; /* not the gate */
        uc.uc_mcontext.regs[8] = __NR_faccessat;
        uc.uc_mcontext.regs[0] = (unsigned long long)(long)CNG_AT_FDCWD;
        uc.uc_mcontext.regs[1] = (unsigned long long)(unsigned long)root;
        uc.uc_mcontext.regs[2] = 0; /* F_OK */
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == 0);
        cng_dprintf(1, "nettest dispatch: faccessat(/)=%d -> %s\n", (int)got,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2b) a blocked non-path syscall reaching default -> emulated ENOSYS. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;
        uc.uc_mcontext.regs[8] = __NR_setgid;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == -ENOSYS);
        cng_dprintf(1, "nettest blocked-direct: setgid=%d want=%d -> %s\n",
                    (int)got, (int)-ENOSYS, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2c) rt_sigprocmask(SETMASK, block-all) must apply the mask but leave
     * SIGSYS unblocked (else a later blocked seccomp trap force-kills). */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        unsigned long block_all = ~0UL;
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;
        uc.uc_mcontext.regs[8] = __NR_rt_sigprocmask;
        uc.uc_mcontext.regs[0] = 2; /* SIG_SETMASK */
        uc.uc_mcontext.regs[1] = (unsigned long)&block_all;
        uc.uc_mcontext.regs[3] = sizeof(cng_sigset_t);
        uc.uc_sigmask.sig[0] = 0;
        cng_sigsys_body(&uc, &si);
        int sigsys_blocked = (uc.uc_sigmask.sig[0] >> (CNG_SIGSYS - 1)) & 1;
        long ret = (long)uc.uc_mcontext.regs[0];
        int ok = (ret == 0 && !sigsys_blocked);
        cng_dprintf(1, "nettest sigprocmask: ret=%d sigsys_blocked=%d -> %s\n",
                    (int)ret, sigsys_blocked, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2d) the same call with ONE variable for both masks — sigprocmask(how, &m,
     * &m) is legal and common. The writability probe validates a range by
     * zeroing it, so the new mask has to be read out before the old-mask pointer
     * is probed, or SIG_UNBLOCK clears everything instead of the one signal
     * named. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        unsigned long usr1 = 1UL << (CNG_SIGUSR1 - 1);
        unsigned long usr2 = 1UL << (12 /*SIGUSR2*/ - 1);
        unsigned long m = usr1;
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;
        uc.uc_mcontext.regs[8] = __NR_rt_sigprocmask;
        uc.uc_mcontext.regs[0] = 1; /* SIG_UNBLOCK */
        uc.uc_mcontext.regs[1] = (unsigned long)&m;
        uc.uc_mcontext.regs[2] = (unsigned long)&m; /* the same variable */
        uc.uc_mcontext.regs[3] = sizeof(cng_sigset_t);
        uc.uc_sigmask.sig[0] = usr1 | usr2;
        cng_sigsys_body(&uc, &si);
        int ok = (long)uc.uc_mcontext.regs[0] == 0 &&
                 uc.uc_sigmask.sig[0] == usr2 && m == (usr1 | usr2);
        cng_dprintf(1, "nettest sigprocmask aliased: mask=0x%lx old=0x%lx -> %s\n",
                    uc.uc_sigmask.sig[0], m, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 2e) the two argument checks the kernel makes before it changes anything:
     * a sigsetsize that is not its own, and a `how` outside the three it
     * defines. This call is answered entirely in the handler, so nothing else
     * was going to make them — a bad size passed silently, and any other `how`
     * was taken as SIG_SETMASK, which REPLACES the mask a miscalled SIG_BLOCK
     * meant to add to. Both must leave the mask exactly as it was. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        unsigned long usr1 = 1UL << (CNG_SIGUSR1 - 1);
        unsigned long set = 0;
        long bad_size, bad_how;
        int kept_size, kept_how;
        memset(&si, 0, sizeof si);
        si.si_code = CNG_SYS_SECCOMP;
        si._u._sigsys.call_addr = (void *)0x1000;

        memset(&uc, 0, sizeof uc);
        uc.uc_mcontext.regs[8] = __NR_rt_sigprocmask;
        uc.uc_mcontext.regs[0] = 2; /* SIG_SETMASK */
        uc.uc_mcontext.regs[1] = (unsigned long)&set;
        uc.uc_mcontext.regs[3] = 4; /* not the kernel's sigset_t */
        uc.uc_sigmask.sig[0] = usr1;
        cng_sigsys_body(&uc, &si);
        bad_size = (long)uc.uc_mcontext.regs[0];
        kept_size = uc.uc_sigmask.sig[0] == usr1;

        memset(&uc, 0, sizeof uc);
        uc.uc_mcontext.regs[8] = __NR_rt_sigprocmask;
        uc.uc_mcontext.regs[0] = 7; /* no such `how` */
        uc.uc_mcontext.regs[1] = (unsigned long)&set;
        uc.uc_mcontext.regs[3] = sizeof(cng_sigset_t);
        uc.uc_sigmask.sig[0] = usr1;
        cng_sigsys_body(&uc, &si);
        bad_how = (long)uc.uc_mcontext.regs[0];
        kept_how = uc.uc_sigmask.sig[0] == usr1;

        int ok = bad_size == -EINVAL && kept_size && bad_how == -EINVAL &&
                 kept_how;
        cng_dprintf(1,
                    "nettest sigprocmask args: size=%d kept=%d how=%d kept=%d "
                    "-> %s\n",
                    (int)bad_size, kept_size, (int)bad_how, kept_how,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }
    /* 3) guest-directed SIGSYS (si_code != SYS_SECCOMP) -> untouched. */
    {
        struct cng_ucontext uc;
        cng_siginfo_t si;
        memset(&uc, 0, sizeof uc);
        memset(&si, 0, sizeof si);
        si.si_code = 0;
        uc.uc_mcontext.regs[0] = 0xABCD;
        cng_sigsys_body(&uc, &si);
        long got = (long)uc.uc_mcontext.regs[0];
        int ok = (got == 0xABCD);
        cng_dprintf(1, "nettest passthrough: regs0=0x%lx -> %s\n",
                    (unsigned long)got, ok ? "OK" : "FAIL");
        fails += !ok;
    }
    return fails ? 1 : 0;
}

/* _proctest -r ROOT [-b G:H] — exercise the /proc emulation through the
 * dispatcher: the passthrough and its hidden-process view, the registry-backed
 * files (cmdline, environ), the synthesized mount table, the time-varying
 * files and their refresh-on-rewind, the fake-id status remap, and the fd-link
 * untranslation. No seccomp needed: every check calls cng_dispatch directly. */

/* Read a whole synthesized fd into `buf`; returns the byte count or -1. */
static long pt_slurp(long fd, char *buf, size_t cap) {
    if (fd < 0)
        return -1;
    long total = 0;
    for (;;) {
        long n = sys_read((int)fd, buf + total, cap - 1 - (size_t)total);
        if (n <= 0)
            break;
        total += n;
        if ((size_t)total >= cap - 1)
            break;
    }
    buf[total] = '\0';
    return total;
}

/* Open a guest path through the dispatcher (the openat the guest would make). */
static long pt_open(const char *guest) {
    return cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)guest,
                        CNG_O_RDONLY | CNG_O_CLOEXEC, 0, 0, 0, /*trapped=*/0);
}

/* 1 if `hay` contains `needle`. */
static int pt_has(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++)
        if (!strncmp(p, needle, nl))
            return 1;
    return 0;
}

/* Count of NUL-separated entries in a cmdline/environ blob. */
static int pt_nul_fields(const char *b, long n) {
    int c = 0;
    for (long i = 0; i < n; i++)
        if (!b[i])
            c++;
    return c;
}

int cng_cmd_proctest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)auxv;
    const char *rootfs = "/";
    const char *bind_spec = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc)
            rootfs = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc)
            bind_spec = argv[++i];
    }

    static struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    if (bind_spec) {
        char spec[512];
        cng_strlcpy(spec, bind_spec, sizeof spec);
        char *c = strchr(spec, ':');
        if (c) { /* SRC:DST[:ro] — host first, as the -b CLI option spells it */
            *c = '\0';
            char *dst = c + 1;
            int ro = 0;
            unsigned long dl = strlen(dst);
            if (dl >= 3 && !strcmp(dst + dl - 3, ":ro")) {
                ro = 1;
                dst[dl - 3] = '\0';
            }
            cng_fs_add_bind(&fs, dst, spec, ro);
        }
    }
    cng_g_fs = &fs;
    cng_g_exe_guest = "/bin/busybox";
    cng_g_procstat_synth = 1; /* exercise the fallback where the host allows /proc/stat */

    int fails = 0;
    char buf[8192];
    int self = (int)sys_getpid();

    /* The guest identity this process publishes; the registry-backed files must
     * hand back exactly these bytes. The registry runs broker-backed
     * (--shared-proc) so every check below also exercises that plumbing; the
     * mktemp rootfs keys a fresh broker per run. */
    static char *gargv[] = {"/bin/busybox", "sh", "-c", "true", 0};
    static char *genvp[] = {"PATH=/usr/bin:/bin", "HOME=/root", 0};
    cng_g_host_envp = envp; /* shared_dir env lookups (file-tier fallback) */
    cng_g_shared_proc = 1;
    cng_procfs_init();
    cng_procreg_publish(gargv, genvp, 0, 0, cng_g_exe_guest, "/");

    /* 0) the --shared-proc backing actually engaged: the broker daemon must
     *    have spawned and handed us its memfd (a degrade to the file or
     *    anonymous tier on a normal host is a broker bug). */
    {
        int ok = cng_g_procreg_backing == CNG_PROCREG_B_BROKER;
        cng_dprintf(1, "proctest shared-proc backing: %d -> %s\n",
                    cng_g_procreg_backing, ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 1) passthrough + hidden-process view, at the path layer. */
    {
        char out[CNG_PATH_MAX];
        int ok = 1;
        ok &= cng_fs_translate(&fs, "/proc/self/status", out, sizeof out) == 0 &&
              !strcmp(out, "/proc/self/status");
        ok &= cng_fs_translate(&fs, "/proc/version", out, sizeof out) == 0 &&
              !strcmp(out, "/proc/version");
        /* our own pid is a guest process: visible */
        char mine[64];
        cng_snprintf(mine, sizeof mine, "/proc/%d/stat", self);
        ok &= cng_fs_translate(&fs, mine, out, sizeof out) == 0 &&
              !strcmp(out, mine);
        /* pid 1 is a host process: redirected to /proc/0, which never exists */
        ok &= cng_fs_translate(&fs, "/proc/1/stat", out, sizeof out) == 0 &&
              !strcmp(out, "/proc/0/stat");
        cng_dprintf(1, "proctest passthrough+hidden -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 1b) the hidden view keys on where the path LANDS, not on which map rule
     *     put it there: binding the host /proc at /proc must not hand the guest
     *     the host's process list back. The listing side of the same rule is
     *     proc_name_visible, driven through the getdents64 hook. */
    {
        static struct cng_fs pb;
        cng_fs_init(&pb, rootfs);
        cng_fs_add_bind(&pb, "/proc", "/proc", 0);
        char out[CNG_PATH_MAX];
        int ok = 1;
        ok &= cng_fs_translate(&pb, "/proc/1/stat", out, sizeof out) == 0 &&
              !strcmp(out, "/proc/0/stat");
        char mine[64];
        cng_snprintf(mine, sizeof mine, "/proc/%d/stat", self);
        ok &= cng_fs_translate(&pb, mine, out, sizeof out) == 0 &&
              !strcmp(out, mine);
        /* non-numeric names are unaffected by the bind */
        ok &= cng_fs_translate(&pb, "/proc/version", out, sizeof out) == 0 &&
              !strcmp(out, "/proc/version");
        cng_dprintf(1, "proctest bound-proc hidden -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 1c) the listing filter itself: host pids are dropped from a /proc
     *     listing, guest pids and named entries survive. */
    {
        long dfd = cng_dispatch(__NR_openat, CNG_AT_FDCWD, (long)"/proc",
                                CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                                0, 0, 0, /*trapped=*/0);
        int ok = dfd >= 0, saw_self = 0, saw_mine = 0, saw_host = 0;
        while (dfd >= 0) {
            long n = cng_dispatch(__NR_getdents64, dfd, (long)buf, sizeof buf, 0,
                                  0, 0, /*trapped=*/0);
            if (n <= 0)
                break;
            for (long o = 0; o + 19 <= n;) {
                unsigned short reclen;
                memcpy(&reclen, buf + o + 16, 2);
                if (reclen == 0 || o + reclen > n)
                    break;
                const char *nm = buf + o + 19;
                if (!strcmp(nm, "self"))
                    saw_self = 1;
                if (nm[0] >= '0' && nm[0] <= '9') {
                    long pid = 0;
                    for (const char *p = nm; *p >= '0' && *p <= '9'; p++)
                        pid = pid * 10 + (*p - '0');
                    if (pid == self)
                        saw_mine = 1;
                    else if (!cng_procreg_has((int)pid))
                        saw_host = 1;
                }
                o += reclen;
            }
        }
        if (dfd >= 0)
            sys_close((int)dfd);
        ok = ok && saw_self && saw_mine && !saw_host;
        cng_dprintf(1, "proctest listing: self=%d own_pid=%d host_pids=%d -> %s\n",
                    saw_self, saw_mine, saw_host, ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 2) cmdline and environ come from the registry, not from our own exec. */
    {
        long fd = pt_open("/proc/self/cmdline");
        long n = pt_slurp(fd, buf, sizeof buf);
        int ok = n > 0 && !strcmp(buf, "/bin/busybox") &&
                 pt_nul_fields(buf, n) == 4 && pt_has(buf + 13, "sh");
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest cmdline: %ld bytes argv0=%s -> %s\n", n, buf,
                    ok ? "OK" : "FAIL");
        fails += !ok;

        fd = pt_open("/proc/self/environ");
        n = pt_slurp(fd, buf, sizeof buf);
        ok = n > 0 && pt_nul_fields(buf, n) == 2 && !strcmp(buf, genvp[0]);
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest environ: %ld bytes -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 3) the same files for ANOTHER guest process, via a real fork the parent
     *    registers exactly as the clone hook does. */
    {
        long kid = sys_fork();
        if (kid == 0) { /* outlive the parent's checks, then go away */
            struct cng_timespec nap = {5, 0};
            CNG_SYS(__NR_nanosleep, &nap, 0, 0, 0, 0, 0);
            sys_exit_group(0);
        }
        int ok = kid > 0;
        if (ok) {
            cng_procreg_fork((int)kid);
            ok &= cng_procreg_has((int)kid);
            char p[64];
            cng_snprintf(p, sizeof p, "/proc/%d/cmdline", (int)kid);
            long fd = pt_open(p);
            long n = pt_slurp(fd, buf, sizeof buf);
            ok &= n > 0 && !strcmp(buf, "/bin/busybox");
            if (fd >= 0)
                sys_close((int)fd);
            /* and its exe/cwd links resolve in guest terms */
            char lb[CNG_PATH_MAX];
            cng_snprintf(p, sizeof p, "/proc/%d/exe", (int)kid);
            long r = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)p,
                                  (long)lb, sizeof lb - 1, 0, 0, 0);
            if (r > 0)
                lb[r] = '\0';
            ok &= r > 0 && !strcmp(lb, "/bin/busybox");
            CNG_SYS(__NR_kill, kid, 9, 0, 0, 0, 0);
            sys_wait4((int)kid, 0, 0, 0);
        }
        cng_dprintf(1, "proctest other-pid: -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 3b) two registry properties around a child's slot. First, ordering: an
     *     exec the child has already published must survive the parent's
     *     later fork-publish (cng_procreg_fork backs off from a slot already
     *     stamped with the child's own incarnation). Second, death: once the
     *     child is reaped its slot must stop answering, or a host process
     *     that gets the pid next would inherit the dead guest's identity —
     *     exit is not a trapped syscall, so the starttime check inside
     *     cng_procreg_has is the only thing standing there. */
    {
        int pfd[2] = {-1, -1};
        int ok = CNG_SYS(__NR_pipe2, pfd, 0, 0, 0, 0, 0) == 0;
        long kid = ok ? sys_fork() : -1;
        if (kid == 0) { /* the "exec": publish an identity of our own */
            static char *kargv[] = {"/bin/kid-prog", 0};
            static char *kenvp[] = {"K=1", 0};
            cng_procreg_publish(kargv, kenvp, 0, 0, "/bin/kid-prog", "/");
            sys_close(pfd[0]);
            cng_write_all(pfd[1], "x", 1);
            struct cng_timespec nap = {5, 0};
            CNG_SYS(__NR_nanosleep, &nap, 0, 0, 0, 0, 0);
            sys_exit_group(0);
        }
        ok &= kid > 0;
        int st = 0; /* first failed stage, 0 = none */
        if (ok) {
            char c;
            sys_close(pfd[1]);
            if (sys_read(pfd[0], &c, 1) != 1)
                st = 1; /* child never published its exec */
            sys_close(pfd[0]);
            cng_procreg_fork((int)kid); /* must not clobber it */
            struct cng_procsnap snap;
            if (!st && cng_procreg_get((int)kid, &snap) != 1)
                st = 2;
            if (!st && strcmp(snap.cmd, "/bin/kid-prog"))
                st = 3; /* the fork publish overwrote the child's exec */
            CNG_SYS(__NR_kill, kid, 9, 0, 0, 0, 0);
            sys_wait4((int)kid, 0, 0, 0);
            if (!st && cng_procreg_has((int)kid))
                st = 4; /* a dead pid still answers */
            if (!st && cng_procreg_get((int)kid, &snap))
                st = 5;
            ok &= !st;
        }
        if (st)
            cng_dprintf(1, "proctest fork-guard+stale-pid: stage %d -> FAIL\n",
                        st);
        else
            cng_dprintf(1, "proctest fork-guard+stale-pid: -> %s\n",
                        ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 4) the mount table describes the rootfs and the binds, never the host's
     *    real mount namespace. */
    {
        long fd = pt_open("/proc/mounts");
        long n = pt_slurp(fd, buf, sizeof buf);
        int ok = n > 0 && pt_has(buf, "/dev/root / ") && pt_has(buf, "proc /proc proc ");
        if (bind_spec)
            ok &= pt_has(buf, fs.binds[0].guest);
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest mounts: %ld bytes -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;

        fd = pt_open("/proc/self/mountinfo");
        n = pt_slurp(fd, buf, sizeof buf);
        ok = n > 0 && pt_has(buf, "1 1 ") && pt_has(buf, " / / rw,relatime - ");
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest mountinfo: %ld bytes -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 5) loadavg/uptime/stat: shape, and refresh-on-rewind (the same fd, read
     *    twice from offset 0, must be regenerated — top holds its fd open). */
    {
        long fd = pt_open("/proc/loadavg");
        long n = pt_slurp(fd, buf, sizeof buf);
        int fields = 0;
        for (long i = 0; i < n; i++)
            if (buf[i] == ' ')
                fields++;
        int ok = n > 0 && fields == 4 && pt_has(buf, ".") && pt_has(buf, "/");
        cng_dprintf(1, "proctest loadavg: %ld bytes 4-spaces=%d -> %s\n", n,
                    fields == 4, ok ? "OK" : "FAIL");
        fails += !ok;
        if (fd >= 0) {
            /* rewind + reread through the dispatcher, as procps does */
            sys_lseek((int)fd, 0, CNG_SEEK_SET);
            char again[512];
            long m = cng_dispatch(__NR_read, fd, (long)again, sizeof again - 1,
                                  0, 0, 0, 0);
            if (m > 0)
                again[m] = '\0';
            int fresh = m > 0 && again[0] >= '0' && again[0] <= '9';
            cng_dprintf(1, "proctest loadavg refresh: %ld bytes -> %s\n", m,
                        fresh ? "OK" : "FAIL");
            fails += !fresh;
            /* the same rewind through readv — the rest of the read family
             * takes the identical pre-read hook, so one representative is
             * enough at this layer (the filter side is bpftest's job) */
            sys_lseek((int)fd, 0, CNG_SEEK_SET);
            struct {
                void *base;
                unsigned long len;
            } iov = {again, sizeof again - 1};
            m = cng_dispatch(__NR_readv, fd, (long)&iov, 1, 0, 0, 0, 0);
            if (m > 0)
                again[m] = '\0';
            fresh = m > 0 && again[0] >= '0' && again[0] <= '9';
            cng_dprintf(1, "proctest loadavg readv refresh: %ld bytes -> %s\n",
                        m, fresh ? "OK" : "FAIL");
            fails += !fresh;
            sys_close((int)fd);
        }

        fd = pt_open("/proc/uptime");
        n = pt_slurp(fd, buf, sizeof buf);
        ok = n > 0 && buf[0] >= '0' && buf[0] <= '9' && pt_has(buf, ".");
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest uptime: %ld bytes -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;

        fd = pt_open("/proc/stat");
        n = pt_slurp(fd, buf, sizeof buf);
        ok = n > 0 && !strncmp(buf, "cpu  ", 5) && pt_has(buf, "\nbtime ") &&
             pt_has(buf, "\nprocs_running 1\n");
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest stat: %ld bytes -> %s\n", n, ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 6) maps: the guest's own mappings, with no host path left in them. */
    {
        long fd = pt_open("/proc/self/maps");
        long n = pt_slurp(fd, buf, sizeof buf);
        int ok = n > 0;
        if (fs.rootfs[0])
            ok &= !pt_has(buf, fs.rootfs); /* no rootfs host prefix leaked */
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest maps: %ld bytes no-host-prefix -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 7) an fd link reports the guest path, not the host one. */
    {
        char hp[CNG_PATH_MAX];
        long ffd = -1;
        int ok = 0;
        if (cng_fs_translate(&fs, "/", hp, sizeof hp) == 0)
            ffd = sys_openat(CNG_AT_FDCWD, hp, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
        if (ffd >= 0) {
            char p[64], lb[CNG_PATH_MAX];
            cng_snprintf(p, sizeof p, "/proc/self/fd/%d", (int)ffd);
            long r = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD, (long)p,
                                  (long)lb, sizeof lb - 1, 0, 0, 0);
            if (r > 0)
                lb[r] = '\0';
            ok = r > 0 && !strcmp(lb, "/");
            cng_dprintf(1, "proctest fdlink: %s -> %s\n", r > 0 ? lb : "(err)",
                        ok ? "OK" : "FAIL");
            sys_close((int)ffd);
        } else {
            cng_dprintf(1, "proctest fdlink: cannot open rootfs -> FAIL\n");
        }
        fails += !ok;
    }

    /* 7b) a map_files link target is mapped back into the guest view, like an
     *     fd link: map a file that lives inside the rootfs and readlink its
     *     map_files entry. The range must come from the HOST's view of our
     *     mappings — under qemu-user the guest-facing maps file is address-
     *     translated, so its ranges don't name host map_files entries;
     *     "/proc/self/../self/maps" dodges qemu's interception and is the
     *     same file on a native kernel. A denied readlink (pre-4.3 kernels
     *     want CAP_SYS_ADMIN) skips the assertion rather than failing it. */
    {
        int ok = 1, skipped = 0;
        char fpath[CNG_PATH_MAX], range[64];
        range[0] = '\0';
        cng_snprintf(fpath, sizeof fpath, "%s/mf", rootfs);
        long ffd = sys_openat(CNG_AT_FDCWD, fpath,
                              CNG_O_RDWR | CNG_O_CREAT | CNG_O_CLOEXEC, 0644);
        ok &= ffd >= 0;
        if (ok) {
            cng_write_all((int)ffd, "map_files probe\n", 16);
            void *mp = sys_mmap(0, 4096, CNG_PROT_READ, CNG_MAP_PRIVATE,
                                (int)ffd, 0);
            ok &= mp != CNG_MAP_FAILED && !cng_is_err((long)mp);
            if (ok) {
                static char mbuf[32768];
                long mfd = sys_openat(CNG_AT_FDCWD, "/proc/self/../self/maps",
                                      CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
                long mn = pt_slurp(mfd, mbuf, sizeof mbuf);
                if (mfd >= 0)
                    sys_close((int)mfd);
                const char *hit = 0;
                size_t fl = strlen(fpath);
                for (const char *p = mbuf; mn > 0 && *p; p++)
                    if (!strncmp(p, fpath, fl)) {
                        hit = p;
                        break;
                    }
                ok &= hit != 0; /* our own mapping must be in the host maps */
                if (hit) {
                    const char *ls = hit;
                    while (ls > mbuf && ls[-1] != '\n')
                        ls--;
                    unsigned ri = 0;
                    while (ls[ri] && ls[ri] != ' ' && ri < sizeof range - 1) {
                        range[ri] = ls[ri];
                        ri++;
                    }
                    range[ri] = '\0';
                }
                if (ok && range[0]) { /* readlink while the mapping is live */
                    char lp[CNG_PATH_MAX], lb[CNG_PATH_MAX];
                    cng_snprintf(lp, sizeof lp, "/proc/self/map_files/%s",
                                 range);
                    long r = cng_dispatch(__NR_readlinkat, CNG_AT_FDCWD,
                                          (long)lp, (long)lb, sizeof lb - 1,
                                          0, 0, 0);
                    if (r < 0) {
                        skipped = 1; /* kernel or LSM policy: no verdict */
                    } else {
                        lb[r] = '\0'; /* r < sizeof lb - 1: the size arg */
                        ok &= !strcmp(lb, "/mf");
                    }
                }
                CNG_SYS(__NR_munmap, mp, 4096, 0, 0, 0, 0);
            }
            sys_close((int)ffd);
            CNG_SYS(__NR_unlinkat, CNG_AT_FDCWD, fpath, 0, 0, 0, 0);
        }
        cng_dprintf(1, "proctest map_files: %s -> %s\n",
                    skipped ? "(denied; skipped)" : range,
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 8) under --fake-id the status Uid:/Gid: lines carry the fake identity. */
    {
        cng_g_fake_id = 1;
        cng_g_fake_uid = 0;
        cng_g_fake_gid = 0;
        cng_g_host_uid = (unsigned)sys_getuid();
        cng_g_host_gid = (unsigned)sys_getgid();
        cng_cred_seed();
        long fd = pt_open("/proc/self/status");
        long n = pt_slurp(fd, buf, sizeof buf);
        int ok = n > 0 && pt_has(buf, "\nUid:\t0\t0\t0\t0\n");
        if (fd >= 0)
            sys_close((int)fd);
        cng_dprintf(1, "proctest status remap: %ld bytes -> %s\n", n,
                    ok ? "OK" : "FAIL");
        fails += !ok;
        cng_g_fake_id = 0;
    }

    /* 9) --no-proc turns all of it off. */
    {
        cng_g_no_proc = 1;
        char out[CNG_PATH_MAX];
        long pr = 0;
        int ok = cng_procfs_open("/proc/loadavg", CNG_O_RDONLY, &pr) == 0;
        ok &= cng_fs_translate(&fs, "/proc/self/status", out, sizeof out) == 0 &&
              strncmp(out, "/proc/", 6) != 0;
        cng_g_no_proc = 0;
        cng_dprintf(1, "proctest no-proc -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    (void)envp;
    cng_dprintf(1, "proctest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

/* _bpftest — build the seccomp filter and run it through a classic-BPF
 * interpreter, checking the action for representative (nr, arg0, ip) triples.
 * The filter itself only ever executes on a real AArch64 kernel (qemu-user does
 * not honor a guest's seccomp filter), so this is the only place its logic can
 * be verified before a build reaches a device. */

/* Minimal classic-BPF interpreter over a seccomp_data buffer: the subset the
 * filter uses (LD W ABS, JEQ/JGE K, ALU AND K, RET K). */
static u32 bpf_run(const struct sock_filter *f, int n, const u32 *data,
                   int *bad) {
    u32 A = 0;
    for (int pc = 0; pc < n;) {
        const struct sock_filter *i = &f[pc];
        switch (i->code) {
        case CNG_BPF_LD | CNG_BPF_W | CNG_BPF_ABS:
            if (i->k & 3 || i->k >= 64) { /* seccomp_data is 64 bytes */
                *bad = 1;
                return 0;
            }
            A = data[i->k / 4];
            pc++;
            break;
        case CNG_BPF_ALU | CNG_BPF_AND | CNG_BPF_K:
            A &= i->k;
            pc++;
            break;
        case CNG_BPF_JMP | CNG_BPF_JEQ | CNG_BPF_K:
            pc += 1 + (A == i->k ? i->jt : i->jf);
            break;
        case CNG_BPF_JMP | CNG_BPF_JGE | CNG_BPF_K:
            pc += 1 + (A >= i->k ? i->jt : i->jf);
            break;
        case CNG_BPF_JMP | CNG_BPF_JGT | CNG_BPF_K:
            pc += 1 + (A > i->k ? i->jt : i->jf);
            break;
        case CNG_BPF_RET | CNG_BPF_K:
            return i->k;
        default:
            *bad = 1; /* an opcode this interpreter does not model */
            return 0;
        }
        if (pc < 0 || pc >= n) { /* fell off the end: the kernel rejects this */
            *bad = 1;
            return 0;
        }
    }
    *bad = 1;
    return 0;
}

/* Fill a seccomp_data image: nr, arch, instruction_pointer, args[0]. args[1]
 * mirrors args[0] so an ioctl case can drive the request without a second
 * column: nothing reads args[1] except the ioctl band test, and that only after
 * the syscall number has matched. */
static void bpf_data(u32 *d, int nr, unsigned long ip, unsigned long arg0) {
    memset(d, 0, 64);
    d[0] = (u32)nr;
    d[1] = CNG_AUDIT_ARCH_AARCH64;
    d[2] = (u32)ip;
    d[3] = (u32)(ip >> 32);
    d[4] = (u32)arg0;
    d[5] = (u32)(arg0 >> 32);
    d[6] = (u32)arg0;
    d[7] = (u32)(arg0 >> 32);
}

int cng_cmd_bpftest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    cng_g_synth_fd_base = 1008; /* as cng_procfs_init would compute it */

    static struct sock_filter f[CNG_SECCOMP_MAX_INSNS];
    int n = cng_build_seccomp(f, CNG_SECCOMP_MAX_INSNS);
    if (n <= 0) {
        cng_dprintf(1, "bpftest: build failed (%d) -> FAIL\n", n);
        return 1;
    }

    /* Every jump must land inside the program, and the last instruction must be
     * a RET — the two structural rules the kernel's verifier enforces. */
    int fails = 0, structural = 1;
    for (int i = 0; i < n; i++) {
        int cls = f[i].code & 0x07;
        if (cls == CNG_BPF_JMP) {
            if (i + 1 + f[i].jt >= n || i + 1 + f[i].jf >= n)
                structural = 0;
        }
    }
    if ((f[n - 1].code & 0x07) != CNG_BPF_RET)
        structural = 0;
    cng_dprintf(1, "bpftest structure: %d insns jumps_in_range=%d -> %s\n", n,
                structural, structural ? "OK" : "FAIL");
    fails += !structural;

    unsigned long gate = (unsigned long)__cng_gate_start;
    struct {
        const char *what;
        int nr;
        unsigned long ip, arg0;
        u32 want;
    } cases[] = {
        {"openat traps", __NR_openat, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"getpid runs native", __NR_getpid, 0x1000, 0, CNG_SECCOMP_RET_ALLOW},
        {"in-gate reissue allowed", __NR_openat, gate, 0,
         CNG_SECCOMP_RET_ALLOW},
        /* clone: process creation traps, thread creation does not */
        {"fork traps", __NR_clone, 0x1000, 17 /*SIGCHLD*/,
         CNG_SECCOMP_RET_TRAP},
        {"vfork traps", __NR_clone, 0x1000, CNG_CLONE_VM | CNG_CLONE_VFORK,
         CNG_SECCOMP_RET_TRAP},
        {"thread runs native", __NR_clone, 0x1000, CNG_CLONE_VM | 0x10000,
         CNG_SECCOMP_RET_ALLOW},
        /* read: only the reserved synthesized fd range traps */
        {"ordinary read runs native", __NR_read, 0x1000, 5,
         CNG_SECCOMP_RET_ALLOW},
        {"read of a synth fd traps", __NR_read, 0x1000, 1008,
         CNG_SECCOMP_RET_TRAP},
        {"read with a dirty upper half is judged on the low word", __NR_read,
         0x1000, 0xdeadbeef00000005uL, CNG_SECCOMP_RET_ALLOW},
        {"pread of a synth fd traps", __NR_pread64, 0x1000, 1100,
         CNG_SECCOMP_RET_TRAP},
        {"readv of a synth fd traps", __NR_readv, 0x1000, 1008,
         CNG_SECCOMP_RET_TRAP},
        {"readv of an ordinary fd runs native", __NR_readv, 0x1000, 4,
         CNG_SECCOMP_RET_ALLOW},
        {"preadv of a synth fd traps", __NR_preadv, 0x1000, 1023,
         CNG_SECCOMP_RET_TRAP},
#ifdef __NR_preadv2
        {"preadv2 of an ordinary fd runs native", __NR_preadv2, 0x1000, 7,
         CNG_SECCOMP_RET_ALLOW},
#endif
        {"write is never trapped", __NR_write, 0x1000, 1008,
         CNG_SECCOMP_RET_ALLOW},
        /* System V shm: always trapped, so the guest gets the emulated
         * namespace whatever the host's own IPC would have allowed. */
        {"shmget traps", __NR_shmget, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"shmat traps", __NR_shmat, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"shmdt traps", __NR_shmdt, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"shmctl traps", __NR_shmctl, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        /* Designed-ENOSYS: io_uring must be refused by the filter itself. Its
         * ring operations never execute an svc, so a created ring would reach
         * the host filesystem with no trap and no translation. */
#ifdef __NR_io_uring_setup
        {"io_uring_setup is refused ENOSYS", __NR_io_uring_setup, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38 /*ENOSYS*/},
#endif
#ifdef __NR_io_uring_enter
        {"io_uring_enter is refused ENOSYS", __NR_io_uring_enter, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
#ifdef __NR_io_uring_register
        {"io_uring_register is refused ENOSYS", __NR_io_uring_register, 0x1000,
         0, CNG_SECCOMP_RET_ERRNO | 38},
#endif
        /* ...including from inside the gate. The gate exempts our own
         * re-issues, but we never issue io_uring, so it must not be a hole. */
#ifdef __NR_io_uring_setup
        {"in-gate io_uring is refused too", __NR_io_uring_setup, gate, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
        /* clone3 carries its flags behind a pointer, so BPF cannot tell a
         * thread from a vfork. Refusing it puts glibc's posix_spawn and
         * pthread_create back on __NR_clone, which the conversion below
         * handles. A CLONE_VM|CLONE_VFORK clone3 would otherwise reach the
         * emulated execve with the parent's address space still shared. */
#ifdef __NR_clone3
        {"clone3 is refused ENOSYS", __NR_clone3, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
        /* SysV sem/msg: emulated from the same broker as shm, and trapped
         * unconditionally for the same reason — one guest namespace whatever
         * the host's own IPC would have allowed. */
        {"semget traps", __NR_semget, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"semop traps", __NR_semop, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"semtimedop traps", __NR_semtimedop, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"msgget traps", __NR_msgget, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"msgsnd traps", __NR_msgsnd, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        {"msgrcv traps", __NR_msgrcv, 0x1000, 0, CNG_SECCOMP_RET_TRAP},
        /* POSIX mqueue: the same leak in the namespace next door. An mq name is
         * not a path, so nothing translates it — left native the guest opened
         * queues in the HOST's mqueue namespace. */
#ifdef __NR_mq_open
        {"mq_open is refused ENOSYS", __NR_mq_open, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
#ifdef __NR_mq_timedsend
        {"mq_timedsend is refused ENOSYS", __NR_mq_timedsend, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
#ifdef __NR_mq_getsetattr
        {"mq_getsetattr is refused ENOSYS", __NR_mq_getsetattr, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
        /* ...while shm stays emulated, not refused. */
        {"shmget still traps for emulation", __NR_shmget, 0x1000, 0,
         CNG_SECCOMP_RET_TRAP},
#ifdef __NR_fchmodat2
        /* fchmodat2 is translated, not refused: it is glibc's modern chmod. */
        {"fchmodat2 traps for translation", __NR_fchmodat2, 0x1000, 0,
         CNG_SECCOMP_RET_TRAP},
#endif
#ifdef __NR_clone3
        {"plain clone still traps for the conversion", __NR_clone, 0x1000,
         CNG_CLONE_VM | CNG_CLONE_VFORK, CNG_SECCOMP_RET_TRAP},
#endif
        /* seccomp(2): a guest filter would also govern the syscalls the handler
         * re-issues through the gate. Refused by the filter itself. */
#ifdef __NR_seccomp
        {"seccomp(2) is refused ENOSYS", __NR_seccomp, 0x1000, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
        {"in-gate seccomp(2) is refused too", __NR_seccomp, gate, 0,
         CNG_SECCOMP_RET_ERRNO | 38},
#endif
        /* prctl is selective: the four ops that describe OUR confinement are
         * trapped, and the rest of the syscall — real process state, some of it
         * on the hot path — is not. */
        {"prctl PR_SET_SECCOMP traps", __NR_prctl, 0x1000, CNG_PR_SET_SECCOMP,
         CNG_SECCOMP_RET_TRAP},
        {"prctl PR_GET_SECCOMP traps", __NR_prctl, 0x1000, CNG_PR_GET_SECCOMP,
         CNG_SECCOMP_RET_TRAP},
        {"prctl PR_SET_NO_NEW_PRIVS traps", __NR_prctl, 0x1000,
         CNG_PR_SET_NO_NEW_PRIVS, CNG_SECCOMP_RET_TRAP},
        {"prctl PR_GET_NO_NEW_PRIVS traps", __NR_prctl, 0x1000,
         CNG_PR_GET_NO_NEW_PRIVS, CNG_SECCOMP_RET_TRAP},
        {"prctl PR_SET_NAME runs native", __NR_prctl, 0x1000, CNG_PR_SET_NAME,
         CNG_SECCOMP_RET_ALLOW},
        {"prctl PR_SET_VMA runs native", __NR_prctl, 0x1000, 0x53564d41,
         CNG_SECCOMP_RET_ALLOW},
        {"our own prctl re-issue is allowed", __NR_prctl, gate,
         CNG_PR_SET_SECCOMP, CNG_SECCOMP_RET_ALLOW},
        /* ioctl: only the SIOCxIF request band traps, so a terminal TCGETS and
         * every driver call keep running native. The request is args[1]. */
        {"SIOCGIFCONF traps", __NR_ioctl, 0x1000, 0x8912,
         CNG_SECCOMP_RET_TRAP},
        {"SIOCGIFADDR traps", __NR_ioctl, 0x1000, 0x8915,
         CNG_SECCOMP_RET_TRAP},
        {"the band's last request traps", __NR_ioctl, 0x1000, 0x8970,
         CNG_SECCOMP_RET_TRAP},
        {"TCGETS runs native", __NR_ioctl, 0x1000, 0x5401,
         CNG_SECCOMP_RET_ALLOW},
        {"just below the band runs native", __NR_ioctl, 0x1000, 0x890f,
         CNG_SECCOMP_RET_ALLOW},
        {"just above the band runs native", __NR_ioctl, 0x1000, 0x8971,
         CNG_SECCOMP_RET_ALLOW},
    };
    for (unsigned k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        u32 d[16];
        int bad = 0;
        bpf_data(d, cases[k].nr, cases[k].ip, cases[k].arg0);
        u32 got = bpf_run(f, n, d, &bad);
        int ok = !bad && got == cases[k].want;
        cng_dprintf(1, "bpftest %s: %s -> %s\n", cases[k].what,
                    bad             ? "malformed"
                    : got == CNG_SECCOMP_RET_TRAP ? "TRAP"
                    : got == CNG_SECCOMP_RET_ALLOW ? "ALLOW"
                    : (got & 0xffff0000U) == CNG_SECCOMP_RET_ERRNO ? "ERRNO"
                                                   : "other",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* A foreign architecture must be killed, not allowed. */
    {
        u32 d[16];
        int bad = 0;
        bpf_data(d, __NR_openat, 0x1000, 0);
        d[1] = 0xc000003e; /* AUDIT_ARCH_X86_64 */
        u32 got = bpf_run(f, n, d, &bad);
        int ok = !bad && got == CNG_SECCOMP_RET_KILL_THREAD;
        cng_dprintf(1, "bpftest foreign arch killed -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* The --fake-id set is conditional, and this is the only place its effect on
     * the filter can be seen: with the identity on, fstat joins the trapped set
     * (stat and fstat must agree about ownership) along with fchmod (a chmod on
     * a descriptor needs the same fail-soft the path form gets); with it off both
     * stay untrapped, so an ordinary fstat costs nothing. Rebuilds the filter, so
     * it runs after every case above. */
    {
        int was = cng_g_fake_id;
        u32 d[16];
        int bad = 0;
        cng_g_fake_id = 0;
        int n0 = cng_build_seccomp(f, CNG_SECCOMP_MAX_INSNS);
        bpf_data(d, __NR_fstat, 0x1000, 3);
        int off_ok = n0 > 0 && bpf_run(f, n0, d, &bad) == CNG_SECCOMP_RET_ALLOW;
        cng_g_fake_id = 1;
        int n1 = cng_build_seccomp(f, CNG_SECCOMP_MAX_INSNS);
        bpf_data(d, __NR_fstat, 0x1000, 3);
        int on_ok = n1 > 0 && bpf_run(f, n1, d, &bad) == CNG_SECCOMP_RET_TRAP;
        bpf_data(d, __NR_fchmod, 0x1000, 3);
        int ch_ok = n1 > 0 && bpf_run(f, n1, d, &bad) == CNG_SECCOMP_RET_TRAP;
        cng_g_fake_id = was;
        int ok2 = !bad && off_ok && on_ok && ch_ok;
        cng_dprintf(1,
                    "bpftest fake-id: fstat_off=%d fstat_on=%d fchmod_on=%d "
                    "-> %s\n",
                    off_ok, on_ok, ch_ok, ok2 ? "OK" : "FAIL");
        fails += !ok2;
    }

    /* The two filters a ptrace role stacks on a task. Neither can be observed
     * any other way — they are only installed once a guest traces, and a guest
     * filter never runs under qemu-user — so simulating them here is the only
     * check they get before a device sees them. */
    {
        static struct sock_filter tf[CNG_SECCOMP_TRACEALL_INSNS];
        int tn = cng_build_seccomp_traceall(tf, CNG_SECCOMP_TRACEALL_INSNS);
        struct {
            const char *what;
            int nr;
            unsigned long ip, arg0;
            u32 want;
        } tcases[] = {
            /* The point of the filter: a tracee must stop on everything, not
             * just the path-bearing set the base filter traps. */
            {"traceall: read traps", __NR_read, 0x1000, 0,
             CNG_SECCOMP_RET_TRAP},
            {"traceall: getpid traps", __NR_getpid, 0x1000, 0,
             CNG_SECCOMP_RET_TRAP},
            {"traceall: openat traps", __NR_openat, 0x1000, 0,
             CNG_SECCOMP_RET_TRAP},
            /* Our own re-issue must not re-trap, or the handler recurses. */
            {"traceall: in-gate reissue allowed", __NR_read, gate, 0,
             CNG_SECCOMP_RET_ALLOW},
            /* rt_sigreturn must execute with sp still on the kernel's signal
             * frame; there is no way to re-issue it from the handler, so it
             * has to stay native. */
            {"traceall: rt_sigreturn stays native", __NR_rt_sigreturn, 0x1000,
             0, CNG_SECCOMP_RET_ALLOW},
            /* A thread-creating clone likewise cannot be re-issued from the
             * handler; process creation can, and must trap so the fork event
             * and the child's attach happen. */
            {"traceall: thread clone stays native", __NR_clone, 0x1000,
             CNG_CLONE_VM | 0x10000, CNG_SECCOMP_RET_ALLOW},
            {"traceall: fork traps", __NR_clone, 0x1000, 17 /*SIGCHLD*/,
             CNG_SECCOMP_RET_TRAP},
            {"traceall: vfork traps", __NR_clone, 0x1000,
             CNG_CLONE_VM | CNG_CLONE_VFORK, CNG_SECCOMP_RET_TRAP},
        };
        int tf_ok = tn > 0;
        for (unsigned k = 0; tf_ok && k < sizeof tcases / sizeof tcases[0];
             k++) {
            u32 d[16];
            int bad = 0;
            bpf_data(d, tcases[k].nr, tcases[k].ip, tcases[k].arg0);
            u32 got = bpf_run(tf, tn, d, &bad);
            int ok = !bad && got == tcases[k].want;
            cng_dprintf(1, "bpftest %s -> %s\n", tcases[k].what,
                        ok ? "OK" : "FAIL");
            fails += !ok;
        }
        if (!tf_ok) {
            cng_dprintf(1, "bpftest traceall: build failed -> FAIL\n");
            fails++;
        }

        static struct sock_filter rf[CNG_SECCOMP_TRACER_INSNS];
        int rn = cng_build_seccomp_tracer(rf, CNG_SECCOMP_TRACER_INSNS);
        struct {
            const char *what;
            int nr;
            u32 want;
        } rcases[] = {
            /* A tracer's wait has to account for stops that are not the
             * kernel's, and its SIGSTOP has to become a cooperative one. */
            {"tracer: wait4 traps", __NR_wait4, CNG_SECCOMP_RET_TRAP},
            {"tracer: waitid traps", __NR_waitid, CNG_SECCOMP_RET_TRAP},
            {"tracer: kill traps", __NR_kill, CNG_SECCOMP_RET_TRAP},
            {"tracer: tgkill traps", __NR_tgkill, CNG_SECCOMP_RET_TRAP},
            {"tracer: process_vm_readv traps", __NR_process_vm_readv,
             CNG_SECCOMP_RET_TRAP},
            /* ...and nothing else does: this is the filter an ordinary tracer
             * (gdb, strace) runs its own work through. */
            {"tracer: read stays native", __NR_read, CNG_SECCOMP_RET_ALLOW},
            {"tracer: openat stays native", __NR_openat,
             CNG_SECCOMP_RET_ALLOW},
        };
        int rf_ok = rn > 0;
        for (unsigned k = 0; rf_ok && k < sizeof rcases / sizeof rcases[0];
             k++) {
            u32 d[16];
            int bad = 0;
            bpf_data(d, rcases[k].nr, 0x1000, 0);
            u32 got = bpf_run(rf, rn, d, &bad);
            int ok = !bad && got == rcases[k].want;
            cng_dprintf(1, "bpftest %s -> %s\n", rcases[k].what,
                        ok ? "OK" : "FAIL");
            fails += !ok;
        }
        if (!rf_ok) {
            cng_dprintf(1, "bpftest tracer: build failed -> FAIL\n");
            fails++;
        }
    }

    cng_dprintf(1, "bpftest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

/* ---- M18: ptrace single-step decoder (-t ptracetest) ---------------------
 *
 * The next-PC decoder is the one piece of the ptrace emulation with no safety
 * net: everything else fails visibly (a stop that does not arrive, a request
 * that answers an error), but a branch this misreads plants the breakpoint at
 * an address the tracee never executes, and the "stepped" tracee runs away.
 * It is also pure — registers in, address out — so it is checked directly here
 * rather than through a guest, and on every host.
 */
/* `absolute` distinguishes "the answer is this address" (a register-form
 * branch, or the 0 that means "not decodable") from "the answer is this far
 * past pc". */
static int ptstep_case(const char *what, u32 insn, struct cng_uregs *r, u64 want,
                       int absolute) {
    static u32 code[2];
    code[0] = insn;
    code[1] = 0xD503201Fu; /* nop, so a fall-through lands on something real */
    r->pc = (u64)(unsigned long)&code[0];
    if (!absolute)
        want += r->pc;
    u64 got = cng_pt_next_pc(r);
    int ok = got == want;
    cng_dprintf(1, "ptracetest %s: %s\n", what, ok ? "OK" : "FAIL");
    if (!ok)
        cng_dprintf(1, "  want=+%ld got=%ld\n", (long)(want - r->pc),
                    (long)((long)got - (long)r->pc));
    return !ok;
}

/* The SIGSYS tier's stop path, driven without a filter.
 *
 * On a device that tier is the one that runs, and on a cross host it cannot be
 * reached at all: qemu-user does not apply a guest seccomp filter, so every
 * live-guest ptrace test in the suite goes through the -R trampoline instead.
 * Both tiers call the same emulation, but the wrapper around it is separate
 * code, so this drives the SIGSYS one directly — a real fork, a real
 * tracer/tracee pair over the real registry and mailbox, with the trap itself
 * synthesized: a ucontext whose x8 says getpid and a siginfo that says seccomp,
 * which is exactly what the kernel hands cng_sigsys_body.
 */
static int pt_sim_child(int wfd) {
    cng_pt_sig_install_kick();
    if (cng_pt_syscall(CNG_PTRACE_TRACEME, 0, 0, 0) != 0)
        return 91;
    char c = 'r';
    sys_write(wfd, &c, 1);
    /* Stop cooperatively so the tracer can arm us, the way a tracee's own
     * SIGSTOP is routed. The kick lands as soon as the queueing syscall
     * returns, and its handler parks us. */
    cng_pt_signal_route(sys_getpid(), 19 /*SIGSTOP*/);

    /* Now the synthesized trap. */
    static struct cng_ucontext uc;
    static cng_siginfo_t si;
    memset(&uc, 0, sizeof uc);
    memset(&si, 0, sizeof si);
    uc.uc_mcontext.regs[8] = __NR_getpid;
    uc.uc_mcontext.pc = 0x1000;
    uc.uc_mcontext.sp = 0x2000;
    si.si_code = CNG_SYS_SECCOMP;
    si._u._sigsys.call_addr = (void *)0x1000; /* outside the gate */
    si._u._sigsys.syscall = __NR_getpid;
    cng_sigsys_body(&uc, &si);
    return (long)uc.uc_mcontext.regs[0] == sys_getpid() ? 0 : 92;
}

static int pt_sim_sigsys(unsigned long *auxv) {
    int fds[2];
    if (CNG_SYS(__NR_pipe2, fds, 0, 0, 0, 0, 0) < 0) {
        cng_dprintf(1, "ptracetest sigsys tier: no pipe -> FAIL\n");
        return 1;
    }
    long kid = CNG_SYS(__NR_clone, 17 /*SIGCHLD*/, 0, 0, 0, 0, 0);
    if (kid == 0) {
        sys_close(fds[0]);
        CNG_SYS(__NR_exit_group, pt_sim_child(fds[1]), 0, 0, 0, 0, 0);
    }
    sys_close(fds[1]);
    char c = 0;
    sys_read(fds[0], &c, 1);
    sys_close(fds[0]);
    if (kid < 0) {
        cng_dprintf(1, "ptracetest sigsys tier: no fork -> FAIL\n");
        return 1;
    }

    int fails = 0, st = 0;
    long r = cng_pt_wait4(kid, (u64)(unsigned long)&st, 0, 0, 0);
    int ok = r == kid && (st & 0xff) == 0x7f && ((st >> 8) & 0xff) == 19;
    cng_dprintf(1, "ptracetest sigsys tier: cooperative stop -> %s\n",
                ok ? "OK" : "FAIL");
    fails += !ok;

    cng_pt_syscall(CNG_PTRACE_SETOPTIONS, kid, 0, CNG_PTRACE_O_TRACESYSGOOD);
    cng_pt_syscall(CNG_PTRACE_SYSCALL, kid, 0, 0);
    r = cng_pt_wait4(kid, (u64)(unsigned long)&st, 0, 0, 0);
    ok = r == kid && (st & 0xff) == 0x7f && ((st >> 8) & 0xff) == (5 | 0x80);
    cng_dprintf(1, "ptracetest sigsys tier: syscall-entry stop -> %s\n",
                ok ? "OK" : "FAIL");
    fails += !ok;

    /* NT_ARM_PAC_MASK, which gdb asks for whenever AT_HWCAP advertises pointer
     * authentication and is fatal about ("unable to fetch pauth registers").
     * The kernel's answer is GENMASK(54, vabits_actual); ours is measured, so
     * check the shape it must have — a contiguous field ending at bit 54 — and
     * print it, since no oracle here can confirm the exact width. */
    {
        u64 pac[2] = {0, 0};
        u64 piov[2] = {(u64)(unsigned long)pac, sizeof pac};
        long pr = cng_pt_syscall(CNG_PTRACE_GETREGSET, kid,
                                 CNG_NT_ARM_PAC_MASK,
                                 (u64)(unsigned long)piov);
        unsigned long hwcap = 0;
        for (unsigned long *a = auxv; a && a[0]; a += 2)
            if (a[0] == 16 /*AT_HWCAP*/)
                hwcap = a[1];
        if (hwcap & (1UL << 30)) {
            int shape = pac[0] != 0 && pac[0] == pac[1] &&
                        (pac[0] & ~0x007FFFFFFFFFFFFFuLL) == 0 &&
                        pac[0] + (pac[0] & (~pac[0] + 1)) ==
                            0x0080000000000000uLL;
            ok = pr == 0 && piov[1] == sizeof pac && shape;
            cng_dprintf(1,
                        "ptracetest sigsys tier: pauth mask 0x%lx -> %s\n",
                        (unsigned long)pac[0], ok ? "OK" : "FAIL");
        } else {
            ok = pr < 0; /* no PAC here: the kernel refuses it too */
            cng_dprintf(1,
                        "ptracetest sigsys tier: no pauth, refused -> %s\n",
                        ok ? "OK" : "FAIL");
        }
        fails += !ok;
    }

    /* The register file the tracer sees is the trapped ucontext itself. */
    struct cng_uregs regs;
    memset(&regs, 0, sizeof regs);
    u64 iov[2] = {(u64)(unsigned long)&regs, sizeof regs};
    cng_pt_syscall(CNG_PTRACE_GETREGSET, kid, CNG_NT_PRSTATUS,
                   (u64)(unsigned long)iov);
    ok = (long)regs.x[8] == __NR_getpid && regs.pc == 0x1000;
    cng_dprintf(1, "ptracetest sigsys tier: regs at the entry stop -> %s\n",
                ok ? "OK" : "FAIL");
    fails += !ok;

    cng_pt_syscall(CNG_PTRACE_SYSCALL, kid, 0, 0);
    r = cng_pt_wait4(kid, (u64)(unsigned long)&st, 0, 0, 0);
    ok = r == kid && (st & 0xff) == 0x7f && ((st >> 8) & 0xff) == (5 | 0x80);
    fails += !ok;
    iov[1] = sizeof regs;
    cng_pt_syscall(CNG_PTRACE_GETREGSET, kid, CNG_NT_PRSTATUS,
                   (u64)(unsigned long)iov);
    int rok = (long)regs.x[0] == kid; /* the syscall really ran */
    cng_dprintf(1, "ptracetest sigsys tier: syscall-exit stop -> %s\n",
                (ok && rok) ? "OK" : "FAIL");
    fails += !(ok && rok);

    cng_pt_syscall(CNG_PTRACE_CONT, kid, 0, 0);
    r = cng_pt_wait4(kid, (u64)(unsigned long)&st, 0, 0, 0);
    ok = r == kid && (st & 0x7f) == 0 && ((st >> 8) & 0xff) == 0;
    cng_dprintf(1, "ptracetest sigsys tier: tracee exited clean -> %s\n",
                ok ? "OK" : "FAIL");
    fails += !ok;
    return fails;
}

int cng_cmd_ptracetest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)envp;
    (void)auxv;
    /* The pauth-mask probe reads AT_HWCAP from here, as it does in a real run
     * (cng_run sets it long before the monitor). */
    if (!cng_host_auxv)
        cng_host_auxv = auxv;
    int fails = 0;
    struct cng_uregs r;
    memset(&r, 0, sizeof r);

    /* Anything that is not a branch simply advances. */
    fails += ptstep_case("nop advances by 4", 0xD503201Fu, &r, 4, 0);
    fails += ptstep_case("svc advances by 4", 0xD4000001u, &r, 4, 0);

    /* Unconditional, PC-relative. */
    fails += ptstep_case("b +8", 0x14000002u, &r, 8, 0);
    fails += ptstep_case("b -8", 0x17FFFFFEu, &r, (u64)-8, 0);
    fails += ptstep_case("bl +4", 0x94000001u, &r, 4, 0);

    /* Conditional: the flags in the frame decide, so exactly one target is
     * planted rather than one on each side. */
    r.pstate = 0x40000000u; /* Z set */
    fails += ptstep_case("b.eq taken when Z", 0x54000040u, &r, 8, 0);
    r.pstate = 0;
    fails += ptstep_case("b.eq falls through when !Z", 0x54000040u, &r, 4, 0);
    r.pstate = 0x40000000u;
    fails += ptstep_case("b.ne falls through when Z", 0x54000041u, &r, 4, 0);
    r.pstate = 0;

    /* Compare-and-branch, including the 32-bit form's upper half. */
    r.x[3] = 0;
    fails += ptstep_case("cbz x3 taken when zero", 0xB4000043u, &r, 8, 0);
    r.x[3] = 1;
    fails += ptstep_case("cbz x3 falls through", 0xB4000043u, &r, 4, 0);
    r.x[4] = 0x100000000uLL; /* w4 == 0, x4 != 0 */
    fails += ptstep_case("cbnz w4 judges the low word", 0x35000044u, &r, 4, 0);
    fails += ptstep_case("cbnz x4 judges all 64 bits", 0xB5000044u, &r, 8, 0);

    /* Test-and-branch, both halves of the split bit number. */
    r.x[5] = 0;
    fails += ptstep_case("tbz x5,#3 taken when clear", 0x36180045u, &r, 8, 0);
    r.x[5] = 8;
    fails += ptstep_case("tbz x5,#3 falls through when set", 0x36180045u, &r, 4,
                         0);
    r.x[6] = 1uLL << 40;
    fails += ptstep_case("tbnz x6,#40 taken (bit 5 of the index)", 0xB7400046u,
                         &r, 8, 0);

    /* Register forms read the frame. */
    r.x[30] = 0x0BEE0;
    fails += ptstep_case("ret follows x30", 0xD65F03C0u, &r, 0x0BEE0, 1);
    r.x[7] = 0x12340;
    fails += ptstep_case("br follows xn", 0xD61F00E0u, &r, 0x12340, 1);
    r.x[9] = 0x9000;
    fails += ptstep_case("blr follows xn", 0xD63F0120u, &r, 0x9000, 1);

    /* A pointer-authenticated branch is not decoded, and must say so rather
     * than guess: 0 makes the caller report the step in place instead of
     * planting a breakpoint somewhere the tracee will never reach. */
    fails += ptstep_case("braaz is refused, not guessed", 0xD61F0820u, &r, 0, 1);

    cng_pt_init();
    fails += pt_sim_sigsys(auxv);

    cng_dprintf(1, "ptracetest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

/* ---- M12: System V shared memory (-t shmtest) ---------------------------
 *
 * Drives the four syscalls through cng_dispatch, which is exactly what the
 * SIGSYS handler does — so this needs no seccomp and runs under qemu. It spans
 * a real fork (through the dispatcher's own clone path, so the fork hook is the
 * one that ships) and a real broker daemon, which is the only way to see that
 * two processes share the memory and that nattch tracks them.
 *
 * The test script re-runs this with CNG_SHM_FORCE_FILE=1 to cover the
 * file-backed tier the broker falls back to where memfd_create is unavailable.
 */
#define SHMT_SZ 8192

static long shm_call(long nr, long a0, long a1, long a2) {
    return cng_dispatch(nr, a0, a1, a2, 0, 0, 0, /*trapped=*/0);
}

static long shmt_stat(long id, struct cng_shmid64_ds *ds) {
    return shm_call(__NR_shmctl, id, CNG_IPC_STAT | 0x100 /*IPC_64*/,
                    (long)ds);
}

/* A page-aligned address that is currently free: map it, then drop it. Single
 * threaded here, and nothing else in this process allocates behind our back. */
static unsigned long shmt_hole(unsigned long len) {
    void *p = sys_mmap(0, len, CNG_PROT_NONE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    sys_munmap(p, len);
    return (unsigned long)p;
}

int cng_cmd_shmtest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)auxv;
    cng_g_host_envp = envp; /* the broker's env lookups (CNG_SHM_FORCE_FILE, TMPDIR) */
    int fails = 0;
    int self = (int)sys_getpid();
    unsigned long pg = cng_page_size;

    /* 0) the enumeration commands on a namespace that holds nothing yet — which
     *    is what `ipcs -m` asks first, and the one state step 7 below cannot
     *    reach because it creates a segment before looking. The kernel clamps
     *    its "no ids" answer (-1) to 0, so both must succeed. */
    {
        struct cng_shm_info info;
        struct cng_shminfo64 li;
        memset(&info, 0, sizeof info);
        memset(&li, 0, sizeof li);
        long e1 = shm_call(__NR_shmctl, 0, CNG_SHM_INFO, (long)&info);
        long e2 = shm_call(__NR_shmctl, 0, CNG_IPC_INFO, (long)&li);
        int ok = e1 == 0 && e2 == 0 && info.used_ids == 0 && li.shmmni >= 1;
        cng_dprintf(1, "shmtest empty-namespace shm_info+ipc_info -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 0b) a reply that carries an SCM_RIGHTS fd and then fails to complete must
     *     not leave that fd behind. The ancillary fd arrives with the first
     *     byte, so it is already installed by the time the top-up read finds
     *     the peer gone — and host fd == guest fd here, so a leaked one is a
     *     descriptor onto a segment's backing that the guest can see and use.
     *     Staged exactly: 4 bytes plus an fd, writer closed, 64 asked for. */
    {
        int sv[2] = {-1, -1};
        int ok = CNG_SYS(__NR_socketpair, CNG_AF_UNIX, CNG_SOCK_STREAM, 0,
                         (long)sv, 0, 0) == 0;
        long pass = ok ? sys_memfd_create("cng-leak", CNG_MFD_CLOEXEC) : -1;
        ok = ok && pass >= 0 &&
             cng_broker_send(sv[1], "abcd", 4, (int)pass) == 0;
        if (pass >= 0)
            sys_close((int)pass);
        if (sv[1] >= 0)
            sys_close(sv[1]);
        /* With both of those closed, the lowest free descriptor is where the
         * kernel will install the one riding on the message. */
        long probe = CNG_SYS(__NR_fcntl, 0, 0 /*F_DUPFD*/, 0, 0, 0, 0);
        int expect = (int)probe;
        if (probe >= 0)
            sys_close(expect);
        char rb[64];
        int got = 0;
        ok = ok && probe >= 0 &&
             cng_broker_recv(sv[0], rb, sizeof rb, &got) == -1 && got == -1 &&
             CNG_SYS(__NR_fcntl, expect, 1 /*F_GETFD*/, 0, 0, 0, 0) < 0;
        if (sv[0] >= 0)
            sys_close(sv[0]);
        cng_dprintf(1, "shmtest short reply leaks no fd -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 1) create, attach, and see the memory. */
    long id = shm_call(__NR_shmget, 0 /*IPC_PRIVATE*/, SHMT_SZ,
                       CNG_IPC_CREAT | 0600);
    long p = shm_call(__NR_shmat, id, 0, 0);
    {
        int ok = id > 0 && !cng_is_err(p);
        if (ok)
            cng_strlcpy((char *)p, "parent-wrote-this", 32);
        struct cng_shmid64_ds ds;
        ok = ok && shmt_stat(id, &ds) == 0 && ds.shm_segsz == SHMT_SZ &&
             ds.shm_nattch == 1 && ds.shm_cpid == self &&
             (ds.shm_perm.mode & 0777) == 0600;
        cng_dprintf(1, "shmtest create+attach+stat -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
        if (!ok) { /* nothing below can mean anything without a segment */
            cng_dprintf(1, "shmtest: %d failure(s)\n", fails + 1);
            return 1;
        }
    }

    /* 2) a fork child inherits the attachment: it must see our store, its own
     *    store must come back to us, and nattch must count it — then drop it
     *    again once the child is gone (chroot-ng traps no exit path, so that
     *    last part is the broker's death reclaim doing its job). */
    {
        struct cng_shmid64_ds ds;
        long kid = shm_call(__NR_clone, 17 /*SIGCHLD*/, 0, 0);
        if (kid == 0) {
            int saw = !strcmp((char *)p, "parent-wrote-this");
            cng_strlcpy((char *)p, saw ? "child-wrote-this" : "child-saw-junk",
                        32);
            /* Prove the child's attach is counted while it is alive. */
            if (shmt_stat(id, &ds) == 0 && ds.shm_nattch != 2)
                cng_strlcpy((char *)p, "child-nattch-wrong", 32);
            sys_exit_group(0);
        }
        int st = 0;
        sys_wait4((int)kid, &st, 0, 0);
        int ok = kid > 0 && !strcmp((char *)p, "child-wrote-this");
        int reclaimed = shmt_stat(id, &ds) == 0 && ds.shm_nattch == 1;
        cng_dprintf(1, "shmtest fork share=%d nattch-after-exit=%lu -> %s\n", ok,
                    (unsigned long)ds.shm_nattch,
                    ok && reclaimed ? "OK" : "FAIL");
        fails += !(ok && reclaimed);
    }

    /* 3) attach-address rules, expressed as mmap flags here: an unaligned
     *    address is EINVAL, SHM_RND rounds down to SHMLBA (the page size on
     *    arm64), an occupied range is EINVAL, and SHM_REMAP takes it over. */
    {
        long bad = shm_call(__NR_shmat, id, 0x1234, 0);
        unsigned long hole = shmt_hole(SHMT_SZ);
        long rnd = shm_call(__NR_shmat, id, (long)(hole + 0x40), CNG_SHM_RND);
        void *occ = sys_mmap(0, SHMT_SZ, CNG_PROT_READ | CNG_PROT_WRITE,
                             CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
        long taken = shm_call(__NR_shmat, id, (long)occ, 0);
        long remap = shm_call(__NR_shmat, id, (long)occ, CNG_SHM_REMAP);
        int ok = bad == -EINVAL && hole && (unsigned long)rnd == hole &&
                 taken == -EINVAL && remap == (long)occ &&
                 !strcmp((char *)remap, "child-wrote-this");
        cng_dprintf(1, "shmtest attach-addr unaligned/rnd/occupied/remap -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
        if (!cng_is_err(rnd))
            shm_call(__NR_shmdt, rnd, 0, 0);
        if (!cng_is_err(remap))
            shm_call(__NR_shmdt, remap, 0, 0);
    }

    /* 4) a read-only attach sees the same memory. */
    {
        long ro = shm_call(__NR_shmat, id, 0, CNG_SHM_RDONLY);
        int ok = !cng_is_err(ro) && !strcmp((char *)ro, "child-wrote-this");
        cng_dprintf(1, "shmtest rdonly attach -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
        if (!cng_is_err(ro))
            shm_call(__NR_shmdt, ro, 0, 0);
    }

    /* 5) detach, remove, and confirm the id is dead. A second shmdt of the same
     *    address is EINVAL, as it is on a real kernel. */
    {
        long d1 = shm_call(__NR_shmdt, p, 0, 0);
        long d2 = shm_call(__NR_shmdt, p, 0, 0);
        long rm = shm_call(__NR_shmctl, id, CNG_IPC_RMID, 0);
        long again = shm_call(__NR_shmat, id, 0, 0);
        int ok = d1 == 0 && d2 == -EINVAL && rm == 0 && again == -EINVAL;
        cng_dprintf(1, "shmtest detach+rmid -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 6) keyed lookup: the same key finds the same segment, IPC_EXCL refuses an
     *    existing one, and a missing key without IPC_CREAT is ENOENT. */
    {
        s32 key = (s32)(0x51000000 + (self & 0xffffff));
        long a = shm_call(__NR_shmget, key, SHMT_SZ, CNG_IPC_CREAT | 0600);
        long b = shm_call(__NR_shmget, key, SHMT_SZ, 0);
        long e = shm_call(__NR_shmget, key, SHMT_SZ,
                          CNG_IPC_CREAT | CNG_IPC_EXCL | 0600);
        long n = shm_call(__NR_shmget, key + 1, SHMT_SZ, 0);
        long big = shm_call(__NR_shmget, key, SHMT_SZ * 4, 0);
        int ok = a > 0 && b == a && e == -EEXIST && n == -ENOENT &&
                 big == -EINVAL;
        cng_dprintf(1, "shmtest keyed lookup -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
        if (a > 0)
            shm_call(__NR_shmctl, a, CNG_IPC_RMID, 0);
    }

    /* 7) the enumeration path ipcs(1) walks: SHM_INFO for the highest index,
     *    then SHM_STAT by index until our own segment turns up. */
    {
        long id2 = shm_call(__NR_shmget, 0, 12288, CNG_IPC_CREAT | 0600);
        struct cng_shm_info info;
        long maxid = shm_call(__NR_shmctl, 0, CNG_SHM_INFO, (long)&info);
        int found = 0, size_ok = 0, cpid_ok = 0;
        for (long i = 0; i <= maxid; i++) {
            struct cng_shmid64_ds ds;
            long sid = shm_call(__NR_shmctl, i, CNG_SHM_STAT, (long)&ds);
            if (sid != id2)
                continue;
            found = 1;
            size_ok = ds.shm_segsz == 12288;
            cpid_ok = ds.shm_cpid == self;
        }
        /* IPC_INFO reports the limits, not the segments; ipcs -m -l reads it. */
        struct cng_shminfo64 li;
        memset(&li, 0, sizeof li);
        shm_call(__NR_shmctl, 0, CNG_IPC_INFO, (long)&li);
        int limits_ok = li.shmmni >= 1 && li.shmseg >= 1 && li.shmmax >= 12288;
        int ok = id2 > 0 && maxid >= 0 && info.used_ids >= 1 &&
                 info.shm_tot >= 12288 / pg && found && size_ok && cpid_ok &&
                 limits_ok;
        cng_dprintf(1, "shmtest shm_info+shm_stat+ipc_info -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
        if (id2 > 0)
            shm_call(__NR_shmctl, id2, CNG_IPC_RMID, 0);
    }

    /* 8) IPC_SET writes the permission triad back. */
    {
        long id3 = shm_call(__NR_shmget, 0, SHMT_SZ, CNG_IPC_CREAT | 0600);
        struct cng_shmid64_ds ds;
        memset(&ds, 0, sizeof ds);
        ds.shm_perm.mode = 0640;
        ds.shm_perm.uid = (u32)sys_geteuid();
        ds.shm_perm.gid = (u32)sys_getegid();
        long set = shm_call(__NR_shmctl, id3, CNG_IPC_SET, (long)&ds);
        struct cng_shmid64_ds back;
        int ok = id3 > 0 && set == 0 && shmt_stat(id3, &back) == 0 &&
                 (back.shm_perm.mode & 0777) == 0640;
        cng_dprintf(1, "shmtest ipc_set -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
        if (id3 > 0)
            shm_call(__NR_shmctl, id3, CNG_IPC_RMID, 0);
    }

    /* 9) execve semantics: attaches do not survive it. cng_shm_detach_all is
     *    what the emulated execve calls at its commit point. */
    {
        long id4 = shm_call(__NR_shmget, 0, SHMT_SZ, CNG_IPC_CREAT | 0600);
        long a1 = shm_call(__NR_shmat, id4, 0, 0);
        long a2 = shm_call(__NR_shmat, id4, 0, 0);
        struct cng_shmid64_ds ds;
        int before = shmt_stat(id4, &ds) == 0 && ds.shm_nattch == 2;
        cng_shm_detach_all();
        int after = shmt_stat(id4, &ds) == 0 && ds.shm_nattch == 0;
        /* The mappings are gone too, not just the accounting: both ranges must
         * now be free, which MAP_FIXED_NOREPLACE reports by handing back the
         * very address we asked for. */
        int unmapped = 1;
        for (int k = 0; k < 2; k++) {
            long a = k ? a2 : a1;
            void *m = sys_mmap((void *)a, SHMT_SZ, CNG_PROT_READ,
                               CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS |
                                   CNG_MAP_FIXED_NOREPLACE,
                               -1, 0);
            if (cng_is_err((long)m) || (long)m != a)
                unmapped = 0;
            if (!cng_is_err((long)m))
                sys_munmap(m, SHMT_SZ);
        }
        int ok = id4 > 0 && !cng_is_err(a1) && !cng_is_err(a2) && before &&
                 after && unmapped;
        cng_dprintf(1, "shmtest execve detach-all -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
        if (id4 > 0)
            shm_call(__NR_shmctl, id4, CNG_IPC_RMID, 0);
    }

    /* 10) a bad shmid, a zero size and an unknown command are refused. */
    {
        int ok = shm_call(__NR_shmat, 999999, 0, 0) == -EINVAL &&
                 shm_call(__NR_shmctl, 999999, CNG_IPC_STAT, 0) == -EINVAL &&
                 shm_call(__NR_shmget, 0, 0, CNG_IPC_CREAT | 0600) == -EINVAL &&
                 shm_call(__NR_shmdt, 0, 0, 0) == -EINVAL;
        cng_dprintf(1, "shmtest error cases -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    cng_dprintf(1, "shmtest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

/* ---- _ipctest: System V semaphores and message queues ------------------- */

/* The differential guests (tests/guests/sem_*.c) are the real coverage here —
 * they diff the emulation against the host kernel's own SysV IPC. This drives
 * the same dispatcher without a libc or a working host implementation, which is
 * what makes it the only coverage available on Android, where bionic drops the
 * API and the app domain is denied the syscalls outright. */

static long ipc_call(long nr, long a0, long a1, long a2, long a3, long a4) {
    return cng_dispatch(nr, a0, a1, a2, a3, a4, 0, /*trapped=*/0);
}

static long sem_ctl(long id, long num, long cmd, long arg) {
    return ipc_call(__NR_semctl, id, num, cmd | 0x100 /*IPC_64*/, arg, 0);
}

int cng_cmd_ipctest(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)argc;
    (void)argv;
    (void)auxv;
    cng_g_host_envp = envp; /* the broker's env lookups (TMPDIR, ...) */
    int fails = 0;
    int self = (int)sys_getpid();

    long sid = ipc_call(__NR_semget, 0 /*IPC_PRIVATE*/, 3, CNG_IPC_CREAT | 0600,
                        0, 0);
    if (sid <= 0) {
        cng_dprintf(1, "ipctest semget -> FAIL (%ld)\n", sid);
        return 1;
    }

    /* 1) fresh semaphores read zero; SETVAL/GETVAL round-trip; a multi-op
     *    vector applies as a whole and stamps sempid on every member. */
    {
        int ok = sem_ctl(sid, 0, CNG_GETVAL, 0) == 0 &&
                 sem_ctl(sid, 2, CNG_GETVAL, 0) == 0 &&
                 sem_ctl(sid, 1, CNG_SETVAL, 5) == 0 &&
                 sem_ctl(sid, 1, CNG_GETVAL, 0) == 5;
        struct cng_sembuf ops[2] = {{1, -2, 0}, {0, +3, 0}};
        ok = ok && ipc_call(__NR_semop, sid, (long)ops, 2, 0, 0) == 0 &&
             sem_ctl(sid, 0, CNG_GETVAL, 0) == 3 &&
             sem_ctl(sid, 1, CNG_GETVAL, 0) == 3 &&
             sem_ctl(sid, 0, CNG_GETPID, 0) == self;
        cng_dprintf(1, "ipctest semget+setval+semop -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 2) the vector is atomic: an operation that cannot proceed rolls the whole
     *    thing back, so the +9 in front of the blocking -99 must not stick. */
    {
        struct cng_sembuf mixed[2] = {{0, +9, 0}, {2, -99, CNG_IPC_NOWAIT}};
        long r = ipc_call(__NR_semop, sid, (long)mixed, 2, 0, 0);
        int ok = r == -EAGAIN && sem_ctl(sid, 0, CNG_GETVAL, 0) == 3;
        cng_dprintf(1, "ipctest semop atomic rollback -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 3) GETALL/SETALL, which stream their vector over the broker connection
     *    rather than riding in the fixed request. */
    {
        u16 set[3] = {7, 8, 9}, got[3] = {0, 0, 0};
        int ok = sem_ctl(sid, 0, CNG_SETALL, (long)set) == 0 &&
                 sem_ctl(sid, 0, CNG_GETALL, (long)got) == 0 && got[0] == 7 &&
                 got[1] == 8 && got[2] == 9;
        cng_dprintf(1, "ipctest semctl getall+setall -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 4) IPC_STAT / IPC_SET, and the ipcs enumeration commands. */
    {
        struct cng_semid64_ds ds;
        memset(&ds, 0, sizeof ds);
        int ok = sem_ctl(sid, 0, CNG_IPC_STAT, (long)&ds) == 0 &&
                 ds.sem_nsems == 3 && (ds.sem_perm.mode & 0777) == 0600;
        ds.sem_perm.mode = 0640;
        ok = ok && sem_ctl(sid, 0, CNG_IPC_SET, (long)&ds) == 0 &&
             sem_ctl(sid, 0, CNG_IPC_STAT, (long)&ds) == 0 &&
             (ds.sem_perm.mode & 0777) == 0640;
        struct cng_seminfo si;
        memset(&si, 0, sizeof si);
        long maxidx = sem_ctl(sid, 0, CNG_SEM_INFO, (long)&si);
        ok = ok && maxidx >= 0 && si.semusz >= 1 && si.semaem >= 3 &&
             si.semmsl == CNG_SEMMSL;
        /* SEM_STAT takes the array index SEM_INFO just reported, not an id. */
        memset(&ds, 0, sizeof ds);
        ok = ok && sem_ctl(maxidx, 0, CNG_SEM_STAT, (long)&ds) == sid;
        cng_dprintf(1, "ipctest semctl stat+set+enumeration -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 5) a blocking semop, woken by a fork child — which also proves the daemon
     *    keeps serving while one connection sits parked. */
    {
        u16 zero[3] = {0, 0, 0};
        sem_ctl(sid, 0, CNG_SETALL, (long)zero);
        long kid = cng_dispatch(__NR_clone, 17 /*SIGCHLD*/, 0, 0, 0, 0, 0, 0);
        if (kid == 0) {
            struct cng_timespec ms = {0, 200000000};
            CNG_SYS(__NR_nanosleep, &ms, 0, 0, 0, 0, 0);
            struct cng_sembuf up = {0, +1, 0};
            ipc_call(__NR_semop, sid, (long)&up, 1, 0, 0);
            sys_exit_group(0);
        }
        struct cng_sembuf down = {0, -1, 0};
        long r = ipc_call(__NR_semop, sid, (long)&down, 1, 0, 0);
        sys_wait4((int)kid, 0, 0, 0);
        int ok = kid > 0 && r == 0;
        cng_dprintf(1, "ipctest blocking semop woken -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 6) semtimedop's deadline, which the daemon owns (the client sets no
     *    timeout of its own). */
    {
        struct cng_sembuf down = {0, -1, 0};
        struct cng_timespec to = {0, 200000000};
        long r = ipc_call(__NR_semtimedop, sid, (long)&down, 1, (long)&to, 0);
        cng_dprintf(1, "ipctest semtimedop timeout -> %s\n",
                    r == -EAGAIN ? "OK" : "FAIL");
        fails += !(r == -EAGAIN);
    }

    /* 7) SEM_UNDO across a child's death. chroot-ng traps no exit path, so this
     *    is the broker's incarnation check doing what the kernel does at exit —
     *    and it has to be visible immediately after the reap, not a tick later. */
    {
        sem_ctl(sid, 0, CNG_SETVAL, 2);
        long kid = cng_dispatch(__NR_clone, 17, 0, 0, 0, 0, 0, 0);
        if (kid == 0) {
            struct cng_sembuf d = {0, -2, CNG_SEM_UNDO};
            ipc_call(__NR_semop, sid, (long)&d, 1, 0, 0);
            sys_exit_group(0);
        }
        sys_wait4((int)kid, 0, 0, 0);
        long v = sem_ctl(sid, 0, CNG_GETVAL, 0);
        cng_dprintf(1, "ipctest sem_undo after exit val=%ld -> %s\n", v,
                    v == 2 ? "OK" : "FAIL");
        fails += !(v == 2);
    }

    /* 7b) the semadj range, at both ends. A vector naming one semaphore twice
     *     accumulates its adjustment across the operations, so the middle
     *     no-undo step below leaves the third asking for a semadj of -65534: the
     *     kernel refuses the whole vector with ERANGE and changes nothing.
     *     Applied one operation at a time the same total is legal, because the
     *     bound is the s16 range and -32768 is inside it. */
    {
        sem_ctl(sid, 0, CNG_SETVAL, 0); /* also clears every pending semadj */
        struct cng_sembuf over[3] = {
            {0, +32767, CNG_SEM_UNDO}, {0, -32767, 0}, {0, +32767, CNG_SEM_UNDO}};
        int ok = ipc_call(__NR_semop, sid, (long)over, 3, 0, 0) == -ERANGE &&
                 sem_ctl(sid, 0, CNG_GETVAL, 0) == 0;

        sem_ctl(sid, 0, CNG_SETVAL, 0);
        struct cng_sembuf up = {0, +32767, CNG_SEM_UNDO};
        struct cng_sembuf down = {0, -32767, 0};
        struct cng_sembuf one = {0, +1, CNG_SEM_UNDO};
        ok = ok && ipc_call(__NR_semop, sid, (long)&up, 1, 0, 0) == 0 &&
             ipc_call(__NR_semop, sid, (long)&down, 1, 0, 0) == 0 &&
             ipc_call(__NR_semop, sid, (long)&one, 1, 0, 0) == 0 &&
             sem_ctl(sid, 0, CNG_GETVAL, 0) == 1;
        sem_ctl(sid, 0, CNG_SETVAL, 0);
        cng_dprintf(1, "ipctest sem_undo range -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 7c) nsops is `unsigned`: the kernel narrows it and acts on the low word,
     *     so a 64-bit count with a set top half is one operation, not E2BIG. */
    {
        sem_ctl(sid, 0, CNG_SETVAL, 0);
        struct cng_sembuf up = {0, +1, 0};
        int ok = ipc_call(__NR_semop, sid, (long)&up, 0x100000001L, 0, 0) == 0 &&
                 sem_ctl(sid, 0, CNG_GETVAL, 0) == 1;
        sem_ctl(sid, 0, CNG_SETVAL, 0);
        cng_dprintf(1, "ipctest semop nsops width -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 8) the error cases, in the kernel's order. */
    {
        struct cng_sembuf bad = {99, -1, 0};
        struct cng_sembuf ok1 = {0, 0, 0};
        int ok = ipc_call(__NR_semop, sid, (long)&bad, 1, 0, 0) == -EFBIG &&
                 ipc_call(__NR_semop, sid, (long)&ok1, 0, 0, 0) == -EINVAL &&
                 sem_ctl(999999, 0, CNG_GETVAL, 0) == -EINVAL &&
                 sem_ctl(sid, 0, CNG_SETVAL, 99999) == -ERANGE &&
                 ipc_call(__NR_semget, 0, -1, CNG_IPC_CREAT | 0600, 0, 0) ==
                     -EINVAL;
        cng_dprintf(1, "ipctest sem error cases -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 9) keyed lookup, IPC_EXCL, and the id dying with IPC_RMID. */
    {
        long a = ipc_call(__NR_semget, 0x63bb0002, 2, CNG_IPC_CREAT | 0600, 0, 0);
        long b = ipc_call(__NR_semget, 0x63bb0002, 2, 0, 0, 0);
        int ok = a > 0 && a == b &&
                 ipc_call(__NR_semget, 0x63bb0002, 2,
                          CNG_IPC_CREAT | CNG_IPC_EXCL | 0600, 0, 0) == -EEXIST &&
                 sem_ctl(a, 0, CNG_IPC_RMID, 0) == 0 &&
                 ipc_call(__NR_semget, 0x63bb0002, 2, 0, 0, 0) == -ENOENT;
        cng_dprintf(1, "ipctest sem keyed lookup -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }
    sem_ctl(sid, 0, CNG_IPC_RMID, 0);

    /* ---- message queues ---- */
    long qid = ipc_call(__NR_msgget, 0, CNG_IPC_CREAT | 0600, 0, 0, 0);
    if (qid <= 0) {
        cng_dprintf(1, "ipctest msgget -> FAIL (%ld)\n", qid);
        cng_dprintf(1, "ipctest: %d failure(s)\n", fails + 1);
        return 1;
    }

    struct {
        s64 mtype;
        char t[32];
    } m;

    /* 10) send three types, then take them back by type, by "at most", and by
     *     FIFO — the whole msgrcv selection rule in one group. */
    {
        int ok = 1;
        for (long t = 1; t <= 3; t++) {
            memset(&m, 0, sizeof m);
            m.mtype = t;
            m.t[0] = (char)('0' + t);
            ok = ok && ipc_call(__NR_msgsnd, qid, (long)&m, sizeof m.t, 0, 0) == 0;
        }
        struct cng_msqid64_ds ds;
        memset(&ds, 0, sizeof ds);
        ok = ok &&
             ipc_call(__NR_msgctl, qid, CNG_IPC_STAT | 0x100, (long)&ds, 0, 0) ==
                 0 &&
             ds.msg_qnum == 3 && ds.msg_cbytes == 96 && ds.msg_lspid == self &&
             ds.msg_qbytes == CNG_MSGMNB;
        memset(&m, 0, sizeof m);
        ok = ok && ipc_call(__NR_msgrcv, qid, (long)&m, sizeof m.t, 2, 0) == 32 &&
             m.mtype == 2 && m.t[0] == '2';
        memset(&m, 0, sizeof m);
        ok = ok && ipc_call(__NR_msgrcv, qid, (long)&m, sizeof m.t, -3, 0) == 32 &&
             m.mtype == 1;
        memset(&m, 0, sizeof m);
        ok = ok && ipc_call(__NR_msgrcv, qid, (long)&m, sizeof m.t, 0, 0) == 32 &&
             m.mtype == 3;
        ok = ok && ipc_call(__NR_msgrcv, qid, (long)&m, sizeof m.t, 0,
                            CNG_IPC_NOWAIT) == -ENOMSG;
        cng_dprintf(1, "ipctest msgsnd+msgrcv selection -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 10b) the msg enumeration commands, the counterpart of the sem group in 4:
     *      MSG_INFO for the highest index, MSG_STAT by that index, and IPC_INFO
     *      for the limits. msgssz/msgseg are asserted for both info commands
     *      because msgctl_info fills them for both — MSG_INFO repurposes only
     *      the pool/map/tql triple. */
    {
        struct cng_msginfo mi;
        memset(&mi, 0, sizeof mi);
        long maxidx = ipc_call(__NR_msgctl, 0, CNG_MSG_INFO, (long)&mi, 0, 0);
        int ok = maxidx >= 0 && mi.msgpool >= 1 && mi.msgmnb == CNG_MSGMNB &&
                 mi.msgmax == CNG_MSGMAX && mi.msgssz == 16 &&
                 mi.msgseg == 0xffff;
        struct cng_msqid64_ds ds;
        memset(&ds, 0, sizeof ds);
        ok = ok && ipc_call(__NR_msgctl, maxidx, CNG_MSG_STAT | 0x100, (long)&ds,
                            0, 0) == qid;
        memset(&mi, 0, sizeof mi);
        ok = ok && ipc_call(__NR_msgctl, 0, CNG_IPC_INFO, (long)&mi, 0, 0) >= 0 &&
             mi.msgmni >= 1 && mi.msgssz == 16 && mi.msgseg == 0xffff;
        cng_dprintf(1, "ipctest msgctl enumeration -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 11) a buffer too small is E2BIG and leaves the message queued; with
     *     MSG_NOERROR it is truncated instead. */
    {
        memset(&m, 0, sizeof m);
        m.mtype = 9;
        ipc_call(__NR_msgsnd, qid, (long)&m, sizeof m.t, 0, 0);
        struct {
            s64 mtype;
            char t[4];
        } sm;
        int ok = ipc_call(__NR_msgrcv, qid, (long)&sm, 4, 0, 0) == -E2BIG &&
                 ipc_call(__NR_msgrcv, qid, (long)&sm, 4, 0, CNG_MSG_NOERROR) ==
                     4 &&
                 sm.mtype == 9;
        cng_dprintf(1, "ipctest msgrcv E2BIG+MSG_NOERROR -> %s\n",
                    ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 12) a receive that waits for a sender in another process. */
    {
        long kid = cng_dispatch(__NR_clone, 17, 0, 0, 0, 0, 0, 0);
        if (kid == 0) {
            struct cng_timespec ms = {0, 200000000};
            CNG_SYS(__NR_nanosleep, &ms, 0, 0, 0, 0, 0);
            memset(&m, 0, sizeof m);
            m.mtype = 5;
            m.t[0] = 'L';
            ipc_call(__NR_msgsnd, qid, (long)&m, sizeof m.t, 0, 0);
            sys_exit_group(0);
        }
        memset(&m, 0, sizeof m);
        long n = ipc_call(__NR_msgrcv, qid, (long)&m, sizeof m.t, 0, 0);
        sys_wait4((int)kid, 0, 0, 0);
        int ok = kid > 0 && n == 32 && m.mtype == 5 && m.t[0] == 'L';
        cng_dprintf(1, "ipctest blocking msgrcv woken -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    /* 13) the message error cases and IPC_RMID. */
    {
        memset(&m, 0, sizeof m);
        m.mtype = 0;
        int ok = ipc_call(__NR_msgsnd, qid, (long)&m, sizeof m.t, 0, 0) ==
                     -EINVAL &&
                 ipc_call(__NR_msgsnd, qid, (long)&m, CNG_MSGMAX + 1, 0, 0) ==
                     -EINVAL &&
                 ipc_call(__NR_msgctl, 999999, CNG_IPC_STAT | 0x100, (long)&m, 0,
                          0) == -EINVAL &&
                 ipc_call(__NR_msgctl, qid, CNG_IPC_RMID, 0, 0, 0) == 0 &&
                 ipc_call(__NR_msgctl, qid, CNG_IPC_STAT | 0x100, (long)&m, 0,
                          0) == -EINVAL;
        cng_dprintf(1, "ipctest msg error cases+rmid -> %s\n", ok ? "OK" : "FAIL");
        fails += !ok;
    }

    cng_dprintf(1, "ipctest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
