/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Syscall dispatcher: translate path arguments of a trapped syscall and
 * re-issue the real syscall through the gate (cng_syscall6), whose IP the
 * seccomp filter allows so we don't re-trap. Runs in-process, so path pointers
 * are directly readable — no cross-process memory access like proot needs.
 *
 * Also applies the M7 fidelity fixups: credential/ownership faking (--fake-id),
 * /proc/self readlink fixups, and the link2symlink fallback (--link2symlink).
 */
#include "cng/execmap.h"
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/pin.h"
#include "cng/procfs.h"
#include "cng/procreg.h"
#include "cng/ptrace.h"
#include "cng/netlink.h"
#include "cng/unixsock.h"
#include "cng/rt.h"
#include "cng/shm.h"
#include "cng/sysvipc.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

/* cng_g_fs, the published fs view, lives in path.c. */

/* The fake-identity globals (cng_g_fake_id, cng_g_cred, ...) live in cred.c. */
const char *cng_g_exe_guest = "/";

/* AArch64 struct stat / statx field offsets for ownership rewriting, plus the
 * st_mode offset used by the fake-root access() fallback. */
/* The kernel's own struct sizes: what a stat/statx writes, and so exactly what
 * has to come back out of a guest buffer and go back into it. */
#define STAT_BUF_SIZE  128
#define STATX_BUF_SIZE 256
#define STATFS_BUF_SIZE 120
#define STAT_DEV_OFF   0
#define STAT_INO_OFF   8
#define STAT_MODE_OFF  16
#define STAT_UID_OFF   24
#define STAT_GID_OFF   28
#define STATX_UID_OFF  20
#define STATX_GID_OFF  24
#define STATX_MODE_OFF 28   /* stx_mode is a u16 at offset 28 */
#define CNG_X_OK        1   /* access(2) X_OK */
#define CNG_W_OK        2   /* access(2) W_OK */

/* Rewrite a struct stat / statx buffer's ownership under a fake identity: files
 * owned by the real invoking user appear owned by the fake id, and a setuid/
 * setgid executable appears root-owned under --setuid-root/--setgid-root (the
 * st_mode drives that; see cng_exec_vis_*). A no-op unless --fake-id is active. */
static void stat_remap(void *st) {
    unsigned mode = *(unsigned *)((char *)st + STAT_MODE_OFF);
    unsigned *u = (unsigned *)((char *)st + STAT_UID_OFF);
    unsigned *g = (unsigned *)((char *)st + STAT_GID_OFF);
    *u = cng_exec_vis_uid(*u, mode);
    *g = cng_exec_vis_gid(*g, mode);
}
static void statx_remap(void *st) {
    unsigned mode = *(unsigned short *)((char *)st + STATX_MODE_OFF);
    unsigned *u = (unsigned *)((char *)st + STATX_UID_OFF);
    unsigned *g = (unsigned *)((char *)st + STATX_GID_OFF);
    *u = cng_exec_vis_uid(*u, mode);
    *g = cng_exec_vis_gid(*g, mode);
}

/* Fake-root turns a privilege-denied ownership/mode change into success — the
 * real process is unprivileged, but the guest believes it is root. Denied
 * (EPERM/EACCES/EINVAL) and Android-blocked (ENOSYS) results are faked; genuine
 * errors (ENOENT, EROFS, ...) still propagate, as do all results when the
 * identity is unprivileged or inactive. */
static long chattr_result(long r) {
    if (r == 0)
        return 0;
    if (cng_fake_root() &&
        (r == -EPERM || r == -EACCES || r == -EINVAL || r == -ENOSYS))
        return 0;
    return r;
}

static int fs_has_ro(void);
static size_t proc_pid_prefix(const char *p, int self_only);
static long parse_int_run(const char **p);

/* --- :ro binds, through an fd magic link ----------------------------------
 *
 * "/proc/<pid>/fd/<n>" resolves to a host path that names no mount of ours,
 * so a write-open of it passed every :ro check: open a file under the bind
 * read-only (or O_PATH), reopen its fd link with O_WRONLY or O_TRUNC, and the
 * host file was written. On a real read-only mount the reopen inherits the
 * vfsmount the description was opened through and answers EROFS. Here the
 * mount is a prefix of the description's own path — which the link reports —
 * so that is what the question is asked about. (A link with components after
 * the fd is expanded by the walk into the directory's guest name, so the host
 * path that arrives here is already the file's own.)
 *
 * Except through the link2symlink emulation. A descriptor opened through an
 * l2s name is on the group's DATA file, in the store under the rootfs where no
 * bind covers it, and which name it was opened through is not something a
 * description remembers. What it does remember is its access mode: a writable
 * one came through a writable name, since every write-open under a :ro name is
 * refused by name, so it may be reopened; a read-only or O_PATH one is judged
 * as if it had come through the :ro bind whenever the view has one at all.
 * That over-refuses exactly one shape — a read-only descriptor on a hardlinked
 * file opened through a writable name and then reopened for writing through
 * its fd link, while some :ro bind exists — and nothing else.
 *
 * Returns 1 for a link on a file the guest may not write, 0 for one it may
 * (an anonymous description too: a pipe or a memfd is on no mount of ours),
 * and -1 when `host` is not an fd link at all. */
static int fd_link_ro(const char *host) {
    size_t pl = proc_pid_prefix(host, 0);
    if (!pl || strncmp(host + pl, "fd/", 3) != 0)
        return -1;
    const char *d = host + pl + 3;
    if (parse_int_run(&d) < 0 || *d)
        return -1; /* the fd directory, or a name below the link: not this */
    char real[CNG_PATH_MAX];
    long n = sys_readlinkat(CNG_AT_FDCWD, host, real, sizeof real - 1);
    if (n <= 0 || real[0] != '/')
        return 0;
    real[n] = '\0';
    if (cng_fs_host_ro(cng_g_fs, real))
        return 1;
    if (cng_g_l2s && fs_has_ro()) {
        const char *b = strrchr(real, '/');
        if (cng_l2s_hidden(b ? b + 1 : real)) {
            int fd = cng_proc_self_fd(host);
            long fl = fd >= 0 ? sys_fcntl(fd, CNG_F_GETFL, 0) : -1;
            /* Another process's descriptor cannot be asked (fl < 0): it is
             * taken as read-only, the side that refuses. */
            if (fl < 0 || (fl & CNG_O_ACCMODE) == CNG_O_RDONLY)
                return 1;
        }
    }
    return 0;
}

/* A mutating syscall whose target lands under a `:ro` bind must answer -EROFS,
 * the way it would on a real read-only mount. Keyed on the already-resolved
 * HOST path, so a guest symlink that leads into the bind is covered however the
 * path got there — and an fd magic link is asked about the file it stands for
 * (fd_link_ro). Checked before the reissue, and before chattr_result — a
 * read-only mount is a genuine error that fake-root does not paper over. */
static int ro_denied(const char *host) {
    if (!host || !cng_g_fs)
        return 0;
    int l = fd_link_ro(host);
    if (l >= 0)
        return l;
    return cng_fs_host_ro(cng_g_fs, host);
}

/* ...but a real read-only mount refuses at the point the kernel reaches it, and
 * the calls that have to operate on an *existing* name reach it only after the
 * path has resolved. So a name that is not there is ENOENT, exactly as it would
 * be on a writable mount, and only a name that is there is EROFS. Measured on a
 * squashfs mount, and uniform across the family: open(missing, O_WRONLY),
 * truncate, chmod, utimensat, chown and setxattr all answer ENOENT for a name
 * that is not there and EROFS for one that is. `[ -e f ] || : >f` is the shape
 * that notices — a configure-style probe for an optional file read "read-only"
 * as "present" and took the wrong branch.
 *
 * The create-and-remove family orders it the other way, taking write access on
 * the parent before it looks at the final component: unlink, rmdir, mkdir,
 * mknod, symlink, rename and an O_CREAT open are all EROFS even for a name that
 * is not there (measured too). Those keep the plain ro_denied() pre-check.
 *
 * Answers with the lookup's own error rather than falling through to the
 * reissue, so the refusal stays absolute — a :ro bind's host directory is
 * genuinely writable, and letting a "not there" pass through to the real call
 * would put the containment behind a race. newfstatat resolves the same path
 * the same way, so its errno is what the real call would have reported from the
 * same lookup: ENOENT, ENOTDIR, EACCES, ELOOP. `atflags` must carry the caller's
 * own AT_SYMLINK_NOFOLLOW, or an lchown of a dangling link reads as absent. */
static long ro_refusal(const char *host, int atflags) {
    if (!ro_denied(host))
        return 0;
    char st[144];
    long r = cng_pin_fstatat(host, st, atflags);
    return r < 0 ? r : -EROFS;
}

/* One-shot-per-number diagnostic that a syscall was emulated away (blocked by
 * Android's seccomp filter, or a credential change we can't perform). Shared
 * with the SIGSYS gate-net. Async-signal-safe. */
void cng_note_blocked(int nr) {
    static unsigned char warned[600];
    if (nr < 0 || nr >= (int)sizeof warned || warned[nr])
        return;
    warned[nr] = 1;
    cng_dprintf(2, "chroot-ng: syscall %d not permitted here -> emulated\n", nr);
}

/* Re-issue the guest's (translated) syscall through the gate — but if Android's
 * filter blocks it (measured by cng_probe_blocked), emulate ENOSYS instead, so
 * we never trap on the re-issue. Same signature as cng_syscall6. */
int cng_g_debug = 0;
char **cng_g_host_envp = 0;

/* Best-effort path argument among a0/a1 for logging (path syscalls put the path
 * in a0 or a1), taken into `buf` rather than handed back as a guest pointer.
 *
 * A magnitude test would not do: the args of a *failing* syscall include plain
 * scalars (a uid, an offset, a length) that are large enough to look like
 * pointers, and dereferencing one reads a wild address — a SIGSEGV inside the
 * handler, with SIGSEGV masked, kills the guest outright. CNG_DEBUG must never
 * change behaviour. Neither would asking the kernel first (a faccessat that
 * answers EFAULT for what is not a string): that leaves the printing itself
 * walking guest memory a syscall later, and the guest is free to unmap it in
 * between. Copying it settles both questions at once — what will not come
 * across is not a string, and what did is ours to print. */
static const char *dbg_path(long a0, long a1, char *buf, unsigned long sz) {
    if (cng_user_strcopyin(buf, (const char *)a1, sz) > 0 && buf[0] == '/')
        return buf;
    if (cng_user_strcopyin(buf, (const char *)a0, sz) > 0 && buf[0] == '/')
        return buf;
    return "";
}

/* The newer forms a pinned re-issue reaches for (see pin_args): faccessat2
 * and fchmodat2 where the old call has no NOFOLLOW to give, and openat2 for
 * every open. A kernel without one answers ENOSYS, which is remembered so
 * the other form is taken directly from then on; a filter that blocks them
 * is already in cng_blocked. */
static int g_no_faccessat2, g_no_fchmodat2, g_no_openat2;

/* An open is not made with O_NOFOLLOW added: the kernel keeps that flag on
 * the description, F_GETFL and fdinfo report it, and a program that reopens
 * a name with the flags it read back would then be refused a symlink it
 * never asked to avoid. RESOLVE_NO_SYMLINKS refuses the same link without a
 * trace on the description, so the open is made as an openat2 with the how
 * the kernel itself builds for an openat (build_open_how: the flags outside
 * its own set dropped, O_PATH keeping only its companions, the mode kept only
 * for a creating open) — openat2 refuses what openat silently strips, and
 * the two calls must answer alike. A flag this table does not know is left
 * alone and takes the O_NOFOLLOW form instead, so a newer kernel's flag is
 * never stripped here; so does a host without openat2 (Android's filter
 * blocks it), where the bit on the description is the residue. */
#define OPEN_FLAGS_KNOWN                                                      \
    (CNG_O_ACCMODE | CNG_O_CREAT | CNG_O_EXCL | CNG_O_NOCTTY | CNG_O_TRUNC |  \
     CNG_O_APPEND | CNG_O_NONBLOCK | CNG_O_DSYNC | 020000 /*FASYNC*/ |        \
     CNG_O_DIRECT | CNG_O_LARGEFILE | CNG_O_DIRECTORY | CNG_O_NOFOLLOW |      \
     CNG_O_NOATIME | CNG_O_CLOEXEC | 04000000 /*__O_SYNC*/ | CNG_O_PATH |     \
     CNG___O_TMPFILE)
#define OPEN_FLAGS_PATH (CNG_O_DIRECTORY | CNG_O_NOFOLLOW | CNG_O_PATH | CNG_O_CLOEXEC)

static int open_as_openat2(long flags, long mode, struct cng_open_how *how) {
    if (g_no_openat2 || cng_blocked[__NR_openat2] ||
        (flags & ~(long)OPEN_FLAGS_KNOWN))
        return 0;
    how->flags = (unsigned long)flags;
    if (how->flags & CNG_O_PATH)
        how->flags &= OPEN_FLAGS_PATH;
    how->mode = (how->flags & (CNG_O_CREAT | CNG___O_TMPFILE))
                    ? (unsigned long)mode & 07777
                    : 0;
    how->resolve = CNG_RESOLVE_NO_SYMLINKS;
    return 1;
}

/* Which argument slots of a path-bearing re-issue carry a (dirfd, path) pair,
 * for pin_args and the errno probe below: the first pair's dirfd and path
 * indices, the second's, -1 where there is none. A path-only syscall has a
 * path slot and no dirfd. */
static int reissue_pairs(long nr, int *d1, int *p1, int *d2, int *p2) {
    *d1 = *p1 = *d2 = *p2 = -1;
    switch (nr) {
    case __NR_openat:
    case __NR_openat2:
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_name_to_handle_at:
    case __NR_faccessat:
    case __NR_faccessat2:
    case __NR_fchmodat:
    case __NR_fchmodat2:
    case __NR_unlinkat:
    case __NR_utimensat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_fchownat:
    case __NR_readlinkat:
    case __NR_setxattrat:
    case __NR_getxattrat:
    case __NR_listxattrat:
    case __NR_removexattrat:
    case __NR_file_getattr:
    case __NR_file_setattr:
        *d1 = 0;
        *p1 = 1;
        return 1;
    case __NR_symlinkat:
        *d1 = 1;
        *p1 = 2;
        return 1;
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_linkat:
        *d1 = 0;
        *p1 = 1;
        *d2 = 2;
        *p2 = 3;
        return 2;
    case __NR_inotify_add_watch:
        *p1 = 1;
        return 1;
    case __NR_truncate:
    case __NR_statfs:
    case __NR_chdir:
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr:
        *p1 = 0;
        return 1;
    }
    return 0;
}

/* The errno a pin could not produce. The kernel checks a call's flags, its
 * mode, its lengths before it resolves anything, and answers those first:
 * `fstatat("/missing/x", badflags)` is EINVAL, not ENOENT. A pin that failed
 * on the directory has skipped that order, so the call is made once more with
 * the pinned pair replaced by a descriptor that is no descriptor and a name
 * that needs one — resolution then fails at EBADF, after every check that
 * comes before it. EBADF means the checks passed and the pin's own answer
 * stands; anything else is the kernel's answer, given in its order. The
 * path-only calls that check first use an empty name for the same sentinel,
 * ENOENT. */
static long pin_errno(long nr, const long *a, long err) {
    int d1, p1, d2, p2;
    if (!reissue_pairs(nr, &d1, &p1, &d2, &p2))
        return err;
    long b[6];
    memcpy(b, a, sizeof b);
    long want;
    if (d1 >= 0) {
        b[d1] = -1;
        b[p1] = (long)".";
        if (d2 >= 0) {
            b[d2] = -1;
            b[p2] = (long)".";
        }
        want = -EBADF;
    } else if (nr == __NR_truncate || nr == __NR_inotify_add_watch) {
        b[p1] = (long)"";
        want = -ENOENT;
    } else
        return err; /* the path is what the kernel looks at first */
    long r = cng_syscall6(b[0], b[1], b[2], b[3], b[4], b[5], nr);
    if (r >= 0) { /* cannot happen for these; never leak what it made */
        if (nr == __NR_openat || nr == __NR_openat2 ||
            nr == __NR_name_to_handle_at)
            sys_close((int)r);
        return err;
    }
    return r == want ? err : r;
}

/* Rewrite a re-issue's arguments so that no host path reaches the kernel as
 * a string (cng/pin.h): each (dirfd, path) pair becomes the pinned directory
 * and the last component with the family's NOFOLLOW set, and the forms with
 * no NOFOLLOW to set — or where the kernel follows regardless, after a
 * trailing slash — are made through the leaf's own fd link. `spell` and
 * `how` are storage the rewritten arguments may point into for the call.
 * Returns 0, or the errno of a directory that could not be pinned (already
 * put through pin_errno). The caller unpins both, whatever the answer. */
static long pin_args(long *nr, long *a, struct cng_pin *x, struct cng_pin *y,
                     char *spell, struct cng_open_how *how) {
    int d1, p1, d2, p2;
    x->pinned = y->pinned = 0;
    x->own = y->own = 0;
    x->leaf = y->leaf = -1;
    x->dfd = y->dfd = -1;
    if (!reissue_pairs(*nr, &d1, &p1, &d2, &p2))
        return 0;
    long e = cng_pin_at(d1 >= 0 ? (int)a[d1] : CNG_AT_FDCWD,
                        (const char *)a[p1], x);
    if (e)
        return pin_errno(*nr, a, e);
    if (d2 >= 0) {
        e = cng_pin_at((int)a[d2], (const char *)a[p2], y);
        if (e)
            return pin_errno(*nr, a, e);
        if (y->pinned) {
            a[d2] = y->dfd;
            a[p2] = (long)y->name;
        }
    }
    if (!x->pinned)
        return 0;
    if (d1 >= 0)
        a[d1] = x->dfd;
    a[p1] = (long)x->name;

    /* The forms below that take the leaf: `leaf` pins it (a directory where
     * the name asked for one) and re-aims the pair at its link. */
#define LEAF(need_dir)                                                        \
    do {                                                                      \
        long le = cng_pin_leaf(x, (need_dir));                                \
        if (le)                                                               \
            return le;                                                        \
        if (d1 >= 0)                                                          \
            a[d1] = CNG_AT_FDCWD;                                             \
        a[p1] = (long)x->link;                                                \
    } while (0)

    switch (*nr) {
    case __NR_openat:
        if (x->want_dir && !(a[2] & CNG_O_CREAT)) {
            LEAF(1);
            a[2] &= ~(long)CNG_O_NOFOLLOW;
        } else if (a[2] & CNG_O_NOFOLLOW) {
            ; /* the guest's own, and all the refusal needed */
        } else if (open_as_openat2(a[2], a[3], how)) {
            *nr = __NR_openat2;
            a[2] = (long)how;
            a[3] = (long)sizeof *how;
        } else
            a[2] |= CNG_O_NOFOLLOW;
        break;
    case __NR_openat2:
        /* The caller's copy of the how is not edited: this one is. */
        *how = *(const struct cng_open_how *)a[2];
        a[2] = (long)how;
        a[3] = (long)sizeof *how;
        if (x->want_dir && !(how->flags & CNG_O_CREAT)) {
            LEAF(1);
            how->flags &= ~(unsigned long)CNG_O_NOFOLLOW;
        } else if (!(how->flags & CNG_O_NOFOLLOW))
            how->resolve |= CNG_RESOLVE_NO_SYMLINKS;
        break;
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_unlinkat:
    case __NR_readlinkat:
    case __NR_symlinkat:
    case __NR_renameat:
    case __NR_renameat2:
        break; /* the last component is never followed */
    case __NR_linkat:
        /* The walk followed the source where AT_SYMLINK_FOLLOW asked it to;
         * the pinned name is what it reached, and is not followed again. */
        a[4] &= ~(long)CNG_AT_SYMLINK_FOLLOW;
        break;
    case __NR_name_to_handle_at:
        a[4] &= ~(long)CNG_AT_SYMLINK_FOLLOW;
        if (x->want_dir) {
            long le = cng_pin_leaf(x, 1);
            if (le)
                return le;
            a[0] = x->leaf;
            a[1] = (long)"";
            a[4] |= CNG_AT_EMPTY_PATH;
        }
        break;
    case __NR_faccessat:
        /* No flags word at all: the NOFOLLOW is faccessat2's, where the host
         * has it, and the leaf's link otherwise. */
        if (x->want_dir || g_no_faccessat2 || cng_blocked[__NR_faccessat2]) {
            LEAF(0);
            a[3] = 0;
        } else {
            *nr = __NR_faccessat2;
            a[3] = CNG_AT_SYMLINK_NOFOLLOW;
        }
        break;
    case __NR_faccessat2:
        if (x->want_dir) {
            LEAF(1);
            a[3] &= ~(long)CNG_AT_SYMLINK_NOFOLLOW;
        } else
            a[3] |= CNG_AT_SYMLINK_NOFOLLOW;
        break;
    case __NR_fchmodat:
        if (x->want_dir || g_no_fchmodat2 || cng_blocked[__NR_fchmodat2]) {
            LEAF(0);
            a[3] = 0;
        } else {
            *nr = __NR_fchmodat2;
            a[3] = CNG_AT_SYMLINK_NOFOLLOW;
        }
        break;
    case __NR_fchmodat2:
    case __NR_utimensat:
    case __NR_newfstatat:
        if (x->want_dir) {
            LEAF(1);
            a[3] &= ~(long)CNG_AT_SYMLINK_NOFOLLOW;
        } else
            a[3] |= CNG_AT_SYMLINK_NOFOLLOW;
        break;
    case __NR_statx:
    case __NR_setxattrat:
    case __NR_getxattrat:
    case __NR_listxattrat:
    case __NR_removexattrat:
        if (x->want_dir) {
            LEAF(1);
            a[2] &= ~(long)CNG_AT_SYMLINK_NOFOLLOW;
        } else
            a[2] |= CNG_AT_SYMLINK_NOFOLLOW;
        break;
    case __NR_fchownat:
    case __NR_file_getattr:
    case __NR_file_setattr:
        if (x->want_dir) {
            LEAF(1);
            a[4] &= ~(long)CNG_AT_SYMLINK_NOFOLLOW;
        } else
            a[4] |= CNG_AT_SYMLINK_NOFOLLOW;
        break;
    case __NR_truncate:
    case __NR_statfs:
        LEAF(0);
        break;
    case __NR_chdir:
        LEAF(1);
        *nr = __NR_fchdir;
        a[0] = x->leaf;
        break;
    case __NR_setxattr:
    case __NR_getxattr:
    case __NR_listxattr:
    case __NR_removexattr:
    case __NR_lsetxattr:
    case __NR_lgetxattr:
    case __NR_llistxattr:
    case __NR_lremovexattr: {
        /* The l-forms never follow their last component, so the pinned pair
         * spelled through the directory's fd link is the race-free form of
         * both families: what the following forms would have followed, the
         * walk already did. After a trailing slash the leaf is a directory
         * and its link is followed to it. */
        int follow = *nr == __NR_setxattr || *nr == __NR_getxattr ||
                     *nr == __NR_listxattr || *nr == __NR_removexattr;
        if (x->want_dir) {
            LEAF(1);
            if (!follow)
                *nr = *nr == __NR_lsetxattr    ? __NR_setxattr
                      : *nr == __NR_lgetxattr  ? __NR_getxattr
                      : *nr == __NR_llistxattr ? __NR_listxattr
                                               : __NR_removexattr;
        } else {
            if (cng_pin_spell(x, spell, CNG_PATH_MAX) != 0)
                return -ENAMETOOLONG;
            a[0] = (long)spell;
            if (follow)
                *nr = *nr == __NR_setxattr    ? __NR_lsetxattr
                      : *nr == __NR_getxattr  ? __NR_lgetxattr
                      : *nr == __NR_listxattr ? __NR_llistxattr
                                              : __NR_lremovexattr;
        }
        break;
    }
    case __NR_inotify_add_watch:
        if (x->want_dir) {
            LEAF(1);
            a[2] &= ~(long)CNG_IN_DONT_FOLLOW;
        } else {
            if (cng_pin_spell(x, spell, CNG_PATH_MAX) != 0)
                return -ENAMETOOLONG;
            a[1] = (long)spell;
            a[2] |= CNG_IN_DONT_FOLLOW;
        }
        break;
    }
#undef LEAF
    return 0;
}

static long reissue(long a0, long a1, long a2, long a3, long a4, long a5,
                    long nr) {
    char pb[CNG_PATH_MAX];
    if (nr >= 0 && nr < CNG_NR_MAX && cng_blocked[nr]) {
        cng_note_blocked((int)nr);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] nr=%ld %s -> BLOCKED ENOSYS\n", nr,
                        dbg_path(a0, a1, pb, sizeof pb));
        return -ENOSYS;
    }
    long a[6] = {a0, a1, a2, a3, a4, a5}, callnr = nr;
    struct cng_pin x, y;
    char spell[CNG_PATH_MAX];
    struct cng_open_how how;
    long r = pin_args(&callnr, a, &x, &y, spell, &how);
    if (r == 0) {
        r = cng_syscall6(a[0], a[1], a[2], a[3], a[4], a[5], callnr);
        /* A kernel without the newer form: remembered, and the other form
         * taken this time and every time after. */
        if (r == -ENOSYS && callnr != nr &&
            (callnr == __NR_faccessat2 || callnr == __NR_fchmodat2 ||
             callnr == __NR_openat2)) {
            if (callnr == __NR_faccessat2)
                g_no_faccessat2 = 1;
            else if (callnr == __NR_fchmodat2)
                g_no_fchmodat2 = 1;
            else
                g_no_openat2 = 1;
            cng_unpin(&x);
            cng_unpin(&y);
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        }
    }
    cng_unpin(&x);
    cng_unpin(&y);
    if (cng_g_debug && r < 0 && r != -ENOENT)
        cng_dprintf(2, "[cng] nr=%ld %s -> errno=%ld\n", nr,
                    dbg_path(a0, a1, pb, sizeof pb), -r);
    return r;
}

/* --- /proc magic links ---------------------------------------------------
 *
 * Links under /proc/<pid|self|thread-self>/ belong to the HOST namespace: what
 * readlink() reports for them is a host path — and for an fd link it may name
 * no path at all (memfd, O_TMPFILE, a deleted file). Re-rooting such a target
 * into the rootfs, the way an ordinary guest symlink target must be, produces
 * a path that does not exist: that is how apk's script runner, which execve()s
 * "/proc/self/fd/N", came out as ENOENT. */
#define PROC_MAGIC_NONE  0 /* not a magic link */
#define PROC_MAGIC_GUEST 1 /* rewritten to a guest path; keep resolving */
#define PROC_MAGIC_HOST  2 /* already a host path; resolution is done */

static long proc_self_fixup(const char *canon, char *buf, unsigned long bufsz);

/* The decimal run at *p, which in every /proc name that matters here is a pid
 * or a descriptor number — both ints. So anything past INT_MAX names neither,
 * and is refused rather than accumulated: the multiply-add is signed, and the
 * digit string is the guest's to make as long as it likes, so letting it run
 * is undefined behaviour that can wrap into a small valid number — a
 * "/proc/self/fd/<20 digits>" that came out as one of OUR descriptors. Returns
 * the value and advances *p past the run, or -1 for no digits or out of range.
 */
static long parse_int_run(const char **p) {
    const char *q = *p;
    long v = 0;
    if (*q < '0' || *q > '9')
        return -1;
    for (; *q >= '0' && *q <= '9'; q++) {
        v = v * 10 + (*q - '0');
        if (v > 0x7fffffff)
            return -1;
    }
    *p = q;
    return v;
}

/* Length of a leading "/proc/<pid|self|thread-self>/" in a canonical guest
 * path, or 0. `self_only` matches only this process's own view. */
static size_t proc_pid_prefix(const char *p, int self_only) {
    if (strncmp(p, "/proc/", 6) != 0)
        return 0;
    const char *q = p + 6;
    size_t n = 0;
    if (strncmp(q, "self/", 5) == 0)
        n = 5;
    else if (strncmp(q, "thread-self/", 12) == 0)
        n = 12;
    else if (!self_only) {
        while (q[n] >= '0' && q[n] <= '9')
            n++;
        if (n == 0 || q[n] != '/')
            return 0;
        n++;
    }
    return n ? (size_t)(q - p) + n : 0;
}

/* Classify (and for the guest-visible links rewrite in place) a canonical
 * guest path that starts with a /proc magic link. See PROC_MAGIC_*. */
/* May the guest see the process a "/proc/<pid|self|thread-self>/" prefix names?
 * Its own two spellings always; another pid only where the registry knows it as
 * a guest process of this session. */
static int proc_pid_visible(const char *canon) {
    if (proc_pid_prefix(canon, 1))
        return 1; /* self / thread-self */
    const char *q = canon + 6;
    long pid = parse_int_run(&q);
    return pid < 0 ? 0 : cng_procreg_has((int)pid);
}

/* Is `canon` exactly "/proc/<pid|self|thread-self>/fd" — the directory the fd
 * links live in, rather than one of them? proc_magic classifies it with them,
 * since the kernel takes that path to the host's own fd table either way, but
 * it is not a link: opening it is an ordinary directory open, which both
 * RESOLVE_NO_MAGICLINKS and a scoped lookup allow (measured). Only when
 * nothing follows it — with a component after it, that component is the link
 * and the walk is about to traverse it. */
static int proc_fd_dir(const char *canon) {
    size_t pl = proc_pid_prefix(canon, 0);
    return pl && strcmp(canon + pl, "fd") == 0;
}

static int proc_magic(char *cur, size_t sz) {
    size_t pl = proc_pid_prefix(cur, 0);
    if (!pl)
        return PROC_MAGIC_NONE;
    /* A process the guest may not see has no magic links either. The hidden
     * view is applied by cng_fs_translate, and PROC_MAGIC_HOST is precisely the
     * verdict that skips it — so without this the fd branch below handed back
     * "/proc/<hostpid>/fd/<n>" as a host path and the kernel took it straight
     * to that process's open file description. A hidden process's open files
     * were readable by pid and descriptor number, anywhere on the host
     * filesystem and whatever the rootfs was. */
    if (!proc_pid_visible(cur))
        return PROC_MAGIC_NONE;
    const char *rest = cur + pl;

    /* "fd[/<n>]": the magic path *is* the host path — the kernel takes it
     * straight to the open file description, including the anonymous and
     * deleted files no re-rooted target could ever name. What follows a
     * directory's link is not the kernel's to walk from there, though: the
     * walk (cng_resolve_lim) expands the link into the directory's guest name
     * and goes on itself, as it does for a real dirfd.
     *
     * The directory itself counts, and not only for symmetry: it used to fall
     * through to cng_fs_translate, which answered it out of the /proc zone —
     * and --no-proc switches that zone off, so `/dev/fd` was re-rooted into the
     * rootfs and came back ENOENT while `/dev/fd/1` next to it kept working.
     * (`ls /dev` lost the entry to the same thing: busybox lstats each name.)
     * The fd table is a host object under every flag, so name it as one. */
    if (strncmp(rest, "fd", 2) == 0 && (rest[2] == '\0' || rest[2] == '/')) {
        if (rest[2] == '\0')
            return PROC_MAGIC_HOST;
        const char *d = rest + 3;
        while (*d >= '0' && *d <= '9')
            d++;
        if (d > rest + 3 && (*d == '\0' || *d == '/'))
            return PROC_MAGIC_HOST;
        return PROC_MAGIC_NONE;
    }

    /* exe/cwd/root: substitute the guest-visible target that readlink(2)
     * reports (proc_self_fixup), so exec'ing or opening one lands where the
     * guest expects. The host links point at chroot-ng itself (we never issue
     * a real execve) or at host paths, so following them is never right. This
     * covers another guest process too — its target comes from the registry —
     * while a host process never reaches here (the path layer hides it). */
    size_t vl = 0;
    if (strncmp(rest, "exe", 3) == 0 || strncmp(rest, "cwd", 3) == 0)
        vl = 3;
    else if (strncmp(rest, "root", 4) == 0)
        vl = 4;
    if (!vl || (rest[vl] != '\0' && rest[vl] != '/'))
        return PROC_MAGIC_NONE;

    /* The link component alone, for the fixup; the rest rides along after. */
    char link[CNG_PATH_MAX], tmp[CNG_PATH_MAX];
    if (pl + vl >= sizeof link)
        return PROC_MAGIC_NONE;
    memcpy(link, cur, pl + vl);
    link[pl + vl] = '\0';
    long n = proc_self_fixup(link, tmp, sizeof tmp - 1);
    if (n < 0)
        return PROC_MAGIC_NONE;
    tmp[n] = '\0';
    cng_strlcpy(tmp + n, rest + vl, sizeof tmp - (size_t)n);
    return cng_path_canon(tmp, cur, sz) == 0 ? PROC_MAGIC_GUEST
                                             : PROC_MAGIC_NONE;
}

/* If `host` names one of *this* process's own open fds — "/proc/self/fd/<n>",
 * the thread-self spelling, or our own pid — return that fd, else -1. We run
 * in-process, so the guest's fds are ours: the caller can use the open file
 * description directly instead of reopening the magic link. Trailing
 * components (a directory fd) are not this, and neither is another process. */
int cng_proc_self_fd(const char *host) {
    size_t pl = proc_pid_prefix(host, 0);
    if (!pl || strncmp(host + pl, "fd/", 3) != 0)
        return -1;
    if (!proc_pid_prefix(host, 1)) { /* numeric form: must be our own pid */
        const char *q = host + 6;
        long pid = parse_int_run(&q);
        if (pid < 0 || pid != sys_getpid())
            return -1;
    }
    const char *d = host + pl + 3;
    long fd = parse_int_run(&d);
    /* Nothing may follow the number: a trailing component is a path through a
     * directory fd, not this. */
    return (fd >= 0 && !*d) ? (int)fd : -1;
}

/* Rewrite the /dev aliases of the /proc fd links in place — /dev/fd[/...] to
 * /proc/self/fd[/...], /dev/std{in,out,err} to /proc/self/fd/{0,1,2} — so the
 * resolver's existing magic-link handling covers them. Returns 1 if `cur` was
 * rewritten (the caller re-runs the round), 0 otherwise. */
static int dev_magic(char *cur, size_t sz) {
    if (cng_g_no_dev || strncmp(cur, "/dev/", 5) != 0)
        return 0;
    const char *leaf = cur + 5;
    const char *rest = 0;
    const char *base = 0;
    if (!strncmp(leaf, "fd", 2) && (leaf[2] == '\0' || leaf[2] == '/')) {
        base = "/proc/self/fd";
        rest = leaf + 2;
    } else if (!strcmp(leaf, "stdin")) {
        base = "/proc/self/fd/0";
        rest = "";
    } else if (!strcmp(leaf, "stdout")) {
        base = "/proc/self/fd/1";
        rest = "";
    } else if (!strcmp(leaf, "stderr")) {
        base = "/proc/self/fd/2";
        rest = "";
    } else {
        return 0;
    }
    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, base, sizeof tmp);
    cng_strlcpy(tmp + n, rest, sizeof tmp > n ? sizeof tmp - n : 0);
    cng_strlcpy(cur, tmp, sz);
    return 1;
}

static int dirfd_host(int dfd, char *hdir, size_t sz);
static int host_dir_guest(const char *hdir, char *gdir, size_t sz);

/* A guest path the rootfs/bind map cannot express inside CNG_PATH_MAX. Not a
 * path — never dereferenced — so that a caller which forgets to test for it
 * faults on a null page rather than quietly operating on host storage. The
 * syscall answers -ENAMETOOLONG, which is what a kernel whose own PATH_MAX the
 * name exceeded would say, and what proot answers in the same spot.
 *
 * It matters because the alternative is not an error but the WRONG FILE: a
 * silently cut "<rootfs>/very/long/name" names something else that exists, so
 * an unlink deletes the wrong entry and an O_CREAT makes the wrong one. */
#define XLATE_TOOLONG ((const char *)8)
#define XLATE_AT_LONG (-2) /* xlate_at's spelling of the same verdict */
/* A name relative to a directory the guest has no name for (host_dir_guest):
 * the resolution cannot be performed, and the syscall answers -EACCES — the
 * guest may not search a directory that is not in its view. Not a path either,
 * for the same reason as above. */
#define XLATE_OUTSIDE ((const char *)16)
#define XLATE_AT_OUTSIDE (-3) /* xlate_at's spelling of the same verdict */

/* The two refusals a translation can come back as, and the errno each earns.
 * Every caller asks these of what xlate() handed it before using it as a path. */
static int xlate_bad(const char *p) {
    return p == XLATE_TOOLONG || p == XLATE_OUTSIDE;
}
static long xlate_errno(const char *p) {
    return p == XLATE_OUTSIDE ? -EACCES : -ENAMETOOLONG;
}

/* Append one synthesized linux_dirent64. Layout is a fixed kernel ABI:
 * d_ino @0, d_off @8, d_reclen @16 (u16), d_type @18, d_name @19, records
 * 8-byte aligned. `d_off` is an opaque stream cookie, so a high constant keeps
 * these clear of the kernel's own. Returns the bytes written, or 0 if the record
 * would not fit — a short batch is legal and the guest simply reads again. */
static long put_dent(char *buf, long at, long cap, const char *name,
                     unsigned long long ino, unsigned char dtype,
                     long long cookie) {
    size_t nl = strlen(name);
    if (nl > 255) /* NAME_MAX: no dirent the kernel emits is longer either */
        return 0;
    long reclen = (long)((19 + nl + 1 + 7) & ~(size_t)7);
    if (at < 0 || cap < 0 || at + reclen > cap)
        return 0;
    /* `buf` is the dispatcher's own batch buffer, not the guest's — see
     * do_getdents64 for why nothing here may touch the guest's. */
    char *rec = buf + at;
    memset(rec, 0, (size_t)reclen);
    memcpy(rec, &ino, 8);
    memcpy(rec + 8, &cookie, 8);
    unsigned short rl = (unsigned short)reclen;
    memcpy(rec + 16, &rl, 2);
    rec[18] = (char)dtype;
    memcpy(rec + 19, name, nl + 1);
    return reclen;
}

/* Is `name` already present in the batch, or a real dirent of the directory? */
static int dent_present(long dirfd, const char *name, const char *buf,
                        long used) {
    for (long o = 0; o + 19 <= used;) {
        unsigned short rl;
        memcpy(&rl, buf + o + 16, 2);
        if (rl == 0)
            break;
        if (!strcmp(buf + o + 19, name))
            return 1;
        o += rl;
    }
    char st[144];
    return CNG_SYS(__NR_newfstatat, dirfd, (long)name, (long)st,
                   CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0;
}

/* Splice the entries that exist only as path-resolution overlays and therefore
 * have no physical dirent for getdents64 to return:
 *
 *  - **bind mount points**: a -b destination is pure resolution (cng_fs_translate
 *    matches the prefix), so `ls /` never showed a `-b SRC:/host`. Anything that
 *    enumerates before opening — shell globbing, find, a package manager's tree
 *    walk — could not see it.
 *  - the **device nodes**: the /dev whitelist grants access by name only, so a
 *    rootfs /dev (usually empty) listed as empty even though /dev/null opens.
 *
 * Both are skipped when the name is already there, so a rootfs that ships a real
 * `null`, or a bind over an existing directory, is not duplicated. d_ino/d_type
 * come from an lstat of the real host target, so `ls -l` and `find -type` agree
 * with what an open of the same name gets. Returns the bytes appended. */
static long inject_dents(long dirfd, const char *gdir, char *buf, long used,
                         long cap) {
    long added = 0;
    const struct cng_fs *v;
    unsigned seq;
again:
    added = 0;
    seq = cng_fs_read_begin(&v);
    /* Bind mount points whose parent is exactly this directory. */
    for (int i = 0; i < v->nbinds; i++) {
        const char *g = v->binds[i].guest;
        if (!v->binds[i].base || !g[v->binds[i].base])
            continue; /* "/" itself: no parent to list it in */
        const char *slash = g + v->binds[i].base - 1;
        char parent[CNG_PATH_MAX];
        size_t plen = (size_t)(slash - g);
        if (plen == 0)
            cng_strlcpy(parent, "/", sizeof parent);
        else {
            if (plen >= sizeof parent)
                continue;
            memcpy(parent, g, plen);
            parent[plen] = '\0';
        }
        if (strcmp(parent, gdir) != 0)
            continue;
        const char *base = slash + 1;
        if (dent_present(dirfd, base, buf, used + added))
            continue;
        unsigned long long ino = 0xffffffffULL - (unsigned)i;
        unsigned char type = CNG_DT_DIR;
        char st[144];
        if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, (long)v->binds[i].host,
                    (long)st, 0, 0, 0) == 0) {
            ino = *(unsigned long long *)(st + 8);
            type = (unsigned char)((*(unsigned *)(st + STAT_MODE_OFF) >> 12) &
                                   0xf);
        }
        long k = put_dent(buf, used + added, cap, base, ino, type,
                          0x7fffffff00000000LL + i);
        if (!k)
            break;
        added += k;
    }
    /* The binds walked above are the view's own; a chroot meanwhile has
     * replaced it, and the entries were built from a table since compacted. */
    if (cng_fs_read_retry(seq))
        goto again;
    /* /dev whitelist, when this is the guest's own /dev (a -b for /dev makes
     * that directory's real contents authoritative, and cng_fs_translate would
     * have matched the bind first, so gdir would not be "/dev" here). */
    if (!cng_g_no_dev && strcmp(gdir, "/dev") == 0) {
        for (int i = 0; i < cng_dev_nnodes; i++) {
            const char *name = cng_dev_nodes[i].name;
            char st[144];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD,
                        (long)cng_dev_nodes[i].host, (long)st,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) != 0)
                continue; /* not present on this host */
            if (dent_present(dirfd, name, buf, used + added))
                continue;
            unsigned long long ino = *(unsigned long long *)(st + 8);
            unsigned char type =
                (unsigned char)((*(unsigned *)(st + STAT_MODE_OFF) >> 12) & 0xf);
            long k = put_dent(buf, used + added, cap, name, ino, type,
                              0x7ffffffe00000000LL + i);
            if (!k)
                return added;
            added += k;
        }
    }
    return added;
}

/* Which guest mount a canonical guest path belongs to, for RESOLVE_NO_XDEV.
 * Asked of the path layer rather than reimplemented, so it can never disagree
 * with where the path actually resolves: cng_fs_mount_of is the classifier
 * the translation itself is built on, asked without the host path being
 * spelled out (a walk asks this per component). */
static int mount_of(const char *canon) {
    return cng_fs_mount_of(cng_g_fs, canon);
}

/* Has the walk left the mount it started in? Records the violation so the
 * caller can tell it from a translation that merely did not fit. */
static int xdev_hit(struct cng_res_limit *lim, int start, const char *canon) {
    if (!lim || !lim->no_xdev || mount_of(canon) == start)
        return 0;
    lim->err = -EXDEV;
    return 1;
}

/* Append one component to the resolved prefix ("/a" + "b" -> "/a/b"). 0/-1. */
static int canon_push(char *c, size_t sz, const char *comp, size_t clen) {
    size_t n = strlen(c);
    if (n == 1 && c[0] == '/')
        n = 0; /* the root is spelled "/", not "" — do not double the slash */
    if (n + 1 + clen + 1 > sz)
        return -1;
    c[n] = '/';
    memcpy(c + n + 1, comp, clen);
    c[n + 1 + clen] = '\0';
    return 0;
}

/* Drop the last component ("/a/b" -> "/a", "/a" -> "/"). "/" stays "/", which
 * is what clamps a `..` run at the guest root. */
static void canon_pop(char *c) {
    char *s = strrchr(c, '/');
    if (!s || s == c) {
        c[0] = '/';
        c[1] = '\0';
        return;
    }
    *s = '\0';
}

/* rest = tgt + remainder, where `remainder` points into `rest` itself. */
static int splice_rest(char *rest, size_t sz, const char *tgt,
                       const char *remainder) {
    char tmp[CNG_PATH_MAX];
    size_t n = cng_strlcpy(tmp, tgt, sizeof tmp);
    if (n >= sizeof tmp || cng_strlcpy(tmp + n, remainder, sizeof tmp - n) >=
                               sizeof tmp - n)
        return -1;
    return cng_strlcpy(rest, tmp, sz) < sz ? 0 : -1;
}

/* Resolve a guest path to a host path, following symlinks *within the guest*:
 * an absolute symlink target is re-rooted into the rootfs rather than resolved
 * against the host root (which is what breaks Alpine's busybox symlinks).
 *
 * The walk is *physical*, like the kernel's: components are consumed one at a
 * time against a resolved prefix, and `..` pops that prefix — so it backs out of
 * where a symlink actually led. Canonicalizing `..` up front instead (which is
 * what this used to do) is logical resolution, the shell's convention, not the
 * kernel's: with /bin a symlink to /usr/bin, "/bin/../lib" is "/usr/lib" to
 * every syscall and was "/lib" to us. `..` at the guest root stays at the guest
 * root, which is what keeps the rootfs closed.
 *
 * deref_final controls whether the last component's own symlink is followed;
 * "last" is judged against the path as it stands, so a symlink expanded earlier
 * moves it, exactly as O_NOFOLLOW behaves. Returns 0/-errno. */
int cng_resolve(const char *path, int deref_final, char *out, size_t outsz) {
    return cng_resolve_lim(path, deref_final, out, outsz, 0);
}

int cng_resolve_lim(const char *path, int deref_final, char *out, size_t outsz,
                    struct cng_res_limit *lim) {
    char canon[CNG_PATH_MAX], rest[CNG_PATH_MAX];
    if (!path || !path[0])
        return -ENOENT;
    /* A scoped lookup starts at its scope, not at the root or the cwd, and an
     * absolute name does not restart the walk: IN_ROOT re-roots it onto the
     * scope (which is what starting there does, the leading slashes being
     * skipped like any other), BENEATH refuses it outright. Measured both. */
    int scoped = lim && (lim->beneath || lim->in_root) && lim->scope;
    if (scoped && path[0] == '/' && lim->beneath) {
        lim->err = -EXDEV;
        return -EXDEV;
    }
    /* The cwd is copied out under the view's protocol (a chdir on another
     * thread replaces the view whole; it never edits the one being read). */
    size_t bl = scoped            ? cng_strlcpy(canon, lim->scope, sizeof canon)
                : path[0] == '/'  ? cng_strlcpy(canon, "/", sizeof canon)
                                  : cng_fs_cwd(canon, sizeof canon);
    if (bl >= sizeof canon || cng_strlcpy(rest, path, sizeof rest) >= sizeof rest)
        return -ENAMETOOLONG;

    /* "This must be a directory" — a trailing slash or "/." — which the walk
     * below has to know about for the final component, and which is put back
     * onto the host path at the end. Read off what is left to walk rather than
     * off `path` once, so a symlink whose own target ends in one (or does not)
     * changes the answer where it should: after a splice, `rest` holds the
     * whole of what remains, and the last component of the name is always
     * somewhere in it. */
    int want_dir = cng_path_wants_dir(rest);

    /* The mount the resolution starts in. For a name reached through a real
     * dirfd the walk is handed an absolute path built from that directory, so
     * the caller names the true starting point; otherwise it is this base. */
    int start = CNG_MOUNT_ROOTFS;
    if (lim && lim->no_xdev)
        start = mount_of(lim->xdev_base && lim->xdev_base[0] ? lim->xdev_base
                                                             : canon);

    int nlinks = 0;
    char *p = rest;
    while (*p) {
        while (*p == '/')
            p++;
        if (!*p)
            break;
        char *end = p;
        while (*end && *end != '/')
            end++;
        const char *comp = p;
        size_t clen = (size_t)(end - p);
        int last = 1; /* nothing but slashes left after this component */
        for (const char *q = end; *q; q++)
            if (*q != '/') {
                last = 0;
                break;
            }
        p = end;

        if (clen == 1 && comp[0] == '.')
            continue;
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') {
            /* At the scope this is the escape the scoping exists to stop: the
             * kernel keeps IN_ROOT's `..` where it is, exactly as `..` at the
             * real root stays there, and answers BENEATH with -EXDEV. */
            if (scoped && strcmp(canon, lim->scope) == 0) {
                if (lim->beneath) {
                    lim->err = -EXDEV;
                    return -EXDEV;
                }
                continue;
            }
            /* What is being left has to be a directory that exists: see
             * cng_dotdot_verdict, which is the only caller that asks for this
             * and the only one that acts on the answer. */
            if (lim && lim->check_dotdot) {
                char dh[CNG_PATH_MAX], dst[144];
                long e = 0; /* a name with no host path is not this to answer */
                if (cng_fs_translate(cng_g_fs, canon, dh, sizeof dh) == 0) {
                    e = cng_pin_fstatat(dh, dst, 0);
                    if (e >= 0)
                        e = (*(unsigned *)(dst + STAT_MODE_OFF) & CNG_S_IFMT) ==
                                    CNG_S_IFDIR
                                ? 0
                                : -ENOTDIR;
                }
                if (e) {
                    lim->dotdot_err = e;
                    return e;
                }
            }
            canon_pop(canon);
            /* Backing out of a bind leaves its mount as surely as entering one
             * does, and RESOLVE_NO_XDEV forbids the crossing either way. */
            if (xdev_hit(lim, start, canon))
                return lim->err;
            continue;
        }
        if (canon_push(canon, sizeof canon, comp, clen) < 0)
            return -ENAMETOOLONG;
        if (xdev_hit(lim, start, canon))
            return lim->err;

        /* /dev/fd/N and /dev/std{in,out,err} are the same magic links as their
         * /proc spelling, so rewrite them to it and let the checks below treat
         * them as such — readlink-ing an fd link like an ordinary symlink would
         * try to re-root whatever it names, which for a pipe or a memfd is not a
         * path at all ("pipe:[12345]"). */
        dev_magic(canon, sizeof canon);
        int magic = proc_magic(canon, sizeof canon);
        /* A magic link is a link: RESOLVE_NO_MAGICLINKS refuses it, and
         * RESOLVE_NO_SYMLINKS implies NO_MAGICLINKS. Both are ELOOP, which is
         * what the kernel answers for a constraint it cannot satisfy by
         * resolving. Whether a link was actually traversed: exe/cwd/root
         * always (they are rewritten in place, so the test has to be the
         * verdict rather than the path), an fd link when it is one rather than
         * the directory they live in. */
        int magic_link = magic == PROC_MAGIC_GUEST ||
                         (magic == PROC_MAGIC_HOST && !proc_fd_dir(canon));
        if (magic_link && lim) {
            if (lim->no_magiclinks || lim->no_symlinks) {
                lim->err = -ELOOP;
                return -ELOOP;
            }
            /* "Not currently safe for scoped-lookups", says nd_jump_link(),
             * and it refuses every magic link under BENEATH or IN_ROOT with
             * -EXDEV whatever the link would have named (measured on 6.17:
             * /proc/self/fd/1, /proc/self/cwd and /proc/self/root all). */
            if (scoped) {
                lim->err = -EXDEV;
                return -EXDEV;
            }
        }
        if (magic == PROC_MAGIC_HOST) {
            /* The magic path IS the host path: the kernel takes it straight to
             * the open file description, anonymous and deleted files included.
             *
             * Not so for what may follow it. An fd link that names a directory
             * is a directory fd in every respect, and the components after it
             * used to "ride along, as they do for a real dirfd" — which is to
             * say the kernel walked them from that directory with no rootfs in
             * the way: "/proc/self/fd/<dirfd>/../../etc/passwd" climbed out of
             * the rootfs, and a symlink under the directory was followed from
             * the host root. Both are what the walk exists to prevent, and a
             * real dirfd has had them contained since xlate_at. So the link is
             * expanded the way exe/cwd/root are: the directory's own guest
             * name replaces it and the walk goes on from there. A directory
             * the guest has no name for (host_dir_guest) is refused whether
             * anything follows or not — reopening it would hand the guest a
             * dirfd it may not hold, the reason cng_fd_admit closes such a
             * descriptor on arrival. A file, or a description with no path at
             * all (a pipe, a memfd), is handed over as it stands: the I/O is
             * the descriptor's own, and a name below a file is the kernel's
             * ENOTDIR either way. */
            if (proc_fd_dir(canon)) {
                /* The fd directory itself, which is a directory of the /proc
                 * zone: an entry below it is the link, and is judged when the
                 * walk reaches it. (Only at the end of the name is the
                 * directory the answer, and then as the host path: --no-proc
                 * has switched the zone off in cng_fs_translate, and /dev/fd
                 * still has to resolve.) */
                if (!last)
                    continue;
            } else if (!last || deref_final || want_dir) {
                /* The link is about to be followed. (Not followed — O_NOFOLLOW
                 * or lstat on the link itself — it is the kernel's symlink to
                 * describe or refuse, and nothing is reached through it.) */
                char real[CNG_PATH_MAX], gdir[CNG_PATH_MAX];
                long rn = sys_readlinkat(CNG_AT_FDCWD, canon, real,
                                         sizeof real - 1);
                if (rn > 0 && real[0] == '/') {
                    real[rn] = '\0';
                    char st[STAT_BUF_SIZE];
                    if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, (long)canon,
                                (long)st, 0, 0, 0) == 0 &&
                        (*(unsigned *)(st + STAT_MODE_OFF) & CNG_S_IFMT) ==
                            CNG_S_IFDIR) {
                        if (host_dir_guest(real, gdir, sizeof gdir) != 0)
                            return -EACCES;
                        if (!last) {
                            if (++nlinks > 40)
                                return -ELOOP;
                            if (splice_rest(rest, sizeof rest, gdir, p) < 0)
                                return -ENAMETOOLONG;
                            p = rest;
                            want_dir = cng_path_wants_dir(rest);
                            cng_strlcpy(canon, "/", sizeof canon);
                            continue;
                        }
                    }
                }
            }
            size_t n = cng_strlcpy(out, canon, outsz);
            if (n >= outsz || cng_strlcpy(out + n, p, outsz - n) >= outsz - n)
                return -ENAMETOOLONG;
            return 0;
        }
        if (magic == PROC_MAGIC_GUEST) {
            /* exe/cwd/root: the guest-visible target replaces the link, which
             * is a symlink expansion in everything but name. (A scoped lookup
             * never arrives here — the refusal above covers every magic link.) */
            if (++nlinks > 40)
                return -ELOOP;
            if (splice_rest(rest, sizeof rest, canon, p) < 0)
                return -ENAMETOOLONG;
            p = rest;
            want_dir = cng_path_wants_dir(rest);
            cng_strlcpy(canon, "/", sizeof canon);
            continue;
        }

        /* The final component's own symlink is left alone for O_NOFOLLOW and
         * AT_SYMLINK_NOFOLLOW — unless a trailing slash asked for a directory,
         * which the kernel answers by following the link anyway (measured:
         * lstat("l2d/") describes the DIRECTORY, lstat("l2f/") is ENOTDIR).
         * Following it here is also what keeps the guest inside the rootfs: the
         * host path would otherwise still name the link, the trailing slash
         * would make the kernel follow it, and an absolute target would resolve
         * from the HOST root — the one thing this walk exists to prevent. */
        if (last && !deref_final && !want_dir)
            continue;
        char host[CNG_PATH_MAX], link[CNG_PATH_MAX];
        if (cng_fs_translate(cng_g_fs, canon, host, sizeof host) != 0)
            continue;
        long n = sys_readlinkat(CNG_AT_FDCWD, host, link, sizeof link - 1);
        if (n <= 0)
            continue; /* not a symlink, or missing */
        link[n] = '\0';
        if (lim && lim->no_symlinks) {
            /* ...unless the link is the l2s emulation's own, which to the
             * guest is a regular file and not a symlink at all: refusing it
             * made openat2(RESOLVE_NO_SYMLINKS) ELOOP on an emulated hardlink
             * where a real one opens. */
            char d[CNG_PATH_MAX];
            if (!(cng_g_l2s && cng_l2s_resolve(host, d, sizeof d, 0) == 1)) {
                lim->err = -ELOOP;
                return -ELOOP;
            }
        }
        if (++nlinks > 40)
            return -ELOOP;
        canon_pop(canon); /* the link itself is replaced by its target */
        if (link[0] == '/') {
            /* An absolute target is re-rooted — except one naming an l2s data
             * file, which is a HOST path (central store / cross-directory
             * group) and must be mapped into the guest view instead. */
            char tmp[CNG_PATH_MAX];
            if (cng_g_l2s && cng_l2s_untranslate_target(link, tmp, sizeof tmp))
                cng_strlcpy(link, tmp, sizeof link);
            /* Under a scope the target is re-rooted onto that instead of onto
             * the guest root, and BENEATH refuses it: an absolute target is a
             * jump out of the scope however short it is. */
            if (scoped && lim->beneath) {
                lim->err = -EXDEV;
                return -EXDEV;
            }
            cng_strlcpy(canon, scoped ? lim->scope : "/", sizeof canon);
        }
        if (splice_rest(rest, sizeof rest, link, p) < 0)
            return -ENAMETOOLONG;
        p = rest;
        want_dir = cng_path_wants_dir(rest);
    }
    /* cng_fs_translate fails only on length — the canonical form overflowing,
     * or the rootfs prefix pushing the result past `outsz` — so its refusal is
     * the same -ENAMETOOLONG the walk above answers. */
    if (xdev_hit(lim, start, canon))
        return lim->err;
    /* Hand the requirement to the translation, which puts it on the host path:
     * the walk is done with names, and this is a statement about the file the
     * last name reached. */
    if (want_dir) {
        size_t cl = strlen(canon);
        if (cl && canon[cl - 1] != '/') {
            if (cl + 2 > sizeof canon)
                return -ENAMETOOLONG;
            canon[cl] = '/';
            canon[cl + 1] = '\0';
        }
    }
    return cng_fs_translate(cng_g_fs, canon, out, outsz) == 0 ? 0
                                                              : -ENAMETOOLONG;
}

/* "/proc/self/fd/<fd>" into out[40]. fd args are 32-bit: glibc passes ints in
 * w-registers and may leave the x-register's top half dirty, so truncate.
 *
 * A negative number is not a descriptor and names no such file, but it has to
 * spell as one: writing the digits of -100 without its sign produced
 * "/proc/self/fd/0", so AT_FDCWD arrived at the caller as *stdin*. The sign
 * makes every negative a path that simply does not exist, which is the only
 * honest answer a caller that reaches here with one can be given. */
static void proc_fd_path(long fd, char *out) {
    size_t p = cng_strlcpy(out, "/proc/self/fd/", 40);
    char num[16];
    int ni = 0;
    int v32 = (int)fd;
    /* Negated in unsigned, so INT_MIN has no overflow to fall into. */
    unsigned v = v32 < 0 ? -(unsigned)v32 : (unsigned)v32;
    if (v32 < 0 && p < 39)
        out[p++] = '-';
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v > 0 && ni < 15);
    while (ni > 0 && p < 39)
        out[p++] = num[--ni];
    out[p] = '\0';
}

/* Read the host directory a real dirfd names, from /proc/self/fd/<dirfd>.
 * Returns 0/-1. */
static int dirfd_host(int dfd, char *hdir, size_t sz) {
    if (dfd < 0)
        return -1;
    char proc[40];
    proc_fd_path(dfd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hdir, sz - 1);
    if (n <= 0)
        return -1;
    hdir[n] = '\0';
    return 0;
}

/* Does the open descriptor name a directory? */
static int fd_is_dir(long fd) {
    char st[STAT_BUF_SIZE];
    return sys_fstat((int)fd, st) == 0 &&
           (*(unsigned *)(st + STAT_MODE_OFF) & CNG_S_IFMT) == CNG_S_IFDIR;
}

/* The (st_dev, st_ino) pair behind a descriptor: see the header. */
int cng_fdid_of(int fd, struct cng_fdid *id) {
    char st[STAT_BUF_SIZE];
    if (fd < 0 || sys_fstat(fd, st) != 0)
        return -1;
    id->dev = *(unsigned long *)(st + STAT_DEV_OFF);
    id->ino = *(unsigned long *)(st + STAT_INO_OFF);
    return 0;
}

int cng_fd_is(int fd, const struct cng_fdid *id) {
    struct cng_fdid cur;
    return cng_fdid_of(fd, &cur) == 0 && cur.dev == id->dev &&
           cur.ino == id->ino;
}

/* The guest name of a host directory the kernel reported for an open
 * descriptor (a /proc/self/fd readback, a getcwd), or -1 when the guest has
 * none for it. Three places a directory the guest can hold a descriptor on
 * may sit:
 *
 *  - inside the view — the rootfs or a bind — where the reverse translation
 *    names it;
 *  - the /proc zone, which passes through under its own name: the host path
 *    IS the guest path, and the hidden-process view and the synthesized files
 *    are then applied by the walk exactly as they are for an absolute name;
 *  - the /dev zone, where a whitelist entry stands for a host node the guest
 *    reaches as "/dev/<name>": /dev/pts and its entries, the /dev/shm stand-in
 *    directory (which on a host with no /dev/shm is under $TMPDIR — nowhere
 *    near the rootfs), /dev/fd being the /proc case above.
 *
 * A zone answer is checked the way it was reached: the guest spelling has to
 * translate back to exactly this host directory, or a bind shadows the zone
 * there (`-b DIR:/proc`) and the guest name would mean something else.
 *
 * What is left is a directory the guest has no name for. The launcher's own
 * descriptors are the way one arrives: a dirfd leaked across the exec, an fd
 * received over a socket, one pulled out of another process. There is nothing
 * to resolve a name against, and handing the name to the kernel — which was
 * done, on the grounds that "the dirfd already points inside the guest view"
 * — resolved it wherever that directory is: `openat(dirfd("/proc"),
 * "../etc/passwd")` read the host's, and so did a name through a dirfd on
 * /dev/pts. Every caller answers -EACCES for this — the guest may not search
 * a directory it has no name for — except where it is closing the descriptor
 * on arrival (cng_fd_admit). */
static int host_dir_guest(const char *hdir, char *gdir, size_t sz) {
    if (cng_fs_untranslate(cng_g_fs, hdir, gdir, sz) == 0)
        return 0;
    char back[CNG_PATH_MAX];
    if (!cng_g_no_proc && !strncmp(hdir, "/proc", 5) &&
        (!hdir[5] || hdir[5] == '/')) {
        if (cng_strlcpy(gdir, hdir, sz) < sz &&
            cng_fs_translate(cng_g_fs, gdir, back, sizeof back) == 0 &&
            !strcmp(back, hdir))
            return 0;
    }
    if (!cng_g_no_dev) {
        for (int i = 0; i < cng_dev_nnodes; i++) {
            const char *h = cng_dev_nodes[i].host;
            size_t hl = strlen(h);
            if (!hl || strncmp(hdir, h, hl) != 0 ||
                (hdir[hl] && hdir[hl] != '/'))
                continue;
            size_t n = cng_strlcpy(gdir, "/dev/", sz);
            if (n >= sz)
                return -1;
            n += cng_strlcpy(gdir + n, cng_dev_nodes[i].name, sz - n);
            if (n >= sz || cng_strlcpy(gdir + n, hdir + hl, sz - n) >= sz - n)
                return -1;
            if (cng_fs_translate(cng_g_fs, gdir, back, sizeof back) == 0 &&
                !strcmp(back, hdir))
                return 0;
        }
    }
    return -1;
}

int cng_host_dir_guest(const char *hdir, char *gdir, size_t sz) {
    return host_dir_guest(hdir, gdir, sz);
}

/* May the descriptor stay in the guest's table? One that names a directory the
 * guest has no name for (host_dir_guest) is closed, and 0 says so; anything
 * else — a file, a pipe, a socket, a directory the guest can name — is left
 * alone, and so is a descriptor that cannot be looked at (no /proc), which is
 * the same degraded host on which nothing here can translate.
 *
 * The rule closes the one gap the walk above cannot: a plain name against a
 * directory fd goes to the kernel without a walk (at_needs_xlate, the hot
 * path), on the strength of the directory being inside the view. That holds
 * only if no descriptor on an outside directory is ever in the table — so each
 * way one can arrive is checked as it does: the launcher's inheritance before
 * the guest runs (cng_fds_sanitize), SCM_RIGHTS over a socket (recvmsg and
 * recvmmsg below), pidfd_getfd. Files are let in for the I/O they carry — a
 * redirected stdin, a pipe, a socket handed over at launch are what an
 * inherited descriptor is for — and a file is not a place to resolve a name
 * from. */
int cng_fd_admit(int fd) {
    if (!fd_is_dir(fd))
        return 1;
    char hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX];
    if (dirfd_host(fd, hdir, sizeof hdir) != 0 ||
        host_dir_guest(hdir, gdir, sizeof gdir) == 0)
        return 1;
    if (cng_g_debug)
        cng_dprintf(2, "[cng] fd %d names %s, outside the guest view: closed\n",
                    fd, hdir);
    sys_close(fd);
    return 0;
}

/* Run cng_fd_admit over every descriptor the guest is about to inherit. Called
 * once, from cng_run, with the view published and before the first program is
 * loaded. Our own descriptors are all close-on-exec — the launcher's
 * close-on-exec ones did not survive the exec that started us, so at this
 * point the flag is ours alone — and are skipped, the directory being read
 * among them. One of the standard three that goes (`chroot-ng ... < /`) is
 * replaced by /dev/null rather than left closed, the way a setuid program
 * treats them: a program is entitled to find 0, 1 and 2 open, and the next
 * file it opens must not land on one of them. */
void cng_fds_sanitize(void) {
    long dfd = sys_openat(CNG_AT_FDCWD, "/proc/self/fd",
                          CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (dfd < 0)
        return;
    char buf[4096];
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)dfd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        for (long o = 0; o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            o += reclen;
            long fd = parse_int_run(&nm);
            if (fd < 0 || *nm || fd == dfd)
                continue;
            long fl = sys_fcntl((int)fd, CNG_F_GETFD, 0);
            if (fl < 0 || (fl & 1 /*FD_CLOEXEC*/))
                continue;
            if (!cng_fd_admit((int)fd) && fd <= 2) {
                long nul = sys_openat(CNG_AT_FDCWD, "/dev/null", CNG_O_RDWR, 0);
                if (nul >= 0 && nul != fd) {
                    CNG_SYS(__NR_dup3, nul, fd, 0, 0, 0, 0);
                    sys_close((int)nul);
                }
            }
        }
    }
    sys_close((int)dfd);
}

/* Put a dirfd-relative name through the same containment an absolute path gets:
 * map the dirfd's host directory back to its GUEST path, join the name onto it,
 * and resolve the whole thing through the rootfs/bind map. Concatenating the
 * host directory instead — which is what this used to do — leaves the kernel to
 * resolve the name itself, and the kernel has no rootfs: a ".." component
 * climbs straight past it and an absolute symlink target is taken from the HOST
 * root.
 *
 * `out` comes back an absolute host path. Callers reissue with the original
 * dirfd, which the kernel ignores for an absolute path, so no caller changes.
 * Returns XLATE_AT_OUTSIDE when the dirfd names a directory the guest has no
 * name for (see host_dir_guest) — a name against it cannot be resolved at all,
 * and the caller refuses it — and -1 when the descriptor cannot be read back
 * (no /proc, not open, not a directory), where the kernel's own answer for the
 * name is the right one: EBADF, ENOTDIR. */
static int xlate_at_lim(int dfd, const char *path, char *out, size_t sz,
                        int deref, struct cng_res_limit *lim) {
    char hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX], gp[CNG_PATH_MAX];
    if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
        return -1;
    if (host_dir_guest(hdir, gdir, sizeof gdir) != 0)
        return fd_is_dir(dfd) ? XLATE_AT_OUTSIDE : -1;
    size_t k = cng_strlcpy(gp, gdir, sizeof gp);
    if (k >= sizeof gp)
        return XLATE_AT_LONG;
    if (k && gp[k - 1] != '/' && k + 1 < sizeof gp) {
        gp[k++] = '/';
        gp[k] = '\0';
    }
    if (cng_strlcpy(gp + k, path, sizeof gp - k) >= sizeof gp - k)
        return XLATE_AT_LONG;
    /* RESOLVE_NO_XDEV is judged from where the resolution really starts, which
     * for a dirfd-relative name is the directory it names — not the "/" the
     * absolute form built above begins at. */
    if (lim)
        lim->xdev_base = gdir;
    long r = cng_resolve_lim(gp, deref, out, sz, lim);
    if (lim)
        lim->xdev_base = 0; /* gdir dies with this frame */
    if (r == 0)
        return 0;
    /* A name that does not fit must not be passed through: the kernel would
     * resolve it against the dirfd with no rootfs in the way, which is what
     * the walk above exists to prevent. Neither may one the walk refused for
     * leading through a directory the guest has no name for (an fd link to
     * one, on the way). Every other failure (ELOOP) is one the kernel
     * reproduces for itself on the guest's own name. */
    if (r == -ENAMETOOLONG)
        return XLATE_AT_LONG;
    return r == -EACCES ? XLATE_AT_OUTSIDE : -1;
}

static int xlate_at(int dfd, const char *path, char *out, size_t sz, int deref) {
    return xlate_at_lim(dfd, path, out, sz, deref, 0);
}

/* Could this single component name an entry that exists only as a resolution
 * overlay? The /dev whitelist, a -b destination and the /proc passthrough have
 * no directory entry behind them — cng_fs_translate conjures them out of the
 * path alone — so the kernel cannot find one relative to a dirfd however plain
 * the name looks. Nothing but the name matters, so this is a string test and
 * costs no syscall on the hot path. */
static int name_may_overlay(const char *name) {
    if (!cng_g_no_proc && strcmp(name, "proc") == 0)
        return 1;
    if (!cng_g_no_dev)
        for (int i = 0; i < cng_dev_nnodes; i++)
            if (strcmp(name, cng_dev_nodes[i].name) == 0)
                return 1;
    if (!cng_g_fs)
        return 0;
    const struct cng_fs *v;
    int hit;
    do {
        unsigned seq = cng_fs_read_begin(&v);
        hit = 0;
        for (int i = 0; i < v->nbinds && !hit; i++) {
            const char *bn = v->binds[i].guest + v->binds[i].base;
            if (bn[0] && strcmp(bn, name) == 0)
                hit = 1;
        }
        if (!cng_fs_read_retry(seq))
            break;
    } while (1);
    return hit;
}

/* Is any bind in the view read-only? The :ro refusal is keyed on the resolved
 * HOST path, and a dirfd-relative name that needs no walk never acquires one —
 * so every mutating *at call made against a directory fd inside the bind went
 * straight through to the host, and the mount was read-only only to whoever
 * spelled the name out in full. That is not a corner: `rm -rf`, `find -delete`,
 * tar, rsync and git all open a directory once and work relative to it.
 *
 * A resolution is the only thing that produces a host path, so a session that
 * asked for :ro pays for one per relative name. Sessions without one, which is
 * the default, are untouched. */
static int fs_has_ro(void) {
    if (!cng_g_fs)
        return 0;
    const struct cng_fs *v;
    int ro;
    do {
        unsigned seq = cng_fs_read_begin(&v);
        ro = v->has_ro;
        if (!cng_fs_read_retry(seq))
            break;
    } while (1);
    return ro;
}

/* Is the first component of `path` all digits — the only shape that can name a
 * process against a /proc directory fd, and so the only one the hidden-process
 * view has anything to say about? A string test, so the hot path pays nothing
 * for it. */
static int name_may_be_pid(const char *p) {
    if (*p < '0' || *p > '9')
        return 0;
    for (; *p && *p != '/'; p++)
        if (*p < '0' || *p > '9')
            return 0;
    return 1;
}

/* Does a dirfd-relative name need the guest-side walk above, or can the kernel
 * be trusted with it? The dirfd itself points inside the guest view or one of
 * its zones — a descriptor on a directory the guest has no name for never
 * enters its table: the launcher's are closed before the guest runs and every
 * way one could arrive later is checked as it does (cng_fd_admit), and the
 * walk refuses to start from one (host_dir_guest) — so only three things can
 * redirect out of it: a ".." component, a symlink, and a name the kernel
 * cannot resolve at all because it is ours. This is the hot path (every
 * relative openat), so the cheap cases stay cheap.
 *
 *  - any '/' => some intermediate component is followed as a symlink => walk;
 *  - a ".." component => walk;
 *  - a name that could be a resolution overlay => walk, since the kernel has no
 *    dirent to find it by: without this `fstatat(dirfd("/dev"), "zero")` and
 *    `fstatat(dirfd("/"), "<bind>")` answered ENOENT for entries the same
 *    absolute path opens fine — which is exactly what `ls -l` asks;
 *  - a :ro bind anywhere in the view => walk, since the refusal needs a host
 *    path to key on (see fs_has_ro);
 *  - otherwise a single component, and only its own symlink can escape: one
 *    readlinkat settles it. EINVAL (not a symlink) and ENOENT (nothing there)
 *    are safe for the kernel to finish; a real link needs the walk. */
static int at_needs_xlate(int dfd, const char *path, int deref) {
    for (const char *p = path; *p; p++)
        if (*p == '/')
            return 1;
    if (path[0] == '.' && path[1] == '.' && !path[2])
        return 1;
    if (name_may_overlay(path))
        return 1;
    if (fs_has_ro())
        return 1;
    /* A pid-shaped name may be a host process seen through a /proc dirfd,
     * which only the walk can hide: the zone's guest spelling of the join is
     * what the hidden-process view is keyed on. */
    if (!cng_g_no_proc && name_may_be_pid(path))
        return 1;
    if (!deref)
        return 0;
    char lb[8];
    return sys_readlinkat(dfd, path, lb, sizeof lb) >= 0;
}

/* Resolve (dirfd, path) to a HOST path. Handles absolute paths and AT_FDCWD
 * (through the rootfs, re-rooting guest symlinks — except the /proc magic
 * links, which cng_resolve keeps in the host namespace), and real dirfds (via
 * xlate_at, so a relative name is contained the same way an absolute one is).
 * `deref` follows the final component's symlink. Returns 0/-1. */
int cng_resolve_at(long dirfd, const char *path, int deref, char *out,
                   size_t sz) {
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || dfd == CNG_AT_FDCWD) {
        long r = cng_resolve(path, deref, out, sz);
        if (r == 0)
            return 0;
        if (r == -EACCES)
            return -1; /* through a directory the guest has no name for */
        return cng_fs_translate(cng_g_fs, path, out, sz) == 0 ? 0 : -1;
    }
    if (dfd < 0)
        return -1;
    /* Every failure is one: a name that does not fit, a directory the guest
     * has no name for (host_dir_guest), a descriptor that cannot be read back.
     * This used to join the host directory and the name for the last two, on
     * the grounds that a /proc dirfd wants the host namespace — which the walk
     * now reaches through the zone's own guest spelling — and that join was
     * the host path of a name the guest had never been allowed to spell. */
    return xlate_at(dfd, path, out, sz, deref) == 0 ? 0 : -1;
}

/* Is guest path `x` at or below the directory `base`? Both canonical, `base`
 * without a trailing slash except for the root, which everything is under. */
static int guest_under(const char *x, const char *base) {
    if (!base[0] || (base[0] == '/' && !base[1]))
        return 1;
    size_t n = strlen(base);
    return strncmp(x, base, n) == 0 && (x[n] == '\0' || x[n] == '/');
}

/* The two zones and the binds are the whole of what the guest sees that the
 * host does not, so this is the whole of the question cng_scope_needs_walk
 * asks. A bind matters when its mount point is at or below the scope: that is
 * where the guest's answer for a name diverges from the physical directory
 * under the rootfs. The zones matter on either side of the scope — at or below
 * it, for the same reason; and above it because their own contents are
 * synthesized (the /dev whitelist, the /proc files procfs.c serves, the hidden
 * pids), so a dirfd inside one is looking at a directory whose entries the
 * kernel and the guest do not agree about. */
static int scope_overlay(const char *gdir) {
    if (cng_g_fs) {
        const struct cng_fs *v;
        int hit;
        do {
            unsigned seq = cng_fs_read_begin(&v);
            hit = 0;
            for (int i = 0; i < v->nbinds && !hit; i++) {
                const char *bg = v->binds[i].guest;
                /* Strictly below: a dirfd on the bind's own mount point
                 * already IS the bind — its host directory is the bound one —
                 * so everything the kernel can reach under it is what the
                 * guest sees there. Only a mount point *inside* the scope
                 * makes the two trees differ. */
                if (guest_under(bg, gdir) && strcmp(bg, gdir) != 0)
                    hit = 1;
            }
            if (!cng_fs_read_retry(seq))
                break;
        } while (1);
        if (hit)
            return 1;
    }
    /* The zones, unlike a bind, are not a directory handed over whole: their
     * own contents are synthesized (the /dev whitelist, the files procfs.c
     * serves, the hidden pids), so the scope being one of them is as much a
     * divergence as it containing one. */
    if (!cng_g_no_proc &&
        (guest_under("/proc", gdir) || guest_under(gdir, "/proc")))
        return 1;
    if (!cng_g_no_dev && (guest_under("/dev", gdir) || guest_under(gdir, "/dev")))
        return 1;
    return 0;
}

int cng_scope_needs_walk(long dirfd, char *gdir, size_t sz) {
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (dfd == CNG_AT_FDCWD) {
        /* The virtual cwd, which is the guest's own answer — the host cwd is
         * only its translation and would have to be mapped back. */
        if (cng_fs_cwd(gdir, sz) >= sz)
            return 0;
    } else {
        char hdir[CNG_PATH_MAX];
        if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
            return 0;
        /* The zones are named too (the synthesized /proc files and the
         * hidden-process view live under a dirfd like that, and they are
         * exactly what the kernel's own resolution would miss). A directory
         * the guest has no name for is refused, not handed to the kernel to
         * scope a resolution under: the scoping keeps the answer beneath that
         * directory, and beneath it is still outside the view. */
        if (host_dir_guest(hdir, gdir, sz) != 0)
            return fd_is_dir(dfd) ? -1 : 0;
    }
    return scope_overlay(gdir);
}

/* at_canon() for a scoped openat2: the same lexical canonicalization the
 * synthesized-/proc check runs on every other open, but anchored at the scope
 * rather than at the dirfd's own path — an absolute name is re-rooted onto it
 * (IN_ROOT) or refused (BENEATH), and a `..` run is clamped there or refused.
 * Lexical, like the check it feeds: a symlink expanded on the way moves the
 * answer, and that is the walk's business, not this one's.
 *
 * Returns 0 with `out` filled; -EXDEV where the scope refuses the name outright
 * and -1 where it does not fit, which the caller treats the same way — there is
 * no synthesized file to serve, and the walk answers for the name itself. */
static long scope_canon(const char *gdir, const char *gp, int beneath,
                        char *out, size_t sz) {
    char tmp[CNG_PATH_MAX], rel[CNG_PATH_MAX], full[CNG_PATH_MAX];
    if (gp[0] == '/' && beneath)
        return -EXDEV;
    /* Against "/" first: for a relative name that is the walk with the scope
     * standing in for the root, and cng_path_canon clamps a `..` run there
     * exactly as the kernel clamps IN_ROOT's. An absolute name needs no join —
     * re-rooting it onto the scope is what IN_ROOT means. */
    size_t k = 0;
    if (gp[0] != '/') {
        tmp[0] = '/';
        k = 1;
    }
    if (cng_strlcpy(tmp + k, gp, sizeof tmp - k) >= sizeof tmp - k ||
        cng_path_canon(tmp, rel, sizeof rel) != 0)
        return -1;
    if (beneath) {
        /* That clamp is what BENEATH must NOT do, so the same name is asked
         * again against the scope itself: an answer that left it is -EXDEV. */
        size_t n = cng_strlcpy(tmp, gdir, sizeof tmp);
        if (n >= sizeof tmp ||
            cng_strlcpy(tmp + n, "/", sizeof tmp - n) >= sizeof tmp - n)
            return -1;
        n = strlen(tmp);
        if (cng_strlcpy(tmp + n, gp, sizeof tmp - n) >= sizeof tmp - n ||
            cng_path_canon(tmp, full, sizeof full) != 0)
            return -1;
        if (!guest_under(full, gdir))
            return -EXDEV;
    }
    size_t n = cng_strlcpy(out, gdir, sz);
    if (n >= sz)
        return -1;
    if (n == 1 && out[0] == '/')
        n = 0; /* the root is spelled "/", not "" — do not double the slash */
    return cng_strlcpy(out + n, rel, sz - n) >= sz - n ? -1 : 0;
}

/* --- :ro binds, through the link2symlink emulation -----------------------
 *
 * A :ro verdict is keyed on the resolved HOST path, which is what makes a
 * guest symlink leading into a read-only bind refuse however the name got
 * there. An l2s name walks straight out of that keying: the resolution follows
 * the emulation's own symlink into the central store, which sits under the
 * rootfs and no bind covers — so a name inside a :ro bind resolved to a
 * perfectly writable file and every mutator went through. The guest sees none
 * of this. To it the name IS a regular file, and the mount that name sits
 * under is the one that governs it (a real hardlink cannot span mounts at all,
 * so there is no second mount to argue for).
 *
 * Hence: where the guest's own name is an l2s link, the :ro question is asked
 * about the link — and about where the data is, which a link out of a :ro bind
 * used to put under it for a writable name (the linkat refusal below keeps any
 * more from being made): the file lives on that mount, and every name of it
 * is read-only there. The l2s hop is always the last component — a link to a
 * regular file has nothing under it — so the name's own path is exactly the
 * resolution with the final hop not taken. Asked only when -l and a :ro bind
 * are both in play, so the default path pays nothing for it. */
static int l2s_ro(const char *hnf, const char *data) {
    return ro_denied(hnf) || cng_fs_host_ro(cng_g_fs, data);
}

static int ro_denied_l2s(long dirfd, const char *gp) {
    if (!cng_g_l2s || !gp || !gp[0] || !fs_has_ro())
        return 0;
    char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
    return cng_resolve_at(dirfd, gp, 0, hnf, sizeof hnf) == 0 &&
           cng_l2s_resolve(hnf, data, sizeof data, 0) == 1 && l2s_ro(hnf, data);
}

/* --- links out of a :ro bind ----------------------------------------------
 *
 * A link cannot span mounts: the kernel answers EXDEV for one whose source is
 * on another mount than the new name's directory, after the new name's own
 * verdict and before anything else about the source. A :ro bind is a mount
 * of its own, however the host has it, so a source under one is on another
 * mount than any writable destination (one in the bind itself is EROFS) —
 * and linked anyway, the host's filesystem permitting, the new name was a
 * writable way into the :ro file: written through it, the bind's file
 * changed. Under -l the fallback went further and moved the file into the
 * store, leaving a symlink in the bind. The file a link is made from is where
 * its data is: the descriptor's own file for AT_EMPTY_PATH (asked of the path
 * the kernel reports — not fd_link_ro's reopen rule, which is about the name
 * a descriptor came through), and an l2s name's backing file. */
static int link_src_ro(long fd, const char *srch, int by_fd, int followed) {
    if (!cng_g_fs || !fs_has_ro())
        return 0;
    if (by_fd) {
        char lk[40], real[CNG_PATH_MAX];
        proc_fd_path(fd, lk);
        long n = sys_readlinkat(CNG_AT_FDCWD, lk, real, sizeof real - 1);
        if (n <= 0 || real[0] != '/')
            return 0; /* anonymous: on no mount of ours */
        real[n] = '\0';
        return cng_fs_host_ro(cng_g_fs, real);
    }
    if (ro_denied(srch))
        return 1;
    char data[CNG_PATH_MAX];
    return cng_g_l2s && !followed &&
           cng_l2s_resolve(srch, data, sizeof data, 0) == 1 &&
           cng_fs_host_ro(cng_g_fs, data);
}

/* What the kernel's filename_create says of a link's new name before the
 * mount question is reached: the directory's own error (ENOENT, ENOTDIR),
 * EEXIST for a name that is taken; 0 for a free one. */
static long link_dst_verdict(const char *dsth) {
    struct cng_pin p;
    long e = cng_pin_at(CNG_AT_FDCWD, dsth, &p);
    if (e == 0) {
        char st[STAT_BUF_SIZE];
        long r = CNG_SYS(__NR_newfstatat, p.dfd, (long)p.name, (long)st,
                         CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
        e = r == 0 ? -EEXIST : r == -ENOENT ? 0 : r;
    }
    cng_unpin(&p);
    return e;
}

/* --- no-follow calls on an l2s name -----------------------------------------
 *
 * To the guest an l2s name IS a regular file, so a call that declines to follow
 * the final component — AT_SYMLINK_NOFOLLOW, O_NOFOLLOW, IN_DONT_FOLLOW, the
 * l-prefixed xattr calls, name_to_handle_at without AT_SYMLINK_FOLLOW — has to
 * land on the backing file all the same. Handed the name, the kernel operates
 * on (or refuses) the emulation's own symlink instead, and the guest is shown a
 * symlink where it has a file: a handle that opens the link, an xattr set on
 * it, a watch that never fires for the data, EOPNOTSUPP from fchmodat2, an
 * O_PATH fd whose fstat says S_IFLNK. stat, access, chown and utimensat were
 * already redirected this way; this is the same hop for the rest of them.
 *
 * Returns 1 with `data` filled when (dirfd, gp) is such a name, 0 otherwise.
 * `hnf`, when given, gets the name's own host path, which is the one the :ro
 * question is asked about (see ro_denied_l2s above). The l2s hop is always the
 * last component, so the backing path is absolute and a dirfd-relative call
 * can simply be re-issued against it. */
static int l2s_nofollow_data(long dirfd, const char *gp, char *hnf_out,
                             size_t hsz, char *data, size_t dsz) {
    if (!cng_g_l2s || !gp || !gp[0])
        return 0;
    char hnf[CNG_PATH_MAX];
    if (cng_resolve_at(dirfd, gp, 0, hnf, sizeof hnf) != 0 ||
        cng_l2s_resolve(hnf, data, dsz, 0) != 1)
        return 0;
    if (hnf_out)
        cng_strlcpy(hnf_out, hnf, hsz);
    return 1;
}

/* --- :ro binds, by descriptor -----------------------------------------------
 *
 * A read-only mount refuses the calls that reach a file by its descriptor as
 * surely as the ones that reach it by name — mnt_want_write_file() is the
 * same test either way — and a descriptor on a file under a :ro bind is easy
 * to come by: the read-only open the bind allows. fchmod, fchown, futimens,
 * fsetxattr and fremovexattr on it, and the AT_EMPTY_PATH spellings of the
 * path forms, went to the kernel with nothing in the way: they carry no path
 * for the refusal to key on. What they carry is the descriptor, whose own
 * path the kernel reports, so the question is put to the fd link of it —
 * which ro_denied resolves (fd_link_ro) exactly as it does for a guest that
 * spells "/proc/self/fd/<n>" out. Only asked with a :ro bind in the view;
 * the calls are only trapped then. */
static int fd_ro(long fd) {
    if (!cng_g_fs || !fs_has_ro())
        return 0;
    char link[40];
    proc_fd_path(fd, link);
    return ro_denied(link);
}

/* ro_refusal() for a call whose resolution followed the final component. The
 * l2s case is answered first and always with EROFS: the name resolved to a
 * link of ours, so it is there, and "there" is the whole of what the ENOENT
 * half of ro_refusal exists to establish. An empty name is AT_EMPTY_PATH (the
 * dispatcher has already refused one the call does not allow): the dirfd is
 * the file, and it is there — or, with AT_FDCWD, the working directory is,
 * which the translation has already named in `host`. */
static long ro_refusal_name(long dirfd, const char *gp, const char *host,
                            int atflags) {
    if (gp && !gp[0])
        return ((int)dirfd == CNG_AT_FDCWD ? ro_denied(host) : fd_ro(dirfd))
                   ? -EROFS
                   : 0;
    if (ro_denied_l2s(dirfd, gp))
        return -EROFS;
    return ro_refusal(host, atflags);
}

/* An open the host refused on a path naming one of *our own* fds. We hold that
 * descriptor, so the guest can still be served — two distinct refusals, two
 * answers (apk 3 runs into both when it execs a package script and the shebang
 * interpreter reopens it):
 *
 *  - the inode already grants us the access asked for, so the refusal did not
 *    come from DAC. On Android that is SELinux declining an app an `open` on
 *    the tmpfs inode behind a memfd — where apk 3 keeps its scripts (mode 0777,
 *    owned by us). A fresh description of the same file is exactly what the
 *    open would have produced: duplicate ours and rewind it. The duplicate
 *    shares the original's file offset, hence the rewind — a real open always
 *    starts at 0.
 *  - the inode denies it and the guest is fake-root: real root would have
 *    bypassed DAC, so lend the inode the owner bit *through the fd* (no path
 *    race), reopen properly, and put the mode straight back.
 *
 * Returns the new fd, or `err` unchanged when this is not that case. */
long cng_fd_reopen(const char *host, long flags, long mode, long err) {
    int fd = cng_proc_self_fd(host);
    if (fd < 0)
        return err;
    /* Nothing here reproduces creation/truncation/append semantics. */
    if ((int)flags & (CNG_O_CREAT | CNG_O_EXCL | CNG_O_TRUNC | CNG_O_APPEND |
                      CNG_O_DIRECTORY))
        return err;
    char st[128];
    if (CNG_SYS(__NR_fstat, fd, st, 0, 0, 0, 0) != 0)
        return err;
    unsigned m = *(unsigned *)(st + STAT_MODE_OFF);
    if ((m & 0170000) != 0100000)
        return err; /* plain files only */

    int acc = (int)flags & 3; /* O_ACCMODE: RDONLY/WRONLY/RDWR */
    unsigned need = (acc == CNG_O_WRONLY)  ? 0200u
                    : (acc == CNG_O_RDWR)  ? 0600u
                                           : 0400u;
    int ours = (*(unsigned *)(st + STAT_UID_OFF) == (unsigned)sys_getuid());

    if (ours && (m & need) == need) {
        /* Not a DAC refusal: hand over a duplicate of the description. */
        long cur = CNG_SYS(__NR_fcntl, fd, 3 /*F_GETFL*/, 0, 0, 0, 0);
        if (cur < 0)
            return err;
        if ((cur & 3) != CNG_O_RDWR && (cur & 3) != acc)
            return err; /* our fd cannot serve that access mode */
        long nfd = CNG_SYS(__NR_fcntl, fd,
                           ((int)flags & CNG_O_CLOEXEC) ? 1030 /*F_DUPFD_CLOEXEC*/
                                                        : 0 /*F_DUPFD*/,
                           0, 0, 0, 0);
        if (nfd < 0)
            return err;
        sys_lseek((int)nfd, 0, CNG_SEEK_SET);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] fd reopen %s -> dup %ld (mode %o)\n", host,
                        nfd, m & 07777);
        return nfd;
    }

    if (!cng_fake_root() || !ours)
        return err;
    if (CNG_SYS(__NR_fchmod, fd, (m & 07777) | need, 0, 0, 0, 0) != 0)
        return err;
    long r = cng_pin_open(host, flags, mode);
    CNG_SYS(__NR_fchmod, fd, m & 07777, 0, 0, 0, 0);
    if (cng_g_debug)
        cng_dprintf(2, "[cng] fake-root reopen %s (mode %o) -> %ld\n", host,
                    m & 07777, r);
    return r;
}

static const char *xlate_lim(long dirfd, const char *gp, char *buf,
                             size_t bufsz, int deref_final,
                             struct cng_res_limit *lim) {
    if (!gp)
        return gp;
    /* A scoped openat2 is always walked, and from the scope the caller
     * anchored rather than from the cwd or the dirfd: the fast path below
     * would hand the kernel a name with the scope's own rules never applied,
     * and the join in xlate_at_lim would turn a relative name into the
     * absolute one BENEATH exists to refuse. */
    if (lim && lim->scope) {
        if (cng_resolve_lim(gp, deref_final, buf, bufsz, lim) == 0)
            return buf;
        return XLATE_TOOLONG; /* the caller reads lim->err where it is set */
    }
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (gp[0] == '/' || dfd == CNG_AT_FDCWD) {
        long r = cng_resolve_lim(gp, deref_final, buf, bufsz, lim);
        if (r == 0)
            return buf;
        if (lim && lim->err)
            return XLATE_TOOLONG; /* the caller reads lim->err, not this */
        /* The walk's own refusal, which the lexical translation below would
         * paper over: the name leads through a directory the guest has no
         * name for (an fd link to one; see cng_resolve_lim). */
        if (r == -EACCES)
            return XLATE_OUTSIDE;
        if (cng_fs_translate(cng_g_fs, gp, buf, bufsz) == 0)
            return buf;
        /* Both routes failing means the name does not fit — cng_fs_translate
         * has no other way to fail — so there is nothing to hand back. Falling
         * through to the guest's own spelling, which is what this used to do,
         * would put an untranslated name in front of the kernel. */
        return XLATE_TOOLONG;
    }
    /* Relative to a real dirfd. Handing this to the kernel unchanged — which is
     * what we used to do — lets a ".." run climb out of the rootfs and an
     * absolute symlink target resolve from the HOST root, since the kernel does
     * not know about the rootfs. Contain it like any other path, but only when
     * something in it could actually redirect (see at_needs_xlate). */
    /* An empty name against a real dirfd is AT_EMPTY_PATH: the descriptor IS
     * the file and there is no name to resolve. It must not be walked. The
     * probe at_needs_xlate ends on is a readlinkat, which for an empty name
     * reports on the *dirfd* — so an fd opened O_PATH|O_NOFOLLOW on a symlink
     * answered "this is a link, walk it", and the walk then joined the empty
     * name onto the fd's own guest path and resolved it with deref_final=1.
     * The reissued call named the symlink's TARGET and ignored the dirfd
     * entirely: fstatat described the target where the kernel describes the
     * link, fchownat changed the target's owner and left the link alone, and on
     * a dangling link a call the kernel answers came back -ENOENT. That is the
     * standard race-free lstat-by-fd idiom (O_PATH|O_NOFOLLOW then *at(fd, "",
     * AT_EMPTY_PATH)), which systemd and util-linux use everywhere.
     *
     * Nothing is given up by passing it through: the dirfd is already inside
     * the guest view, which is what contains it. AT_FDCWD is handled above and
     * still resolves through the virtual cwd. */
    if (dfd >= 0 && gp[0] && at_needs_xlate(dfd, gp, deref_final)) {
        int r = xlate_at_lim(dfd, gp, buf, bufsz, deref_final, lim);
        if (r == 0)
            return buf;
        if (lim && lim->err)
            return XLATE_TOOLONG; /* the caller reads lim->err, not this */
        if (r == XLATE_AT_LONG)
            return XLATE_TOOLONG;
        /* A directory the guest has no name for: nothing here can be resolved
         * against it, and the kernel must not be the one to try. (A /proc or
         * /dev zone dirfd is not this — host_dir_guest names it, and the walk
         * above has applied the hidden-process view to `openat(dirfd("/proc"),
         * "1/status")` the same way it does to "/proc/1/status".) */
        if (r == XLATE_AT_OUTSIDE)
            return XLATE_OUTSIDE;
    }
    /* A plain name against a dirfd already inside the guest view: the kernel
     * resolves it there, which is the containment. */
    return gp;
}

static const char *xlate(long dirfd, const char *gp, char *buf, size_t bufsz,
                         int deref_final) {
    return xlate_lim(dirfd, gp, buf, bufsz, deref_final, 0);
}

/* /proc/<pid>/{exe,cwd,root} -> guest-visible link target. Our own process
 * answers from the live view; another guest process from the registry entry it
 * published (a host process never gets here — the path layer hides it). Returns
 * bytes written (no NUL, like readlink) or -1 if `canon` isn't one of these. */
static long proc_self_fixup(const char *canon, char *buf, unsigned long bufsz) {
    size_t pl = proc_pid_prefix(canon, 0);
    if (!pl)
        return -1;
    const char *rest = canon + pl;
    if (strcmp(rest, "exe") && strcmp(rest, "cwd") && strcmp(rest, "root"))
        return -1;

    const char *val = 0;
    char own[CNG_PROCREG_PATH + 1], cwd[CNG_PATH_MAX];
    if (rest[0] == 'c')
        cng_fs_cwd(cwd, sizeof cwd);
    if (proc_pid_prefix(canon, 1)) { /* self / thread-self */
        val = rest[0] == 'e' ? cng_g_exe_guest : rest[0] == 'c' ? cwd : "/";
    } else {
        const char *q = canon + 6;
        long pid = parse_int_run(&q);
        if (pid < 0)
            return -1; /* no process is numbered that high */
        if (pid == sys_getpid()) {
            val = rest[0] == 'e' ? cng_g_exe_guest : rest[0] == 'c' ? cwd : "/";
        } else if (rest[0] == 'r') {
            val = "/"; /* every guest process shares this session's root */
        } else {
            struct cng_procsnap snap;
            if (!cng_procreg_get((int)pid, &snap))
                return -1;
            unsigned n = rest[0] == 'e' ? snap.exe_len : snap.cwd_len;
            const char *src = rest[0] == 'e' ? snap.exe : snap.cwd;
            if (!n) {
                if (rest[0] == 'e')
                    return -1; /* no recorded exe: nothing safe to report */
                val = "/"; /* an empty cwd snapshot reads as the guest root —
                            * falling through would leak the host path */
            } else {
                if (n > CNG_PROCREG_PATH)
                    n = CNG_PROCREG_PATH;
                memcpy(own, src, n);
                own[n] = '\0';
                val = own;
            }
        }
    }
    if (!val)
        return -1;
    size_t len = strlen(val);
    if (len > bufsz)
        len = bufsz;
    memcpy(buf, val, len);
    return (long)len;
}

/* Cheap pre-filter for the /proc hooks on a dirfd-relative path: resolving one
 * costs a readlink of the dirfd, which must not be paid by every openat a guest
 * makes. Only a final component that could name a synthesized file is worth
 * resolving — procps opens "<pid>/stat" and "status" against a /proc dirfd, so
 * the test is on the basename, not the whole path. */
static int leaf_may_synth(const char *p) {
    /* Every name cng_procfs_open() can serve has to be here, or that name is
     * simply not synthesized when it arrives against a dirfd. "version" was
     * missing, and it is the one whose absence contradicts something else we
     * fake: uname reported 6.1.0-chroot-ng while openat(dirfd_of_/proc,
     * "version") returned the host's real kernel, build host and compiler. */
    static const char *const leafs[] = {
        "cmdline", "environ",   "auxv",    "maps",   "mounts", "mountinfo",
        "status",  "mountstats", "loadavg", "uptime", "stat",   "version",
    };
    const char *b = strrchr(p, '/');
    b = b ? b + 1 : p;
    for (unsigned i = 0; i < sizeof leafs / sizeof leafs[0]; i++)
        if (!strcmp(b, leafs[i]))
            return 1;
    return 0;
}

/* Same idea for readlinkat: could this name be an fd or map_files link, whose
 * target is a host path that has to be mapped back into the guest view? An
 * absolute name must be under /proc; a cwd-relative one is cheap to
 * canonicalize either way; a dirfd-relative one only matters for the entries
 * of a /proc/<pid>/fd directory (digit names, `ls -l /proc/self/fd`) or of
 * /proc/<pid>/map_files ("<start>-<end>" in lowercase hex), so the basename
 * must consist of hex digits and '-'. */
static int rl_may_fdlink(long dirfd, const char *p) {
    if (!p)
        return 0;
    if (p[0] == '/')
        return !strncmp(p, "/proc", 5);
    if ((int)dirfd == CNG_AT_FDCWD)
        return 1;
    const char *b = strrchr(p, '/');
    b = b ? b + 1 : p;
    if (!*b)
        return 0;
    for (; *b; b++)
        if (!((*b >= '0' && *b <= '9') || (*b >= 'a' && *b <= 'f') ||
              *b == '-'))
            return 0;
    return 1;
}

/* readlinkat of an fd or map_files link, whose target is a host path. The
 * kernel answers into a buffer of ours, long enough that its answer cannot
 * truncate (it is at most PATH_MAX-1 bytes, or ENAMETOOLONG), the target is
 * mapped back into the guest view, and the guest spelling goes out cut to
 * bufsiz — exactly as the kernel cuts its own. What is not the view's (a
 * pipe, a memfd, a host-only file) goes out as the kernel wrote it.
 *
 * It used to be the other way around: the kernel filled the guest's buffer
 * with the host path and this layer read it back and corrected it there. The
 * host path — where the rootfs lives on the device, the one thing the fixup
 * exists to keep from the guest — then sat in the guest's memory for the
 * interval, readable by any other thread of it; a buffer shorter than the
 * value held a prefix of it that no mapping could recognize; and the readback
 * itself was of memory the guest owns, which it can rewrite or unmap between
 * the kernel's write and ours. Now nothing of the host's is ever written
 * there: the guest's buffer receives the guest's answer, once. */
static long rl_fdlink(long dirfd, const char *host, long ubuf, int bufsiz) {
    char tgt[CNG_PATH_MAX], guest[CNG_PATH_MAX];
    long tl = reissue(dirfd, (long)host, (long)tgt, sizeof tgt - 1, 0, 0,
                      __NR_readlinkat);
    if (tl <= 0)
        return tl;
    const char *out = tgt;
    long ol = tl;
    if ((size_t)tl < sizeof tgt && tgt[0] == '/') {
        tgt[tl] = '\0';
        /* A synthesized /proc file's fd is a memfd named after it: the link
         * says so, not "memfd:... (deleted)". */
        if (cng_fs_untranslate(cng_g_fs, tgt, guest, sizeof guest) == 0 ||
            (!cng_g_no_proc && cng_procfs_link_name(tgt, guest, sizeof guest))) {
            out = guest;
            ol = (long)strlen(guest);
        }
    }
    if (ol > bufsiz)
        ol = bufsiz;
    /* Our own copy_to_user: the kernel validated nothing of the guest's
     * buffer here, so a bad one is -EFAULT from us. */
    if (ol && cng_user_copyout((char *)ubuf, out, (unsigned long)ol) < 0)
        return -EFAULT;
    return ol;
}

/* The canonical GUEST path an (dirfd, path) pair names, for the /proc hooks.
 * Lexical, as the absolute form is: the name is joined onto the guest spelling
 * of the directory the dirfd names (host_dir_guest — a /proc dirfd's is its
 * host path, that zone passing through) and canonicalized. Not walked: the
 * walk expands a magic link into what it points at, and "exe" against a
 * dirfd on /proc/self has to come out as "/proc/<pid>/exe" for the fixup to
 * recognize it, not as the program's own path. Returns 0/-1. */
static int at_canon(long dirfd, const char *path, char *out, size_t sz) {
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || (int)dirfd == CNG_AT_FDCWD)
        return cng_fs_abscanon(cng_g_fs, path, out, sz);
    char hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX], tmp[CNG_PATH_MAX];
    if (dirfd_host((int)dirfd, hdir, sizeof hdir) != 0 ||
        host_dir_guest(hdir, gdir, sizeof gdir) != 0)
        return -1;
    size_t n = cng_strlcpy(tmp, gdir, sizeof tmp);
    if (n >= sizeof tmp)
        return -1;
    if (n && tmp[n - 1] != '/') {
        if (n + 1 >= sizeof tmp)
            return -1;
        tmp[n++] = '/';
        tmp[n] = '\0';
    }
    if (cng_strlcpy(tmp + n, path, sizeof tmp - n) >= sizeof tmp - n)
        return -1;
    return cng_path_canon(tmp, out, sz);
}

/* 1 if the open fd refers to the host's real /proc — the directory whose
 * numeric entries the hidden-process view has to filter out of a listing.
 * Keyed on the fd's host path, so an explicit `-b /proc:/proc` (or the host
 * /proc bound at some other guest path) is covered exactly like the built-in
 * passthrough. */
static int fd_is_host_proc(long fd) {
    char proc[40], hp[CNG_PATH_MAX];
    proc_fd_path(fd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hp, sizeof hp - 1);
    if (n <= 0)
        return 0;
    hp[n] = '\0';
    return strcmp(hp, "/proc") == 0;
}

/* Does this getdents64 batch contain an all-digit name? Only then can the
 * hidden-process filter have anything to do, so this keeps the readlink in
 * fd_is_host_proc off every ordinary directory listing. */
static int dents_have_pid(const char *buf, long n) {
    for (long o = 0; o + 19 <= n;) {
        unsigned short reclen;
        memcpy(&reclen, buf + o + 16, 2);
        if (reclen == 0 || o + reclen > n)
            break;
        const char *nm = buf + o + 19;
        if (*nm >= '0' && *nm <= '9')
            return 1;
        o += reclen;
    }
    return 0;
}

/* A /proc entry the guest may see: anything not all-digits (self, sys, net,
 * version, ...), plus the guest processes' own pids. */
static int proc_name_visible(const char *nm) {
    if (*nm < '0' || *nm > '9')
        return 1;
    const char *p = nm;
    long pid = parse_int_run(&p);
    if (pid < 0 || *p)
        return 1; /* out of range, or "1abc": an ordinary name, not a pid */
    return cng_procreg_has((int)pid);
}

/* 1 if the open fd refers to the rootfs root directory (where the ".l2s"
 * store entry itself must be hidden from listings). */
static int fd_is_rootfs_root(long fd) {
    if (!cng_g_fs)
        return 0;
    char proc[40], hp[CNG_PATH_MAX];
    proc_fd_path(fd, proc);
    long n = sys_readlinkat(CNG_AT_FDCWD, proc, hp, sizeof hp - 1);
    if (n <= 0)
        return 0;
    hp[n] = '\0';
    char root[CNG_PATH_MAX];
    if (!cng_fs_rootfs(root, sizeof root))
        cng_strlcpy(root, "/", sizeof root);
    return strcmp(hp, root) == 0;
}

/* getdents64: hide the l2s machinery from directory listings — backing
 * data/marker names anywhere, and the ".l2s" store dir in the rootfs root — and
 * make the links themselves read as what stat() says they are: the kernel's
 * record for an emulated hardlink is the symlink's (DT_LNK, its own inode),
 * and a guest taking d_type/d_ino on trust — GNU ls -F and --color, find -type
 * f, ls -i, anything using the readdir fast path — saw a symlink where stat
 * showed a regular file (busybox stats every entry, which is why the shell
 * differential never caught it). When a whole batch is ours, re-read so a
 * filtered 0 isn't mistaken for end-of-directory. Then splice in the entries
 * that exist only as resolution overlays (bind mount points, /dev nodes) and so
 * have no physical dirent to return.
 *
 * All of that examines the records and rewrites them, and the buffer the guest
 * offered is the guest's. So whenever anything here is going to look at them,
 * the kernel fills a batch buffer of ours and the guest's buffer is written
 * once, with the final view, through cng_user_copyout. Filling the guest's
 * buffer first and correcting it afterwards was wrong twice over: the guest
 * owns that memory, so another of its threads can unmap it between the
 * kernel's write and the readback (which runs with SIGSEGV masked, where a
 * fault is the death of the process rather than an -EFAULT) — and for that
 * interval the records the view exists to hide, the host's pids and the l2s
 * store's names, sat in the guest's memory for any thread to read, and any
 * thread could rewrite them into what got filtered.
 *
 * A function of its own because of that buffer: DENTS_BOUNCE is stack, and in
 * cng_dispatch's frame every other syscall would carry it — that frame already
 * runs ~100 KiB deep on the execve path. noinline keeps it here (there is one
 * call site, so gcc would otherwise fold it straight back in).
 *
 * The bound costs nothing a guest can see. It is the size of glibc's own
 * readdir buffer, musl's is 2 KiB and bionic's 4 KiB, and a batch shorter than
 * the buffer offered is legal and simply read again — which is the same
 * contract the injection path below already relies on. */
#define DENTS_BOUNCE 32768

/* The final view goes out in one copy. A guest buffer that will not take it
 * is -EFAULT — and the stream is put back where it was before the kernel was
 * asked, since the records it moved past were never delivered: the kernel
 * itself leaves f_pos at the record it could not copy. `pos` is that place
 * (0 for the first read of a stream, which is also where the overlay records
 * are injected, so a retried first read injects them again), or -1 where it
 * could not be read, and then the stream stays where the kernel left it. */
static long dents_out(long fd, long guest, const char *bnc, long n, long pos) {
    if (n <= 0)
        return n;
    if (cng_user_copyout((char *)guest, bnc, (unsigned long)n) == 0)
        return n;
    if (pos >= 0)
        sys_lseek((int)fd, pos, CNG_SEEK_SET);
    return -EFAULT;
}

__attribute__((noinline)) static long do_getdents64(long a0, long a1, long a2,
                                                    long a3, long a4, long a5) {
    /* Injection belongs at the start of the stream and only there, so the
     * decision is taken before the read: lseek(SEEK_CUR) == 0 means nothing
     * has been read from this fd yet. Deciding it up front also means an
     * empty directory still gets its overlay entries.
     *
     * They go in *ahead* of the kernel's own, which is what guarantees they
     * go in at all. Appended to a batch the kernel had already filled, they
     * had nowhere to fit and were simply dropped — and since injection
     * happens only on the first read of the stream, dropped meant the guest
     * never saw them. Whether that happened came down to the guest libc's
     * readdir buffer: musl reads 2 KiB at a time where glibc reads 32 KiB,
     * so a bind mount point in a directory of any size was listed on a
     * Debian rootfs and invisible on an Alpine one. */
    char injdir[CNG_PATH_MAX], hdir[CNG_PATH_MAX];
    long pos = a1 ? sys_lseek((int)a0, 0, CNG_SEEK_CUR) : -1;
    int first = pos == 0;
    int named = first && dirfd_host((int)a0, hdir, sizeof hdir) == 0;
    int inject = named &&
                 cng_fs_untranslate(cng_g_fs, hdir, injdir, sizeof injdir) == 0;
    /* Whether anything here is going to look at the records at all. When
     * nothing is — no injection, no l2s, no hidden-process view — the call is
     * a plain pass-through and the guest's own buffer size is honored whole.
     * A NULL buffer is one too: the kernel answers it (-EFAULT at the first
     * record, 0 for an empty stream) with the stream where it was.
     *
     * The hidden-process view has records to drop from one directory only,
     * the host's real /proc (fd_is_host_proc), and whether this is that is
     * settled before the read rather than after it: with the zone on, every
     * listing used to be bounced — and scanned for a numeric name — to find
     * out, for all but `ls /proc`, that there was nothing to do. On the first
     * read of a stream the readback above has already named the directory; a
     * later read (a directory too big for one batch) asks for it again, which
     * is one readlink against a copy of the whole batch. */
    int at_proc = a1 && !cng_g_no_proc &&
                  (first ? named && strcmp(hdir, "/proc") == 0
                         : fd_is_host_proc(a0));
    int bounce = a1 && (inject || cng_g_l2s || at_proc);
    char bnc[DENTS_BOUNCE];
    /* The count as the kernel takes it, an unsigned int: the register's top
     * half is not part of it, and with the kernel writing into a buffer of
     * ours the clamp below has to be applied to the number it will use. */
    long ask = (long)(unsigned)a2;
    if (bounce && ask > DENTS_BOUNCE)
        ask = DENTS_BOUNCE;

    /* ...and the room left over has to admit at least one of the kernel's
     * own records, or the stream never moves. put_dent stops only when the
     * *next* record does not fit, so what remains was routinely below the
     * smallest possible dirent (24 bytes, for "."); filldir64 then refuses
     * the whole batch with EINVAL and iterate_dir writes back an *unchanged*
     * f_pos (measured). Reporting our records as a short batch left the
     * position at 0, so the next read decided "first read" all over again
     * and injected the identical entries — forever. `ls /dev` through a raw
     * getdents64 of 184..407 bytes never reached the real dirents at all;
     * only the 32 KiB/2 KiB/4 KiB readdir buffers of glibc, musl and bionic
     * kept every guest that has been tried out of it.
     *
     * So hand a record back and re-ask until the kernel can make progress.
     * inject_dents fills greedily from the two lists, so a cap one byte
     * under what it just produced yields strictly fewer records: the loop
     * shrinks monotonically and ends at worst with pre == 0, which is the
     * guest's own buffer being too small — the kernel's answer to give.
     *
     * Keyed on "it refused", not on one errno: the refusal is EINVAL on a
     * real kernel, but where we left it exactly nothing qemu-user answers
     * ENOMEM instead (its bounce buffer for a zero-length read), and both
     * mean the same thing here. Both measured.
     *
     * A record dropped this way is not seen again (injection happens once,
     * at the start of the stream). That bound is the buffer's, not ours: at
     * 408 bytes the whole /dev overlay plus a kernel record fits and nothing
     * is dropped, and no real readdir asks for less.
     *
     * The injected records sit at the front of the batch buffer and the
     * kernel's go in after them, so a refusal here has touched nothing of
     * the guest's: it is answered with the stream still where it was, which
     * is what a plain getdents64 on the same buffer would have answered. */
    long pre = 0, n, injcap = ask;
    for (;;) {
        pre = inject ? inject_dents(a0, injdir, bnc, 0, injcap) : 0;
        n = bounce ? reissue(a0, (long)(bnc + pre), ask - pre, a3, a4, a5,
                             __NR_getdents64)
                   : reissue(a0, a1, a2, a3, a4, a5, __NR_getdents64);
        if (n >= 0 || pre == 0)
            break;
        injcap = pre - 1;
    }
    /* A refusal is the guest's to see: the position did not move, so
     * answering with the spliced-in bytes would repeat them next time. */
    if (n < 0 || !bounce)
        return n;
    char *kb = bnc + pre;
    long cap = ask - pre;
    /* End of stream on the very first read means a directory that emitted
     * neither "." nor "..", which no filesystem does; the overlay records
     * are the whole answer. */
    if (n == 0)
        return dents_out(a0, a1, bnc, pre, pos);
    /* Hidden-process view, listing side: the path layer makes a host
     * process's /proc entry unreachable, but `ls /proc` and `ps` read the
     * directory, so the numeric entries have to go as well (at_proc, decided
     * above). A batch of it with no numeric name has nothing to drop. */
    if (at_proc && !dents_have_pid(kb, n))
        at_proc = 0;
    if (!cng_g_l2s && !at_proc)
        return dents_out(a0, a1, bnc, pre + n, pos);
    int at_root = cng_g_l2s && fd_is_rootfs_root(a0);
    for (;;) {
        /* linux_dirent64: d_ino u64 @0, d_reclen u16 @16, d_type u8 @18,
         * d_name @19. d_off cookies are directory-stream positions, so
         * compaction is seek-safe. */
        long w = 0, o = 0;
        while (o + 19 <= n) {
            unsigned short reclen;
            memcpy(&reclen, kb + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = kb + o + 19;
            int hide = (cng_g_l2s && (cng_l2s_hidden(nm) ||
                                      (at_root && !strcmp(nm, ".l2s")))) ||
                       (at_proc && !proc_name_visible(nm));
            if (!hide) {
                /* An emulated hardlink's record is rewritten to the data
                 * file's inode and type. Asked only of a record that can be a
                 * symlink: DT_LNK, or DT_UNKNOWN from a filesystem that does
                 * not type its entries — a guest then stats every entry, and
                 * the inode it compares against must still agree. Costs one
                 * readlink per symlink listed under -l, two per link. */
                unsigned char dt = (unsigned char)kb[o + 18];
                if (cng_g_l2s && (dt == CNG_DT_LNK || dt == CNG_DT_UNKNOWN)) {
                    unsigned long long ino;
                    unsigned type;
                    if (cng_l2s_dirent(a0, nm, &ino, &type)) {
                        memcpy(kb + o, &ino, sizeof ino);
                        kb[o + 18] = (char)type;
                    }
                }
                if (w != o)
                    memmove(kb + w, kb + o, reclen);
                w += reclen;
            }
            o += reclen;
        }
        if (w > 0)
            return dents_out(a0, a1, bnc, pre + w, pos);
        /* A whole batch of ours: re-read, so a filtered 0 is not mistaken
         * for end-of-directory. */
        n = reissue(a0, (long)kb, cap, a3, a4, a5, __NR_getdents64);
        if (n <= 0)
            return pre ? dents_out(a0, a1, bnc, pre, pos) : n;
    }
}

/* The guest's own path arguments of a trapped syscall — up to two (dirfd, path)
 * pairs, as the guest wrote them, before any resolution. `p1`/`p2` stay 0 for a
 * syscall that carries no path there (and utimensat's legitimate NULL path,
 * which means "operate on the dirfd"), and the index of the a0..a5 slot each
 * came out of. The index is what lets cng_dispatch put its own copy of a path
 * back where the guest's pointer was, so that everything downstream — the
 * resolver, the l2s check, the re-issue — reads bytes nobody else can change. */
struct path_args {
    const char *p1, *p2;
    long d1, d2;
    int i1, i2; /* which argument p1/p2 arrived in; -1 for none */
};

static void path_args_of(long nr, long a0, long a1, long a2, long a3,
                         struct path_args *pa) {
    pa->p1 = pa->p2 = 0;
    pa->d1 = pa->d2 = CNG_AT_FDCWD;
    pa->i1 = pa->i2 = -1;
    switch (nr) {
    case __NR_openat:
    case __NR_openat2:
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_name_to_handle_at:
    case __NR_faccessat:
    case __NR_faccessat2:
    case __NR_fchmodat:
    case __NR_fchmodat2:
    case __NR_unlinkat:
    case __NR_utimensat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_fchownat:
    case __NR_readlinkat:
    case __NR_setxattrat:
    case __NR_getxattrat:
    case __NR_listxattrat:
    case __NR_removexattrat:
    case __NR_file_getattr:
    case __NR_file_setattr:
        pa->d1 = a0;
        pa->p1 = (const char *)a1;
        pa->i1 = 1;
        break;
    case __NR_symlinkat: /* only the linkpath names something new */
        pa->d1 = a1;
        pa->p1 = (const char *)a2;
        pa->i1 = 2;
        break;
    case __NR_inotify_add_watch: /* a0 is the instance, not a dirfd */
        pa->p1 = (const char *)a1;
        pa->i1 = 1;
        break;
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_linkat:
        pa->d1 = a0;
        pa->p1 = (const char *)a1;
        pa->i1 = 1;
        pa->d2 = a2;
        pa->p2 = (const char *)a3;
        pa->i2 = 3;
        break;
    case __NR_truncate:
    case __NR_statfs:
    case __NR_chdir:
    case __NR_chroot:
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr:
        pa->p1 = (const char *)a0;
        pa->i1 = 0;
        break;
    }
}

/* Is there a ".." component in this path at all? A string test, so the walk
 * below is paid for only by the paths that have one — which is very few. */
static int has_dotdot(const char *p) {
    for (const char *q = p; *q; q++)
        if (q[0] == '.' && q[1] == '.' && (q == p || q[-1] == '/') &&
            (q[2] == '/' || q[2] == '\0'))
            return 1;
    return 0;
}

/* ".." is walked THROUGH the directory it leaves, and the kernel requires that
 * directory to exist and to be one: "f/.." is ENOTDIR, so is "f/../g", and
 * "missing/.." is ENOENT. Canonicalization collapses the pair away instead —
 * which is what keeps a guest inside its rootfs, since "/../../etc" has to come
 * out as "/etc" — and the component being left is then never looked at, so
 * every one of these answered about a path the kernel would have refused to
 * reach. `unlink("f/../f")` did not merely answer wrongly: it removed f.
 *
 * The verdict is reached by the ordinary walk, in one pass, because the walk is
 * the only thing that knows what each component really is — it has expanded the
 * symlinks by then, so "l2f/.." is ENOTDIR because the link leads to a file.
 * Asking prefix by prefix from outside would have re-resolved the path once per
 * ".." in it, and a guest may write a PATH_MAX name that is nothing but those:
 * a thousand walks of a thousand components each, for one syscall.
 *
 * A second walk, though. The verdict cannot ride out of cng_resolve_lim on its
 * return value, because that value is advisory — xlate falls back to the
 * lexical translation for a walk that fails, on the grounds that the kernel
 * re-derives an ELOOP or an ENAMETOOLONG for itself on the guest's own name,
 * which it cannot do for this one: the name it is handed no longer has the ".."
 * in it. So the check runs as its own pass, once, on the copy of the guest's
 * own spelling, and every path-bearing syscall gets it from one place.
 *
 * What it deliberately does not do is stop the collapse. The host path handed
 * over still has no ".." in it, so a race that turned the component into a
 * directory between this and the syscall costs a wrong errno and cannot cost
 * containment.
 *
 * Exported because exec is the one path-bearing call that does not come through
 * the dispatcher's argument table: cng_emulate_execve and cng_execve_tramp go
 * straight to the emulation, and it asks this for itself. */
long cng_dotdot_verdict(long dirfd, const char *path) {
    if (!path || !has_dotdot(path))
        return 0;
    struct cng_res_limit lim;
    memset(&lim, 0, sizeof lim);
    lim.check_dotdot = 1;
    char out[CNG_PATH_MAX];
    int dfd = (int)dirfd;
    /* deref_final=0: every ".." here is preceded by a component the walk treats
     * as non-final and therefore expands anyway, so nothing is gained by
     * following the last one — and a dangling final link is not this check's
     * business. */
    if (path[0] == '/' || dfd == CNG_AT_FDCWD)
        cng_resolve_lim(path, 0, out, sizeof out, &lim);
    else if (dfd >= 0)
        xlate_at_lim(dfd, path, out, sizeof out, 0, &lim);
    /* Only the ".." verdict is acted on. Every other way the walk can fail is
     * one the ordinary translation already absorbs or the kernel reproduces. */
    return lim.dotdot_err;
}

/* RESOLVE_BENEATH / RESOLVE_IN_ROOT scope the whole resolution to `dirfd`, and
 * the kernel is the only thing that can apply them exactly — so where the
 * guest's namespace has nothing to add under that directory (which is what
 * cng_scope_needs_walk answers) the call goes over untranslated, and the two
 * policies that a path-keyed check would have applied are re-expressed against
 * the directory instead. Both are sound because the scoping guarantees the
 * answer lies under that directory:
 *
 *  - a :ro bind covering the dirfd covers everything the open can reach, so a
 *    write-intent open is refused here exactly as it would be by name. The
 *    existence half of the refusal (ENOENT for a name that is not there, EROFS
 *    for one that is) is asked with the guest's OWN scoping, so it describes
 *    the same file the open would have found;
 *  - the /proc zone hides processes by path, and a scoped resolution never
 *    produces one. Only a dirfd already inside /proc can reach a hidden pid,
 *    and one whose guest path is in the zone is walked rather than passed
 *    through — what is left is a directory bound onto the host's /proc from
 *    somewhere else in the view, which this asks the descriptor about
 *    afterwards. Nothing in /proc is created or truncated by an open, so
 *    asking after the fact costs nothing.
 *
 * What gets re-issued is the validated COPY, never the guest's own struct —
 * which is why the struct is not passed here at all. Both of the above, and the
 * decision to come here rather than translate, were taken on the copy's
 * `resolve` and `flags`; handing the kernel the guest's pointer would let a
 * second thread rewrite them in between and have the call performed under a
 * word nobody checked. Clearing the scoping alone is enough to matter: the path
 * goes over untranslated, and it is the scoping that makes that safe. An
 * oversized `size` is not carried over either — read_open_how has already
 * proved the tail zero, which is what makes the two forms the same call.
 *
 * Returns the syscall result. */
static long how_precheck(const struct cng_open_how *how);

static long openat2_scoped(long dirfd, long path,
                           const struct cng_open_how *how) {
    char hdir[CNG_PATH_MAX];
    int have_dir = (int)dirfd == CNG_AT_FDCWD
                       ? sys_getcwd(hdir, sizeof hdir) > 0
                       : dirfd_host((int)dirfd, hdir, sizeof hdir) == 0;
    long oflags = (long)how->flags;

    if (have_dir && ro_denied(hdir) &&
        ((oflags & 3) != CNG_O_RDONLY ||
         (oflags & (CNG_O_CREAT | CNG_O_TRUNC)))) {
        /* We are about to answer instead of the kernel, and build_open_flags()
         * would have run before it looked at a path at all — so an open_how it
         * refuses is EINVAL ahead of our EROFS. The probe below carries the
         * guest's `resolve` and would draw that on its own, but not the flags,
         * which it replaces; and the O_CREAT branch never gets that far. */
        long inval = how_precheck(how);
        if (inval)
            return inval;
        if (oflags & CNG_O_CREAT)
            return -EROFS; /* creation takes write access on the parent first */
        struct cng_open_how probe = *how;
        /* O_PATH so nothing is opened for real, and the caller's own
         * O_NOFOLLOW carried over — ro_refusal() passes AT_SYMLINK_NOFOLLOW the
         * same way, or a write-open of a dangling link reads as absent. Raw,
         * not reissue(): the precheck above has already answered ENOSYS for a
         * blocked openat2, so nothing reaches this line where the number would
         * trap. */
        probe.flags = CNG_O_PATH | CNG_O_CLOEXEC | (oflags & CNG_O_NOFOLLOW);
        probe.mode = 0;
        long e = cng_syscall6(dirfd, path, (long)&probe, (long)sizeof probe, 0,
                              0, __NR_openat2);
        if (e < 0)
            return e; /* the lookup's own error: ENOENT, ENOTDIR, ELOOP... */
        sys_close((int)e);
        return -EROFS;
    }

    /* Raw, not reissue(): the pin is for a walk's product — a host path the
     * kernel would resolve a second time — and there is no walk here. The
     * name goes over as the guest spelled it, against the guest's own
     * descriptor, and the scoping is the kernel's to apply within that one
     * resolution: an absolute name is EXDEV under BENEATH and re-rooted onto
     * the directory under IN_ROOT, a symlink on the way is followed under the
     * same rule, and a rename racing a `..` is its EAGAIN. Whatever the tree
     * does meanwhile, the answer stays under the directory. Pinned, the name
     * was split at its last slash and re-aimed at the directory it spelled —
     * an absolute one at the HOST root, where BENEATH had nothing left to
     * refuse and IN_ROOT nothing to re-root (ENOENT for both) — and
     * RESOLVE_NO_SYMLINKS was added, which turned every link the scope would
     * have followed or refused into ELOOP. */
    if (cng_blocked[__NR_openat2]) {
        cng_note_blocked(__NR_openat2);
        return -ENOSYS;
    }
    long r = cng_syscall6(dirfd, path, (long)how, (long)sizeof *how, 0, 0,
                          __NR_openat2);
    if (r >= 0 && have_dir && !cng_g_no_proc && !strncmp(hdir, "/proc", 5) &&
        (!hdir[5] || hdir[5] == '/')) {
        char land[CNG_PATH_MAX];
        if (dirfd_host((int)r, land, sizeof land) == 0 &&
            proc_pid_prefix(land, 0) && !proc_pid_visible(land)) {
            sys_close((int)r);
            return -ENOENT; /* the answer the hidden view gives by name */
        }
    }
    return r;
}

/* Read the guest's `struct open_how`, applying the kernel's own ABI rules for
 * `size` before anything else looks at the contents: below the struct is
 * EINVAL, past a page is E2BIG, and in between every trailing byte must be zero
 * (E2BIG again) — which is also what makes an oversized call identical to one
 * sized exactly, and so safe to re-issue as one. Returns 0, or the errno to
 * answer with. */
static long read_open_how(long a2, unsigned long size, struct cng_open_how *out) {
    memset(out, 0, sizeof *out);
    if (size < sizeof *out)
        return -EINVAL;
    /* ...and the bound openat2 puts on the other end of `size`, before it looks
     * at the pointer at all: copy_struct_from_user is asked for at most a page,
     * and anything longer is -E2BIG whatever its tail holds. Without it the
     * scan below was the guest's to size — a mapped zero range as long as it
     * liked, walked a byte at a time inside the handler, where nothing can
     * interrupt us. */
    if (size > cng_page_size)
        return -E2BIG;
    if (!a2 || cng_user_copyin(out, (void *)a2, sizeof *out) < 0)
        return -EFAULT;
    unsigned long extra = size - sizeof *out;
    const unsigned char *tail = (const unsigned char *)a2 + sizeof *out;
    /* The tail is examined out of a copy, a window at a time — reading the
     * guest's own bytes after probing them lets another thread fill in a
     * non-zero one between the check and the re-issue, which is the difference
     * between the call the kernel refuses and the call it performs. */
    while (extra) {
        unsigned char win[256];
        unsigned long k = extra > sizeof win ? sizeof win : extra;
        if (cng_user_copyin(win, tail, k) < 0)
            return -EFAULT;
        for (unsigned long i = 0; i < k; i++)
            if (win[i])
                return -E2BIG;
        tail += k;
        extra -= k;
    }
    return 0;
}

/* build_open_flags() runs before any path resolution, so an open_how the kernel
 * refuses is EINVAL whatever the path was going to say — an unknown resolve
 * bit, BENEATH and IN_ROOT together, a mode without O_CREAT. We are about to
 * answer a constraint of our own, which would put our error in front of that
 * one, so ask the kernel first with a name that resolves to nothing: it
 * validates the struct, then fails the empty path. Returns 0 when the how is
 * good, else the errno the kernel gave it.
 *
 * Where the ambient filter refuses openat2 there is no kernel to ask: this runs
 * inside the SIGSYS handler, so a raw re-issue of a blocked number is the
 * nested trap the whole design avoids — measured on an Android 13 device,
 * which blocks openat2 outright and killed the process here. ENOSYS is the
 * answer reissue() already gives every other blocked syscall, and it is what
 * the guest would see from a kernel that has no openat2 at all. */
static long how_precheck(const struct cng_open_how *how) {
    if (cng_blocked[__NR_openat2]) {
        cng_note_blocked(__NR_openat2);
        return -ENOSYS;
    }
    long r = cng_syscall6(CNG_AT_FDCWD, (long)"", (long)how, (long)sizeof *how,
                          0, 0, __NR_openat2);
    if (r >= 0) {
        sys_close((int)r); /* an empty name cannot open, but never leak one */
        return 0;
    }
    return (r == -ENOENT || r == -EAGAIN) ? 0 : r;
}

/* May the *first* path argument of `nr` legitimately be the empty string? Only
 * where the call names the dirfd itself instead: AT_EMPTY_PATH where the guest
 * set it, and readlinkat, which has read the link a dirfd names since Linux
 * 2.6.39 without asking for a flag. A second path argument (linkat/renameat's
 * destination) never may — AT_EMPTY_PATH governs the source alone. */
static int empty_path_ok(long nr, long a0, long a2, long a3, long a4) {
    switch (nr) {
    case __NR_newfstatat:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_statx:
        return ((int)a2 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_fchownat:
    case __NR_linkat:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_fchmodat2:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_faccessat2:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_name_to_handle_at:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_setxattrat:
    case __NR_getxattrat:
    case __NR_listxattrat:
    case __NR_removexattrat:
        return ((int)a2 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_file_getattr:
    case __NR_file_setattr:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
    case __NR_readlinkat:
        return (int)a0 != CNG_AT_FDCWD; /* with no dirfd there is no link */
    default:
        return 0;
    }
}

/* Write one 65-byte utsname field. The whole field is cleared first, the way
 * the kernel NUL-pads its own: copying a shorter identity over a longer one
 * leaves the host's tail readable past the terminator, and for release and
 * version that tail is the vendor string the fake exists to withhold —
 * "-android14-11-g<sha>" on a phone, the build date and distro elsewhere. */
static void uts_set(char *field, const char *val) {
    memset(field, 0, 65);
    cng_strlcpy(field, val, 65);
}

/* ---- the guest's no_new_privs bit ---------------------------------------- */

/* cng_install_seccomp sets the real bit, because a filter cannot go in without
 * one, so the kernel's own answer describes us and not the guest. What the
 * guest is told is what the guest itself asked for — and the thing it asked
 * for is per TASK. Linux keeps no_new_privs in task_struct: a thread setting
 * it says nothing about its siblings, a task created afterwards inherits its
 * creator's bit, and fork and execve both carry it across. Measured on the
 * host: a sibling that set it reads 1 while main still reads 0, a thread
 * created by a task holding the bit reads 1, and one created by a task without
 * it reads 0.
 *
 * A single global said 1 for every thread the moment any one of them set it.
 * What replaces it is a tid-keyed table over a process-wide floor:
 *
 *   set, on task T   every OTHER task alive right now predates the call, so
 *                    none of them can have inherited anything — each is
 *                    recorded 0. T is recorded 1, and the floor goes up.
 *   get, on task T   T's own entry, or the floor where it has none: a task we
 *                    have never seen was created after the snapshot, and its
 *                    creator therefore held the bit.
 *
 * The floor is what makes the common shape right without a per-thread hook:
 * set it in main, then spawn workers, and every worker reads 1 as it would on
 * a kernel. The residue is the shape that needs the hook — a task created
 * after the snapshot by a sibling that does NOT hold the bit reads 1 where the
 * kernel says 0 — and there is no honest way to close it here: knowing a new
 * task's creator means trapping thread creation, and a thread-creating clone
 * is the one call this design cannot trap (a re-issued clone comes back into
 * the handler on the new thread's stack, with no frame to sigreturn through;
 * see cng_build_seccomp_traceall). Nothing else about the emulation depends on
 * being told. The other residue is a tid the kernel hands out again after the
 * thread recorded under it has exited, which needs a set, an exit, and the
 * whole pid space to come round before a new task lands on that number.
 *
 * Both leave a task reading a bit it did not ask for either way, which is what
 * a single global did for every task in the process — so neither is a step
 * back from what this replaces.
 *
 * The table is ordinary memory, so it survives our emulated execve exactly as
 * the bit survives a real one. A fork is the one event that has to reset it:
 * the child is one task holding what the forking task held, so it starts with
 * an empty table and that value as its floor — where the parent's table would
 * have been read against tids belonging to threads the child does not have. */
#define NNP_N 128

/* One word per task: the tid shifted up with the bit in its low place, so that
 * claiming a slot and giving it its value are a single store and no reader can
 * catch one without the other. 0 is free, and a tid is never 0, so a free slot
 * cannot be mistaken for an entry. Open addressing from a hash of the tid.
 *
 * Nothing is ever taken back out. A table that fills — 128 tasks recorded, and
 * only a set records any — stops recording, and the tasks that did not fit
 * read the floor, which is exactly where this started. Freeing entries would
 * buy a little and cost the invariant the probe runs rest on: a hole in the
 * middle of a run ends a later entry's chain, and the task it belonged to
 * would start reading the floor as well. */
static long g_nnp[NNP_N];
static int g_nnp_floor;

static unsigned nnp_hash(long tid) {
    return (unsigned)((unsigned long)tid * 2654435761u) % NNP_N;
}

/* This task's recorded bit, or -1 where it has none. */
static int nnp_lookup(long tid) {
    unsigned h = nnp_hash(tid);
    for (unsigned k = 0; k < NNP_N; k++) {
        long e = __atomic_load_n(&g_nnp[(h + k) % NNP_N], __ATOMIC_ACQUIRE);
        if (e == 0)
            return -1; /* the probe run ends here, so the tid is not in it */
        if ((e >> 1) == tid)
            return (int)(e & 1);
    }
    return -1;
}

/* Record `val` for `tid`. `keep` leaves an existing entry alone, which is what
 * a setter's siblings want: the second task to set the bit walks the first,
 * and writing 0 over the 1 already there would take away a bit the kernel
 * never takes away. A setter writes its own entry the other way — over
 * whatever is there — so it wins that race in either order. */
static void nnp_put(long tid, int val, int keep) {
    long want = ((long)tid << 1) | (long)(val & 1);
    unsigned h = nnp_hash(tid);
    for (unsigned k = 0; k < NNP_N; k++) {
        unsigned i = (h + k) % NNP_N;
        long e = __atomic_load_n(&g_nnp[i], __ATOMIC_ACQUIRE);
        if ((e >> 1) == tid) {
            if (!keep)
                __atomic_store_n(&g_nnp[i], want, __ATOMIC_RELEASE);
            return;
        }
        if (e == 0) {
            long free_slot = 0;
            if (__atomic_compare_exchange_n(&g_nnp[i], &free_slot, want, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
                return;
            k--; /* another task took this slot; it may hold OUR tid now, so
                  * read it again rather than stepping past it */
        }
    }
}

/* Every task of this process, into `out`. Returns how many, or -1 where the
 * list cannot be had — no /proc, or more tasks than there is room for — and
 * the caller then records none of them, leaving them on the floor. */
static int nnp_tasks(long *out, int max) {
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/task",
                         CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int n = 0;
    long got;
    while ((got = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0)) >
           0) {
        for (long o = 0; o + 19 <= got;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > got) {
                got = -1;
                break;
            }
            const char *q = buf + o + 19;
            long tid = parse_int_run(&q);
            if (tid > 0 && !*q) { /* "." and ".." are not runs of digits */
                if (n == max) {
                    got = -1;
                    break;
                }
                out[n++] = tid;
            }
            o += reclen;
        }
        if (got < 0)
            break;
    }
    sys_close((int)fd);
    return got < 0 ? -1 : n;
}

/* PR_SET_NO_NEW_PRIVS from this task. */
static void nnp_set(void) {
    long self = sys_gettid();
    long live[NNP_N];
    int n = nnp_tasks(live, NNP_N);

    /* Ours first, so a sibling taking its own snapshot at the same moment
     * finds an entry to leave alone rather than a free slot to write 0 into. */
    nnp_put(self, 1, 0);
    for (int k = 0; k < n; k++)
        if (live[k] != self)
            nnp_put(live[k], 0, 1);
    /* Last: until it is up, nothing is looked up at all, and a task that has
     * just been recorded 0 must not read 1 on the way there. */
    __atomic_store_n(&g_nnp_floor, 1, __ATOMIC_RELEASE);
}

/* PR_GET_NO_NEW_PRIVS for this task. Cheap until something sets the bit: with
 * the floor still down there is nothing recorded to look up, and no tid to go
 * and ask the kernel for. */
int cng_nnp_get(void) {
    if (!__atomic_load_n(&g_nnp_floor, __ATOMIC_ACQUIRE))
        return 0;
    int v = nnp_lookup(sys_gettid());
    return v < 0 ? 1 : v;
}

/* Called on the child side of a trapped fork with the value the forking task
 * held, sampled before the clone (in the child, gettid answers a tid that has
 * no entry). One task, one value, nothing inherited to look up: the floor
 * carries it, and every thread the child goes on to create inherits it too,
 * which is what a kernel does with the bit as well. */
void cng_nnp_fork_child(int val) {
    for (unsigned i = 0; i < NNP_N; i++)
        __atomic_store_n(&g_nnp[i], 0L, __ATOMIC_RELAXED);
    __atomic_store_n(&g_nnp_floor, val, __ATOMIC_RELEASE);
}

/* Does the hidden-process view hide `pid` (a pid_t argument: an int)? See the
 * process_vm_readv case. */
static int pid_hidden(long pid) {
    int p = (int)pid;
    return !cng_g_no_proc && p > 0 && !cng_procreg_has_task(p);
}

/* FIDEDUPERANGE: the descriptor is the source, and the destinations are the
 * dest_fd fields of the argument — each of which the kernel takes write
 * access on the mount for (vfs_dedupe_file_range_one), answering per
 * destination in that entry's status rather than for the call as a whole.
 * So the argument is taken as a copy, every destination under a :ro bind is
 * replaced by a descriptor that is not open — the kernel then skips it with
 * EBADF and goes on to the rest — and on the way back that status becomes
 * the EROFS the mount would have given, with the guest's own dest_fd put
 * back. The size rules are the kernel's: the count is read first, and a
 * struct that would exceed a page is ENOMEM before anything else is looked
 * at. The copy lives on the handler's stack, bounded at a page of the
 * largest page size this runs with; the same ENOMEM answers above it. */
static long ioctl_dedupe(long fd, long req, long argp, long a3, long a4,
                         long a5) {
    unsigned short count;
    if (!argp ||
        cng_user_copyin(&count, (char *)argp + CNG_DEDUPE_COUNT_OFF,
                        sizeof count) < 0)
        return -EFAULT;
    unsigned long size = CNG_DEDUPE_HDR + (unsigned long)count * CNG_DEDUPE_INFO;
    char buf[16384];
    if (size > cng_page_size || size > sizeof buf)
        return -ENOMEM;
    if (cng_user_copyin(buf, (void *)argp, size) < 0)
        return -EFAULT;
    /* Which destinations were taken out, to put back afterwards. A bit per
     * entry: at most 511 entries fit the page. */
    unsigned long ro[8] = {0};
    long dest[512];
    for (unsigned i = 0; i < count; i++) {
        char *info = buf + CNG_DEDUPE_HDR + (unsigned long)i * CNG_DEDUPE_INFO;
        memcpy(&dest[i], info, sizeof dest[i]);
        if (fd_ro(dest[i])) {
            ro[i / 64] |= 1UL << (i % 64);
            long none = -1;
            memcpy(info, &none, sizeof none);
        }
    }
    long r = reissue(fd, req, (long)buf, a3, a4, a5, __NR_ioctl);
    if (r < 0)
        return r;
    for (unsigned i = 0; i < count; i++) {
        char *info = buf + CNG_DEDUPE_HDR + (unsigned long)i * CNG_DEDUPE_INFO;
        if (!(ro[i / 64] & (1UL << (i % 64))))
            continue;
        memcpy(info, &dest[i], sizeof dest[i]);
        int st = -EROFS;
        memcpy(info + CNG_DEDUPE_STATUS_OFF, &st, sizeof st);
    }
    if (cng_user_copyout((void *)argp, buf, size) < 0)
        return -EFAULT;
    return r;
}

/* Deliver a translated sockaddr to the guest exactly as move_addr_to_user()
 * would: copy at most what the caller's buffer holds, then report the
 * UNtruncated length ("fromlen shall refer to the value before truncation",
 * 1003.1g). `src`/`slen` is the guest-view address in our own buffer; `aa`/`alp`
 * are the guest's buffer and its in/out length. Returns 0 or -errno.
 *
 * The reason the readback side bounces through our buffer at all: the kernel
 * writes only min(caller's length, real length) bytes but stores the *real*
 * length back, so a guest with a short buffer left us a truncated host path and
 * a length describing bytes that were never written. Translating that in place
 * read past the guest's buffer — a fault the SIGSYS handler cannot survive,
 * since it runs with SIGSEGV masked — and could write the shortened guest path
 * past its end. With the whole address in hand there is nothing to reconstruct:
 * the guest sees precisely what a kernel with no rootfs under it would have
 * written, short buffer and all. */
static long addr_out(const void *src, long slen, long aa, long alp) {
    if (!aa || !alp)
        return 0;
    /* The writability probe validates a range by zeroing it (uaccess.c), so the
     * caller's length has to be read out before anything is probed for writing. */
    int n;
    if (cng_user_copyin(&n, (void *)alp, sizeof n) < 0)
        return -EFAULT;
    if (n > (int)slen)
        n = (int)slen;
    if (n < 0)
        return -EINVAL;
    if (n && cng_user_copyout((void *)aa, src, (unsigned long)n) < 0)
        return -EFAULT;
    int back = (int)slen;
    if (cng_user_copyout((void *)alp, &back, sizeof back) < 0)
        return -EFAULT;
    return 0;
}

/* Take a window of a guest mmsghdr array into our own memory. A window at a
 * time is what keeps the array forms to a syscall per MMSG_WIN messages rather
 * than one per message — sendmmsg exists to spend one syscall on a batch, and
 * probing (or copying) each element in turn would give that back. A window that
 * will not come across whole is retried element by element, because the kernel
 * stops at the first unreadable message rather than refusing the batch, and
 * that boundary is part of the answer. Returns how many elements landed. */
#define MMSG_WIN 16
static unsigned long mmsg_take(struct cng_mmsghdr *dst,
                               const struct cng_mmsghdr *v, unsigned long k) {
    if (cng_user_copyin(dst, v, k * sizeof *dst) == 0)
        return k;
    unsigned long got = 0;
    while (got < k && cng_user_copyin(dst + got, v + got, sizeof *dst) == 0)
        got++;
    return got;
}

/* The SCM_RIGHTS records of a just-received message's control data, which is
 * in a buffer of ours (recvmsg_bounced): each descriptor they name is handed
 * to `fn`. A record the walk cannot make sense of ends it, as the kernel's
 * own CMSG_NXTHDR would. */
static void scm_rights_walk(const char *control, unsigned long len,
                            void (*fn)(int)) {
    unsigned long off = 0;
    while (off + sizeof(struct cng_cmsghdr) <= len) {
        struct cng_cmsghdr ch;
        memcpy(&ch, control + off, sizeof ch);
        if (ch.len < sizeof ch || ch.len > len - off)
            return;
        if (ch.level == CNG_SOL_SOCKET && ch.type == CNG_SCM_RIGHTS) {
            unsigned long nfd = (ch.len - sizeof ch) / sizeof(int);
            const char *fds = control + off + sizeof ch;
            for (unsigned long i = 0; i < nfd; i++) {
                int fd;
                memcpy(&fd, fds + i * sizeof fd, sizeof fd);
                fn(fd);
            }
        }
        off += (ch.len + 7) & ~7UL; /* CMSG_ALIGN */
    }
}

/* Put a received descriptor through cng_fd_admit. A number closed there stays
 * in the record: the guest sees it and finds it not open, which is the whole
 * of what an import it may not have looks like. */
static void scm_rights_admit_one(int fd) { cng_fd_admit(fd); }

/* ...and take one back that the guest never learned the number of. */
static void scm_rights_close_one(int fd) {
    if (fd >= 0)
        sys_close(fd);
}

/* Does a recvmsg header ask for control data that could carry descriptors? A
 * buffer shorter than one SCM_RIGHTS record with a single descriptor in it
 * receives none: scm_detach_fds installs nothing into it and reports
 * MSG_CTRUNC, whatever the message carried. */
static int ctl_may_carry_fds(const struct cng_msghdr *h) {
    return h->control &&
           h->controllen >= sizeof(struct cng_cmsghdr) + sizeof(int);
}

/* One recvmsg with the header, and what it points at that this layer has to
 * look at, taken out of the guest's memory: the header is always a copy of
 * ours (the kernel writes msg_namelen, msg_controllen and msg_flags back into
 * the one it is given, and those are carried over to the guest's afterwards);
 * with `bname` the source address goes into a buffer of ours to be mapped
 * back into the guest view (sun_deliver); with `bctl` the control data does,
 * so the descriptors an SCM_RIGHTS record names are admitted (cng_fd_admit)
 * out of the numbers the kernel wrote rather than out of the guest's buffer
 * a syscall later, where another thread of the guest could have rewritten
 * them into numbers of its choosing and kept the one that was to be closed.
 * The records then go out to the guest in one copy.
 *
 * The control bounce is exact: a buffer up to CTL_BOUNCE is taken at its own
 * size, so the kernel fills and truncates it exactly as it would have the
 * guest's. Longer than that, the socket's family is asked (one getsockopt,
 * and only then): AF_UNIX is the one family that can deliver descriptors,
 * and it never produces more than an SCM_RIGHTS record of SCM_MAX_FD (253)
 * descriptors, a credentials record and a security label — well under the
 * bound — so its buffer is taken at CTL_BOUNCE with nothing lost; any other
 * family's stays the guest's own, since nothing arriving on it needs
 * admitting and a raw IPv6 socket's extension headers can run past the bound.
 *
 * A guest control buffer that will not take the records is answered as the
 * kernel answers a control buffer it cannot write: no descriptor is left
 * installed whose number the guest could not be told (receive_fd() installs
 * nothing on a failed put), and the control data is reported truncated and
 * empty. `flags_out` is the msg_flags the kernel
 * wrote, for a caller that has to see MSG_OOB. A function of its own for the
 * buffer it holds, which cng_dispatch's frame must not carry for every other
 * syscall. */
#define CTL_BOUNCE 8192
static long sun_deliver(int own, char *ab, unsigned al, long aa, long alp);
__attribute__((noinline)) static long
recvmsg_bounced(long fd, struct cng_msghdr *g, const struct cng_msghdr *snap,
                long flags, int bname, int bctl, unsigned *flags_out) {
    char ab[CNG_SOCKADDR_MAX], cb[CTL_BOUNCE];
    struct cng_msghdr mh = *snap;
    if (bname) {
        mh.name = ab;
        mh.namelen = sizeof ab;
    }
    if (bctl) {
        unsigned long cl = snap->controllen;
        if (cl > sizeof cb) {
            int dom = 0;
            unsigned dlen = sizeof dom;
            if (CNG_SYS(__NR_getsockopt, fd, CNG_SOL_SOCKET, CNG_SO_DOMAIN,
                        &dom, &dlen, 0) == 0 &&
                dom != CNG_AF_UNIX)
                bctl = 0;
            else
                cl = sizeof cb;
        }
        if (bctl) {
            mh.control = cb;
            mh.controllen = cl;
        }
    }
    long r = reissue(fd, (long)&mh, flags, 0, 0, 0, __NR_recvmsg);
    if (r < 0)
        return r;
    if (bctl) {
        unsigned long cl = mh.controllen;
        if (cl > sizeof cb)
            cl = sizeof cb; /* not a length the kernel reports; bounded anyway */
        /* Handed over before it is judged: a record the guest could not be
         * given is taken back whole, and every number in it is still the
         * kernel's fresh install at that point — judged first, a number the
         * judgement had closed would be closed here a second time, and by
         * then it could be another thread's. */
        if (cl && cng_user_copyout(snap->control, cb, cl) < 0) {
            scm_rights_walk(cb, cl, scm_rights_close_one);
            cl = 0;
            mh.flags |= CNG_MSG_CTRUNC;
        } else {
            scm_rights_walk(cb, cl, scm_rights_admit_one);
        }
        mh.controllen = cl;
    }
    /* Written back whole rather than field by field: the guest's header is
     * ours to restore in full, and the copy that carries it also validates
     * it, so there is no zeroed remainder to worry about either. */
    struct cng_msghdr back = *snap;
    back.controllen = mh.controllen;
    back.flags = mh.flags;
    if (cng_user_copyout(g, &back, sizeof back) < 0)
        return -EFAULT;
    if (bname) {
        long e = sun_deliver(-1, ab, mh.namelen, (long)snap->name,
                             (long)&g->namelen);
        if (e)
            return e;
    }
    if (flags_out)
        *flags_out = mh.flags;
    return r;
}

/* Run the readback translation over an address the kernel just wrote into our
 * bounce buffer, and hand the result to the guest. `al` is what the kernel
 * reported; it cannot exceed the buffer (the kernel bounds every address by
 * sockaddr_storage), but it is clamped rather than trusted. */
static long sun_deliver(int own, char *ab, unsigned al, long aa, long alp) {
    long got = (long)al;
    if (got > CNG_SOCKADDR_MAX)
        got = CNG_SOCKADDR_MAX;
    cng_sun_out(own, ab, &got);
    return addr_out(ab, got, aa, alp);
}

/* ---- recvmmsg's timeout ------------------------------------------------- */

/* It is not a bound on the wait, and a decomposed batch must not treat it as
 * one. The kernel (net/socket.c, do_recvmmsg) turns the argument into an
 * absolute deadline and then consults it only *between* datagrams: each receive
 * — the first one included — blocks with no deadline of its own, so a socket
 * that never speaks again blocks forever even with a timeout set, and one that
 * speaks slowly is read until the deadline has already passed. recvmmsg(2) says
 * so under BUGS; measured against this host's kernel, an idle socket with a 1 s
 * timeout is still blocked at 5 s, and a feed of one datagram every 300 ms with
 * the same timeout returns 4 of them at 1.2 s.
 *
 * What the deadline does do is stop the loop from asking for the NEXT message
 * once it has passed, and the time left over is written back to the caller's
 * own timespec when at least one datagram arrived. Taking a non-NULL timeout to
 * mean "first only" instead cut every such batch short at one message.
 *
 * The clock is CLOCK_MONOTONIC (ktime_get_ts64), so setting the wall clock
 * mid-batch moves nothing. */
struct mmsg_deadline {
    int on;                   /* a timeout argument was supplied */
    struct cng_timespec end;  /* absolute; {0,0} for a zero timeout, i.e. past */
    struct cng_timespec left; /* what the caller gets back */
};

#define CNG_NSEC_PER_SEC 1000000000L

static void ts_norm(struct cng_timespec *t) {
    while (t->tv_nsec < 0) {
        t->tv_nsec += CNG_NSEC_PER_SEC;
        t->tv_sec--;
    }
    while (t->tv_nsec >= CNG_NSEC_PER_SEC) {
        t->tv_nsec -= CNG_NSEC_PER_SEC;
        t->tv_sec++;
    }
}

/* Read and validate the timeout, and set the deadline from it. Returns 0, or
 * the errno the kernel answers before it so much as looks the socket up:
 * -EFAULT for a timespec it cannot read, -EINVAL for one that is not a valid
 * relative time (poll_select_set_timeout -> timespec64_valid). */
static long mmsg_deadline_init(struct mmsg_deadline *d, long tp) {
    d->on = tp != 0;
    d->end.tv_sec = d->end.tv_nsec = 0;
    d->left.tv_sec = d->left.tv_nsec = 0;
    if (!d->on)
        return 0;
    struct cng_timespec ts;
    if (cng_user_copyin(&ts, (void *)tp, sizeof ts) < 0)
        return -EFAULT;
    if (ts.tv_sec < 0 || (unsigned long)ts.tv_nsec >= (unsigned long)CNG_NSEC_PER_SEC)
        return -EINVAL;
    d->left = ts;
    if (!ts.tv_sec && !ts.tv_nsec)
        return 0; /* the kernel's zero-timeout shortcut: a deadline in the past */
    struct cng_timespec now = {0, 0};
    sys_clock_gettime(CNG_CLOCK_MONOTONIC, &now);
    d->end.tv_sec = now.tv_sec + ts.tv_sec;
    d->end.tv_nsec = now.tv_nsec + ts.tv_nsec;
    if (d->end.tv_sec < now.tv_sec) /* timespec64_add_safe saturates */
        d->end.tv_sec = 0x7fffffffffffffffL;
    ts_norm(&d->end);
    return 0;
}

/* Called once per delivered datagram: 1 when the loop must stop asking for
 * another. Also refreshes what the writeback will report. */
static int mmsg_deadline_hit(struct mmsg_deadline *d) {
    if (!d->on)
        return 0;
    struct cng_timespec now = {0, 0};
    sys_clock_gettime(CNG_CLOCK_MONOTONIC, &now);
    d->left.tv_sec = d->end.tv_sec - now.tv_sec;
    d->left.tv_nsec = d->end.tv_nsec - now.tv_nsec;
    ts_norm(&d->left);
    if (d->left.tv_sec < 0) {
        d->left.tv_sec = d->left.tv_nsec = 0;
        return 1;
    }
    return !d->left.tv_sec && !d->left.tv_nsec;
}

/* The kernel writes the remaining time back only when the batch delivered
 * something, and turns a failure to write it into the call's whole answer. */
static long mmsg_deadline_report(struct mmsg_deadline *d, long tp,
                                 unsigned long got) {
    if (d->on && got && cng_user_copyout((void *)tp, &d->left, sizeof d->left) < 0)
        return -EFAULT;
    return 0;
}

/* clone, for the process-making kinds the tiers trap (a thread's clone runs
 * natively on both: the filter tests CLONE_VM/CLONE_VFORK, tramp.S does the
 * same). `ur` is the guest's register frame — the SIGSYS tier's signal context
 * or the -R trampoline's saved register file — read for the arguments and
 * written with the result, and in the child with its stack.
 *
 * A vfork-style clone (CLONE_VM|CLONE_VFORK) shares the parent's address space
 * and suspends the parent until the child execs. Our execve is emulated
 * in-process, so a shared-VM child would load the new program over the parent
 * and never issue the real execve that resumes it. Convert it to a plain COW
 * fork, with two stack adjustments:
 *  - pass child_stack=0 to the real clone so the forked child inherits (COW)
 *    the parent's current SP — which here is the *scratch stack* this runs on.
 *    The child must unwind these frames and leave through the tier's exit;
 *    giving it the caller-supplied child stack instead sets its SP into a
 *    buffer with none of them -> the return from the raw syscall restores
 *    garbage and the child dies before it can even execve. The -R tier did
 *    exactly that: glibc's vfork passes the current sp as child_stack, and
 *    every vfork/posix_spawn under -R ended in the child's SIGSEGV.
 *  - then point the frame's sp at that caller-supplied child stack for the
 *    child, so once the tier returns to the guest it resumes on the stack the
 *    guest's clone wrapper expects (musl's __clone/posix_spawn stored the child
 *    fn+arg there). child_stack==0 is a bare vfork: the child continues on the
 *    parent's stack, so the frame's sp is left alone. A bare glibc vfork hands
 *    the parent's own sp, which is the same value the frame already holds.
 * The parent then publishes the child into the PID registry, which is what
 * makes the new process visible as a guest one. The child cannot do this
 * itself: nothing guarantees it makes another traced syscall before something
 * reads its /proc entry — and a tracer attaching to it by pid needs it to be a
 * known guest process. */
void cng_clone_convert(struct cng_uregs *ur) {
    unsigned long orig_flags = (unsigned long)ur->x[0];
    unsigned long child_stack = (unsigned long)ur->x[1];
    /* Decided before the fork, from the flags the guest asked for: the
     * conversion below erases CLONE_VFORK, and a tracer following vforks must
     * still see EVENT_VFORK rather than EVENT_FORK. */
    int ev = cng_pt_clone_event(orig_flags);
    /* The guest's no_new_privs bit is per task and the child inherits the
     * forking task's, so it is sampled before the fork: in the child, gettid
     * answers a tid the table has never seen. */
    int nnp = cng_nnp_get();
    /* Same for the rseq registration the child inherits (execve.c). */
    int rseq_keep = cng_rseq_fork_prepare();
    long flags = (long)(orig_flags &
                        ~(unsigned long)(CNG_CLONE_VM | CNG_CLONE_VFORK));
    long ret = cng_syscall6(flags, 0, (long)ur->x[2], (long)ur->x[3],
                            (long)ur->x[4], (long)ur->x[5], __NR_clone);
    if (ret == 0) {
        cng_nnp_fork_child(nnp); /* one task, holding what we held */
        cng_rseq_fork_child(rseq_keep);
        cng_exec_fork_child(); /* an exec another thread had in flight is not ours */
        /* The child inherited both the mappings and the attach list, so the
         * broker must count those attaches again (shm.c). */
        cng_shm_fork_child();
        if (child_stack)
            ur->sp = child_stack;
        ur->x[0] = 0;
        cng_pt_fork_child(ur, ev);
        return;
    }
    ur->x[0] = (u64)ret;
    if (ret > 0) {
        cng_procreg_fork((int)ret);
        cng_pt_report_event(ur, ev, (u64)ret);
        /* A real vfork would have suspended us until the child exec'd or
         * exited; ours does not, so the "vfork done" event is reported as soon
         * as the child exists. */
        if (orig_flags & CNG_CLONE_VFORK)
            cng_pt_report_event(ur, CNG_PTRACE_EVENT_VFORK_DONE, (u64)ret);
    }
}

long cng_dispatch(long nr, long a0, long a1, long a2, long a3, long a4, long a5,
                  int trapped) {
    char b1[CNG_PATH_MAX], b2[CNG_PATH_MAX];

    /* The address space an emulated execve retired, given back at the first
     * syscall of the program that replaced it — which is the first moment the
     * signal frame the SIGSYS tier returned through is certainly gone. A load
     * and a branch until an exec has actually retired something. */
    cng_exec_reap();

    struct path_args pa;
    path_args_of(nr, a0, a1, a2, a3, &pa);

    /* The path itself is guest memory, and everything below reads it — the
     * empty test right here, the l2s check, the resolver's 4 KiB copy, the
     * re-issue — before the kernel has been given a chance to validate
     * anything. A pointer into nothing, or a string with no terminator before
     * the end of its mapping, is what the kernel answers -EFAULT and
     * -ENAMETOOLONG for; here it faulted inside the handler, where SIGSEGV is
     * masked and the fault is the death of the guest.
     *
     * Measuring it first was half an answer. It gave the two errnos, but it
     * left every later reader looking at the guest's own bytes, which another
     * thread of the guest is free to unmap or rewrite in between — so the walk
     * that survived the measurement could still fault, and a name that passed
     * the l2s and /proc checks need not be the name the kernel was then handed.
     * (fs/namei.c has no such gap: getname() copies the path in once, and every
     * decision after that is taken on the kernel's own copy.)
     *
     * So take the copy here, in one act, and put it back where the guest's
     * pointer was: pa.p1/p2 and the argument slot itself now name bytes only we
     * can reach, and nothing downstream needs to know. -E2BIG from the copy is
     * a path with no terminator inside PATH_MAX, which is -ENAMETOOLONG. */
    char pb1[CNG_PATH_MAX], pb2[CNG_PATH_MAX];
    if (pa.p1 || pa.p2) {
        long *arg[6] = {&a0, &a1, &a2, &a3, &a4, &a5};
        long n1 = pa.p1 ? cng_user_strcopyin(pb1, pa.p1, CNG_PATH_MAX) : 0;
        long n2 = pa.p2 ? cng_user_strcopyin(pb2, pa.p2, CNG_PATH_MAX) : 0;
        if (n1 < 0 || n2 < 0) {
            long e = n1 < 0 ? n1 : n2;
            return e == -E2BIG ? -ENAMETOOLONG : e;
        }
        if (pa.p1) {
            pa.p1 = pb1;
            *arg[pa.i1] = (long)pb1;
        }
        if (pa.p2) {
            pa.p2 = pb2;
            *arg[pa.i2] = (long)pb2;
        }
    }

    /* An empty pathname is ENOENT to the kernel — the one answer every
     * path-bearing syscall agrees on — except where AT_EMPTY_PATH (or
     * readlinkat) makes the dirfd the subject. Without this the resolver made
     * "" mean the cwd and answered for a directory the guest never named, so
     * `[ -x "" ]` came back true: that is how every dpkg maintainer script
     * generated by dh_installmenu (`[ -x "$(command -v update-menus)" ]`) went
     * on to run a program that is not installed, and exited 127. */
    if ((pa.p1 && !pa.p1[0] && !empty_path_ok(nr, a0, a2, a3, a4)) ||
        (pa.p2 && !pa.p2[0]))
        return -ENOENT;

    /* -l: paths naming the l2s machinery (backing data/marker names anywhere,
     * the "/.l2s" store dir) do not exist as far as the guest is concerned.
     * Checked on the guest's own path argument, before any resolution, so the
     * resolver's internal symlink-target expansion is unaffected. */
    if (cng_g_l2s) {
        if ((pa.p1 && cng_l2s_deny(pa.d1, pa.p1)) ||
            (pa.p2 && cng_l2s_deny(pa.d2, pa.p2))) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] l2s deny nr=%ld (%s)\n", nr,
                            pa.p1 ? pa.p1 : "");
            return -ENOENT;
        }
    }

    /* ...and every ".." in them goes through a directory that has to be one.
     * After the l2s refusal above, which has to stay absolute: a name the store
     * hides must look like nothing at all, not like something with a file in
     * front of it. */
    if (pa.p1 || pa.p2) {
        long e = pa.p1 ? cng_dotdot_verdict(pa.d1, pa.p1) : 0;
        if (!e && pa.p2)
            e = cng_dotdot_verdict(pa.d2, pa.p2);
        if (e) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] nr=%ld \"..\" through a non-directory "
                               "-> errno=%ld\n", nr, -e);
            return e;
        }
    }

    /* The designed-ENOSYS set. The filter answers these with RET_ERRNO, so a
     * seccomp-tier guest never gets here; a rewritten svc site (-R) has no
     * filter and calls straight in, so the refusal has to live here too. */
    if (cng_denied_syscall(nr)) {
        if (cng_g_debug)
            cng_dprintf(2, "[cng] nr=%ld denied (designed ENOSYS)\n", nr);
        return -ENOSYS;
    }

    switch (nr) {
    /* Simple translate + reissue: dirfd = a0, path = a1. */
    case __NR_openat:
    case __NR_openat2:
    case __NR_mkdirat:
    case __NR_mknodat:
    case __NR_name_to_handle_at: {
        /* openat2 carries its flags in the open_how it points at. */
        int is_open = (nr == __NR_openat || nr == __NR_openat2);
        long oflags = 0;
        struct cng_open_how how;
        struct cng_res_limit lim = {0}; /* every field: see the header */
        unsigned long resolve = 0;
        char sdir[CNG_PATH_MAX]; /* a scoped openat2's scope, as a guest path */
        int scoped = 0;          /* ...and whether this is one */
        if (is_open) {
            oflags = a2;
            /* openat2's flags live in the open_how it points at, so reading
             * them is a guest dereference like any other — and so is the
             * `resolve` beside them, which constrains a resolution WE are the
             * ones performing. */
            if (nr == __NR_openat2) {
                long e = read_open_how(a2, (unsigned long)a3, &how);
                if (e)
                    return e;
                oflags = (long)how.flags;
                resolve = how.resolve;
            }
        }
        /* RESOLVE_BENEATH / RESOLVE_IN_ROOT scope the whole resolution to
         * `dirfd`, which the guest can only hold because we handed it over —
         * so it already names a directory inside the view, and the kernel's
         * own scoping then contains the call at least as tightly as the rootfs
         * does. Where the guest's namespace has nothing to add under that
         * directory the call goes over untranslated and is answered exactly:
         * absolute symlinks, escaping `..`, mount crossings and all.
         *
         * Where it does have something to add — a bind mount at or below the
         * dirfd, or the /proc or /dev zone on the same branch — the kernel
         * would resolve in the HOST's view of that subtree, which is a
         * different tree: `openat2(dirfd("/"), "mnt/file", RESOLVE_IN_ROOT)`
         * found the empty mount point under the rootfs rather than what is
         * bound over it, and a scoped name in /proc missed the synthesized
         * files entirely. Those are walked here instead, with the scope
         * applied by the walk (cng_resolve_lim) and then stripped from the
         * re-issue, exactly as the other resolve bits already are. */
        if (resolve & (CNG_RESOLVE_BENEATH | CNG_RESOLVE_IN_ROOT)) {
            int walk = cng_scope_needs_walk(a0, sdir, sizeof sdir);
            if (walk < 0)
                return -EACCES; /* a directory the guest has no name for */
            if (!walk)
                return openat2_scoped(a0, a1, &how);
            /* From here we answer in place of the kernel, so the how has to be
             * judged the way it would have been: build_open_flags() runs before
             * any lookup, and BENEATH and IN_ROOT together are one of the things
             * it refuses. */
            long e = how_precheck(&how);
            if (e)
                return e;
            scoped = 1;
            lim.beneath = (resolve & CNG_RESOLVE_BENEATH) != 0;
            lim.in_root = (resolve & CNG_RESOLVE_IN_ROOT) != 0;
            lim.scope = sdir;
            lim.xdev_base = sdir; /* NO_XDEV starts where the scope does */
        }
        /* O_NOFOLLOW must reach the kernel as a symlink, or it has nothing to
         * refuse: resolving the final component here would hand over the
         * target and the open would succeed where it must ELOOP. (An l2s link
         * name is the deliberate exception, restored by the ELOOP retry below —
         * the guest believes that name IS the file.) */
        int deref = !(nr == __NR_mkdirat || nr == __NR_mknodat) &&
                    !(is_open && (oflags & CNG_O_NOFOLLOW));
        /* ...except this one, whose flag runs the other way: it does NOT follow
         * a final symlink unless AT_SYMLINK_FOLLOW is given, where every other
         * *at() call follows unless told not to. Taken as a follower, it
         * described the target instead of the link — and a dangling link, which
         * the kernel happily encodes because it never looks at the target, came
         * back ENOENT (measured both ways). */
        if (nr == __NR_name_to_handle_at)
            deref = ((int)a4 & CNG_AT_SYMLINK_FOLLOW) != 0;
        /* A read-only open of a /proc file that would describe chroot-ng
         * instead of the guest is served from an in-memory copy of the guest
         * view (see procfs.c). */
        /* The name the :ro checks below ask the l2s question about: the
         * guest's own, which for an ordinary call is the one it passed. */
        long rkd = a0;
        const char *rkp = (const char *)a1;
        /* For a scoped call it is not: the scope re-roots and clamps the name,
         * so neither that question nor the synthesized-/proc lookup below is
         * about the join of the dirfd and the name that every other call
         * makes. Spelled out once here, lexically — which is what both of
         * those already work from, the walk being the one that resolves. */
        char scanon[CNG_PATH_MAX];
        int have_scanon = 0;
        if (scoped && a1) {
            have_scanon = scope_canon(sdir, (const char *)a1, lim.beneath,
                                      scanon, sizeof scanon) == 0;
            rkd = CNG_AT_FDCWD;
            rkp = have_scanon ? scanon : 0;
        }
        if (is_open) {
            const char *gp = (const char *)a1;
            char canon[CNG_PATH_MAX];
            long pr;
            /* Absolute and cwd-relative names canonicalize without a syscall;
             * a real dirfd costs a readlink, so it is resolved only when the
             * name could be a synthesized file at all. */
            int have = 0;
            if (scoped) {
                /* Already spelled out above, and it is not the join of the
                 * dirfd and the name: where the scope refuses the name there
                 * is nothing to synthesize for, and the refusal itself is left
                 * to the walk, which resolves `..` physically as the kernel
                 * does and so is the one entitled to answer EXDEV. */
                if ((have = have_scanon))
                    cng_strlcpy(canon, scanon, sizeof canon);
            } else if (gp && (gp[0] == '/' || (int)a0 == CNG_AT_FDCWD))
                have = cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0;
            else if (gp && leaf_may_synth(gp))
                have = at_canon(a0, gp, canon, sizeof canon) == 0;
            if (have && !strncmp(canon, "/proc", 5) &&
                cng_procfs_open(canon, oflags, &pr))
                return pr;
        }
        if (resolve) {
            /* The rest constrain the walk itself, and are answered against the
             * GUEST's namespace — the one the guest described — then stripped.
             * Left in place they would be re-judged against the host path,
             * where the rootfs prefix is a symlink chain and a mount boundary
             * that the guest cannot see and did not mean. The scoped pair is
             * already settled above; its how has been prechecked there. */
            if (!scoped) {
                long e = how_precheck(&how);
                if (e)
                    return e;
            }
            lim.no_symlinks = (resolve & CNG_RESOLVE_NO_SYMLINKS) != 0;
            lim.no_magiclinks = (resolve & CNG_RESOLVE_NO_MAGICLINKS) != 0;
            lim.no_xdev = (resolve & CNG_RESOLVE_NO_XDEV) != 0;
        }
        const char *p =
            xlate_lim(a0, (const char *)a1, b1, sizeof b1, deref,
                      (resolve && nr == __NR_openat2) ? &lim : 0);
        if (lim.err)
            return lim.err;
        if (xlate_bad(p))
            return xlate_errno(p);
        /* :ro bind — mkdirat/mknodat always create; an open only offends with
         * write intent (non-RDONLY, or O_CREAT/O_TRUNC). name_to_handle_at also
         * lands here and never writes, so its a2 (a handle pointer) is never
         * read as flags. */
        if (ro_denied(p) || ro_denied_l2s(rkd, rkp)) {
            if (nr == __NR_mkdirat || nr == __NR_mknodat)
                return -EROFS;
            if (is_open && ((oflags & 3) != CNG_O_RDONLY ||
                            (oflags & (CNG_O_CREAT | CNG_O_TRUNC)))) {
                /* O_CREAT puts the open in the create family, where the kernel
                 * takes write access on the parent before it looks at the final
                 * component: a name that is not there is EROFS too. Without it
                 * the open must find an existing name first, so one that is not
                 * there is ENOENT. Both measured. */
                if (oflags & CNG_O_CREAT)
                    return -EROFS;
                long ro = ro_refusal_name(rkd, rkp, p,
                                          deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
                if (ro)
                    return ro;
            }
        }
        long ha2 = a2, ha3 = a3;
        if (nr == __NR_openat2) {
            /* Our copy, never the guest's struct: the constraints we answered
             * are cleared for the re-issue, and editing guest memory would
             * change what the caller believes it asked for. `size` becomes our
             * struct's, which is what the kernel's ABI check compares against —
             * an oversized one was already proved zero-tailed, and a zero tail
             * is exactly what makes the two forms the same call. */
            how.resolve =
                resolve & ~(unsigned long)(CNG_RESOLVE_NO_SYMLINKS |
                                           CNG_RESOLVE_NO_MAGICLINKS |
                                           CNG_RESOLVE_NO_XDEV |
                                           CNG_RESOLVE_BENEATH |
                                           CNG_RESOLVE_IN_ROOT);
            ha2 = (long)&how;
            ha3 = (long)sizeof how;
        }
        /* An l2s name asked about without following it (see l2s_nofollow_data)
         * is answered from its backing file. For a plain O_NOFOLLOW open that
         * is done after the fact, on the ELOOP the kernel draws for the link —
         * so the common case, a name that is not ours, costs no extra
         * resolution. Two calls never draw that ELOOP and have to be redirected
         * before: O_PATH|O_NOFOLLOW, which opens the symlink itself and handed
         * over an fd whose fstat said S_IFLNK (glibc's own fchmodat emulation
         * goes this way and then refuses with ENOTSUP); and name_to_handle_at
         * without AT_SYMLINK_FOLLOW, which encoded a handle to the link. The
         * backing path is absolute, so the dirfd is simply ignored. */
        char l2d[CNG_PATH_MAX];
        int l2nf = (is_open && (oflags & CNG_O_NOFOLLOW) && (oflags & CNG_O_PATH)) ||
                   (nr == __NR_name_to_handle_at && !deref);
        if (l2nf && l2s_nofollow_data(rkd, rkp, 0, 0, l2d, sizeof l2d))
            p = l2d;
        long r = reissue(a0, (long)p, ha2, ha3, a4, a5, nr);
        /* O_NOFOLLOW through a real dirfd lands on the l2s symlink and draws
         * ELOOP where a real hardlink would open. Retry on the backing file —
         * never a symlink itself, so O_NOFOLLOW stays honored for real
         * guest symlinks. openat2 carries the flag in its open_how and drew
         * the same ELOOP; the retry re-issues our copy of that struct, its
         * resolve constraints already answered and stripped. */
        if (r == -ELOOP && is_open && (oflags & CNG_O_NOFOLLOW) &&
            l2s_nofollow_data(rkd, rkp, 0, 0, l2d, sizeof l2d))
            r = reissue(CNG_AT_FDCWD, (long)l2d, ha2, ha3, a4, a5, nr);
        if ((r == -EACCES || r == -EPERM) && nr == __NR_openat)
            r = cng_fd_reopen(p, a2, a3, r);
        return r;
    }

    /* access: translate + reissue; under fake-root apply root's DAC bypass when
     * the real (unprivileged) check is denied — existence and R/W are granted,
     * X requires at least one execute bit. mode is a2 for both variants. This is
     * what "check-then-write" tools (package managers, `test -w`) rely on. */
    case __NR_faccessat:
    case __NR_faccessat2: {
        /* faccessat2 has a real flags word, so unlike its predecessor it can ask
         * about the symlink itself. Resolving the final component here would
         * hand the kernel the target and answer for the wrong file. */
        int deref = 1;
        if (nr == __NR_faccessat2 && ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW))
            deref = 0;
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        /* faccessat(2) takes three arguments and has no flags word at all —
         * only faccessat2 does. a3 is therefore whatever the guest happened to
         * leave in x3, and reading it as flags made the fake-root stat below
         * AT_SYMLINK_NOFOLLOW at random: on a symlink that answers about the
         * link (mode 0777, so X_OK is always granted) rather than the target. */
        long fl = 0;
        if (nr == __NR_faccessat2)
            fl = a3;
        long dfd = a0;
        /* faccessat2 with AT_SYMLINK_NOFOLLOW on an l2s name must report on
         * the backing file — to the guest, the name IS a regular file. */
        char fdata[CNG_PATH_MAX];
        if (nr == __NR_faccessat2 && cng_g_l2s &&
            ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, fdata, sizeof fdata, 0) == 1) {
                p = fdata;
                dfd = CNG_AT_FDCWD;
                fl = a3 & ~CNG_AT_SYMLINK_NOFOLLOW;
            }
        }
        long r = reissue(dfd, (long)p, a2, fl, a4, a5, nr);
        /* Only what root actually bypasses, which is a *permission* denial.
         * This used to fire on any negative answer at all, and the stat below
         * succeeds for most of them, so two refusals the kernel gives root as
         * readily as anyone else came back as "granted":
         *
         *  - EROFS. sb_permission() refuses MAY_WRITE on a read-only superblock
         *    before it ever reaches the DAC check — "Nobody gets write access to
         *    a read-only fs", no capability escape — so real root sees it too.
         *    ro_denied() below re-applies it, but only for our own :ro binds; a
         *    rootfs that is genuinely mounted read-only (on Android /system,
         *    /vendor, /apex, and anything on a ro mount) is invisible to it. The
         *    result was exactly what that check exists to prevent: `test -w`
         *    answers yes and the write that follows gets EROFS. Measured on a
         *    squashfs mount: access(W_OK) = -EROFS, open(O_WRONLY) = -EROFS.
         *  - EINVAL, for a mode word with bits outside R_OK|W_OK|X_OK. Not a
         *    permission question at all; measured faccessat(..., 8) = -EINVAL. */
        if ((r == -EACCES || r == -EPERM) && cng_fake_root()) {
            /* Root's DAC bypass, applied to the file the check asked about:
             * under AT_SYMLINK_NOFOLLOW that is the symlink itself, so the
             * stat has to carry the flag too or the mode it reads — and the
             * X_OK verdict drawn from it — belongs to the target instead. */
            char sb[128]; /* AArch64 struct stat is 128 bytes */
            if (reissue(dfd, (long)p, (long)sb,
                        fl & CNG_AT_SYMLINK_NOFOLLOW, 0, 0,
                        __NR_newfstatat) == 0) {
                unsigned mode = *(unsigned *)(sb + STAT_MODE_OFF);
                if (((int)a2 & CNG_X_OK) && !(mode & 0111))
                    return -EACCES;
                r = 0;
            }
        }
        /* "SuS v2 requires we report a read only fs too", as fs/open.c puts it:
         * a W_OK that the inode itself grants is still EROFS on a read-only
         * mount, and a :ro bind is one. Without it `test -w` answered yes about
         * a file whose host copy is perfectly writable, and the write that
         * followed got the EROFS the check existed to avoid. Applied after the
         * access check, where the kernel applies it. */
        if (r == 0 && ((int)a2 & CNG_W_OK) &&
            (ro_denied(p) || ro_denied_l2s(a0, (const char *)a1)))
            return -EROFS;
        return r;
    }

    /* chmod: translate + reissue; fake success under fake-root when the host
     * denies the mode change (a chmod on a file you own still applies for real). */
    case __NR_fchmodat: {
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 1);
        if (xlate_bad(p))
            return xlate_errno(p);
        long ro = ro_refusal_name(a0, (const char *)a1, p, 0);
        if (ro)
            return ro;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }

    /* fchmodat2(dirfd, path, mode, flags): same as fchmodat but with a real
     * flags word, so unlike its predecessor it can chmod a symlink itself. */
    case __NR_fchmodat2: {
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        /* An l2s name, not followed: the mode belongs to the backing file
         * (handed the link, the kernel answers EOPNOTSUPP — a symlink has no
         * mode to change). The name's own mount governs the :ro question. */
        char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
        if (!deref && l2s_nofollow_data(a0, (const char *)a1, hnf, sizeof hnf,
                                        data, sizeof data)) {
            if (l2s_ro(hnf, data))
                return -EROFS;
            return chattr_result(reissue(CNG_AT_FDCWD, (long)data, a2, a3, a4,
                                         a5, nr));
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        long ro = ro_refusal_name(a0, (const char *)a1, p,
                                  deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
        if (ro)
            return ro;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }

    /* unlinkat: on removing one of our link2symlink names, drop the group's
     * refcount (and reclaim the backing file on the last reference). */
    case __NR_unlinkat: {
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0;
        if (cng_g_l2s && !((int)a2 & CNG_AT_REMOVEDIR)) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1)
                dec = 1;
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        if (xlate_bad(p))
            return xlate_errno(p);
        if (ro_denied(p))
            return -EROFS;
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_unlinkat);
        /* A group whose data is under a :ro bind (see ro_denied_l2s) loses a
         * writable name, and keeps its count: the marker is on the :ro
         * mount, and nothing is written there. */
        if (r == 0 && dec && !cng_fs_host_ro(cng_g_fs, data))
            cng_l2s_decref(data, cnt);
        return r;
    }

    /* utimensat(dirfd, path, times, flags): if the target is one of our
     * link2symlink entries, redirect to its backing file (the guest thinks it's
     * a regular file, so a set-then-lstat-verify — as apk does to preserve mtime
     * — must land on the backing, not the link). Setting an explicit time needs
     * ownership; under fake-root fake success on EPERM. */
    case __NR_utimensat: {
        /* A NULL path names the dirfd (futimens). The flags have to be zero
         * for that, and the kernel says so before it looks at the descriptor,
         * so only a call it would perform is asked the :ro question. */
        if (!a1 && !(int)a3 && fd_ro(a0))
            return -EROFS;
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1) {
                /* The backing file is in the store, which no bind covers: the
                 * mount that governs this call is the one the NAME sits under,
                 * or the data's where that is a :ro one (see ro_denied_l2s).
                 * Asked here, before the redirect, since the check below never
                 * sees the guest's name again. */
                if (l2s_ro(hnf, data))
                    return -EROFS;
                long r = reissue(CNG_AT_FDCWD, (long)data, a2, 0, 0, 0,
                                 __NR_utimensat);
                if (cng_fake_root() && (r == -EPERM || r == -EACCES))
                    return 0;
                return r;
            }
        }
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        long ro = ro_refusal_name(a0, (const char *)a1, p,
                                  deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
        if (ro)
            return ro;
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_utimensat);
        if (cng_fake_root() && (r == -EPERM || r == -EACCES))
            return 0;
        return r;
    }

    /* stat: translate, reissue, then remap ownership under a fake id. A
     * link2symlink entry is presented as its backing file (a regular file) with
     * st_nlink = the live group count, regardless of the NOFOLLOW flag — so the
     * guest never sees the emulation as a symlink. */
    case __NR_newfstatat: {
        /* The kernel fills this buffer and then this layer edits it: an l2s
         * name's link count, a fake-id uid/gid. Editing it where it lies reads
         * the struct back out of guest memory a syscall later, and the guest
         * can have unmapped it by then — a fault in the handler rather than the
         * answer it already earned. So whenever there is an edit to make, the
         * kernel fills a struct of ours and the guest gets it in one copy;
         * where there is none, it fills the guest's directly as before. */
        /* The fstat-by-fd form, newfstatat(fd, "", AT_EMPTY_PATH): an l2s
         * backing file's link count and a synthesized /proc fd's stat are both
         * keyed on the fd, not the name. */
        int byfd = ((int)a3 & CNG_AT_EMPTY_PATH) && a1 &&
                   !((const char *)a1)[0];
        int bounce = a2 && (cng_g_l2s || cng_g_fake_id || !cng_g_no_proc);
        char sb[STAT_BUF_SIZE];
        long ob = bounce ? (long)sb : a2;
        if (cng_g_l2s && a2) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_stat(hnf, sb) == 1) {
                if (cng_g_fake_id)
                    stat_remap(sb);
                return cng_user_copyout((void *)a2, sb, sizeof sb) < 0 ? -EFAULT
                                                                       : 0;
            }
        }
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        long r = reissue(a0, (long)p, ob, a3, a4, a5, __NR_newfstatat);
        /* A synthesized /proc fd, asked about by fd or through its own fd link
         * (stat -L /proc/self/fd/N lands on the memfd the same way). */
        if (r == 0 && !cng_g_no_proc && a2) {
            if (byfd)
                cng_procfs_fix_fd((int)a0, sb);
            else if (deref)
                cng_procfs_fix_path(a0, p, sb);
        }
        if (r == 0 && byfd && a2 && cng_g_l2s)
            cng_l2s_fix_fd(a0, sb);
        if (r == 0 && cng_g_fake_id && a2)
            stat_remap(sb);
        if (r == 0 && bounce && cng_user_copyout((void *)a2, sb, sizeof sb) < 0)
            return -EFAULT;
        return r;
    }
    case __NR_statx: {
        /* Bounced on the same terms as newfstatat above. */
        int byfd = ((int)a2 & CNG_AT_EMPTY_PATH) && a1 &&
                   !((const char *)a1)[0];
        int bounce = a4 && (cng_g_l2s || cng_g_fake_id || !cng_g_no_proc);
        char sx[STATX_BUF_SIZE];
        long ob = bounce ? (long)sx : a4;
        if (cng_g_l2s && a4) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_statx(hnf, sx, (unsigned)a3, (unsigned)a2) == 1) {
                if (cng_g_fake_id)
                    statx_remap(sx);
                return cng_user_copyout((void *)a4, sx, sizeof sx) < 0 ? -EFAULT
                                                                       : 0;
            }
        }
        int deref = !((int)a2 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        long r = reissue(a0, (long)p, a2, a3, ob, a5, __NR_statx);
        if (r == 0 && !cng_g_no_proc && a4) {
            if (byfd)
                cng_procfs_fix_fd_statx((int)a0, (unsigned)a2, (unsigned)a3,
                                        sx);
            else if (deref)
                cng_procfs_fix_path_statx(a0, p, (unsigned)a2, (unsigned)a3,
                                          sx);
        }
        if (r == 0 && byfd && a4 && cng_g_l2s)
            cng_l2s_fix_fd_statx(a0, sx);
        if (r == 0 && cng_g_fake_id && a4)
            statx_remap(sx);
        if (r == 0 && bounce && cng_user_copyout((void *)a4, sx, sizeof sx) < 0)
            return -EFAULT;
        return r;
    }

    /* chown: try the real change (a chown to your own id succeeds for real),
     * then fake success under fake-root when the host denies it. An l2s name
     * redirects to its backing file even under AT_SYMLINK_NOFOLLOW — the
     * guest thinks the name IS the file, so lchown must land on the data. */
    case __NR_fchownat: {
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1) {
                if (l2s_ro(hnf, data)) /* the name's mount, not the store's */
                    return -EROFS;
                return chattr_result(reissue(CNG_AT_FDCWD, (long)data, a2, a3,
                                             0, a5, __NR_fchownat));
            }
        }
        int deref = !((int)a4 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        long ro = ro_refusal_name(a0, (const char *)a1, p,
                                  deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
        if (ro)
            return ro;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, __NR_fchownat));
    }

    /* readlinkat: /proc/self magic-link fixups, else translate + reissue. */
    case __NR_readlinkat: {
        const char *gp = (const char *)a1;
        /* bufsiz is an int, and the kernel refuses a non-positive one before it
         * looks at anything else. It has to be read at that width here rather
         * than as the raw register: the magic-link answers below are written by
         * us, not by the kernel, so a negative bufsiz became a buffer of ~2^64
         * bytes to clamp the answer against — no clamp at all. */
        int bufsiz = (int)a3;
        if (bufsiz <= 0)
            return -EINVAL;
        /* at_canon rather than cng_fs_abscanon: a name relative to a real dirfd
         * is a guest path too, and skipping it here meant `exe`, `cwd` and
         * `root` were passed to the kernel and answered with the HOST path.
         * `readlink /proc/self/exe` was right while `readlinkat(dirfd, "exe")`
         * handed back the monitor's own binary, and "cwd" handed back where the
         * rootfs lives on the device — the one thing this layer exists to keep
         * from the guest. It is not an exotic spelling either: it is what GNU
         * coreutils does for every entry of `ls -l /proc/self/`. The fd-link
         * fixup below already canonicalizes this way; only the magic-link one
         * did not. */
        if (gp) {
            char canon[CNG_PATH_MAX], val[CNG_PATH_MAX];
            if (at_canon(a0, gp, canon, sizeof canon) == 0) {
                long fx = proc_self_fixup(canon, val, sizeof val);
                if (fx >= 0) {
                    if (fx > bufsiz)
                        fx = bufsiz;
                    /* Our own copy_to_user. The kernel never sees this buffer,
                     * so a bad one has to come back -EFAULT rather than fault
                     * in the handler, where SIGSEGV is masked and fatal. */
                    if (cng_user_copyout((void *)a2, val, (unsigned long)fx) < 0)
                        return -EFAULT;
                    return fx;
                }
            }
        }
        const char *p = xlate(a0, gp, b1, sizeof b1, /*deref_final=*/0);
        if (xlate_bad(p))
            return xlate_errno(p);
        /* A link2symlink entry presents as a regular file: readlink must fail
         * with EINVAL rather than leak the backing path — including through a
         * real dirfd, which xlate passes through untranslated. */
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (cng_resolve_at(a0, gp, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return -EINVAL;
        }
        /* An fd link reports a HOST path (the kernel names the open file
         * description), and a map_files link the host path of the mapped file.
         * Map them back into the guest view so the guest never sees where its
         * rootfs really lives — `ls -l /proc/self/fd`, Alpine's /dev/fd, and
         * lsof's map_files walk all land here. Targets outside the view
         * (memfd:, pipe:[..], a host-only file) are left exactly as the kernel
         * wrote them. Decided before the call: the answer for one of these
         * has to be produced into a buffer of ours (rl_fdlink), not into the
         * guest's and corrected there. */
        if (rl_may_fdlink(a0, gp)) {
            char canon[CNG_PATH_MAX];
            if (at_canon(a0, gp, canon, sizeof canon) == 0) {
                size_t pl = proc_pid_prefix(canon, 0);
                if (pl && (!strncmp(canon + pl, "fd/", 3) ||
                           !strncmp(canon + pl, "map_files/", 10)))
                    return rl_fdlink(a0, p, a2, bufsiz);
            }
        }
        return reissue(a0, (long)p, a2, a3, a4, a5, __NR_readlinkat);
    }

    /* symlinkat(target, newdirfd, linkpath): translate only the linkpath. */
    case __NR_symlinkat: {
        /* -l: the emulation recognizes its links by their target, so a guest
         * link whose target's last component is in the ".l2s." grammar would
         * be taken for one of them (see l2s.c) — counted into a group it was
         * never counted into, and its unlink the decref that deletes the data
         * under the group's other names. Such a target names the machinery,
         * which does not exist for the guest; the link is refused as the
         * names themselves are. Judged on a copy of ours, which is what the
         * kernel is then handed: the guest's buffer could say otherwise by
         * the time the kernel read it. */
        long tgt = a0;
        if (cng_g_l2s) {
            long n = cng_user_strcopyin(b1, (const char *)a0, sizeof b1);
            if (n < 0)
                return n == -E2BIG ? -ENAMETOOLONG : n;
            const char *tb = strrchr(b1, '/');
            if (cng_l2s_hidden(tb ? tb + 1 : b1)) {
                if (cng_g_debug)
                    cng_dprintf(2, "[cng] l2s deny nr=%ld (target %s)\n", nr,
                                b1);
                return -ENOENT;
            }
            tgt = (long)b1;
        }
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2, 0);
        if (xlate_bad(lp))
            return xlate_errno(lp);
        if (ro_denied(lp))
            return -EROFS;
        return reissue(tgt, a1, (long)lp, a3, a4, a5, __NR_symlinkat);
    }

    /* fchown(fd,...): no path — try the real change, fake success under fake-root
     * (apk fchown()s each extracted file to root and a non-root app gets EPERM).
     * Routed through reissue so an Android-blocked fchown emulates ENOSYS rather
     * than trapping from the handler (fchown is in the block-list probe set). */
    /* fchmod(fd): the same fail-soft. A guest that opens a file and chmods the
     * descriptor (tar, cp -p, install) has no path for the fchmodat branch to
     * catch, so without this the fake root saw EPERM where the path form
     * succeeded. */
    case __NR_fchown:
    case __NR_fchmod:
        if (fd_ro(a0))
            return -EROFS;
        return chattr_result(reissue(a0, a1, a2, a3, a4, a5, nr));

    /* The fd forms of the xattr setters: trapped only with a :ro bind in the
     * view, for the refusal alone. */
    case __NR_fsetxattr:
    case __NR_fremovexattr:
        if (fd_ro(a0))
            return -EROFS;
        return reissue(a0, a1, a2, a3, a4, a5, nr);

    /* fstat(fd): no path, but the fd may name an l2s backing file whose
     * st_nlink must reflect the live group count (tar/rsync/ls stat open
     * fds). Trapped only under -l; the fake-id remap rides along. */
    case __NR_fstat: {
        /* Bounced whenever anything here is going to edit the answer — see
         * newfstatat above for why the guest's buffer is not the place to do
         * that. With nothing to edit, the kernel fills it directly. A
         * synthesized /proc fd answers with the real file's stat first, then
         * takes the fake-id remap stat() of its path gets. */
        int bounce = a1 && (cng_g_l2s || cng_g_fake_id || !cng_g_no_proc);
        char sb[STAT_BUF_SIZE];
        long r = reissue(a0, bounce ? (long)sb : a1, a2, a3, a4, a5,
                         __NR_fstat);
        if (r == 0 && bounce) {
            if (!cng_g_no_proc)
                cng_procfs_fix_fd((int)a0, sb);
            if (cng_g_l2s)
                cng_l2s_fix_fd(a0, sb);
            if (cng_g_fake_id)
                stat_remap(sb);
            if (cng_user_copyout((void *)a1, sb, sizeof sb) < 0)
                return -EFAULT;
        }
        return r;
    }

    /* fstatfs: a synthesized /proc fd is a memfd on the kernel's internal
     * tmpfs, and said so — TMPFS_MAGIC where statfs of the path says
     * PROC_SUPER_MAGIC. Answered with procfs's own statfs for one of ours. */
    case __NR_fstatfs: {
        if (!cng_g_no_proc && a1) {
            char fb[STATFS_BUF_SIZE];
            int k = cng_procfs_fstatfs((int)a0, fb);
            if (k < 0)
                return k;
            if (k == 1)
                return cng_user_copyout((void *)a1, fb, sizeof fb) < 0 ? -EFAULT
                                                                       : 0;
        }
        return reissue(a0, a1, a2, a3, a4, a5, __NR_fstatfs);
    }

    case __NR_getdents64:
        return do_getdents64(a0, a1, a2, a3, a4, a5);

    /* A guest's clone never arrives here: both tiers hand it to
     * cng_clone_convert with their register frame first, because the child's
     * stack is a frame edit and not a return value. This entry is for the
     * direct callers (the tests) that fork through the dispatcher to have the
     * child-side hooks run; with no frame to return through they cannot ask for
     * a child stack, and a bare fork does not. */
    case __NR_clone: {
        struct cng_uregs fr;
        memset(&fr, 0, sizeof fr);
        fr.x[0] = (u64)a0;
        fr.x[1] = (u64)a1;
        fr.x[2] = (u64)a2;
        fr.x[3] = (u64)a3;
        fr.x[4] = (u64)a4;
        fr.x[5] = (u64)a5;
        fr.x[8] = __NR_clone;
        cng_clone_convert(&fr);
        return (long)fr.x[0];
    }

    /* System V shared memory. Android's seccomp filter denies all four
     * outright, so they are served from the broker instead of the host kernel
     * — see shm.c. Trapped unconditionally (seccomp.c), so the guest gets one
     * shm namespace whatever the host's own SysV IPC would have allowed. */
    case __NR_shmget:
    case __NR_shmat:
    case __NR_shmdt:
    case __NR_shmctl: {
        long r = cng_shm_handle(nr, a0, a1, a2);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] sysv-shm nr=%ld -> %ld\n", nr, r);
        return r;
    }

    /* System V semaphores and message queues, served from the same broker
     * (sysvipc.c). Trapped unconditionally for the same reason shm is: the
     * guest gets one namespace of its own whatever the host's own IPC would
     * have allowed, and Android denies the whole family anyway. */
    case __NR_semget:
    case __NR_semop:
    case __NR_semtimedop:
    case __NR_semctl:
    case __NR_msgget:
    case __NR_msgsnd:
    case __NR_msgrcv:
    case __NR_msgctl: {
        long r = cng_sysvipc_handle(nr, a0, a1, a2, a3, a4);
        if (cng_g_debug)
            cng_dprintf(2, "[cng] sysv-ipc nr=%ld -> %ld\n", nr, r);
        return r;
    }

    /* The read family is trapped only for fds in the reserved synthesized
     * range (the seccomp filter compares fd against cng_g_synth_fd_base),
     * where a read starting at offset 0 regenerates a time-varying file —
     * procps opens /proc/loadavg once and lseek(0)+rereads it every cycle.
     * Any other fd that lands in the range just gets re-issued. The p-variants
     * carry their offset in a3 (LP64: the full offset in pos_l; -1 means the
     * current position, which pre_read resolves with an lseek). */
    case __NR_read:
    case __NR_readv:
        /* A netlink stand-in is a socketpair end, so the read itself works —
         * but a request the guest submitted with untrapped write(2) must be
         * served first or this read blocks on an empty queue (busybox ip under
         * the -R tier; the seccomp tier never traps read on ordinary fds). */
        cng_nl_poke((int)a0);
        cng_procfs_pre_read((int)a0, -1);
        return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
    case __NR_pread64:
    case __NR_preadv:
    case __NR_preadv2:
        cng_procfs_pre_read((int)a0, a3);
        return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);

    /* execve/execveat: only reached via an M8 trampoline (-R); the SIGSYS path
     * intercepts them in cng_sigsys_body (it must rewrite the signal context).
     * Emulate in-process — re-issuing the raw syscall would exec the
     * untranslated guest path on the host (ENOENT), or worse, succeed and wipe
     * the monitor. On success cng_execve_tramp enters the new program and never
     * returns; on failure return -errno like a real execve. */
    case __NR_execve:
        return cng_execve_tramp(CNG_AT_FDCWD, (const char *)a0, (char **)a1,
                                (char **)a2, 0);
    case __NR_execveat:
        return cng_execve_tramp((int)a0, (const char *)a1, (char **)a2,
                                (char **)a3, (int)a4);

    /* rename: two translated paths. If the destination is one of our
     * link2symlink names, it is replaced by the rename, so drop its group's
     * refcount (apk installs by renaming a temp file over the final name) —
     * except under RENAME_EXCHANGE, where both names live on. A legacy-format
     * source (bare-basename target) moving to another directory is repointed
     * at its (unmoved) data file afterwards. */
    case __NR_renameat:
    case __NR_renameat2: {
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        if (xlate_bad(op))
            return xlate_errno(op);
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2, 0);
        if (xlate_bad(np))
            return xlate_errno(np);
        /* A rename unlinks the old name and creates the new one, so either end
         * under a :ro bind is EROFS. */
        if (ro_denied(op) || ro_denied(np))
            return -EROFS;
        int exch = (nr == __NR_renameat2 && ((int)a4 & CNG_RENAME_EXCHANGE));
        char data[CNG_PATH_MAX], absdata[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        unsigned long cnt;
        int dec = 0, fix = 0;
        if (cng_g_l2s && !exch && strcmp(op, np) != 0 &&
            cng_resolve_at(a2, (const char *)a3, 0, dsth, sizeof dsth) == 0) {
            if (cng_l2s_resolve(dsth, data, sizeof data, &cnt) == 1)
                dec = 1;
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0)
                fix = cng_l2s_rename_prep(hnf, absdata, sizeof absdata);
        }
        long r = reissue(a0, (long)op, a2, (long)np, a4, a5, nr);
        if (r == 0 && dec && !cng_fs_host_ro(cng_g_fs, data))
            cng_l2s_decref(data, cnt); /* not on a :ro mount: see unlinkat */
        if (r == 0 && fix)
            cng_l2s_rename_fixup(dsth, absdata);
        return r;
    }

    /* linkat: hardlink; where the fs forbids hardlinks (Android/SELinux returns
     * EACCES/EXDEV, some EPERM) and -l/--link2symlink was given, fall back to the
     * link2symlink backing-file scheme (see l2s.c): the contents move to a hidden
     * ".l2s.<ino>" and every name becomes a same-directory relative symlink to
     * it, so the group presents as regular files (via the stat fixups) with a
     * shared inode. Without -l the host's refusal reaches the guest unchanged. */
    case __NR_linkat: {
        const char *sp = (const char *)a1;
        const char *dp = (const char *)a3;
        int fl = (int)a4;
        /* The flags word is judged before either name is read: a bit outside
         * the two the call knows is EINVAL ahead of a NULL name's EFAULT
         * (measured). Dropped on the way to the re-issue, as it was, such a
         * bit made a link the kernel would have refused. */
        if (fl & ~(CNG_AT_SYMLINK_FOLLOW | CNG_AT_EMPTY_PATH))
            return -EINVAL;
        int follow = (fl & CNG_AT_SYMLINK_FOLLOW) ? 1 : 0;
        int empty = (fl & CNG_AT_EMPTY_PATH) && (!sp || !sp[0]);
        /* The flag beside a name that is not empty does nothing to the
         * lookup, but the capability rule below is asked of the flag, not
         * the name: before 6.10 the call is ENOENT without the capability
         * whatever the name says. So it is kept on the re-issue — the pinned
         * directory is one we opened, so the newer rule passes it as the
         * guest's own would have — and dropped under fake root, whose
         * capability it is. */
        int flagged = (fl & CNG_AT_EMPTY_PATH) && !empty && !cng_fake_root();
        int force = cng_g_l2s && cng_g_l2s_force; /* CNG_L2S_FORCE: exercise
                                                    * the fallback directly */
        char srch[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        long r;
        /* AT_SYMLINK_FOLLOW is applied at guest level (the host must never
         * follow a guest symlink's target itself); the host call then runs
         * with no flags. Link-by-fd (AT_EMPTY_PATH, the O_TMPFILE publish
         * idiom) is spelled as the descriptor's /proc link, which the host
         * must follow: that is what the l2s fallback links from, and what
         * the fake root's retry below re-issues on. */
        if (empty) {
            /* The number has to be a descriptor before it can be spelled as
             * one. AT_FDCWD is not: the kernel resolves the empty name against
             * the working directory and answers about *that* — EEXIST if the
             * new name is taken, EPERM otherwise, a directory being unlinkable
             * — so it goes through the resolver like any other path. Without
             * this, proc_fd_path spelled AT_FDCWD as "/proc/self/fd/0" and
             * the link was made to stdin. */
            if ((int)a0 == CNG_AT_FDCWD) {
                if (cng_resolve_at(CNG_AT_FDCWD, ".", 1, srch, sizeof srch) != 0)
                    return -ENOENT;
            } else {
                proc_fd_path(a0, srch);
            }
        }
        if (empty && !force) {
            /* Whether the caller may name the source by descriptor at all is
             * the kernel's question, and the kernels in the field answer it
             * two ways. Before 6.10 the flag takes CAP_DAC_READ_SEARCH, and
             * without it the call is ENOENT ahead of everything but the
             * flags check — a NULL name, a number that is no descriptor, the
             * destination, all of it comes after. From 6.10 the descriptor's
             * open-time credentials have to be the caller's own. Made through
             * the /proc link, which every kernel follows for anyone, the call
             * answered like a root's on the older ones (measured on 6.8:
             * link_byfd=2 natively, 0 here). So it goes to the kernel as the
             * guest made it, with the destination translated and nothing
             * else. The empty name is a constant of ours: the guest's own
             * buffer could turn into a relative name between our read of it
             * and the kernel's, and resolve untranslated against the
             * descriptor. A NULL is handed over as a NULL, and a NULL
             * destination too — its EFAULT comes after the source's verdict,
             * and the kernel never looks at the dirfd beside it. */
            long ddfd = a2, dst = 0;
            if (dp) {
                if (cng_resolve_at(a2, dp, 0, dsth, sizeof dsth) != 0) {
                    if (cng_g_debug)
                        cng_dprintf(2, "[cng] linkat: dst unresolved (%s)\n", dp);
                    return -ENOENT;
                }
                if (ro_denied(dsth))
                    return -EROFS;
                ddfd = CNG_AT_FDCWD;
                dst = (long)dsth;
            }
            /* A descriptor on a file under a :ro bind (see link_src_ro): the
             * host would link it, its mount being the host's. What the kernel
             * says of the source is still the kernel's to say — the flag's
             * capability rule, EBADF — so it is asked, with "/" for the new
             * name, which filename_create answers EEXIST once the source has
             * passed (measured); nothing can be created by that. A host that
             * does not let linkat be issued at all (ENOSYS) cannot be asked,
             * and has nothing to refuse the source with either. The new
             * name's own verdict follows, then EXDEV. */
            if (dp && link_src_ro(a0, srch, (int)a0 != CNG_AT_FDCWD, 1)) {
                r = reissue(a0, sp ? (long)"" : 0, CNG_AT_FDCWD, (long)"/", fl,
                            0, __NR_linkat);
                if (r == -EEXIST || r == -ENOSYS) {
                    long e = link_dst_verdict(dsth);
                    return e ? e : -EXDEV;
                }
                if (r == -ENOENT && cng_fake_root())
                    goto by_link;
                return r;
            }
            r = reissue(a0, sp ? (long)"" : 0, ddfd, dst, fl, 0, __NR_linkat);
            /* Under fake root the capability is faked, as chroot's
             * CAP_SYS_CHROOT and the DAC bypass are. Root's AT_EMPTY_PATH
             * links the inode the descriptor holds, and so does a link made
             * through its /proc link, so an ENOENT is retried that way below
             * — where a NULL name and a number that is no descriptor come
             * out as root would have had them, EFAULT and EBADF. (A
             * destination whose parent is missing is ENOENT again.) */
            if (r == -ENOENT && cng_fake_root())
                goto by_link;
            if (cng_g_debug && r != 0)
                cng_dprintf(2, "[cng] linkat %s -> %s real=%ld\n", srch,
                            dp ? dsth : "(null)", r);
            /* An ENOENT here is the flag's refusal or the destination's, and
             * neither is a hardlink denial for the fallback to paper over —
             * the guest gets it as it would natively, and its own /proc idiom
             * then comes through the path route. */
            if (r == -ENOENT || !dp)
                return r;
            goto fallback;
        }
    by_link:
        /* The kernel copies both names in before it looks at either, so a NULL
         * one is -EFAULT: not an empty name, and not the -ENOENT the
         * unresolvable arm below would otherwise have answered for it. Every
         * other path-bearing call gets that for free by handing the NULL to
         * the kernel — xlate_lim passes one straight through, and the re-issue
         * lets the kernel say what it says, which is also how utimensat and
         * statx keep the two spellings where a NULL pathname is legitimate.
         * This route resolves both ends itself and re-issues neither. */
        if (!sp || !dp)
            return -EFAULT;
        if (empty) {
            /* Every negative but AT_FDCWD, and every number that is not open,
             * is EBADF, the same test execveat's own AT_EMPTY_PATH makes. */
            if ((int)a0 != CNG_AT_FDCWD && sys_fcntl((int)a0, CNG_F_GETFD, 0) < 0)
                return -EBADF;
        } else if (cng_resolve_at(a0, sp, follow, srch, sizeof srch) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: src unresolved (%s)\n", sp);
            return -ENOENT;
        }
        if (cng_resolve_at(a2, dp, 0, dsth, sizeof dsth) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: dst unresolved (%s)\n", dp);
            return -ENOENT;
        }
        /* The new name is created, so a destination under a :ro bind is
         * EROFS. Checked after both ends resolve so a bad source still reports
         * ENOENT. A source under one is a link across mounts (see
         * link_src_ro), EXDEV once the new name has had its verdict — never a
         * refusal for the fallback below to paper over. */
        if (ro_denied(dsth))
            return -EROFS;
        if (link_src_ro(a0, srch, empty && (int)a0 != CNG_AT_FDCWD,
                        follow || empty)) {
            long e = link_dst_verdict(dsth);
            return e ? e : -EXDEV;
        }
        if (force)
            r = -EPERM;
        else
            r = reissue(CNG_AT_FDCWD, (long)srch, CNG_AT_FDCWD, (long)dsth,
                        empty     ? CNG_AT_SYMLINK_FOLLOW
                        : flagged ? CNG_AT_EMPTY_PATH
                                  : 0,
                        0, __NR_linkat);
        if (cng_g_debug && r != 0)
            cng_dprintf(2, "[cng] linkat %s -> %s real=%ld\n", srch, dsth, r);
        /* Some Android builds deny app-data hardlinks with ENOENT rather
         * than EACCES/EPERM. ENOENT is only believable when the source is
         * really absent — if it exists, treat the refusal like any other
         * denial. (A genuinely missing dst parent still surfaces as ENOENT
         * from the fallback's own symlink step.) */
        if (cng_g_l2s && r == -ENOENT) {
            char stt[144];
            if (cng_pin_fstatat(srch, stt, CNG_AT_SYMLINK_NOFOLLOW) == 0)
                r = -EPERM;
        }
    fallback:
        if (cng_g_l2s &&
            (r == -EPERM || r == -EMLINK || r == -EXDEV || r == -ENOSYS ||
             r == -EACCES || r == -EOPNOTSUPP)) {
            if (empty) {
                /* If the fd names a live file the guest has a name for, link
                 * its real path — an fd onto a group's data file then bumps
                 * that group, and a plain file becomes one. Anonymous or
                 * deleted files keep the /proc path, and so does a file the
                 * guest has no name for (a descriptor it was handed from
                 * outside the view): the emulation would otherwise rename
                 * it into the store and leave a symlink where it was, in a
                 * directory no name of the guest's reaches. The fallback's
                 * materialize copies the contents through the descriptor. */
                char tgt[CNG_PATH_MAX], gtg[CNG_PATH_MAX], stt[144];
                long tn = cng_pin_readlink(srch, tgt, sizeof tgt - 1);
                if (tn > 0) {
                    tgt[tn] = '\0';
                    if (tgt[0] == '/' &&
                        host_dir_guest(tgt, gtg, sizeof gtg) == 0 &&
                        cng_pin_fstatat(tgt, stt, CNG_AT_SYMLINK_NOFOLLOW) == 0)
                        cng_strlcpy(srch, tgt, sizeof srch);
                }
            }
            int s = cng_l2s_link(srch, dsth);
            if (cng_g_debug)
                cng_dprintf(2, "[cng] l2s %s -> %s rc=%d\n", srch, dsth, s);
            return s;
        }
        return r;
    }

    /* path = a0 */
    /* socket(): where the host denies app domains rtnetlink — Android does —
     * hand back an emulated NETLINK_ROUTE socket instead of the kernel's
     * refusal, so getifaddrs/iproute2/bubblewrap keep working. Every other
     * socket runs native. */
    case __NR_socket: {
        /* Not `>= 0`: the hook also answers the refusals the emulated interface
         * owes a request no kernel would grant, and those are its answers to
         * give — the real syscall below would refuse the same call for the
         * policy reason this whole file exists to paper over. -1 alone means
         * "not ours". */
        long fd = cng_nl_socket(a0, a1, a2);
        if (fd != -1)
            return fd;
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        /* The same policy denies NETLINK_AUDIT, which is not emulated but does
         * need the refusal libaudit's callers survive: a permission error there
         * aborts every shadow-utils tool (`useradd`, `su`), while "no audit in
         * this kernel" is a case they all handle. */
        return cng_nl_audit_refusal(a0, a2, r);
    }

    /* AF_UNIX addresses. A pathname socket's sun_path is a filesystem path and
     * gets the same containment as any other: translated on the way out, mapped
     * back to guest spelling on the way in. bind() keeps the final component
     * literal (it is the name being created); connect/sendto follow it. The
     * translated address lives in our own buffer, so the guest's is untouched. */
    case __NR_bind:
    case __NR_connect:
    case __NR_sendto: {
        /* An emulated netlink socket: bind is a silent success (the guest is
         * binding a netlink address we do not really have), and a send is the
         * request whose reply the matching recv will drain. */
        if (cng_nl_is_fake((int)a0)) {
            if (nr == __NR_bind || nr == __NR_connect)
                return 0;
            long out = 0;
            if (cng_nl_send((int)a0, (const void *)a1, a2, &out))
                return out;
            return 0;
        }
        int is_send = (nr == __NR_sendto);
        long aa = is_send ? a4 : a1;   /* sockaddr */
        long al = is_send ? a5 : a2;   /* addrlen */
        struct cng_sun_xlate x;
        long r;
        int sx = cng_sun_in(&x, nr == __NR_bind ? (int)a0 : -1,
                            (const void *)aa, al, nr != __NR_bind);
        if (sx > 0) {
            if (is_send)
                r = reissue(a0, a1, a2, a3, (long)x.buf, x.len, nr);
            else
                r = reissue(a0, (long)x.buf, x.len, a3, a4, a5, nr);
        } else if (sx < 0) {
            r = sx; /* a name we could not contain is refused, not passed on */
        } else {
            r = reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        cng_sun_done(&x, r); /* after the syscall: the kernel walked the dirfd */
        return r;
    }

    /* sendmsg: the address hangs off msg_name in the msghdr, so the header is
     * copied to swap that pointer — the guest's own struct is never written. */
    case __NR_sendmsg: {
        /* The msghdr is read here, ahead of any kernel call that would have
         * validated it, so a bad one must answer -EFAULT rather than fault —
         * and it is taken as a copy, once, so every field below names what was
         * validated rather than whatever the guest has put there since. */
        struct cng_msghdr mh;
        if (a1 && cng_user_copyin(&mh, (void *)a1, sizeof mh) < 0)
            return -EFAULT;
        if (cng_nl_is_fake((int)a0)) {
            /* The payload is the first iovec; netlink requests are single-iov
             * in every library that builds them. */
            long out = 0;
            if (a1 && mh.iov && mh.iovlen > 0) {
                struct cng_iovec io0;
                if (cng_user_copyin(&io0, mh.iov, sizeof io0) < 0)
                    return -EFAULT;
                cng_nl_send((int)a0, io0.base, (long)io0.len, &out);
            }
            return out;
        }
        struct cng_sun_xlate x;
        long r;
        x.dirfd = -1; /* a NULL msghdr never reaches cng_sun_in, and cng_sun_done
                       * must not then close whatever the stack held */
        x.bind_fd = -1;
        int sx = a1 ? cng_sun_in(&x, -1, mh.name, (long)mh.namelen, 1) : 0;
        if (sx > 0) {
            mh.name = x.buf;
            mh.namelen = (unsigned)x.len;
            r = reissue(a0, (long)&mh, a2, a3, a4, a5, nr);
        } else if (sx < 0) {
            r = sx;
        } else {
            r = reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        cng_sun_done(&x, r);
        return r;
    }

    /* sendmmsg: sendmsg's array form, and one msg_name per message is the whole
     * of what it adds. The call exists to spend one syscall on a batch — UDP is
     * what it is for — so a batch carrying no AF_UNIX address is re-issued
     * whole and costs a scan. Only when a message really does carry one is the
     * array taken apart into per-message sendmsg calls, which is what the
     * kernel's own loop does anyway: send until one fails, write each msg_len
     * back as it goes, report the count if any went out and the error only if
     * none did. The guest's array is never rewritten — each translated header is
     * a copy, exactly as in sendmsg above.
     *
     * (An emulated netlink socket needs nothing here: a native sendmmsg puts the
     * request datagrams into the stand-in socketpair, which is the same route an
     * untrapped write(2) takes, and the matching receive serves them.) */
    case __NR_sendmmsg: {
        struct cng_mmsghdr *v = (struct cng_mmsghdr *)a1;
        unsigned long vlen = (unsigned)a2;
        if (vlen > CNG_UIO_MAXIOV) /* as the kernel clamps it */
            vlen = CNG_UIO_MAXIOV;
        if (!v || !vlen)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        /* A socket that is not AF_UNIX cannot carry a sun_path at all, and a UDP
         * batch is what this call exists for — so ask the socket once instead of
         * reading up to 1024 addresses out of guest memory to find that out.
         * (Each of those reads has to be probed first, since a fault in the
         * handler is unblockable, and a probe is itself a syscall: the whole
         * point of sendmmsg is not to spend one per message.) */
        int dom = 0;
        unsigned dlen = sizeof dom;
        if (CNG_SYS(__NR_getsockopt, a0, CNG_SOL_SOCKET, CNG_SO_DOMAIN, &dom,
                    &dlen, 0) == 0 &&
            dom != CNG_AF_UNIX)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        /* A window of the array at a time (mmsg_take), so the scan costs a
         * syscall per MMSG_WIN messages rather than one per message — and every
         * header below is our copy, never the guest's live struct. */
        struct cng_mmsghdr win[MMSG_WIN];
        int any = 0;
        for (unsigned long i = 0; i < vlen && !any;) {
            unsigned long k = vlen - i < MMSG_WIN ? vlen - i : MMSG_WIN;
            unsigned long got = mmsg_take(win, v + i, k);
            for (unsigned long j = 0; j < got; j++)
                if (cng_sun_needed(win[j].hdr.name, (long)win[j].hdr.namelen)) {
                    any = 1;
                    break;
                }
            if (got < k)
                break; /* the kernel never gets past here either */
            i += k;
        }
        if (!any)
            return reissue(a0, a1, a2, a3, a4, a5, nr);

        unsigned long sent = 0;
        long r = 0;
        for (unsigned long i = 0; i < vlen;) {
            unsigned long k = vlen - i < MMSG_WIN ? vlen - i : MMSG_WIN;
            unsigned long got = mmsg_take(win, v + i, k);
            unsigned long j = 0;
            for (; j < got; j++) {
                struct cng_msghdr mh = win[j].hdr;
                struct cng_sun_xlate x;
                int sx = cng_sun_in(&x, -1, mh.name, (long)mh.namelen, 1);
                if (sx > 0) {
                    mh.name = x.buf;
                    mh.namelen = (unsigned)x.len;
                }
                if (sx < 0)
                    r = sx;
                else
                    r = reissue(a0, (long)&mh, a3, 0, 0, 0, __NR_sendmsg);
                cng_sun_done(&x, r);
                if (r < 0)
                    break;
                /* The kernel does not count a message whose length writeback
                 * faults, even though it has already gone out. Neither do we. */
                unsigned wlen = (unsigned)r;
                if (cng_user_copyout(&v[i + j].len, &wlen, sizeof wlen) < 0) {
                    r = -EFAULT;
                    break;
                }
                sent++;
            }
            if (r < 0)
                break;
            if (got < k) {
                r = -EFAULT;
                break;
            }
            i += k;
        }
        return sent ? (long)sent : r;
    }

    /* The readback side. The kernel writes a HOST sun_path here; handing that to
     * the guest leaks where the rootfs lives and breaks any program comparing it
     * against what it bound. The address is fetched into a buffer of ours and
     * delivered by addr_out, which reproduces the kernel's own truncation rule
     * over the *translated* address — see the note there for why the guest's own
     * buffer cannot be translated in place. */
    case __NR_getsockname:
    case __NR_getpeername:
    case __NR_accept:
    case __NR_accept4:
    case __NR_recvfrom: {
        int is_recv = (nr == __NR_recvfrom);
        long aa = is_recv ? a4 : a1;
        long alp = is_recv ? a5 : a2;
        if (cng_nl_is_fake((int)a0)) {
            if (is_recv) {
                long out = 0;
                cng_nl_recv((int)a0, (void *)a1, a2, a3, &out);
                long e = cng_nl_srcaddr((int)a0, (void *)aa, (unsigned *)alp);
                return e ? e : out;
            }
            /* accept(2) does not apply to a datagram socket, and netlink is
             * one. The stand-in is a socketpair end, so the kernel would have
             * refused it for us — but it never sees the call, and answering
             * with a sockaddr_nl and success would hand back fd 0 as if it were
             * a connection. EOPNOTSUPP is what the family answers. */
            if (nr == __NR_accept || nr == __NR_accept4)
                return -EOPNOTSUPP;
            /* getsockname/getpeername must report a sockaddr_nl: the real
             * AF_UNIX answer is 2 bytes and iproute2 refuses it. */
            return cng_nl_getname((int)a0, (void *)aa, (unsigned *)alp);
        }
        if (!aa || !alp) /* no address wanted: nothing to translate */
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        char ab[CNG_SOCKADDR_MAX];
        unsigned al = sizeof ab;
        long r = is_recv ? reissue(a0, a1, a2, a3, (long)ab, (long)&al, nr)
                         : reissue(a0, (long)ab, (long)&al, a3, a4, a5, nr);
        if (r < 0)
            return r;
        /* getsockname is the one call whose answer is the socket's OWN
         * address; every other one names some other socket's. */
        long e = sun_deliver(nr == __NR_getsockname ? (int)a0 : -1, ab, al, aa,
                             alp);
        if (e) {
            /* accept has already created the descriptor. The kernel drops it
             * when the address writeback fails rather than returning an fd the
             * caller never learned the peer of, so this must too. */
            if (nr == __NR_accept || nr == __NR_accept4)
                sys_close((int)r);
            return e;
        }
        return r;
    }

    case __NR_recvmsg: {
        if (cng_nl_is_fake((int)a0)) {
            long out = 0;
            struct cng_msghdr *m = (struct cng_msghdr *)a1;
            if (m) {
                struct cng_msghdr h;
                if (cng_user_copyin(&h, m, sizeof h) < 0)
                    return -EFAULT;
                if (h.iov && h.iovlen > 0) {
                    struct cng_iovec io0;
                    if (cng_user_copyin(&io0, h.iov, sizeof io0) < 0)
                        return -EFAULT;
                    cng_nl_recv((int)a0, io0.base, (long)io0.len, a2, &out);
                }
                long e = cng_nl_srcaddr((int)a0, h.name, &m->namelen);
                if (e)
                    return e;
            }
            return out;
        }
        /* msg_name is an output buffer of the guest's, so it gets the same
         * bounce the single-address calls get, and the control data one of
         * its own where descriptors could arrive in it (recvmsg_bounced). A
         * header asking for neither is the kernel's to fill as it stands. */
        struct cng_msghdr *g = (struct cng_msghdr *)a1;
        struct cng_msghdr snap; /* our copy of the guest's header, taken once */
        if (!a1 || cng_user_copyin(&snap, g, sizeof snap) < 0)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        int bname = snap.name && snap.namelen;
        int bctl = ctl_may_carry_fds(&snap);
        if (!bname && !bctl)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        return recvmsg_bounced(a0, g, &snap, a2, bname, bctl, 0);
    }

    /* recvmmsg: the readback side of the array forms. A source address cannot be
     * mapped back in the guest's own buffer (see addr_out), so an AF_UNIX batch
     * is taken apart into per-message recvmsg calls, each with the bounce the
     * single form uses — which is what the kernel's own loop does anyway. Only
     * AF_UNIX pays for that: no other family can carry a sun_path, so the socket
     * is asked once and everything else is re-issued whole and left untouched. */
    case __NR_recvmmsg: {
        struct cng_mmsghdr *v = (struct cng_mmsghdr *)a1;
        unsigned long vlen = (unsigned)a2;
        if (vlen > CNG_UIO_MAXIOV)
            vlen = CNG_UIO_MAXIOV;

        /* An emulated netlink socket has to be taken apart per message instead:
         * its replies are built on demand, and a client discards any whose
         * source address is not the kernel's — which means msg_name must be
         * filled by cng_nl_srcaddr from the guest's own buffer length, not
         * overwritten by the socketpair's AF_UNIX answer first. The
         * MSG_WAITFORONE rule applies, since without it a batch larger than the
         * pending replies would block on a socket nothing else will feed, and
         * so does the timeout — a deadline consulted between messages, with the
         * remainder written back, exactly as the kernel applies it (see
         * struct mmsg_deadline). */
        if (cng_nl_is_fake((int)a0) && v && vlen) {
            struct mmsg_deadline dl;
            long te = mmsg_deadline_init(&dl, a4);
            if (te)
                return te;
            unsigned long got = 0;
            long r = 0;
            while (got < vlen) {
                struct cng_mmsghdr *m = &v[got];
                struct cng_mmsghdr h;
                if (cng_user_copyin(&h, m, sizeof h) < 0) {
                    r = -EFAULT;
                    break;
                }
                struct cng_iovec io0;
                if (!h.hdr.iov || !h.hdr.iovlen ||
                    cng_user_copyin(&io0, h.hdr.iov, sizeof io0) < 0) {
                    r = -EFAULT;
                    break;
                }
                long fl = a3 & ~(long)CNG_MSG_WAITFORONE;
                if (got && (a3 & CNG_MSG_WAITFORONE))
                    fl |= CNG_MSG_DONTWAIT;
                long out = 0;
                cng_nl_recv((int)a0, io0.base, (long)io0.len, fl, &out);
                if (out < 0) {
                    r = out;
                    break;
                }
                unsigned wlen = (unsigned)out;
                if (cng_user_copyout(&m->len, &wlen, sizeof wlen) < 0) {
                    r = -EFAULT;
                    break;
                }
                long e = cng_nl_srcaddr((int)a0, h.hdr.name, &m->hdr.namelen);
                if (e) {
                    r = e;
                    break;
                }
                got++;
                if (mmsg_deadline_hit(&dl))
                    break;
            }
            long te2 = mmsg_deadline_report(&dl, a4, got);
            if (te2)
                return te2;
            return got ? (long)got : r;
        }

        /* One question to the socket instead of a scan of the array: a family
         * other than AF_UNIX has no sun_path to map back, and a UDP batch is
         * what this call exists for. (The same shortcut sendmmsg takes.) */
        int dom = 0;
        unsigned dlen = sizeof dom;
        if (!v || !vlen ||
            (CNG_SYS(__NR_getsockopt, a0, CNG_SOL_SOCKET, CNG_SO_DOMAIN, &dom,
                     &dlen, 0) == 0 &&
             dom != CNG_AF_UNIX))
            return reissue(a0, a1, a2, a3, a4, a5, nr);

        /* Per message from here. A loop of recvmsg calls has no timeout to give,
         * but it does not need one: the kernel's timeout is a deadline it looks
         * at between messages and nothing more (see struct mmsg_deadline), so
         * this loop applies it in exactly the same place. MSG_WAITFORONE is the
         * flag that really does bound the wait, and it is passed on. */
        struct mmsg_deadline dl;
        long te = mmsg_deadline_init(&dl, a4);
        if (te)
            return te;
        int first_only = (a3 & CNG_MSG_WAITFORONE) != 0;
        unsigned long got = 0;
        long r = 0;
        while (got < vlen) {
            struct cng_mmsghdr *m = &v[got];
            struct cng_msghdr snap;
            if (cng_user_copyin(&snap, &m->hdr, sizeof snap) < 0) {
                r = -EFAULT;
                break;
            }
            long fl = a3 & ~(long)CNG_MSG_WAITFORONE;
            if (got && first_only)
                fl |= CNG_MSG_DONTWAIT;
            unsigned mflags = 0;
            long n = recvmsg_bounced(a0, &m->hdr, &snap, fl,
                                     snap.name && snap.namelen,
                                     ctl_may_carry_fds(&snap), &mflags);
            if (n < 0) {
                r = n; /* the message is consumed either way, as it is for
                        * the single form */
                break;
            }
            unsigned len = (unsigned)n;
            if (cng_user_copyout(&m->len, &len, sizeof len) < 0) {
                r = -EFAULT;
                break;
            }
            got++;
            if (mmsg_deadline_hit(&dl))
                break;
            /* Out-of-band data ends the batch where the kernel ends it. */
            if (mflags & CNG_MSG_OOB)
                break;
        }
        long te2 = mmsg_deadline_report(&dl, a4, got);
        if (te2)
            return te2;
        /* Whatever arrived is reported; the error only if nothing did. */
        return got ? (long)got : r;
    }

    /* getsockopt(SOL_SOCKET, SO_PEERCRED): the kernel reports the real invoking
     * uid/gid for the peer, but a guest daemon compares it against its own
     * getuid(), which under --fake-id is the fake identity. Remap the pair
     * through the same rule stat uses. The pid is deliberately left alone: guest
     * pid == host pid here, so it is already correct. Trapped only under
     * --fake-id.
     *
     * The kernel fills a ucred of ours and the guest gets the remapped one in
     * one copy. It used to fill the guest's own buffer and be corrected there
     * a syscall later — which put the real uid in the guest's memory for the
     * interval, where any other thread of the guest could read it — and the
     * correction read the buffer back, so a thread that had rewritten it in
     * the meantime chose what was remapped. The length word is ours as well,
     * taken from the guest before the call as sock_getsockopt takes it: a
     * negative one is its EINVAL, a short one gets that many bytes of the
     * struct, and what was written is reported back, in that order. */
    case __NR_getsockopt: {
        if (!(cng_g_fake_id && a1 == CNG_SOL_SOCKET && a2 == CNG_SO_PEERCRED &&
              a3 && a4))
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        int len;
        if (cng_user_copyin(&len, (void *)a4, sizeof len) < 0)
            return -EFAULT;
        unsigned uc[3] = {0, 0, 0}; /* struct ucred: pid,uid,gid */
        int got = len;
        long r = reissue(a0, a1, a2, (long)uc, (long)&got, a5, nr);
        if (r != 0)
            return r;
        if (got < 0 || (unsigned)got > sizeof uc)
            got = sizeof uc; /* not a length the kernel reports; bounded anyway */
        uc[1] = cng_remap_uid(uc[1]);
        uc[2] = cng_remap_gid(uc[2]);
        if ((got && cng_user_copyout((void *)a3, uc, (unsigned long)got) < 0) ||
            cng_user_copyout((void *)a4, &got, sizeof got) < 0)
            return -EFAULT;
        return 0;
    }

    /* Extended attributes: the path is a0 and there is no dirfd, so this is a
     * plain translate + reissue. The "l" forms do not follow a final symlink
     * — except the l2s emulation's own, whose attributes are the backing
     * file's (on the link itself the kernel keeps user.* attributes off
     * symlinks entirely: EPERM to set, ENODATA to get); the setters and
     * removers mutate, so a :ro bind refuses them. */
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr: {
        int deref = !(nr == __NR_lsetxattr || nr == __NR_lgetxattr ||
                      nr == __NR_llistxattr || nr == __NR_lremovexattr);
        int writes = (nr == __NR_setxattr || nr == __NR_lsetxattr ||
                      nr == __NR_removexattr || nr == __NR_lremovexattr);
        char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
        if (!deref && l2s_nofollow_data(CNG_AT_FDCWD, (const char *)a0, hnf,
                                        sizeof hnf, data, sizeof data)) {
            if (writes && ro_denied(hnf))
                return -EROFS;
            return reissue((long)data, a1, a2, a3, a4, a5, nr);
        }
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        if (writes) {
            long ro = ro_refusal_name(CNG_AT_FDCWD, (const char *)a0, p,
                                      deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
            if (ro)
                return ro;
        }
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    /* The dirfd-relative forms of the same (6.13): setxattrat, getxattrat,
     * listxattrat and removexattrat take (dirfd, path, at_flags, ...), where
     * AT_SYMLINK_NOFOLLOW is the l-prefix and AT_EMPTY_PATH the f-prefix. And
     * file_getattr/file_setattr (6.17), the FS_IOC_FS[GS]ETXATTR ioctl pair
     * asked by path — (dirfd, path, attr, size, at_flags), the same two flags
     * with the word at the end. Handled as the eight above are, with the flag
     * read from where each keeps it: an l2s name asked about without following
     * lands on the backing file, a setter or remover answers EROFS under a :ro
     * bind, and everything else is translate + reissue. */
    case __NR_setxattrat:
    case __NR_getxattrat:
    case __NR_listxattrat:
    case __NR_removexattrat:
    case __NR_file_getattr:
    case __NR_file_setattr: {
        int fattr = (nr == __NR_file_getattr || nr == __NR_file_setattr);
        unsigned at = (unsigned)(fattr ? a4 : a2);
        int deref = !(at & CNG_AT_SYMLINK_NOFOLLOW);
        int writes = (nr == __NR_setxattrat || nr == __NR_removexattrat ||
                      nr == __NR_file_setattr);
        char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
        if (!deref && l2s_nofollow_data(a0, (const char *)a1, hnf, sizeof hnf,
                                        data, sizeof data)) {
            if (writes && ro_denied(hnf))
                return -EROFS;
            return reissue(CNG_AT_FDCWD, (long)data, a2, a3, a4, a5, nr);
        }
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        if (writes) {
            long ro = ro_refusal_name(a0, (const char *)a1, p,
                                      deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
            if (ro)
                return ro;
        }
        return reissue(a0, (long)p, a2, a3, a4, a5, nr);
    }

    /* inotify_add_watch(fd, path, mask): a path-bearing syscall whose a0 is the
     * inotify instance rather than a dirfd, so the name is always absolute or
     * cwd-relative. Untranslated it was exactly inverted — a watch on
     * "/etc/passwd" armed on the HOST's file while the rootfs's own answered
     * ENOENT — which is what every file-watching runtime asks for
     * (inotifywait, glib's GFileMonitor, systemd's path units, bundlers). The
     * mask's IN_DONT_FOLLOW is this call's spelling of AT_SYMLINK_NOFOLLOW. */
    case __NR_inotify_add_watch: {
        int deref = !((unsigned)a2 & CNG_IN_DONT_FOLLOW);
        /* An l2s name, not followed: the watch belongs on the backing file,
         * where the events are. Armed on the link it never fired for a write
         * through any name of the group. */
        char data[CNG_PATH_MAX];
        if (!deref && l2s_nofollow_data(CNG_AT_FDCWD, (const char *)a1, 0, 0,
                                        data, sizeof data))
            return reissue(a0, (long)data, a2, a3, a4, a5, nr);
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a1, b1, sizeof b1, deref);
        if (xlate_bad(p))
            return xlate_errno(p);
        return reissue(a0, (long)p, a2, a3, a4, a5, nr);
    }

    case __NR_truncate:
    case __NR_statfs: {
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, 1);
        if (xlate_bad(p))
            return xlate_errno(p);
        if (nr == __NR_truncate) { /* statfs only reads */
            long ro = ro_refusal_name(CNG_AT_FDCWD, (const char *)a0, p, 0);
            if (ro)
                return ro;
        }
        if (nr == __NR_statfs && !cng_g_no_proc && a1) {
            /* A statfs through a synthesized fd's own link (stat -f -L
             * /dev/stdin) lands on the memfd's tmpfs; the file is on procfs. */
            char fb[STATFS_BUF_SIZE];
            long r = reissue((long)p, (long)fb, a2, a3, a4, a5, nr);
            if (r == 0) {
                int k = cng_procfs_fix_path_statfs(CNG_AT_FDCWD, p, fb);
                if (k < 0)
                    return k;
                if (cng_user_copyout((void *)a1, fb, sizeof fb) < 0)
                    return -EFAULT;
            }
            return r;
        }
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_chdir: {
        const char *gp = (const char *)a0;
        const char *hp = xlate(CNG_AT_FDCWD, gp, b1, sizeof b1, 1);
        if (xlate_bad(hp))
            return xlate_errno(hp);
        long r = reissue((long)hp, 0, 0, 0, 0, 0, __NR_chdir);
        if (r == 0) {
            char gc[CNG_PATH_MAX];
            /* Record where the chdir LANDED, not what was typed: the kernel's
             * cwd is the directory itself, so getcwd reports the symlink-free
             * name and a later ".." backs out of the real parent. Falls back to
             * the lexical form only for a directory outside the guest view. */
            if (cng_fs_untranslate(cng_g_fs, hp, gc, sizeof gc) == 0 ||
                cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) == 0) {
                cng_fs_set_cwd(cng_g_fs, gc);
                cng_fs_cwd(gc, sizeof gc);
                cng_procreg_set_cwd(gc); /* /proc/<pid>/cwd */
            }
        }
        return r;
    }

    /* fchdir: the fd already refers to a translated host dir, so perform it,
     * then resync the virtual cwd from the real cwd (reverse-translated). This
     * is what apk relies on when running package scripts.
     *
     * "Already refers to" is asked first rather than assumed: a descriptor on
     * a directory the guest has no name for (host_dir_guest) is not a place
     * it can stand — the real cwd would leave the view while the virtual one
     * stayed put, and getcwd would go on answering for a directory the process
     * is no longer in. EACCES, as for a directory it may not search. The zones
     * are named on the way back too: fchdir(open("/proc")) used to leave the
     * virtual cwd where it was, so "self/status" then resolved under it. */
    case __NR_fchdir: {
        char hc[CNG_PATH_MAX], gc[CNG_PATH_MAX];
        if (dirfd_host((int)a0, hc, sizeof hc) == 0 &&
            host_dir_guest(hc, gc, sizeof gc) != 0 && fd_is_dir(a0))
            return -EACCES;
        long r = cng_syscall6(a0, 0, 0, 0, 0, 0, __NR_fchdir);
        if (r == 0) {
            if (sys_getcwd(hc, sizeof hc) > 0 &&
                host_dir_guest(hc, gc, sizeof gc) == 0) {
                cng_fs_set_cwd(cng_g_fs, gc);
                cng_fs_cwd(gc, sizeof gc);
                cng_procreg_set_cwd(gc);
            }
        }
        return r;
    }

    case __NR_getcwd: {
        char *buf = (char *)a0;
        unsigned long size = (unsigned long)a1;
        char cwd[CNG_PATH_MAX];
        size_t len = cng_fs_cwd(cwd, sizeof cwd) + 1;
        /* ERANGE is decided before the buffer is touched, as the kernel does —
         * which also keeps the write probe's zeroing invisible: it only ever
         * runs immediately before the copy that overwrites it. */
        if (len > size)
            return -ERANGE;
        if (cng_user_copyout(buf, cwd, len) < 0)
            return -EFAULT;
        return (long)len;
    }

    /* chroot: move the guest root, keeping the rest of the view. The binds and
     * the cwd are rebased onto the new root (cng_fs_chroot), not discarded — a
     * real chroot unmounts nothing, and apk runs every package script under
     * chroot("."), which would otherwise strip that child of /proc, /dev and
     * every other bind. */
    case __NR_chroot: {
        const char *gp = (const char *)a0;
        if (!gp)
            return -EFAULT;
        /* chroot(2) needs CAP_SYS_CHROOT, which for us means the guest's
         * effective uid is 0 under --fake-id. Ungated, an unprivileged guest
         * could move its own root where a real kernel would have refused —
         * a privilege check the guest's own code may be relying on (a daemon
         * that drops privileges and then expects chroot to fail). The /proc
         * passthrough surviving into the new root is a deliberate divergence:
         * a real chroot leaves /proc unmounted, but a guest that cannot see
         * /proc cannot run apk's package scripts, which chroot(".") first. */
        if (!cng_fake_root())
            return -EPERM;
        char gc[CNG_PATH_MAX], hp[CNG_PATH_MAX];
        if (cng_fs_abscanon(cng_g_fs, gp, gc, sizeof gc) != 0)
            return -ENAMETOOLONG;
        if (cng_resolve(gc, 1, hp, sizeof hp) != 0 &&
            cng_fs_translate(cng_g_fs, gc, hp, sizeof hp) != 0)
            return -ENAMETOOLONG;
        /* Name the new root by where the symlinks led, so the guest and host
         * sides of the new view describe the same directory. */
        char resolved[CNG_PATH_MAX];
        if (cng_fs_untranslate(cng_g_fs, hp, resolved, sizeof resolved) == 0)
            cng_strlcpy(gc, resolved, sizeof gc);
        char sb[128]; /* AArch64 struct stat is 128 bytes */
        long r = cng_pin_fstatat(hp, sb, 0);
        if (r < 0)
            return r;
        if ((*(unsigned *)(sb + STAT_MODE_OFF) & 0170000) != 0040000)
            return -ENOTDIR;
        cng_fs_chroot(cng_g_fs, gc, hp);
        return 0;
    }

    /* Protect our SIGSYS handler: the guest's disposition for SIGSYS lives in
     * ptsig.c's mirror and never reaches the kernel (it is answered and
     * delivered from there, with the kernel's own argument checks), and SIGSYS
     * is stripped from every other handler's sa_mask so it can't be masked
     * while a guest handler runs. Kernel struct sigaction:
     * handler,flags,restorer,mask (mask at offset 24). */
    case __NR_rt_sigaction: {
        /* The kernel refuses a sigsetsize that is not its own before it looks
         * at anything else, pointers included, and that verdict is the same
         * for every signal — so a call with the wrong size goes straight to
         * it, untouched: the copy-in below would have answered EFAULT for a
         * bad act pointer where the kernel answers EINVAL (measured). */
        if ((unsigned long)a3 != sizeof(cng_sigset_t))
            return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigaction);
        /* While the task is traced, ptsig.c owns the real disposition of every
         * signal (a tracee must stop before its own handler runs), and it owns
         * SIGSYS's and the kick signal's slot always. It answers from its
         * mirror of what the guest asked for; otherwise it just records and
         * lets this through. */
        long ptr;
        if (cng_pt_sigaction((int)a0, (u64)a1, (u64)a2, (u64)a3, &ptr))
            return ptr;
        if (a1) {
            unsigned char act[32];
            if (cng_user_copyin(act, (void *)a1, sizeof act) < 0)
                return -EFAULT;
            *(unsigned long *)(act + 24) &= ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)act, a2, a3, a4, a5,
                                __NR_rt_sigaction);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigaction);
    }

    /* ---- ptrace(2) and the syscalls its emulation has to account for ----
     *
     * ptrace is trapped for every guest (it is the only way to see a
     * PTRACE_TRACEME, and no ordinary program calls it); the rest are trapped
     * only on tasks that have entered a ptrace role, by the filter stacked in
     * cng_pt_arm_tracer/tracee. See src/monitor/ptrace.c. */
    case __NR_ptrace:
        return cng_pt_syscall(a0, a1, (u64)a2, (u64)a3);

    case __NR_wait4:
        return cng_pt_wait4(a0, (u64)a1, a2, (u64)a3, cng_pt_cur_uc());

    case __NR_waitid:
        return cng_pt_waitid(a0, a1, (u64)a2, a3, (u64)a4, cng_pt_cur_uc());

    /* A stop signal aimed at a tracee becomes a cooperative group-stop: a real
     * SIGSTOP would freeze it inside its ptrace service loop, and every later
     * tracer request would deadlock (strace sends exactly that on ^C). SIGCONT
     * ends a PTRACE_LISTEN group-stop the same way. Everything else, and every
     * target that is not a tracee, is sent for real. */
    case __NR_kill:
        if (cng_pt_signal_route(a0, (int)a1))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    case __NR_tkill:
        if (cng_pt_signal_route(a0, (int)a1))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    case __NR_tgkill:
        if (cng_pt_signal_route(a1, (int)a2))
            return 0;
        return reissue(a0, a1, a2, a3, a4, a5, nr);

    /* strace reads tracee memory with these before falling back to PEEKDATA.
     * When the peer is one of our stopped tracees they are served from the
     * ptrace mailbox, because the host has no reason to believe the caller is
     * attached to it and may refuse (Yama ptrace_scope, SELinux). Any other
     * peer runs natively — once the hidden-process view has been asked. The
     * view hides a host process by path, and this pair and pidfd_open are the
     * routes to a process that carry no path: with a ptrace policy that
     * permits same-uid access, a guest read and wrote the memory of a process
     * its /proc said did not exist, and a pidfd on it reaches everything a
     * pidfd reaches (signals, its descriptors, waitid). A pid the view does
     * not show is ESRCH, which is what /proc/<pid> answers for it — a task of
     * a guest process counts, as the kernel finds a task by any tid it has.
     * Off with --no-proc, where nothing is hidden. A pid the kernel would
     * refuse before it looked anything up (zero, negative) is left to it. */
    case __NR_process_vm_readv:
    case __NR_process_vm_writev: {
        long out;
        if (cng_pt_vm_rw(nr, a0, (u64)a1, (u64)a2, (u64)a3, (u64)a4, (u64)a5,
                         &out))
            return out;
        if (pid_hidden(a0))
            return -ESRCH;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }
    case __NR_pidfd_open:
        if (pid_hidden(a0))
            return -ESRCH;
        return reissue(a0, a1, a2, a3, a4, a5, nr);

    /* pidfd_getfd imports a descriptor out of another process's table, which
     * is the third way one can arrive from outside the view (see cng_fd_admit
     * for the other two). The copy is made and then judged: one that names a
     * directory the guest has no name for is closed again and the call
     * answers EPERM, the refusal pidfd_getfd gives for a process the caller
     * may not reach into. */
    case __NR_pidfd_getfd: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r >= 0 && !cng_fd_admit((int)r))
            return -EPERM;
        return r;
    }

    /* exit/exit_group are trapped only on a tracee (the trap-everything
     * filter). The death has to reach the tracer: PTRACE_EVENT_EXIT first if it
     * asked for one, then either a synthetic exit in the registry or a plain
     * link drop when the tracer is our parent and reaps us for real. */
    case __NR_exit:
    case __NR_exit_group: {
        int wstatus = ((int)a0 & 0xff) << 8;
        struct cng_uregs *ur = cng_pt_cur_regs(); /* either tier's frame */
        if (ur)
            cng_pt_exit_stop(ur, wstatus);
        cng_pt_exit_report(wstatus);
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* rt_sigprocmask on the trampoline path (the SIGSYS path handles it via
     * uc_sigmask): apply the mask but never block SIGSYS. */
    case __NR_rt_sigprocmask: {
        int how = (int)a0;
        /* Only a sigsetsize the kernel accepts gets the copy: for any other the
         * mask is not eight bytes wide, and reading it as if it were turns the
         * kernel's -EINVAL into an -EFAULT of ours whenever those bytes happen
         * to end a mapping. Handed straight over, the kernel refuses it. */
        if ((how == 0 /*BLOCK*/ || how == 2 /*SETMASK*/) && a1 &&
            (unsigned long)a3 == sizeof(unsigned long)) {
            unsigned long set;
            if (cng_user_copyin(&set, (void *)a1, sizeof set) < 0)
                return -EFAULT;
            set &= ~(1UL << (CNG_SIGSYS - 1));
            return cng_syscall6(a0, (long)&set, a2, a3, a4, a5,
                                __NR_rt_sigprocmask);
        }
        return cng_syscall6(a0, a1, a2, a3, a4, a5, __NR_rt_sigprocmask);
    }

    /* ioctl, trapped for the SIOCxIF request band and — with a :ro bind in
     * the view — for the requests that write the mount (seccomp.c tests the
     * request in BPF, so every other ioctl runs native). The interface getters
     * are answered from the same enumeration the netlink dumps are built on —
     * a guest told by `ip addr` that it has only loopback must not be shown the
     * host's whole interface list by `ifconfig`. The setters and anything else
     * in the band fall through to the host, which refuses them to an
     * unprivileged process exactly as it should.
     *
     * The mount writers are the descriptor's own :ro question (fd_ro):
     * FS_IOC_SETFLAGS on a read-only descriptor is chattr(1), and ext4 takes
     * mnt_want_write_file before it looks at the flags, so a real read-only
     * mount answers EROFS. So does this, for every request in the table. The
     * kernel orders a few of the private ones the other way (an owner check,
     * a copy of the argument) and would answer EPERM or EFAULT ahead of
     * EROFS for a call that is refused either way; that precedence is not
     * reproduced. FIDEDUPERANGE names its targets in the argument, and is
     * answered per destination (ioctl_dedupe). */
    case __NR_ioctl: {
        long r = 0;
        if (cng_nl_ioctl((int)a0, (unsigned long)a1, (void *)a2, &r))
            return r;
        unsigned req = (unsigned)a1;
        if (req == CNG_FIDEDUPERANGE && fs_has_ro())
            return ioctl_dedupe(a0, a1, a2, a3, a4, a5);
        for (int i = 0; i < cng_ioctl_mnt_write_n; i++)
            if (req == cng_ioctl_mnt_write[i]) {
                if (fd_ro(a0))
                    return -EROFS;
                break;
            }
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* uname: a fixed kernel identity (CNG_KREL/CNG_KVER), which /proc/version
     * repeats word for word. The host's release describes the device rather
     * than the rootfs — on Android it carries `-android14-11-...`/`-perf`
     * vendor suffixes that identify the phone — and a modern glibc rootfs
     * refuses to start on a release below its build-time minimum whatever else
     * is true. nodename and domainname are the host's: they name the machine
     * the guest really is on, which is what a guest expects to see and what
     * `hostname` reports either way.
     *
     * The buffer is six 65-byte fields (__NEW_UTS_LEN + 1), and it is ours, not
     * the guest's: the kernel fills a copy of ours, the four fields are set
     * there, and the whole struct goes out in one cng_user_copyout. Patching
     * the guest's buffer in place — which is what "the kernel validated this
     * pointer just now" invites — is a store into memory the guest owns, made
     * some syscalls after the kernel last looked at it, and another thread of
     * the guest is free to unmap it inside that gap. The store then faults in
     * the SIGSYS handler, where SIGSEGV is masked and a fault is fatal, in
     * place of the -EFAULT uname(2) answers. Filling our own buffer also keeps
     * the host's release out of the guest's memory entirely, rather than
     * putting it there and overwriting it an instant later. */
    case __NR_uname: {
        char u[6 * 65];
        long r = reissue((long)u, a1, a2, a3, a4, a5, nr);
        if (r != 0)
            return r;
        uts_set(u + 0 * 65, "Linux");
        uts_set(u + 2 * 65, CNG_KREL);
        uts_set(u + 3 * 65, CNG_KVER);
        uts_set(u + 4 * 65, "aarch64");
        /* A NULL or unmapped buffer is the -EFAULT the kernel would have given
         * for it, raised here rather than there. */
        return cng_user_copyout((void *)a0, u, sizeof u);
    }

    /* The waits that install a signal mask of their own, and the signalfd
     * that reads from one: SIGSYS is taken out of the copy the kernel is
     * handed, so no guest thread is ever parked with it blocked (execve.c's
     * de_thread has to be able to reach every thread) and no signalfd ever
     * dequeues it. The SIGSYS tier runs the waits from guest context instead
     * (sigsys.c's bounce) and reaches here only for a stack it could not use;
     * the -R tier, in ordinary context, re-issues in place. A set the kernel
     * would refuse is refused as it would: a size that is not its own is
     * EINVAL before the pointer is looked at, an unreadable set EFAULT. */
    case __NR_rt_sigsuspend:
    case __NR_rt_sigtimedwait:
    case __NR_ppoll:
    case __NR_epoll_pwait:
    case __NR_epoll_pwait2:
    case __NR_signalfd4: {
        int mi = nr == __NR_rt_sigsuspend || nr == __NR_rt_sigtimedwait ? 0
                 : nr == __NR_ppoll                                     ? 3
                 : nr == __NR_signalfd4                                 ? 1
                                                                        : 4;
        int si_ = nr == __NR_rt_sigsuspend     ? 1
                  : nr == __NR_rt_sigtimedwait ? 3
                  : nr == __NR_ppoll           ? 4
                  : nr == __NR_signalfd4       ? 2
                                               : 5;
        long a[6] = {a0, a1, a2, a3, a4, a5};
        unsigned long set;
        if (!a[mi])
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        if ((unsigned long)a[si_] != sizeof(cng_sigset_t))
            return -EINVAL;
        if (cng_user_copyin(&set, (void *)a[mi], sizeof set) < 0)
            return -EFAULT;
        set &= ~(1UL << (CNG_SIGSYS - 1));
        a[mi] = (long)&set;
        return reissue(a[0], a[1], a[2], a[3], a[4], a[5], nr);
    }
    case __NR_pselect6: {
        unsigned long sel[2], set;
        if (!a5)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        if (cng_user_copyin(sel, (void *)a5, sizeof sel) < 0)
            return -EFAULT;
        if (sel[0]) {
            if (sel[1] != sizeof(cng_sigset_t))
                return -EINVAL;
            if (cng_user_copyin(&set, (void *)sel[0], sizeof set) < 0)
                return -EFAULT;
            set &= ~(1UL << (CNG_SIGSYS - 1));
            sel[0] = (unsigned long)&set;
        }
        return reissue(a0, a1, a2, a3, a4, (long)sel, nr);
    }

    /* POSIX timers do not survive an execve, and ours is emulated — the address
     * space stays, so a timer would go on firing into a program that never
     * armed it, through a handler that no longer exists. Nothing enumerates a
     * process's timers, so the ids are recorded as they are handed out.
     *
     * The kernel writes the id into a word of ours, and the guest gets a copy:
     * read back out of the guest's buffer a syscall later, the record held
     * whatever was there by then — another thread of the guest can rewrite or
     * unmap that buffer in between, and where the record is all the exec has
     * (qemu-user, whose ids are not the ones in /proc/self/timers) the timer
     * it named wrongly outlived the program. A copy-out that fails deletes
     * the timer, which is what do_timer_create() does when its own put_user
     * fails: -EFAULT, and no timer left behind. */
    case __NR_timer_create: {
        int id = 0;
        long r = reissue(a0, a1, (long)&id, a3, a4, a5, nr);
        if (r != 0)
            return r;
        cng_timer_note(id);
        if (!a2 || cng_user_copyout((void *)a2, &id, sizeof id) < 0) {
            reissue(id, 0, 0, 0, 0, 0, __NR_timer_delete);
            cng_timer_forget(id);
            return -EFAULT;
        }
        return 0;
    }
    case __NR_timer_delete: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0)
            cng_timer_forget((int)a0);
        return r;
    }

    /* rseq: the same story with a sharper edge. The registered area is memory
     * the kernel writes into by itself, on the way back to user mode, and a
     * real execve unregisters it with the address space; ours must do it by
     * hand, with the exact area, length and signature — so they are recorded
     * here (per thread; see the table in execve.c). The call itself runs as
     * the kernel answers it, EBUSY, EINVAL and all. */
    case __NR_rseq: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0) {
            if (a2 & 1 /*RSEQ_FLAG_UNREGISTER*/)
                cng_rseq_forget();
            else
                cng_rseq_note((unsigned long)a0, (unsigned long)a1,
                              (unsigned int)a3);
        }
        return r;
    }

    /* prctl: the four ops that describe OUR confinement rather than the guest's.
     * Only these are trapped (seccomp.c tests args[0] in BPF); every other op is
     * real process state and runs natively.
     *
     * The no_new_privs bit is ours — cng_install_seccomp sets it because a
     * filter cannot be installed without it — so the guest is told what it
     * itself asked for, not what we did. It survives fork (ordinary memory) and
     * our emulated execve, which is where a real one would keep it too. */
    case __NR_prctl: {
        switch ((int)a0) {
        case CNG_PR_GET_SECCOMP:
            /* Mode 2 is the filter WE installed. A sandbox that asks this to
             * find out whether it still has work to do would conclude it is
             * already confined and skip installing anything. */
            return 0;
        case CNG_PR_SET_SECCOMP:
            /* A second filter would also govern the syscalls the handler
             * re-issues through the gate, which the guest's filter has no way to
             * know about — one that kills on an unlisted syscall would take the
             * monitor down with it. EACCES is what a kernel answers when the
             * caller may not install a filter, and the callers that matter
             * (libseccomp, systemd, browser sandboxes) all have a path for it. */
            if (cng_g_debug)
                cng_dprintf(2, "[cng] prctl(PR_SET_SECCOMP) refused\n");
            return -EACCES;
        case CNG_PR_SET_NO_NEW_PRIVS:
            if (a1 != 1 || a2 || a3 || a4)
                return -EINVAL; /* the kernel's own argument check */
            nnp_set();
            return 0; /* already set for real, at install */
        case CNG_PR_GET_NO_NEW_PRIVS:
            if (a1 || a2 || a3 || a4)
                return -EINVAL; /* the kernel's own check, as for the setter */
            return cng_nnp_get();
        }
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }

    /* mmap. Only one shape of it is ours: a PROT_EXEC mapping of a file, which
     * on a true MNT_NOEXEC mount the kernel refuses outright — and that
     * refusal, taken by a dynamic guest's own ld.so mapping a library, is the
     * end of every dynamically linked guest on such a mount. execmap.c serves
     * it from anonymous memory instead. Every other mmap (all the anonymous
     * ones, which is nearly all of them) goes straight back out; the filter
     * already tests the same two arguments, so on the seccomp tier this case is
     * only reached by the mappings it is for, while under -R it sees them all
     * and has to say so itself. */
    case __NR_mmap:
        if (!((int)a2 & CNG_PROT_EXEC) || ((int)a3 & CNG_MAP_ANONYMOUS))
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        return cng_execmap((unsigned long)a0, (unsigned long)a1, a2, a3, a4,
                           (unsigned long)a5);

    /* --- credential syscalls (trapped only when --fake-id is active) ---
     * All get/set uid/gid family, groups, and capability calls are emulated
     * against the synthetic credential set in cred.c, which enforces real POSIX
     * privilege rules. These never re-issue under --fake-id: the setters sit on
     * Android's seccomp block-list, and a re-issue from inside this (SIGSYS)
     * handler force-kills the process (masked nested seccomp SIGSYS). */
    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid:
    case __NR_getresuid:
    case __NR_getresgid:
    case __NR_getgroups:
    case __NR_setuid:
    case __NR_setgid:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_setresuid:
    case __NR_setresgid:
    case __NR_setfsuid:
    case __NR_setfsgid:
    case __NR_setgroups:
    case __NR_capget:
    case __NR_capset:
        return cng_cred_handle(nr, a0, a1, a2, a3, a4, a5);

    default:
        /* A tracee carries the trap-everything filter, so an unhandled syscall
         * here is an ordinary one that simply has to run — the Android-blocked
         * reading below does not apply, and the designed-ENOSYS set (which that
         * filter converts from the base filter's RET_ERRNO into a trap) has to
         * be refused by hand. */
        if (trapped && cng_pt_traceall()) {
            if (cng_denied_syscall(nr))
                return -ENOSYS;
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        /* From a seccomp trap, an unhandled syscall was blocked by Android
         * (our filter only traps handled ones) => emulate ENOSYS rather than
         * re-issue and die on the nested trap. From a trampoline it is just an
         * ordinary syscall we don't translate => run it. */
        if (trapped) {
            cng_note_blocked((int)nr);
            return -ENOSYS;
        }
        return reissue(a0, a1, a2, a3, a4, a5, nr);
    }
}

/* The -R trampoline's entry point: one rewritten `svc` site, with a full
 * register frame the trampoline built on its own stack (see tramp.S).
 *
 * It is the SIGSYS handler's counterpart on a tier that has no signal frame,
 * and it exists so the two tiers behave the same for a ptrace tracee: the same
 * entry/exit stops around the syscall, the same register file for the tracer to
 * read and write, and the same single-step report. `trapped` is 0 here — an
 * unhandled syscall on this path is an ordinary one to re-issue, not one
 * Android blocked. */
/* The trapped syscall itself, the -R counterpart of sigsys_syscall: the one
 * case that needs the register frame rather than six arguments (the converted
 * clone puts the child's stack into it, for the trampoline's exit to install),
 * then the dispatcher for everything else. */
static void tramp_syscall(struct cng_uregs *r, long nr) {
    if (nr == __NR_clone) {
        cng_clone_convert(r);
        return;
    }
    r->x[0] = (u64)cng_dispatch(nr, (long)r->x[0], (long)r->x[1], (long)r->x[2],
                                (long)r->x[3], (long)r->x[4], (long)r->x[5], 0);
}

static void tramp_body(void *p) {
    struct cng_uregs *r = (struct cng_uregs *)p;
    long nr = (long)r->x[8];
    /* An untraced exit does not come back, so the slot it holds would stay
     * claimed and busy — and a thread that later inherits the tid would find it
     * so and run in place. Give it back while still on it: nothing nests below
     * an exit. Traced is left alone, since there a tracer can cancel the call
     * and make it return after all. */
    if ((nr == __NR_exit || nr == __NR_exit_group) && !cng_pt_active())
        cng_scratch_leave();
    cng_pt_set_frame(r, 0);
    if (!cng_pt_active()) {
        tramp_syscall(r, nr);
        return;
    }
    if (!cng_pt_syscall_entry(r, &nr)) {
        cng_pt_syscall_exit(r); /* cancelled: x0 is the tracer's own answer */
        return;
    }
    tramp_syscall(r, nr);
    cng_pt_syscall_exit(r);
    cng_pt_step_report(r);
}

void cng_tramp_dispatch(struct cng_uregs *r) {
    /* On the guest's own stack this is the same overflow the SIGSYS tier has a
     * 256 KiB scratch stack to avoid, and here it is not even a fault: the
     * dispatcher's frame is larger than a guard page, so it steps over the
     * guard and writes into ordinary guest memory below, silently. */
    if (!cng_run_scratch(tramp_body, r))
        tramp_body(r);
}
