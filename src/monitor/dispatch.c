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

#include <asm/unistd.h>

struct cng_fs *cng_g_fs = 0;

/* The fake-identity globals (cng_g_fake_id, cng_g_cred, ...) live in cred.c. */
const char *cng_g_exe_guest = "/";

/* AArch64 struct stat / statx field offsets for ownership rewriting, plus the
 * st_mode offset used by the fake-root access() fallback. */
/* The kernel's own struct sizes: what a stat/statx writes, and so exactly what
 * has to come back out of a guest buffer and go back into it. */
#define STAT_BUF_SIZE  128
#define STATX_BUF_SIZE 256
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

/* A mutating syscall whose target lands under a `:ro` bind must answer -EROFS,
 * the way it would on a real read-only mount. Keyed on the already-resolved
 * HOST path, so a guest symlink that leads into the bind is covered however the
 * path got there. Checked before the reissue, and before chattr_result — a
 * read-only mount is a genuine error that fake-root does not paper over. */
static int ro_denied(const char *host) {
    return host && cng_g_fs && cng_fs_host_ro(cng_g_fs, host);
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
    long r = CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, (long)host, (long)st,
                     atflags, 0, 0);
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
    long r = cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
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
     * deleted files no re-rooted target could ever name. Any trailing
     * components (a directory fd) ride along, as they do for a real dirfd.
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

/* The canonical GUEST directory an open fd names, for the getdents64 overlay
 * splicing below. Returns 0/-1. */
static int dirfd_guest_dir(long dirfd, char *out, size_t sz) {
    char hdir[CNG_PATH_MAX];
    if (dirfd_host((int)dirfd, hdir, sizeof hdir) != 0)
        return -1;
    return cng_fs_untranslate(cng_g_fs, hdir, out, sz);
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
    /* Bind mount points whose parent is exactly this directory. */
    for (int i = 0; i < cng_g_fs->nbinds; i++) {
        const char *g = cng_g_fs->binds[i].guest;
        const char *slash = 0;
        for (const char *p = g; *p; p++)
            if (*p == '/')
                slash = p;
        if (!slash || !slash[1])
            continue;
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
        unsigned char type = 4; /* DT_DIR */
        char st[144];
        if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD,
                    (long)cng_g_fs->binds[i].host, (long)st, 0, 0, 0) == 0) {
            ino = *(unsigned long long *)(st + 8);
            type = (unsigned char)((*(unsigned *)(st + STAT_MODE_OFF) >> 12) &
                                   0xf);
        }
        long k = put_dent(buf, used + added, cap, base, ino, type,
                          0x7fffffff00000000LL + i);
        if (!k)
            return added;
        added += k;
    }
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
 * with where the path actually resolves. */
static int mount_of(const char *canon) {
    char tmp[CNG_PATH_MAX];
    int m = CNG_MOUNT_ROOTFS;
    cng_fs_translate_mnt(cng_g_fs, canon, tmp, sizeof tmp, &m);
    return m;
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
    const char *base = scoped                  ? lim->scope
                       : path[0] == '/'        ? "/"
                       : cng_g_fs->cwd[0] != 0 ? cng_g_fs->cwd
                                               : "/";
    if (cng_strlcpy(canon, base, sizeof canon) >= sizeof canon ||
        cng_strlcpy(rest, path, sizeof rest) >= sizeof rest)
        return -ENAMETOOLONG;

    /* The mount the resolution starts in. For a name reached through a real
     * dirfd the walk is handed an absolute path built from that directory, so
     * the caller names the true starting point; otherwise it is this base. */
    int start = CNG_MOUNT_ROOTFS;
    if (lim && lim->no_xdev)
        start = mount_of(lim->xdev_base && lim->xdev_base[0] ? lim->xdev_base
                                                             : base);

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
                         (magic == PROC_MAGIC_HOST && !(last && proc_fd_dir(canon)));
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
            /* The magic path IS the host path. Any components left ride along,
             * as they do for a real dirfd. */
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
            cng_strlcpy(canon, "/", sizeof canon);
            continue;
        }

        if (last && !deref_final)
            continue;
        char host[CNG_PATH_MAX], link[CNG_PATH_MAX];
        if (cng_fs_translate(cng_g_fs, canon, host, sizeof host) != 0)
            continue;
        long n = sys_readlinkat(CNG_AT_FDCWD, host, link, sizeof link - 1);
        if (n <= 0)
            continue; /* not a symlink, or missing */
        link[n] = '\0';
        if (lim && lim->no_symlinks) {
            lim->err = -ELOOP;
            return -ELOOP;
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
    }
    /* cng_fs_translate fails only on length — the canonical form overflowing,
     * or the rootfs prefix pushing the result past `outsz` — so its refusal is
     * the same -ENAMETOOLONG the walk above answers. */
    if (xdev_hit(lim, start, canon))
        return lim->err;
    return cng_fs_translate(cng_g_fs, canon, out, outsz) == 0 ? 0
                                                              : -ENAMETOOLONG;
}

/* "/proc/self/fd/<fd>" into out[40]. fd args are 32-bit: glibc passes ints in
 * w-registers and may leave the x-register's top half dirty, so truncate. */
static void proc_fd_path(long fd, char *out) {
    size_t p = cng_strlcpy(out, "/proc/self/fd/", 40);
    char num[16];
    int ni = 0;
    long v = (int)fd;
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
 * Returns -1 when the dirfd names a directory outside the guest view (a /proc
 * dirfd, say) — there is no guest path to express it as, and the /proc zone
 * wants the host namespace anyway, so the caller passes the name through. */
static int xlate_at_lim(int dfd, const char *path, char *out, size_t sz,
                        int deref, struct cng_res_limit *lim) {
    char hdir[CNG_PATH_MAX], gdir[CNG_PATH_MAX], gp[CNG_PATH_MAX];
    if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
        return -1;
    if (cng_fs_untranslate(cng_g_fs, hdir, gdir, sizeof gdir) != 0)
        return -1;
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
     * the walk above exists to prevent. Every other failure (ELOOP) is one the
     * kernel reproduces for itself on the guest's own name. */
    return r == -ENAMETOOLONG ? XLATE_AT_LONG : -1;
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
    for (int i = 0; cng_g_fs && i < cng_g_fs->nbinds; i++) {
        const char *g = cng_g_fs->binds[i].guest;
        const char *s = strrchr(g, '/');
        if (s && s[1] && strcmp(s + 1, name) == 0)
            return 1;
    }
    return 0;
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
    for (int i = 0; cng_g_fs && i < cng_g_fs->nbinds; i++)
        if (cng_g_fs->binds[i].ro)
            return 1;
    return 0;
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
 * be trusted with it? The dirfd itself already points inside the guest view, so
 * only three things can redirect out of it: a ".." component, a symlink, and a
 * name the kernel cannot resolve at all because it is ours. This is the hot
 * path (every relative openat), so the cheap cases stay cheap.
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
    /* A pid-shaped name may be a host process seen through a /proc dirfd, which
     * only the join in xlate() can hide (that dirfd has no guest path, so the
     * walk itself fails — the point is to reach the branch after it). */
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
        if (cng_resolve(path, deref, out, sz) == 0)
            return 0;
        return cng_fs_translate(cng_g_fs, path, out, sz) == 0 ? 0 : -1;
    }
    if (dfd < 0)
        return -1;
    int r = xlate_at(dfd, path, out, sz, deref);
    if (r == 0)
        return 0;
    if (r == XLATE_AT_LONG)
        return -1; /* fail closed rather than fall through to the host join */
    /* Outside the guest view (a /proc dirfd): the host directory joined with
     * the name is the only answer available, and the right one there. */
    char hdir[CNG_PATH_MAX];
    if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
        return -1;
    size_t k = cng_strlcpy(out, hdir, sz);
    if (k >= sz)
        return -1;
    if (k && out[k - 1] != '/' && k + 1 < sz) {
        out[k++] = '/';
        out[k] = '\0';
    }
    return cng_strlcpy(out + k, path, sz - k) >= sz - k ? -1 : 0;
}

#ifdef __NR_openat2
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
    for (int i = 0; cng_g_fs && i < cng_g_fs->nbinds; i++) {
        const char *bg = cng_g_fs->binds[i].guest;
        /* Strictly below: a dirfd on the bind's own mount point already IS the
         * bind — its host directory is the bound one — so everything the
         * kernel can reach under it is what the guest sees there. Only a mount
         * point *inside* the scope makes the two trees differ. */
        if (guest_under(bg, gdir) && strcmp(bg, gdir) != 0)
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
        if (cng_strlcpy(gdir, cng_g_fs->cwd[0] ? cng_g_fs->cwd : "/", sz) >= sz)
            return 0;
    } else {
        char hdir[CNG_PATH_MAX];
        if (dirfd_host(dfd, hdir, sizeof hdir) != 0)
            return 0;
        if (cng_fs_untranslate(cng_g_fs, hdir, gdir, sz) != 0) {
            /* No guest path — except in the /proc zone, which passes through
             * to the host under the same name, so the guest path is the host
             * one. That is worth recovering: the synthesized /proc files and
             * the hidden-process view live under a dirfd like that, and they
             * are exactly what the kernel's own resolution would miss. */
            if (cng_g_no_proc || strncmp(hdir, "/proc", 5) != 0 ||
                (hdir[5] && hdir[5] != '/') ||
                cng_strlcpy(gdir, hdir, sz) >= sz)
                return 0; /* the host namespace is the right one here */
        }
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

#endif /* __NR_openat2 */

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
 * about the link, not about the data. The l2s hop is always the last component
 * — a link to a regular file has nothing under it — so the name's own path is
 * exactly the resolution with the final hop not taken. Asked only when -l and
 * a :ro bind are both in play, so the default path pays nothing for it. */
static int ro_denied_l2s(long dirfd, const char *gp) {
    if (!cng_g_l2s || !gp || !gp[0] || !fs_has_ro())
        return 0;
    char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
    return cng_resolve_at(dirfd, gp, 0, hnf, sizeof hnf) == 0 &&
           cng_l2s_resolve(hnf, data, sizeof data, 0) == 1 && ro_denied(hnf);
}

/* ro_refusal() for a call whose resolution followed the final component. The
 * l2s case is answered first and always with EROFS: the name resolved to a
 * link of ours, so it is there, and "there" is the whole of what the ENOENT
 * half of ro_refusal exists to establish. */
static long ro_refusal_name(long dirfd, const char *gp, const char *host,
                            int atflags) {
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
    long r = cng_syscall6(CNG_AT_FDCWD, (long)host, flags, mode, 0, 0,
                          __NR_openat);
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
#ifdef __NR_openat2
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
#endif
    int dfd = (int)dirfd; /* int arg: the x-register's top half may be dirty */
    if (gp[0] == '/' || dfd == CNG_AT_FDCWD) {
        if (cng_resolve_lim(gp, deref_final, buf, bufsz, lim) == 0)
            return buf;
        if (lim && lim->err)
            return XLATE_TOOLONG; /* the caller reads lim->err, not this */
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
        /* The dirfd names no guest path — the /proc zone, which passes through
         * to the host on purpose. That is the right namespace, but the
         * hidden-process view has to hold inside it, and it is keyed on the
         * host path, which a relative name only acquires once it is joined onto
         * the directory's own. Without the join, `openat(dirfd("/proc"),
         * "1/status")` read the host's init while "/proc/1/status" answered
         * ENOENT — the whole host process list, one directory fd away. */
        if (name_may_be_pid(gp)) {
            char hdir[CNG_PATH_MAX], hp[CNG_PATH_MAX];
            if (dirfd_host(dfd, hdir, sizeof hdir) == 0) {
                size_t k = cng_strlcpy(hp, hdir, sizeof hp);
                if (k && k + 1 < sizeof hp && hp[k - 1] != '/') {
                    hp[k++] = '/';
                    hp[k] = '\0';
                }
                /* Only inside /proc: anywhere else this is a host path with no
                 * guest spelling, and re-rooting it would be the wrong answer. */
                if (k < sizeof hp &&
                    cng_strlcpy(hp + k, gp, sizeof hp - k) < sizeof hp - k &&
                    !strncmp(hp, "/proc/", 6) &&
                    cng_fs_translate(cng_g_fs, hp, buf, bufsz) == 0)
                    return buf;
            }
        }
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
    char own[CNG_PROCREG_PATH + 1];
    if (proc_pid_prefix(canon, 1)) { /* self / thread-self */
        val = rest[0] == 'e' ? cng_g_exe_guest
              : rest[0] == 'c' ? cng_g_fs->cwd
                               : "/";
    } else {
        const char *q = canon + 6;
        long pid = parse_int_run(&q);
        if (pid < 0)
            return -1; /* no process is numbered that high */
        if (pid == sys_getpid()) {
            val = rest[0] == 'e' ? cng_g_exe_guest
                  : rest[0] == 'c' ? cng_g_fs->cwd
                                   : "/";
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

/* The canonical GUEST path an (dirfd, path) pair names, for the /proc hooks.
 * A real dirfd is resolved through its host path and mapped back; a host /proc
 * path is already the guest spelling (that zone passes through). Returns 0/-1. */
static int at_canon(long dirfd, const char *path, char *out, size_t sz) {
    if (!path || !path[0])
        return -1;
    if (path[0] == '/' || (int)dirfd == CNG_AT_FDCWD)
        return cng_fs_abscanon(cng_g_fs, path, out, sz);
    char host[CNG_PATH_MAX];
    if (cng_resolve_at(dirfd, path, 0, host, sizeof host) != 0)
        return -1;
    if (!strncmp(host, "/proc/", 6) || !strcmp(host, "/proc"))
        return cng_path_canon(host, out, sz);
    return cng_fs_untranslate(cng_g_fs, host, out, sz);
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
    const char *root = cng_g_fs->rootfs[0] ? cng_g_fs->rootfs : "/";
    return strcmp(hp, root) == 0;
}

/* getdents64: hide the l2s machinery from directory listings — backing
 * data/marker names anywhere, and the ".l2s" store dir in the rootfs root; when
 * a whole batch is ours, re-read so a filtered 0 isn't mistaken for
 * end-of-directory. Then splice in the entries that exist only as resolution
 * overlays (bind mount points, /dev nodes) and so have no physical dirent to
 * return.
 *
 * All of that reads the records back and rewrites them, and the buffer they sit
 * in is the guest's. The kernel having just filled it says nothing about the
 * moment after: another thread of the guest can unmap it, and this runs with
 * SIGSEGV masked, where a fault is the death of the process rather than an
 * -EFAULT. So the records are examined in a batch buffer of our own and the
 * guest's is written only through cng_user_copyout.
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
    char injdir[CNG_PATH_MAX];
    int inject = a1 && sys_lseek((int)a0, 0, CNG_SEEK_CUR) == 0 &&
                 dirfd_guest_dir(a0, injdir, sizeof injdir) == 0;
    /* Whether anything here is going to look at the records at all. When
     * nothing is — no injection, no l2s, no hidden-process view — the call is
     * a plain pass-through and the guest's own buffer size is honored whole. */
    int bounce = inject || cng_g_l2s || !cng_g_no_proc;
    char bnc[DENTS_BOUNCE];
    long ask = (long)a2;
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
     * The injected records are handed over before the kernel is asked, not
     * after: a guest buffer that cannot take them is -EFAULT with the stream
     * still where it was, which is what a plain getdents64 on the same buffer
     * would have answered. */
    long pre = 0, n, injcap = ask;
    for (;;) {
        pre = inject ? inject_dents(a0, injdir, bnc, 0, injcap) : 0;
        if (pre && cng_user_copyout((char *)a1, bnc, (unsigned long)pre) < 0)
            return -EFAULT;
        n = reissue(a0, a1 + pre, ask - pre, a3, a4, a5, __NR_getdents64);
        if (n >= 0 || pre == 0)
            break;
        injcap = pre - 1;
    }
    char *buf = (char *)a1 + pre;
    long cap = ask - pre;

    /* A refusal is the guest's to see: the position did not move, so
     * answering with the spliced-in bytes would repeat them next time. */
    if (n < 0)
        return n;
    /* End of stream on the very first read means a directory that emitted
     * neither "." nor "..", which no filesystem does; the overlay records
     * are the whole answer. */
    if (n == 0 || !a1 || !bounce)
        return pre ? pre : n;
    /* The kernel wrote its records into the guest's buffer, so it has already
     * answered for that pointer; taking them back out is ours to make safe. */
    char *kb = bnc + pre;
    if (cng_user_copyin(kb, buf, (unsigned long)n) < 0)
        return -EFAULT;
    /* Hidden-process view, listing side: the path layer makes a host
     * process's /proc entry unreachable, but `ls /proc` and `ps` read the
     * directory, so the numeric entries have to go as well. Deciding that
     * costs a readlink of the fd, so it is asked only when this batch
     * actually holds a numeric name — outside /proc almost nothing does. */
    int at_proc = !cng_g_no_proc && dents_have_pid(kb, n) && fd_is_host_proc(a0);
    if (!cng_g_l2s && !at_proc)
        return pre + n;
    int at_root = cng_g_l2s && fd_is_rootfs_root(a0);
    for (;;) {
        /* linux_dirent64: d_reclen u16 @16, d_name @19. d_off cookies are
         * directory-stream positions, so compaction is seek-safe. */
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
                if (w != o)
                    memmove(kb + w, kb + o, reclen);
                w += reclen;
            }
            o += reclen;
        }
        if (w > 0) {
            /* Only a batch that lost a record has to go back: what the filter
             * left untouched is already exactly what the kernel wrote there. */
            if (w != n && cng_user_copyout(buf, kb, (unsigned long)w) < 0)
                return -EFAULT;
            return pre + w;
        }
        /* A whole batch of ours: re-read, so a filtered 0 is not mistaken
         * for end-of-directory. */
        n = reissue(a0, (long)buf, cap, a3, a4, a5, __NR_getdents64);
        if (n <= 0)
            return pre ? pre : n;
        if (cng_user_copyin(kb, buf, (unsigned long)n) < 0)
            return -EFAULT;
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
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_mkdirat:
    case __NR_mknodat:
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
#endif
    case __NR_faccessat:
#ifdef __NR_faccessat2
    case __NR_faccessat2:
#endif
    case __NR_fchmodat:
#ifdef __NR_fchmodat2
    case __NR_fchmodat2:
#endif
    case __NR_unlinkat:
    case __NR_utimensat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_fchownat:
    case __NR_readlinkat:
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

#ifdef __NR_openat2
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

static long openat2_scoped(long dirfd, long path, long a4, long a5,
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
         * same way, or a write-open of a dangling link reads as absent. */
        probe.flags = CNG_O_PATH | CNG_O_CLOEXEC | (oflags & CNG_O_NOFOLLOW);
        probe.mode = 0;
        long e = cng_syscall6(dirfd, path, (long)&probe, (long)sizeof probe, 0,
                              0, __NR_openat2);
        if (e < 0)
            return e; /* the lookup's own error: ENOENT, ENOTDIR, ELOOP... */
        sys_close((int)e);
        return -EROFS;
    }

    long r = reissue(dirfd, path, (long)how, (long)sizeof *how, a4, a5,
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
 * good, else the errno the kernel gave it. */
static long how_precheck(const struct cng_open_how *how) {
    long r = cng_syscall6(CNG_AT_FDCWD, (long)"", (long)how, (long)sizeof *how,
                          0, 0, __NR_openat2);
    if (r >= 0) {
        sys_close((int)r); /* an empty name cannot open, but never leak one */
        return 0;
    }
    return (r == -ENOENT || r == -EAGAIN) ? 0 : r;
}
#endif

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
#ifdef __NR_faccessat2
    case __NR_faccessat2:
        return ((int)a3 & CNG_AT_EMPTY_PATH) != 0;
#endif
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
        return ((int)a4 & CNG_AT_EMPTY_PATH) != 0;
#endif
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

/* Run the readback translation over an address the kernel just wrote into our
 * bounce buffer, and hand the result to the guest. `al` is what the kernel
 * reported; it cannot exceed the buffer (the kernel bounds every address by
 * sockaddr_storage), but it is clamped rather than trusted. */
static long sun_deliver(char *ab, unsigned al, long aa, long alp) {
    long got = (long)al;
    if (got > CNG_SOCKADDR_MAX)
        got = CNG_SOCKADDR_MAX;
    cng_sun_out(ab, &got);
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
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_mkdirat:
    case __NR_mknodat:
#ifdef __NR_name_to_handle_at
    case __NR_name_to_handle_at:
#endif
    {
        /* openat2 carries its flags in the open_how it points at. */
#ifdef __NR_openat2
        int is_open = (nr == __NR_openat || nr == __NR_openat2);
#else
        int is_open = (nr == __NR_openat);
#endif
        long oflags = 0;
#ifdef __NR_openat2
        struct cng_open_how how;
        struct cng_res_limit lim = {0, 0, 0, 0, 0, 0, 0, 0};
        unsigned long resolve = 0;
        char sdir[CNG_PATH_MAX]; /* a scoped openat2's scope, as a guest path */
        int scoped = 0;          /* ...and whether this is one */
#endif
        if (is_open) {
            oflags = a2;
#ifdef __NR_openat2
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
#endif
        }
#ifdef __NR_openat2
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
            if (!cng_scope_needs_walk(a0, sdir, sizeof sdir))
                return openat2_scoped(a0, a1, a4, a5, &how);
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
#endif
        /* O_NOFOLLOW must reach the kernel as a symlink, or it has nothing to
         * refuse: resolving the final component here would hand over the
         * target and the open would succeed where it must ELOOP. (An l2s link
         * name is the deliberate exception, restored by the ELOOP retry below —
         * the guest believes that name IS the file.) */
        int deref = !(nr == __NR_mkdirat || nr == __NR_mknodat) &&
                    !(is_open && (oflags & CNG_O_NOFOLLOW));
#ifdef __NR_name_to_handle_at
        /* ...except this one, whose flag runs the other way: it does NOT follow
         * a final symlink unless AT_SYMLINK_FOLLOW is given, where every other
         * *at() call follows unless told not to. Taken as a follower, it
         * described the target instead of the link — and a dangling link, which
         * the kernel happily encodes because it never looks at the target, came
         * back ENOENT (measured both ways). */
        if (nr == __NR_name_to_handle_at)
            deref = ((int)a4 & CNG_AT_SYMLINK_FOLLOW) != 0;
#endif
        /* A read-only open of a /proc file that would describe chroot-ng
         * instead of the guest is served from an in-memory copy of the guest
         * view (see procfs.c). */
        /* The name the :ro checks below ask the l2s question about: the
         * guest's own, which for an ordinary call is the one it passed. */
        long rkd = a0;
        const char *rkp = (const char *)a1;
#ifdef __NR_openat2
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
#endif
        if (is_open) {
            const char *gp = (const char *)a1;
            char canon[CNG_PATH_MAX];
            long pr;
            /* Absolute and cwd-relative names canonicalize without a syscall;
             * a real dirfd costs a readlink, so it is resolved only when the
             * name could be a synthesized file at all. */
            int have = 0;
#ifdef __NR_openat2
            if (scoped) {
                /* Already spelled out above, and it is not the join of the
                 * dirfd and the name: where the scope refuses the name there
                 * is nothing to synthesize for, and the refusal itself is left
                 * to the walk, which resolves `..` physically as the kernel
                 * does and so is the one entitled to answer EXDEV. */
                if ((have = have_scanon))
                    cng_strlcpy(canon, scanon, sizeof canon);
            } else
#endif
            if (gp && (gp[0] == '/' || (int)a0 == CNG_AT_FDCWD))
                have = cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0;
            else if (gp && leaf_may_synth(gp))
                have = at_canon(a0, gp, canon, sizeof canon) == 0;
            if (have && !strncmp(canon, "/proc", 5) &&
                cng_procfs_open(canon, oflags, &pr))
                return pr;
        }
#ifdef __NR_openat2
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
#else
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
#endif
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
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
#ifdef __NR_openat2
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
#endif
        long r = reissue(a0, (long)p, ha2, ha3, a4, a5, nr);
        /* O_NOFOLLOW through a real dirfd lands on the l2s symlink and draws
         * ELOOP where a real hardlink would open. Retry on the backing file —
         * never a symlink itself, so O_NOFOLLOW stays honored for real
         * guest symlinks. */
        if (r == -ELOOP && cng_g_l2s && nr == __NR_openat &&
            ((int)a2 & CNG_O_NOFOLLOW)) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) ==
                    0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                r = reissue(CNG_AT_FDCWD, (long)data, a2, a3, a4, a5,
                            __NR_openat);
        }
        if ((r == -EACCES || r == -EPERM) && nr == __NR_openat)
            r = cng_fd_reopen(p, a2, a3, r);
        return r;
    }

    /* access: translate + reissue; under fake-root apply root's DAC bypass when
     * the real (unprivileged) check is denied — existence and R/W are granted,
     * X requires at least one execute bit. mode is a2 for both variants. This is
     * what "check-then-write" tools (package managers, `test -w`) rely on. */
    case __NR_faccessat:
#ifdef __NR_faccessat2
    case __NR_faccessat2:
#endif
    {
        /* faccessat2 has a real flags word, so unlike its predecessor it can ask
         * about the symlink itself. Resolving the final component here would
         * hand the kernel the target and answer for the wrong file. */
        int deref = 1;
#ifdef __NR_faccessat2
        if (nr == __NR_faccessat2 && ((int)a3 & CNG_AT_SYMLINK_NOFOLLOW))
            deref = 0;
#endif
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        /* faccessat(2) takes three arguments and has no flags word at all —
         * only faccessat2 does. a3 is therefore whatever the guest happened to
         * leave in x3, and reading it as flags made the fake-root stat below
         * AT_SYMLINK_NOFOLLOW at random: on a symlink that answers about the
         * link (mode 0777, so X_OK is always granted) rather than the target. */
        long fl = 0;
#ifdef __NR_faccessat2
        if (nr == __NR_faccessat2)
            fl = a3;
#endif
        long dfd = a0;
#ifdef __NR_faccessat2
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
#endif
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
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        long ro = ro_refusal_name(a0, (const char *)a1, p, 0);
        if (ro)
            return ro;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }

    /* fchmodat2(dirfd, path, mode, flags): same as fchmodat but with a real
     * flags word, so unlike its predecessor it can chmod a symlink itself. */
#ifdef __NR_fchmodat2
    case __NR_fchmodat2: {
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        long ro = ro_refusal_name(a0, (const char *)a1, p,
                                  deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
        if (ro)
            return ro;
        return chattr_result(reissue(a0, (long)p, a2, a3, a4, a5, nr));
    }
#endif

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
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        if (ro_denied(p))
            return -EROFS;
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_unlinkat);
        if (r == 0 && dec)
            cng_l2s_decref(data, cnt);
        return r;
    }

    /* utimensat(dirfd, path, times, flags): if the target is one of our
     * link2symlink entries, redirect to its backing file (the guest thinks it's
     * a regular file, so a set-then-lstat-verify — as apk does to preserve mtime
     * — must land on the backing, not the link). Setting an explicit time needs
     * ownership; under fake-root fake success on EPERM. */
    case __NR_utimensat: {
        char data[CNG_PATH_MAX];
        unsigned long cnt;
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX];
            if (cng_resolve_at(a0, (const char *)a1, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, &cnt) == 1) {
                /* The backing file is in the store, which no bind covers: the
                 * mount that governs this call is the one the NAME sits under
                 * (see ro_denied_l2s). Asked here, before the redirect, since
                 * the check below never sees the guest's name again. */
                if (ro_denied(hnf))
                    return -EROFS;
                long r = cng_syscall6(CNG_AT_FDCWD, (long)data, a2, 0, 0, 0,
                                      __NR_utimensat);
                if (cng_fake_root() && (r == -EPERM || r == -EACCES))
                    return 0;
                return r;
            }
        }
        int deref = !((int)a3 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
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
        int bounce = a2 && (cng_g_l2s || cng_g_fake_id);
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
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        long r = reissue(a0, (long)p, ob, a3, a4, a5, __NR_newfstatat);
        if (r == 0 && cng_g_l2s && a2 && ((int)a3 & CNG_AT_EMPTY_PATH)) {
            const char *gp = (const char *)a1; /* fstat-by-fd form */
            if (!gp || !gp[0])
                cng_l2s_fix_fd(a0, sb);
        }
        if (r == 0 && cng_g_fake_id && a2)
            stat_remap(sb);
        if (r == 0 && bounce && cng_user_copyout((void *)a2, sb, sizeof sb) < 0)
            return -EFAULT;
        return r;
    }
    case __NR_statx: {
        /* Bounced on the same terms as newfstatat above. */
        int bounce = a4 && (cng_g_l2s || cng_g_fake_id);
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
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        long r = reissue(a0, (long)p, a2, a3, ob, a5, __NR_statx);
        if (r == 0 && cng_g_l2s && a4 && ((int)a2 & CNG_AT_EMPTY_PATH)) {
            const char *gp = (const char *)a1; /* fstat-by-fd form */
            if (!gp || !gp[0])
                cng_l2s_fix_fd_statx(a0, sx);
        }
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
                if (ro_denied(hnf)) /* the name's mount, not the store's */
                    return -EROFS;
                return chattr_result(reissue(CNG_AT_FDCWD, (long)data, a2, a3,
                                             0, a5, __NR_fchownat));
            }
        }
        int deref = !((int)a4 & CNG_AT_SYMLINK_NOFOLLOW);
        const char *p = xlate(a0, (const char *)a1, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
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
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        /* A link2symlink entry presents as a regular file: readlink must fail
         * with EINVAL rather than leak the backing path — including through a
         * real dirfd, which xlate passes through untranslated. */
        if (cng_g_l2s) {
            char hnf[CNG_PATH_MAX], data[CNG_PATH_MAX];
            if (cng_resolve_at(a0, gp, 0, hnf, sizeof hnf) == 0 &&
                cng_l2s_resolve(hnf, data, sizeof data, 0) == 1)
                return -EINVAL;
        }
        long r = reissue(a0, (long)p, a2, a3, a4, a5, __NR_readlinkat);
        /* An fd link reports a HOST path (the kernel names the open file
         * description), and a map_files link the host path of the mapped file.
         * Map them back into the guest view so the guest never sees where its
         * rootfs really lives — `ls -l /proc/self/fd`, Alpine's /dev/fd, and
         * lsof's map_files walk all land here. Targets outside the view
         * (memfd:, pipe:[..], a host-only file) are left exactly as the kernel
         * wrote them. */
        if (r > 0 && r < bufsiz && rl_may_fdlink(a0, gp)) {
            char canon[CNG_PATH_MAX];
            if (at_canon(a0, gp, canon, sizeof canon) == 0) {
                size_t pl = proc_pid_prefix(canon, 0);
                if (pl && (!strncmp(canon + pl, "fd/", 3) ||
                           !strncmp(canon + pl, "map_files/", 10))) {
                    char tgt[CNG_PATH_MAX], guest[CNG_PATH_MAX];
                    /* The kernel wrote this buffer, but that says nothing about
                     * reading it back a syscall later: the guest owns it and can
                     * unmap it in between, so it is taken like any other guest
                     * range rather than dereferenced. */
                    if ((size_t)r < sizeof tgt &&
                        cng_user_copyin(tgt, (const char *)a2, (size_t)r) == 0 &&
                        tgt[0] == '/') {
                        tgt[r] = '\0';
                        if (cng_fs_untranslate(cng_g_fs, tgt, guest,
                                               sizeof guest) == 0) {
                            size_t gl = strlen(guest);
                            if (gl > (size_t)bufsiz)
                                gl = (size_t)bufsiz;
                            /* A bind can make the guest spelling longer than
                             * the host one, so this may write past what the
                             * kernel validated — the copy asks as it goes. */
                            if (cng_user_copyout((char *)a2, guest, gl) < 0)
                                return -EFAULT;
                            r = (long)gl;
                        }
                    }
                }
            }
        }
        return r;
    }

    /* symlinkat(target, newdirfd, linkpath): translate only the linkpath. */
    case __NR_symlinkat: {
        const char *lp = xlate(a1, (const char *)a2, b2, sizeof b2, 0);
        if (lp == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        if (ro_denied(lp))
            return -EROFS;
        return reissue(a0, a1, (long)lp, a3, a4, a5, __NR_symlinkat);
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
        return chattr_result(reissue(a0, a1, a2, a3, a4, a5, nr));

    /* fstat(fd): no path, but the fd may name an l2s backing file whose
     * st_nlink must reflect the live group count (tar/rsync/ls stat open
     * fds). Trapped only under -l; the fake-id remap rides along. */
    case __NR_fstat: {
        /* Bounced whenever anything here is going to edit the answer — see
         * newfstatat above for why the guest's buffer is not the place to do
         * that. With nothing to edit, the kernel fills it directly. */
        int bounce = a1 && (cng_g_l2s || cng_g_fake_id);
        char sb[STAT_BUF_SIZE];
        long r = reissue(a0, bounce ? (long)sb : a1, a2, a3, a4, a5,
                         __NR_fstat);
        if (r == 0 && bounce) {
            if (cng_g_l2s)
                cng_l2s_fix_fd(a0, sb);
            if (cng_g_fake_id)
                stat_remap(sb);
            if (cng_user_copyout((void *)a1, sb, sizeof sb) < 0)
                return -EFAULT;
        }
        return r;
    }

    case __NR_getdents64:
        return do_getdents64(a0, a1, a2, a3, a4, a5);

    /* clone with CLONE_VFORK (only these are trapped; see seccomp.c): a
     * vfork-style spawn shares the parent's address space and suspends the
     * parent until the child execs. Our execve is emulated in-process, so a
     * shared-VM child would load the new program over the parent's memory and
     * never issue the real execve that resumes the parent. Strip CLONE_VM and
     * CLONE_VFORK so it becomes an ordinary COW fork: the child gets a private
     * copy, the emulated execve happens there, and the parent continues (the
     * child's execve closes the O_CLOEXEC notify pipe, signalling success). */
    /* The SIGSYS path handles clone in cng_sigsys_body (it needs the ucontext to
     * fix the child's stack). This branch is only reached via an M8 trampoline
     * (-R); best-effort strip of the shared-VM flags. */
    /* clone: trapped for process creation only (a thread keeps CLONE_VM and
     * runs natively). CLONE_VM|CLONE_VFORK are stripped — our execve is
     * emulated in-process, so a child sharing our address space would corrupt
     * it — and the parent then publishes the child into the PID registry, which
     * is what makes the new process visible as a guest one. The child cannot do
     * this itself: nothing guarantees it makes another traced syscall before
     * something reads its /proc entry. */
    case __NR_clone: {
        /* Decided from the flags the guest asked for, before the conversion
         * below erases CLONE_VFORK. */
        int ev = cng_pt_clone_event((unsigned long)a0);
        /* Sampled before the clone: in the child the per-task lookup is keyed
         * by a tid that has no entry yet, so it would answer NULL. The frame
         * itself is on the trampoline's stack, which the child inherits at the
         * same address. */
        struct cng_uregs *ur = cng_pt_cur_regs();
        long flags = a0 & ~(long)(CNG_CLONE_VM | CNG_CLONE_VFORK);
        long r = cng_syscall6(flags, a1, a2, a3, a4, a5, __NR_clone);
        if (r > 0) {
            cng_procreg_fork((int)r);
            if (ur) {
                cng_pt_report_event(ur, ev, (u64)r);
                /* Our fork does not suspend the parent the way a real vfork
                 * would, so "vfork done" is reported as soon as the child is. */
                if (a0 & CNG_CLONE_VFORK)
                    cng_pt_report_event(ur, CNG_PTRACE_EVENT_VFORK_DONE, (u64)r);
            }
        } else if (r == 0) {
            cng_shm_fork_child(); /* the child inherited our shm attaches */
            if (ur)
                cng_pt_fork_child(ur, ev);
        }
        return r;
    }

    /* System V shared memory. Android's seccomp filter denies all four
     * outright, so they are served from the broker instead of the host kernel
     * — see shm.c. Trapped unconditionally (seccomp.c), so the guest gets one
     * shm namespace whatever the host's own SysV IPC would have allowed. */
#ifdef __NR_shmget
    case __NR_shmget:
#endif
#ifdef __NR_shmat
    case __NR_shmat:
#endif
#ifdef __NR_shmdt
    case __NR_shmdt:
#endif
#ifdef __NR_shmctl
    case __NR_shmctl:
#endif
    {
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
#ifdef __NR_preadv2
    case __NR_preadv2:
#endif
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
#ifdef __NR_execveat
    case __NR_execveat:
        return cng_execve_tramp((int)a0, (const char *)a1, (char **)a2,
                                (char **)a3, (int)a4);
#endif

    /* rename: two translated paths. If the destination is one of our
     * link2symlink names, it is replaced by the rename, so drop its group's
     * refcount (apk installs by renaming a temp file over the final name) —
     * except under RENAME_EXCHANGE, where both names live on. A legacy-format
     * source (bare-basename target) moving to another directory is repointed
     * at its (unmoved) data file afterwards. */
    case __NR_renameat:
    case __NR_renameat2: {
        const char *op = xlate(a0, (const char *)a1, b1, sizeof b1, 0);
        if (op == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        const char *np = xlate(a2, (const char *)a3, b2, sizeof b2, 0);
        if (np == XLATE_TOOLONG)
            return -ENAMETOOLONG;
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
        if (r == 0 && dec)
            cng_l2s_decref(data, cnt);
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
        int follow = ((int)a4 & CNG_AT_SYMLINK_FOLLOW) ? 1 : 0;
        int empty = ((int)a4 & CNG_AT_EMPTY_PATH) && (!sp || !sp[0]);
        char srch[CNG_PATH_MAX], dsth[CNG_PATH_MAX];
        /* AT_SYMLINK_FOLLOW is applied at guest level (the host must never
         * follow a guest symlink's target itself); the host call then runs
         * with no flags. Link-by-fd (AT_EMPTY_PATH, the O_TMPFILE publish
         * idiom) goes through /proc/self/fd, which the host must follow. */
        if (empty) {
            proc_fd_path(a0, srch);
        } else if (cng_resolve_at(a0, sp, follow, srch, sizeof srch) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: src unresolved (%s)\n",
                            sp ? sp : "(null)");
            return -ENOENT;
        }
        if (cng_resolve_at(a2, (const char *)a3, 0, dsth, sizeof dsth) != 0) {
            if (cng_g_debug)
                cng_dprintf(2, "[cng] linkat: dst unresolved (%s)\n",
                            a3 ? (const char *)a3 : "(null)");
            return -ENOENT;
        }
        /* Only the new name is created, so only the destination end matters —
         * linking *from* a read-only mount is allowed, as on Linux. Checked
         * after both ends resolve so a bad source still reports ENOENT. */
        if (ro_denied(dsth))
            return -EROFS;
        long r;
        if (cng_g_l2s && cng_g_l2s_force)
            r = -EPERM; /* CNG_L2S_FORCE: exercise the fallback directly */
        else
            r = reissue(CNG_AT_FDCWD, (long)srch, CNG_AT_FDCWD, (long)dsth,
                        empty ? CNG_AT_SYMLINK_FOLLOW : 0, 0, __NR_linkat);
        if (cng_g_debug && r != 0)
            cng_dprintf(2, "[cng] linkat %s -> %s real=%ld\n", srch, dsth, r);
        /* Some Android builds deny app-data hardlinks with ENOENT rather
         * than EACCES/EPERM. ENOENT is only believable when the source is
         * really absent — if it exists, treat the refusal like any other
         * denial. (A genuinely missing dst parent still surfaces as ENOENT
         * from the fallback's own symlink step.) */
        if (cng_g_l2s && r == -ENOENT) {
            char stt[144];
            if (CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, srch, stt,
                        CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0)
                r = -EPERM;
        }
        if (cng_g_l2s &&
            (r == -EPERM || r == -EMLINK || r == -EXDEV || r == -ENOSYS ||
             r == -EACCES || r == -EOPNOTSUPP)) {
            if (empty) {
                /* If the fd names a live file, link its real path — an fd
                 * onto a group's data file then bumps that group. Anonymous
                 * or deleted files keep the /proc path: the fallback's
                 * materialize copies the contents. */
                char tgt[CNG_PATH_MAX], stt[144];
                long tn = sys_readlinkat(CNG_AT_FDCWD, srch, tgt,
                                         sizeof tgt - 1);
                if (tn > 0) {
                    tgt[tn] = '\0';
                    if (tgt[0] == '/' &&
                        CNG_SYS(__NR_newfstatat, CNG_AT_FDCWD, tgt, stt,
                                CNG_AT_SYMLINK_NOFOLLOW, 0, 0) == 0)
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
        long fd = cng_nl_socket(a0, a1, a2);
        if (fd >= 0)
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
        int sx = cng_sun_in(&x, (const void *)aa, al, nr != __NR_bind);
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
        cng_sun_done(&x); /* after the syscall: the kernel walked the dirfd */
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
        int sx = a1 ? cng_sun_in(&x, mh.name, (long)mh.namelen, 1) : 0;
        if (sx > 0) {
            mh.name = x.buf;
            mh.namelen = (unsigned)x.len;
            r = reissue(a0, (long)&mh, a2, a3, a4, a5, nr);
        } else if (sx < 0) {
            r = sx;
        } else {
            r = reissue(a0, a1, a2, a3, a4, a5, nr);
        }
        cng_sun_done(&x);
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
                int sx = cng_sun_in(&x, mh.name, (long)mh.namelen, 1);
                if (sx > 0) {
                    mh.name = x.buf;
                    mh.namelen = (unsigned)x.len;
                }
                if (sx < 0)
                    r = sx;
                else
                    r = reissue(a0, (long)&mh, a3, 0, 0, 0, __NR_sendmsg);
                cng_sun_done(&x);
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
        long e = sun_deliver(ab, al, aa, alp);
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
         * bounce the single-address calls get. The header is copied to point at
         * ours; the three fields the kernel writes back into the header it was
         * given (msg_namelen, msg_controllen, msg_flags) then have to be carried
         * over to the guest's own, or a caller loses MSG_TRUNC/MSG_CTRUNC and
         * the length of the control data it is about to walk. */
        struct cng_msghdr *g = (struct cng_msghdr *)a1;
        struct cng_msghdr snap; /* our copy of the guest's header, taken once */
        if (!a1 || cng_user_copyin(&snap, g, sizeof snap) < 0)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        if (!snap.name || !snap.namelen)
            return reissue(a0, a1, a2, a3, a4, a5, nr);
        char ab[CNG_SOCKADDR_MAX];
        struct cng_msghdr mh = snap;
        mh.name = ab;
        mh.namelen = sizeof ab;
        long r = reissue(a0, (long)&mh, a2, a3, a4, a5, nr);
        if (r < 0)
            return r;
        /* Written back whole rather than field by field: the guest's header is
         * ours to restore in full, and the copy that carries it also validates
         * it, so there is no zeroed remainder to worry about either. */
        struct cng_msghdr back = snap;
        back.controllen = mh.controllen;
        back.flags = mh.flags;
        if (cng_user_copyout(g, &back, sizeof back) < 0)
            return -EFAULT;
        long e = sun_deliver(ab, mh.namelen, (long)snap.name, (long)&g->namelen);
        return e ? e : r;
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
            struct cng_mmsghdr h;
            if (cng_user_copyin(&h, m, sizeof h) < 0) {
                r = -EFAULT;
                break;
            }
            char ab[CNG_SOCKADDR_MAX];
            struct cng_msghdr snap = h.hdr; /* our copy, not the guest's live one */
            struct cng_msghdr mh = snap;
            if (snap.name) {
                mh.name = ab;
                mh.namelen = sizeof ab;
            }
            long fl = a3 & ~(long)CNG_MSG_WAITFORONE;
            if (got && first_only)
                fl |= CNG_MSG_DONTWAIT;
            long n = reissue(a0, (long)&mh, fl, 0, 0, 0, __NR_recvmsg);
            if (n < 0) {
                r = n;
                break;
            }
            h.hdr = snap;
            h.hdr.controllen = mh.controllen;
            h.hdr.flags = mh.flags;
            h.len = (unsigned)n;
            if (cng_user_copyout(m, &h, sizeof h) < 0) {
                r = -EFAULT;
                break;
            }
            if (snap.name) {
                long e = sun_deliver(ab, mh.namelen, (long)snap.name,
                                     (long)&m->hdr.namelen);
                if (e) {
                    r = e; /* the message is consumed either way, as it is
                            * for the single form */
                    break;
                }
            }
            got++;
            if (mmsg_deadline_hit(&dl))
                break;
            /* Out-of-band data ends the batch where the kernel ends it. */
            if (mh.flags & CNG_MSG_OOB)
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
     * --fake-id. */
    case __NR_getsockopt: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0 && cng_g_fake_id && a1 == CNG_SOL_SOCKET &&
            a2 == CNG_SO_PEERCRED && a3 && a4) {
            /* Read back and rewritten in a copy of ours: the kernel filled
             * these twelve bytes, which says nothing about them still being
             * there now (see uaccess.c). */
            unsigned len, uc[3]; /* struct ucred: pid,uid,gid */
            if (cng_user_copyin(&len, (void *)a4, sizeof len) == 0 &&
                len >= sizeof uc &&
                cng_user_copyin(uc, (void *)a3, sizeof uc) == 0) {
                uc[1] = cng_remap_uid(uc[1]);
                uc[2] = cng_remap_gid(uc[2]);
                if (cng_user_copyout((void *)a3, uc, sizeof uc) < 0)
                    return -EFAULT;
            }
        }
        return r;
    }

    /* Extended attributes: the path is a0 and there is no dirfd, so this is a
     * plain translate + reissue. The "l" forms do not follow a final symlink;
     * the setters and removers mutate, so a :ro bind refuses them. */
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
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        if (writes) {
            long ro = ro_refusal_name(CNG_AT_FDCWD, (const char *)a0, p,
                                      deref ? 0 : CNG_AT_SYMLINK_NOFOLLOW);
            if (ro)
                return ro;
        }
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
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
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a1, b1, sizeof b1, deref);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        return reissue(a0, (long)p, a2, a3, a4, a5, nr);
    }

    case __NR_truncate:
    case __NR_statfs: {
        const char *p =
            xlate(CNG_AT_FDCWD, (const char *)a0, b1, sizeof b1, 1);
        if (p == XLATE_TOOLONG)
            return -ENAMETOOLONG;
        if (nr == __NR_truncate) { /* statfs only reads */
            long ro = ro_refusal_name(CNG_AT_FDCWD, (const char *)a0, p, 0);
            if (ro)
                return ro;
        }
        return reissue((long)p, a1, a2, a3, a4, a5, nr);
    }

    case __NR_chdir: {
        const char *gp = (const char *)a0;
        const char *hp = xlate(CNG_AT_FDCWD, gp, b1, sizeof b1, 1);
        if (hp == XLATE_TOOLONG)
            return -ENAMETOOLONG;
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
                cng_procreg_set_cwd(cng_g_fs->cwd); /* /proc/<pid>/cwd */
            }
        }
        return r;
    }

    /* fchdir: the fd already refers to a translated host dir, so perform it,
     * then resync the virtual cwd from the real cwd (reverse-translated). This
     * is what apk relies on when running package scripts. */
    case __NR_fchdir: {
        long r = cng_syscall6(a0, 0, 0, 0, 0, 0, __NR_fchdir);
        if (r == 0) {
            char hc[CNG_PATH_MAX], gc[CNG_PATH_MAX];
            if (sys_getcwd(hc, sizeof hc) > 0 &&
                cng_fs_untranslate(cng_g_fs, hc, gc, sizeof gc) == 0) {
                cng_fs_set_cwd(cng_g_fs, gc);
                cng_procreg_set_cwd(cng_g_fs->cwd);
            }
        }
        return r;
    }

    case __NR_getcwd: {
        char *buf = (char *)a0;
        unsigned long size = (unsigned long)a1;
        size_t len = strlen(cng_g_fs->cwd) + 1;
        /* ERANGE is decided before the buffer is touched, as the kernel does —
         * which also keeps the write probe's zeroing invisible: it only ever
         * runs immediately before the copy that overwrites it. */
        if (len > size)
            return -ERANGE;
        if (cng_user_copyout(buf, cng_g_fs->cwd, len) < 0)
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
        long r = cng_syscall6(CNG_AT_FDCWD, (long)hp, (long)sb, 0, 0, 0,
                              __NR_newfstatat);
        if (r < 0)
            return r;
        if ((*(unsigned *)(sb + STAT_MODE_OFF) & 0170000) != 0040000)
            return -ENOTDIR;
        cng_fs_chroot(cng_g_fs, gc, hp);
        return 0;
    }

    /* Protect our SIGSYS handler: ignore guest attempts to replace it, and
     * strip SIGSYS from any handler's sa_mask so it can't be masked while a
     * guest handler runs. Kernel struct sigaction: handler,flags,restorer,mask
     * (mask at offset 24). */
    case __NR_rt_sigaction: {
        if ((int)a0 == CNG_SIGSYS)
            return 0;
        /* While the task is traced, ptsig.c owns the real disposition of every
         * signal (a tracee must stop before its own handler runs), and it owns
         * the kick signal's slot always. It answers from its mirror of what the
         * guest asked for; otherwise it just records and lets this through. */
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
     * peer runs natively. */
    case __NR_process_vm_readv:
    case __NR_process_vm_writev: {
        long out;
        if (cng_pt_vm_rw(nr, a0, (u64)a1, (u64)a2, (u64)a3, (u64)a4, &out))
            return out;
        return reissue(a0, a1, a2, a3, a4, a5, nr);
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

    /* ioctl, trapped only for the SIOCxIF request band (seccomp.c tests the
     * request in BPF, so every other ioctl runs native). The interface getters
     * are answered from the same enumeration the netlink dumps are built on —
     * a guest told by `ip addr` that it has only loopback must not be shown the
     * host's whole interface list by `ifconfig`. The setters and anything else
     * in the band fall through to the host, which refuses them to an
     * unprivileged process exactly as it should. */
    case __NR_ioctl: {
        long r = 0;
        if (cng_nl_ioctl((int)a0, (unsigned long)a1, (void *)a2, &r))
            return r;
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

    /* POSIX timers do not survive an execve, and ours is emulated — the address
     * space stays, so a timer would go on firing into a program that never
     * armed it, through a handler that no longer exists. Nothing enumerates a
     * process's timers, so the ids are recorded as they are handed out. */
    case __NR_timer_create: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        int id;
        if (r == 0 && a2 && cng_user_copyin(&id, (void *)a2, sizeof id) == 0)
            cng_timer_note(id);
        return r;
    }
    case __NR_timer_delete: {
        long r = reissue(a0, a1, a2, a3, a4, a5, nr);
        if (r == 0)
            cng_timer_forget((int)a0);
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
        static int guest_nnp = 0;
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
            guest_nnp = 1;
            return 0; /* already set for real, at install */
        case CNG_PR_GET_NO_NEW_PRIVS:
            if (a1 || a2 || a3 || a4)
                return -EINVAL; /* the kernel's own check, as for the setter */
            return guest_nnp;
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
        r->x[0] = (u64)cng_dispatch(nr, (long)r->x[0], (long)r->x[1],
                                    (long)r->x[2], (long)r->x[3], (long)r->x[4],
                                    (long)r->x[5], 0);
        return;
    }
    if (!cng_pt_syscall_entry(r, &nr)) {
        cng_pt_syscall_exit(r); /* cancelled: x0 is the tracer's own answer */
        return;
    }
    r->x[0] = (u64)cng_dispatch(nr, (long)r->x[0], (long)r->x[1], (long)r->x[2],
                                (long)r->x[3], (long)r->x[4], (long)r->x[5], 0);
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
