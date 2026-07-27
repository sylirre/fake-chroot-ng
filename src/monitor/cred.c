/* Fake user identity (--fake-id): the synthetic credential set and the
 * credential syscalls that read and mutate it.
 *
 * The set (cng_g_cred) is process-wide, seeded from the configured uid:gid, and
 * — because the guest forks for real — inherited across fork() like the kernel's
 * own credentials. The setter syscalls follow real POSIX privilege rules so that
 * privilege-dropping programs (su, sshd-style daemons, package post-install
 * scripts) observe correct behaviour: while effective-uid 0 any change is
 * allowed, otherwise an id may only move among the current real/effective/saved
 * values. Capabilities are reported as the full set while fake-root, none
 * otherwise, which is what fakeroot-style installs check.
 *
 * These syscalls are trapped only when --fake-id is active (see seccomp.c), so
 * cng_cred_handle's !fake_id branch is reached only via an -R trampoline.
 */
#include "cng/monitor.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

int cng_g_fake_id = 0;
int cng_g_fake_id_explicit = 0;
unsigned cng_g_fake_uid = 0;
unsigned cng_g_fake_gid = 0;
unsigned cng_g_host_uid = 0;
unsigned cng_g_host_gid = 0;
struct cng_cred cng_g_cred;
int cng_g_setuid_root = 0;
int cng_g_setgid_root = 0;

/* AArch64 struct stat field offsets (st_mode/st_uid/st_gid). */
#define ST_MODE_OFF 16
#define ST_UID_OFF  24
#define ST_GID_OFF  28

void cng_cred_seed(void) {
    struct cng_cred *c = &cng_g_cred;
    c->ruid = c->euid = c->suid = c->fsuid = cng_g_fake_uid;
    c->rgid = c->egid = c->sgid = c->fsgid = cng_g_fake_gid;
    c->ngroups = 0;
}

void cng_cred_setup(unsigned host_uid, unsigned host_gid) {
    cng_g_host_uid = host_uid;
    cng_g_host_gid = host_gid;
    /* An identity only implied by --setuid-root/--setgid-root defaults to the
     * real invoking id, not 0:0 — so those flags enable setuid binaries without
     * silently turning the guest into root. An explicit -u/--fake-id wins. */
    if (!cng_g_fake_id_explicit) {
        cng_g_fake_uid = host_uid;
        cng_g_fake_gid = host_gid;
    }
    cng_cred_seed();
}

void cng_cred_exec(const char *host) {
    if (!cng_g_fake_id || !host ||
        (!cng_g_setuid_root && !cng_g_setgid_root))
        return;
    unsigned char st[128]; /* AArch64 struct stat is 128 bytes */
    if (cng_syscall6(CNG_AT_FDCWD, (long)host, (long)st, 0, 0, 0,
                     __NR_newfstatat) != 0)
        return;
    unsigned mode = *(unsigned *)(st + ST_MODE_OFF);
    struct cng_cred *c = &cng_g_cred;
    /* setuid/setgid-on-exec: effective, saved, and fs id take the file's visible
     * owner/group, which cng_exec_vis_* reports as 0 for a setuid/setgid regular
     * file under the flags. ruid/rgid (the caller's real id) are unchanged. */
    if (cng_g_setuid_root && (mode & CNG_S_ISUID) &&
        (mode & CNG_S_IFMT) == CNG_S_IFREG)
        c->euid = c->suid = c->fsuid =
            cng_exec_vis_uid(*(unsigned *)(st + ST_UID_OFF), mode);
    if (cng_g_setgid_root && (mode & CNG_S_ISGID) &&
        (mode & CNG_S_IFMT) == CNG_S_IFREG)
        c->egid = c->sgid = c->fsgid =
            cng_exec_vis_gid(*(unsigned *)(st + ST_GID_OFF), mode);
}

#define ID_KEEP ((unsigned)-1) /* setres*id / setre*id "leave unchanged" */

static int cred_priv(const struct cng_cred *c) { return c->euid == 0; }

/* Is v one of the current real/effective/saved ids? (unprivileged constraint) */
static int in_uset(const struct cng_cred *c, unsigned v) {
    return v == c->ruid || v == c->euid || v == c->suid;
}
static int in_gset(const struct cng_cred *c, unsigned v) {
    return v == c->rgid || v == c->egid || v == c->sgid;
}

/* setuid(2): privileged sets all four; unprivileged may set euid/fsuid only to
 * its real or saved uid. setgid(2) is the exact mirror. */
static long do_setuid(struct cng_cred *c, unsigned u) {
    if (cred_priv(c)) {
        c->ruid = c->euid = c->suid = c->fsuid = u;
        return 0;
    }
    if (u == c->ruid || u == c->suid) {
        c->euid = c->fsuid = u;
        return 0;
    }
    return -EPERM;
}
static long do_setgid(struct cng_cred *c, unsigned g) {
    if (cred_priv(c)) {
        c->rgid = c->egid = c->sgid = c->fsgid = g;
        return 0;
    }
    if (g == c->rgid || g == c->sgid) {
        c->egid = c->fsgid = g;
        return 0;
    }
    return -EPERM;
}

/* setreuid(2): each supplied id must be a current id when unprivileged. The
 * saved uid follows the new euid if ruid changed or euid moved off ruid. */
static long do_setreuid(struct cng_cred *c, unsigned r, unsigned e) {
    struct cng_cred nc = *c;
    if (r != ID_KEEP) {
        if (!cred_priv(c) && r != c->ruid && r != c->euid)
            return -EPERM;
        nc.ruid = r;
    }
    if (e != ID_KEEP) {
        if (!cred_priv(c) && e != c->ruid && e != c->euid && e != c->suid)
            return -EPERM;
        nc.euid = e;
    }
    if (r != ID_KEEP || (e != ID_KEEP && e != c->ruid))
        nc.suid = nc.euid;
    nc.fsuid = nc.euid;
    *c = nc;
    return 0;
}
static long do_setregid(struct cng_cred *c, unsigned r, unsigned e) {
    struct cng_cred nc = *c;
    if (r != ID_KEEP) {
        if (!cred_priv(c) && r != c->rgid && r != c->egid)
            return -EPERM;
        nc.rgid = r;
    }
    if (e != ID_KEEP) {
        if (!cred_priv(c) && e != c->rgid && e != c->egid && e != c->sgid)
            return -EPERM;
        nc.egid = e;
    }
    if (r != ID_KEEP || (e != ID_KEEP && e != c->rgid))
        nc.sgid = nc.egid;
    nc.fsgid = nc.egid;
    *c = nc;
    return 0;
}

/* setresuid(2): unprivileged may set each of r/e/s only to a current id. */
static long do_setresuid(struct cng_cred *c, unsigned r, unsigned e,
                         unsigned s) {
    if (!cred_priv(c)) {
        if (r != ID_KEEP && !in_uset(c, r))
            return -EPERM;
        if (e != ID_KEEP && !in_uset(c, e))
            return -EPERM;
        if (s != ID_KEEP && !in_uset(c, s))
            return -EPERM;
    }
    if (r != ID_KEEP)
        c->ruid = r;
    if (e != ID_KEEP)
        c->euid = e;
    if (s != ID_KEEP)
        c->suid = s;
    c->fsuid = c->euid;
    return 0;
}
static long do_setresgid(struct cng_cred *c, unsigned r, unsigned e,
                         unsigned s) {
    if (!cred_priv(c)) {
        if (r != ID_KEEP && !in_gset(c, r))
            return -EPERM;
        if (e != ID_KEEP && !in_gset(c, e))
            return -EPERM;
        if (s != ID_KEEP && !in_gset(c, s))
            return -EPERM;
    }
    if (r != ID_KEEP)
        c->rgid = r;
    if (e != ID_KEEP)
        c->egid = e;
    if (s != ID_KEEP)
        c->sgid = s;
    c->fsgid = c->egid;
    return 0;
}

/* setfsuid/setfsgid(2): return the previous fs id; change it only to a current
 * id (or anything, when privileged). Never fails. */
static long do_setfsuid(struct cng_cred *c, unsigned u) {
    unsigned old = c->fsuid;
    if (u != ID_KEEP && (cred_priv(c) || u == c->ruid || u == c->euid ||
                         u == c->suid || u == c->fsuid))
        c->fsuid = u;
    return old;
}
static long do_setfsgid(struct cng_cred *c, unsigned g) {
    unsigned old = c->fsgid;
    if (g != ID_KEEP && (cred_priv(c) || g == c->rgid || g == c->egid ||
                         g == c->sgid || g == c->fsgid))
        c->fsgid = g;
    return old;
}

/* The group list is guest memory, so it is validated before it is walked: the
 * kernel answers -EFAULT for a bad one, and we run with SIGSEGV masked. */
static long do_setgroups(struct cng_cred *c, int n, const unsigned *g) {
    if (!cred_priv(c))
        return -EPERM;
    if (n < 0 || n > CNG_NGROUPS_MAX)
        return -EINVAL;
    if (n && !cng_user_readable(g, (unsigned long)n * sizeof *g))
        return -EFAULT;
    for (int i = 0; i < n; i++)
        c->groups[i] = g[i];
    c->ngroups = n;
    return 0;
}
static long do_getgroups(const struct cng_cred *c, int size, unsigned *g) {
    int n = c->ngroups;
    if (size == 0)
        return n;
    if (size < n)
        return -EINVAL;
    if (n && !cng_user_writable(g, (unsigned long)n * sizeof *g))
        return -EFAULT;
    for (int i = 0; i < n; i++)
        g[i] = c->groups[i];
    return n;
}

/* capget/capset: the guest's own capability view. Under fake-root the full set
 * is reported and any change accepted; otherwise none / EPERM, like the host.
 * The header selects v1 (one 32-bit data block) or v2/v3 (two). Pointers are
 * this process's own memory, so they are read/written directly. */
struct cap_header {
    unsigned version;
    int pid;
};
struct cap_data {
    unsigned effective, permitted, inheritable;
};

static long do_capget(const struct cap_header *hdr, struct cap_data *data) {
    if (!cng_user_readable(hdr, sizeof *hdr))
        return -EFAULT;
    if (data) {
        unsigned all = cng_fake_root() ? 0xffffffffu : 0u;
        int n = (hdr->version == 0x19980330u) ? 1 : 2; /* v1 vs v2/v3 */
        if (!cng_user_writable(data, (unsigned long)n * sizeof *data))
            return -EFAULT;
        for (int i = 0; i < n; i++) {
            data[i].effective = all;
            data[i].permitted = all;
            data[i].inheritable = 0;
        }
    }
    return 0;
}
static long do_capset(void) { return cng_fake_root() ? 0 : -EPERM; }

/* Non-faking re-issue for the -R trampoline path: consult the Android block-list
 * so a re-issue can never trap and die (see blocklist.c). */
static long reissue_cred(long nr, long a0, long a1, long a2, long a3, long a4,
                         long a5) {
    if (nr >= 0 && nr < CNG_NR_MAX && cng_blocked[nr]) {
        cng_note_blocked((int)nr);
        return -ENOSYS;
    }
    return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
}

long cng_cred_handle(long nr, long a0, long a1, long a2, long a3, long a4,
                     long a5) {
    struct cng_cred *c = &cng_g_cred;

    if (!cng_g_fake_id) {
        /* Reached only via an -R trampoline (these are trapped only under
         * --fake-id). Getters read the real ids; the setters sit on Android's
         * block-list, so emulate them rather than re-issue from a handler. */
        switch (nr) {
        case __NR_setfsuid:
        case __NR_setfsgid:
            return 0; /* previous fs id (unknown here) is reported as 0 */
        case __NR_setuid:
        case __NR_setgid:
        case __NR_setreuid:
        case __NR_setregid:
        case __NR_setresuid:
        case __NR_setresgid:
        case __NR_setgroups:
        case __NR_capset:
            cng_note_blocked((int)nr);
            return -ENOSYS;
        default:
            return reissue_cred(nr, a0, a1, a2, a3, a4, a5);
        }
    }

    switch (nr) {
    case __NR_getuid:
        return (long)c->ruid;
    case __NR_geteuid:
        return (long)c->euid;
    case __NR_getgid:
        return (long)c->rgid;
    case __NR_getegid:
        return (long)c->egid;
    /* getres*id take three out pointers. The kernel writes none of them if any
     * is bad, so validate all three first — and a NULL one is -EFAULT there
     * too, unlike the optional pointers elsewhere in this family. */
    case __NR_getresuid:
    case __NR_getresgid: {
        if (!cng_user_writable((void *)a0, sizeof(unsigned)) ||
            !cng_user_writable((void *)a1, sizeof(unsigned)) ||
            !cng_user_writable((void *)a2, sizeof(unsigned)))
            return -EFAULT;
        int u = (nr == __NR_getresuid);
        *(unsigned *)a0 = u ? c->ruid : c->rgid;
        *(unsigned *)a1 = u ? c->euid : c->egid;
        *(unsigned *)a2 = u ? c->suid : c->sgid;
        return 0;
    }
    case __NR_setuid:
        return do_setuid(c, (unsigned)a0);
    case __NR_setgid:
        return do_setgid(c, (unsigned)a0);
    case __NR_setreuid:
        return do_setreuid(c, (unsigned)a0, (unsigned)a1);
    case __NR_setregid:
        return do_setregid(c, (unsigned)a0, (unsigned)a1);
    case __NR_setresuid:
        return do_setresuid(c, (unsigned)a0, (unsigned)a1, (unsigned)a2);
    case __NR_setresgid:
        return do_setresgid(c, (unsigned)a0, (unsigned)a1, (unsigned)a2);
    case __NR_setfsuid:
        return do_setfsuid(c, (unsigned)a0);
    case __NR_setfsgid:
        return do_setfsgid(c, (unsigned)a0);
    case __NR_setgroups:
        return do_setgroups(c, (int)a0, (const unsigned *)a1);
    case __NR_getgroups:
        return do_getgroups(c, (int)a0, (unsigned *)a1);
    case __NR_capget:
        return do_capget((const struct cap_header *)a0, (struct cap_data *)a1);
    case __NR_capset:
        return do_capset();
    default:
        return -ENOSYS;
    }
}
