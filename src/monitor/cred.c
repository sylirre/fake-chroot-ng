/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
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
 * cng_cred_handle's !fake_id branch is reached through an -R trampoline, a
 * tracee's trap-everything filter, or an ambient filter's trap of a setter it
 * refuses — Android's refuses most of them (see real_set).
 */
#include "cng/monitor.h"
#include "cng/procreg.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

int cng_g_fake_id = 0;
int cng_g_fake_id_explicit = 0;
unsigned cng_g_fake_uid = 0;
unsigned cng_g_fake_gid = 0;
unsigned cng_g_host_uid = 0;
unsigned cng_g_host_gid = 0;
int cng_g_setuid_root = 0;
int cng_g_setgid_root = 0;

/* ---- the published set ---------------------------------------------------
 *
 * The set is read by every credential syscall, by the stat remap and the
 * fake-root checks, and rewritten by the setters — from any thread, and the
 * setters are what libc's setxid broadcast calls on EVERY thread at once. It
 * was one struct edited field by field: a getgroups running beside a
 * setgroups could read the new count with the old list, a getresuid the new
 * euid with the old suid. The kernel replaces a task's cred as one object
 * (commit_creds); this does the same thing the fs view does (path.c): two
 * buffers, the active one never written, a writer copies it into the other,
 * changes that and swaps the pointer, and a reader re-checks the sequence
 * after its read. cng_g_cred is the pointer.
 *
 * Every reader re-checks, a reader of a single field included. With two
 * buffers, the one a pointer named a moment ago is the one the next writer
 * fills: a getuid() that took cng_g_cred and then read ->ruid off it could
 * find the writer's memcpy under way there — the struct is four-byte aligned,
 * so a field can be mid-copy — or a setter's edits before their publication.
 * cng_cred_ids is the one way to read the ids; cng_fake_root goes through it. */
static struct cng_cred g_cred_buf[2];
const struct cng_cred *cng_g_cred = &g_cred_buf[0];
static unsigned g_cred_seq;
static long g_cred_owner;

unsigned cng_cred_read_begin(const struct cng_cred **c) {
    unsigned s = __atomic_load_n(&g_cred_seq, __ATOMIC_ACQUIRE);
    *c = __atomic_load_n(&cng_g_cred, __ATOMIC_ACQUIRE);
    return s;
}

int cng_cred_read_retry(unsigned s) {
    return __atomic_load_n(&g_cred_seq, __ATOMIC_ACQUIRE) != s;
}

static void ids_of(const struct cng_cred *c, struct cng_cred_ids *out) {
    out->ruid = c->ruid;
    out->euid = c->euid;
    out->suid = c->suid;
    out->fsuid = c->fsuid;
    out->rgid = c->rgid;
    out->egid = c->egid;
    out->sgid = c->sgid;
    out->fsgid = c->fsgid;
}

void cng_cred_ids(struct cng_cred_ids *out) {
    const struct cng_cred *c;
    do {
        unsigned s = cng_cred_read_begin(&c);
        ids_of(c, out);
        if (!cng_cred_read_retry(s))
            break;
    } while (1);
}

int cng_cred_groups(unsigned *out, struct cng_cred_ids *ids) {
    const struct cng_cred *c;
    int n;
    do {
        unsigned s = cng_cred_read_begin(&c);
        n = c->ngroups;
        if (n < 0 || n > CNG_NGROUPS_MAX)
            n = 0; /* a buffer mid-copy: the sequence has moved, and we retry */
        for (int i = 0; i < n; i++)
            out[i] = c->groups[i];
        if (ids)
            ids_of(c, ids);
        if (!cng_cred_read_retry(s))
            break;
    } while (1);
    return n;
}

int cng_fake_root(void) {
    if (!cng_g_fake_id)
        return 0;
    struct cng_cred_ids id;
    cng_cred_ids(&id);
    return id.euid == 0;
}

struct cng_cred *cng_cred_write_begin(struct cng_cred_write *w) {
    unsigned long all = ~0UL;
    CNG_SYS(__NR_rt_sigprocmask, 2 /*SIG_SETMASK*/, &all, &w->mask, 8, 0, 0);
    long me = sys_gettid();
    for (int spin = 0;; spin++) {
        long none = 0;
        if (__atomic_compare_exchange_n(&g_cred_owner, &none, me, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            break;
        if (spin > 100 && none &&
            CNG_SYS(__NR_tgkill, sys_getpid(), none, 0, 0, 0, 0) == -ESRCH)
            __atomic_compare_exchange_n(&g_cred_owner, &none, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
        CNG_SYS(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    const struct cng_cred *src = __atomic_load_n(&cng_g_cred, __ATOMIC_ACQUIRE);
    w->dst = src == &g_cred_buf[0] ? &g_cred_buf[1] : &g_cred_buf[0];
    /* The ids and the groups it has; the buffers start zeroed. */
    memcpy(w->dst, src, (unsigned long)&((struct cng_cred *)0)->groups);
    for (int i = 0; i < src->ngroups; i++)
        w->dst->groups[i] = src->groups[i];
    w->dst->ngroups = src->ngroups;
    return w->dst;
}

void cng_cred_write_end(struct cng_cred_write *w, int commit) {
    if (commit) {
        __atomic_store_n(&cng_g_cred, w->dst, __ATOMIC_RELEASE);
        __atomic_fetch_add(&g_cred_seq, 1, __ATOMIC_RELEASE);
        /* What a socket peer is told about us (procreg.h), published while
         * the lock is still ours, so a later change cannot land first. */
        cng_procreg_set_ids();
    }
    __atomic_store_n(&g_cred_owner, 0, __ATOMIC_RELEASE);
    CNG_SYS(__NR_rt_sigprocmask, 2 /*SIG_SETMASK*/, &w->mask, 0, 8, 0, 0);
}

/* AArch64 struct stat field offsets (st_mode/st_uid/st_gid). */
#define ST_MODE_OFF 16
#define ST_UID_OFF  24
#define ST_GID_OFF  28

void cng_cred_seed(void) {
    struct cng_cred_write w;
    struct cng_cred *c = cng_cred_write_begin(&w);
    c->ruid = c->euid = c->suid = c->fsuid = cng_g_fake_uid;
    c->rgid = c->egid = c->sgid = c->fsgid = cng_g_fake_gid;
    c->ngroups = 0;
    cng_cred_write_end(&w, 1);
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
    if (!cng_g_fake_id)
        return;
    struct cng_cred_write w;
    struct cng_cred *c = cng_cred_write_begin(&w);
    if (host && (cng_g_setuid_root || cng_g_setgid_root)) {
        unsigned char st[128]; /* AArch64 struct stat is 128 bytes */
        if (cng_syscall6(CNG_AT_FDCWD, (long)host, (long)st, 0, 0, 0,
                         __NR_newfstatat) == 0) {
            unsigned mode = *(unsigned *)(st + ST_MODE_OFF);
            /* setuid/setgid-on-exec: effective, saved, and fs id take the
             * file's visible owner/group, which cng_exec_vis_* reports as 0 for
             * a setuid/setgid regular file under the flags. ruid/rgid (the
             * caller's real id) are unchanged. */
            if (cng_g_setuid_root && (mode & CNG_S_ISUID) &&
                (mode & CNG_S_IFMT) == CNG_S_IFREG)
                c->euid = cng_exec_vis_uid(*(unsigned *)(st + ST_UID_OFF), mode);
            if (cng_g_setgid_root && (mode & CNG_S_ISGID) &&
                (mode & CNG_S_IFMT) == CNG_S_IFREG)
                c->egid = cng_exec_vis_gid(*(unsigned *)(st + ST_GID_OFF), mode);
        }
    }
    /* Every exec resets the saved set-ids to the effective ones, set-id bit or
     * not, and that is the rule that makes a privilege drop permanent. Skipping
     * it left a saved 0 in place across the exec: a program that had been
     * elevated, had dropped its *effective* id only — which POSIX allows,
     * keeping suid at 0 so it can come back — and then exec'd anything at all
     * handed the new program a root it could still take. The kernel closes that
     * at the exec; here the chain went on carrying it.
     *
     * Runs whatever the flags are, since it is the exec that does this and not
     * the set-id bit, and outside the stat above, whose failure must not skip
     * it either. */
    c->suid = c->fsuid = c->euid;
    c->sgid = c->fsgid = c->egid;
    cng_cred_write_end(&w, 1);
}

#define ID_KEEP ((unsigned)-1) /* setres*id / setre*id "leave unchanged" */

/* The fake set's privilege is an effective uid of 0, which is what it reports
 * the full capability set for. The rules below take it as an argument, since
 * the host's own set (cng_cred_handle without --fake-id) is judged the way the
 * kernel judges it: by CAP_SETUID for a uid, CAP_SETGID for a gid or groups. */
static int cred_priv(const struct cng_cred *c) { return c->euid == 0; }

/* Is v one of the current real/effective/saved ids? (unprivileged constraint) */
static int in_uset(const struct cng_cred *c, unsigned v) {
    return v == c->ruid || v == c->euid || v == c->suid;
}
static int in_gset(const struct cng_cred *c, unsigned v) {
    return v == c->rgid || v == c->egid || v == c->sgid;
}

/* setuid(2): privileged sets all four; unprivileged may set euid/fsuid only to
 * its real or saved uid. setgid(2) is the exact mirror. (uid_t)-1 is not an id
 * at all here — it is INVALID_UID, refused with EINVAL before any privilege
 * question is asked (measured; the "leave unchanged" reading of -1 belongs to
 * the setreuid/setresuid family only, and was being applied to these two,
 * which installed 4294967295 as every id). */
static long do_setuid(struct cng_cred *c, int priv, unsigned u) {
    if (u == ID_KEEP)
        return -EINVAL;
    if (priv) {
        c->ruid = c->euid = c->suid = c->fsuid = u;
        return 0;
    }
    if (u == c->ruid || u == c->suid) {
        c->euid = c->fsuid = u;
        return 0;
    }
    return -EPERM;
}
static long do_setgid(struct cng_cred *c, int priv, unsigned g) {
    if (g == ID_KEEP)
        return -EINVAL;
    if (priv) {
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
static long do_setreuid(struct cng_cred *c, int priv, unsigned r,
                        unsigned e) {
    struct cng_cred nc = *c;
    if (r != ID_KEEP) {
        if (!priv && r != c->ruid && r != c->euid)
            return -EPERM;
        nc.ruid = r;
    }
    if (e != ID_KEEP) {
        if (!priv && e != c->ruid && e != c->euid && e != c->suid)
            return -EPERM;
        nc.euid = e;
    }
    if (r != ID_KEEP || (e != ID_KEEP && e != c->ruid))
        nc.suid = nc.euid;
    nc.fsuid = nc.euid;
    *c = nc;
    return 0;
}
static long do_setregid(struct cng_cred *c, int priv, unsigned r,
                        unsigned e) {
    struct cng_cred nc = *c;
    if (r != ID_KEEP) {
        if (!priv && r != c->rgid && r != c->egid)
            return -EPERM;
        nc.rgid = r;
    }
    if (e != ID_KEEP) {
        if (!priv && e != c->rgid && e != c->egid && e != c->sgid)
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
static long do_setresuid(struct cng_cred *c, int priv, unsigned r,
                         unsigned e, unsigned s) {
    if (!priv) {
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
static long do_setresgid(struct cng_cred *c, int priv, unsigned r,
                         unsigned e, unsigned s) {
    if (!priv) {
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
static long do_setfsuid(struct cng_cred *c, int priv, unsigned u) {
    unsigned old = c->fsuid;
    if (u != ID_KEEP && (priv || u == c->ruid || u == c->euid ||
                         u == c->suid || u == c->fsuid))
        c->fsuid = u;
    return old;
}
static long do_setfsgid(struct cng_cred *c, int priv, unsigned g) {
    unsigned old = c->fsgid;
    if (g != ID_KEEP && (priv || g == c->rgid || g == c->egid ||
                         g == c->sgid || g == c->fsgid))
        c->fsgid = g;
    return old;
}

/* The group list is guest memory, so it is validated before it is walked: the
 * kernel answers -EFAULT for a bad one, and we run with SIGSEGV masked. */
static long do_setgroups(struct cng_cred *c, int priv, int n,
                         const unsigned *g) {
    if (!priv)
        return -EPERM;
    if (n < 0 || n > CNG_NGROUPS_MAX)
        return -EINVAL;
    /* Into a buffer of ours first: a copy that fails partway must leave the
     * credential exactly as it was, and the kernel's own setgroups does the
     * same (groups_from_user runs before the set is installed). */
    unsigned got[CNG_NGROUPS_MAX];
    if (n && cng_user_copyin(got, g, (unsigned long)n * sizeof *got) < 0)
        return -EFAULT;
    /* ...and validated as a whole before any of it is installed, the way
     * groups_from_user() does: (gid_t)-1 is INVALID_GID, and a list carrying
     * one is EINVAL with the set left as it was. */
    for (int i = 0; i < n; i++)
        if (got[i] == ID_KEEP)
            return -EINVAL;
    for (int i = 0; i < n; i++)
        c->groups[i] = got[i];
    c->ngroups = n;
    return 0;
}
static long do_getgroups(int size, unsigned *g) {
    unsigned got[CNG_NGROUPS_MAX];
    int n = cng_cred_groups(got, 0);
    if (size == 0)
        return n;
    if (size < n)
        return -EINVAL;
    if (n && cng_user_copyout(g, got, (unsigned long)n * sizeof *g) < 0)
        return -EFAULT;
    return n;
}

static long reissue_cred(long nr, long a0, long a1, long a2, long a3, long a4,
                         long a5);

/* capget/capset: the guest's own capability view. Under fake-root the full set
 * is reported, otherwise none, and a capset is judged against that set by the
 * kernel's rules (do_capset); what it changes is not kept.
 * Another task's set is the kernel's to report, except a guest process's (see
 * do_capget).
 * The header selects v1 (one 32-bit data block) or v2/v3 (two). The pointers
 * are the guest's, so header and payload cross through cng_user_copyin/copyout
 * — read where they lie, the version that selects the block count need not
 * still be the version when the blocks are written (see uaccess.c). */
struct cap_header {
    unsigned version;
    int pid;
};
struct cap_data {
    unsigned effective, permitted, inheritable;
};

#define CAP_VER_1 0x19980330u /* one 32-bit data block */
#define CAP_VER_2 0x20071026u /* two */
#define CAP_VER_3 0x20080522u /* two; what a current kernel prefers */

/* cap_validate_magic(): how many data blocks the header asks for. An
 * unrecognised version is not a success — the kernel writes back the version it
 * does speak and fails, which is precisely how libcap and everyone else
 * discovers what to ask for. Answering 0 to it instead left the caller
 * believing its own version was supported, and then took the two-block branch
 * for it: a capget writing 24 bytes into the 12-byte buffer a v1 caller
 * allocated. */
static long cap_magic(struct cap_header *hdr, struct cap_header *out,
                      int *nblocks) {
    if (cng_user_copyin(out, hdr, sizeof *out) < 0)
        return -EFAULT;
    switch (out->version) {
    case CAP_VER_1:
        *nblocks = 1;
        return 0;
    case CAP_VER_2:
    case CAP_VER_3:
        *nblocks = 2;
        return 0;
    }
    unsigned ver = CAP_VER_3;
    if (cng_user_copyout(&hdr->version, &ver, sizeof ver) < 0)
        return -EFAULT;
    return -EINVAL;
}

static long do_capget(struct cap_header *hdr, struct cap_data *data) {
    int n = 0;
    struct cap_header h;
    long r = cap_magic(hdr, &h, &n);
    /* A probe with no data buffer is the negotiation itself, and the kernel
     * calls it a success once the version has been written back. */
    if (r != 0 || !data)
        return (!data && r == -EINVAL) ? 0 : r;
    if (h.pid < 0)
        return -EINVAL;
    /* Whose set? cap_get_target_pid() takes 0 and the caller's own tid as the
     * caller, and looks every other pid up as a task — any thread, not only a
     * group leader — answering ESRCH for one that is not there. The fake set
     * used to be synthesized for every non-negative pid, so a pid that named
     * nothing was described as fully capable (measured: ESRCH, with a pid that
     * exists answered and a bad data pointer only then EFAULT). Our own
     * threads are told apart with tgkill(sig 0), which is ESRCH unless the tid
     * is ours. Another guest process is fully capable when the ids it has
     * published (procreg.h) are a fake root's, a thread by its group's; one
     * whose ids are not there is taken to run under the configured identity,
     * as its status file is. Anything else — a host process, or a pid that is
     * not there — is the kernel's to answer, and it answers from the guest's
     * own pointers exactly as it would have. */
    unsigned all;
    if (h.pid == 0 ||
        CNG_SYS(__NR_tgkill, sys_getpid(), h.pid, 0, 0, 0, 0) == 0)
        all = cng_fake_root() ? 0xffffffffu : 0u;
    else if (cng_procreg_has_task(h.pid)) {
        struct cng_procids p;
        int tg = cng_procreg_has(h.pid) ? h.pid : cng_proc_tgid(h.pid);
        unsigned eu = cng_procreg_ids(tg, &p) && p.fake ? p.euid
                                                         : cng_g_fake_uid;
        all = eu == 0 ? 0xffffffffu : 0u;
    } else
        return reissue_cred(__NR_capget, (long)hdr, (long)data, 0, 0, 0, 0);
    struct cap_data blocks[2];
    for (int i = 0; i < n; i++) {
        blocks[i].effective = all;
        blocks[i].permitted = all;
        blocks[i].inheritable = 0;
    }
    if (cng_user_copyout(data, blocks, (unsigned long)n * sizeof *blocks) < 0)
        return -EFAULT;
    return 0;
}

/* The bits of the second data word that name a capability this kernel has:
 * sys_capset clears the others (CAP_LAST_U32_VALID_MASK) before the sets are
 * judged. PR_CAPBSET_READ is EINVAL past CAP_LAST_CAP. A kernel that answers
 * it for none of them is taken to end at CAP_CHECKPOINT_RESTORE (40), where
 * every kernel since 5.9 does. */
static unsigned cap_high_mask(void) {
    static unsigned mask; /* 0 = not probed yet; the probe is idempotent */
    unsigned m = __atomic_load_n(&mask, __ATOMIC_RELAXED);
    if (m)
        return m;
    int last = 63;
    while (last >= 32 &&
           CNG_SYS(__NR_prctl, CNG_PR_CAPBSET_READ, last, 0, 0, 0, 0) < 0)
        last--;
    if (last < 32)
        last = 40;
    m = (unsigned)((2ull << (last - 32)) - 1);
    __atomic_store_n(&mask, m, __ATOMIC_RELAXED);
    return m;
}

static long do_capset(struct cap_header *hdr, const struct cap_data *data) {
    int n = 0;
    struct cap_header h;
    long r = cap_magic(hdr, &h, &n);
    if (r != 0)
        return r;
    /* "may only affect current", as the kernel puts it: 0, or the caller's
     * pid as task_pid_vnr(current) gives it, which is the calling thread's
     * id, not its group's. */
    if (h.pid != 0 && h.pid != (int)sys_gettid())
        return -EPERM;
    /* The payload is copied in before any decision is taken, so a bad one is
     * -EFAULT whatever the caller's privilege would have been. */
    struct cap_data blocks[2] = {{0, 0, 0}, {0, 0, 0}};
    if (cng_user_copyin(blocks, data, (unsigned long)n * sizeof *blocks) < 0)
        return -EFAULT;
    unsigned hi = cap_high_mask();
    blocks[1].effective &= hi;
    blocks[1].permitted &= hi;
    blocks[1].inheritable &= hi;
    /* cap_capset(): the new permitted set must lie within the old one, the
     * effective within the new permitted, the inheritable within the old
     * inheritable and permitted (or the bounding set, given CAP_SETPCAP). The
     * set here is all of them for a fake root and none for anyone else, and a
     * change is not recorded. So a fake root is refused only an effective bit
     * it does not also permit, and anyone else any capability at all — but
     * not a set that asks for none, which is a drop, and dropping is always
     * allowed. That used to be EPERM too: Chrome's zygote drops every
     * capability in each child it forks and CHECKs the answer, so as any user
     * but root its first child died ("credentials.cc: Check failed: . :
     * Operation not permitted") and the browser never came up. */
    int root = cng_fake_root();
    for (int i = 0; i < n; i++) {
        const struct cap_data *b = &blocks[i];
        if (root ? (b->effective & ~b->permitted) != 0
                 : (b->effective | b->permitted | b->inheritable) != 0)
            return -EPERM;
    }
    return 0;
}

/* Non-faking re-issue: consult the ambient block-list so a re-issue can never
 * trap and die (see blocklist.c). */
static long reissue_cred(long nr, long a0, long a1, long a2, long a3, long a4,
                         long a5) {
    if (nr >= 0 && nr < CNG_NR_MAX && cng_blocked[nr]) {
        cng_note_blocked((int)nr);
        return -ENOSYS;
    }
    return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
}

/* ---- without --fake-id: the host's own set ---------------------------------
 *
 * The ids are then the kernel's, and so are the answers: a setter is re-issued.
 * Our filter traps this family only under --fake-id, so one arrives here
 * through an -R trampoline, a tracee's trap-everything filter, or the trap of
 * an ambient filter that refuses it. Android's app filter refuses every uid
 * and gid setter but setresuid (bionic's SECCOMP_BLOCKLIST_APP.TXT); capset is
 * allowed. All of them were answered ENOSYS, under -R on any host as well:
 * `setgid(getgid())`, which is how many a program drops a set-id bit it may
 * have been started with, failed outright where the kernel says 0.
 *
 * A setter the host refuses is answered the way the kernel would answer this
 * process: by the rules the fake set runs (above), applied to the real ids and
 * to the capability the kernel asks for. An error is the kernel's error, in
 * its order; a call that changes nothing succeeds; and a change the rules
 * allow — which takes the capability, or ids that differ, and an Android app
 * has neither — is EPERM, since the one call that could make it is the one
 * refused. setfsuid and setfsgid answer the current id, which is how they
 * report a change not made. Nothing here issues a setter.
 *
 * The fs ids are read with setfsuid(-1), which changes nothing. Where that is
 * refused too, fsuid is euid: every exec makes them equal, every other setter
 * moves the one with the other, and the filter has been there since this
 * program's exec (it is inherited, and measured at startup). */
static int real_ids(struct cng_cred *c, int *upriv, int *gpriv) {
    unsigned id[6];
    if (reissue_cred(__NR_getresuid, (long)&id[0], (long)&id[1], (long)&id[2],
                     0, 0, 0) < 0 ||
        reissue_cred(__NR_getresgid, (long)&id[3], (long)&id[4], (long)&id[5],
                     0, 0, 0) < 0)
        return -1;
    c->ruid = id[0];
    c->euid = id[1];
    c->suid = id[2];
    c->rgid = id[3];
    c->egid = id[4];
    c->sgid = id[5];
    c->fsuid = cng_blocked[__NR_setfsuid]
                   ? c->euid
                   : (unsigned)cng_syscall6(-1, 0, 0, 0, 0, 0, __NR_setfsuid);
    c->fsgid = cng_blocked[__NR_setfsgid]
                   ? c->egid
                   : (unsigned)cng_syscall6(-1, 0, 0, 0, 0, 0, __NR_setfsgid);
    c->ngroups = 0;
    /* Unreadable capabilities are none, which is what an app has. */
    struct cap_header h = {CAP_VER_3, 0};
    struct cap_data d[2];
    unsigned eff = reissue_cred(__NR_capget, (long)&h, (long)d, 0, 0, 0, 0) == 0
                       ? d[0].effective
                       : 0;
    *upriv = (eff >> 7) & 1; /* CAP_SETUID */
    *gpriv = (eff >> 6) & 1; /* CAP_SETGID */
    return 0;
}

/* The kernel keeps a group list sorted, duplicates and all, so two lists are
 * the same list when they are the same once sorted. */
static void sort_groups(unsigned *g, int n) {
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && g[j - 1] > g[j]; j--) {
            unsigned t = g[j];
            g[j] = g[j - 1];
            g[j - 1] = t;
        }
}

static int same_set(struct cng_cred *a, struct cng_cred *b) {
    if (a->ruid != b->ruid || a->euid != b->euid || a->suid != b->suid ||
        a->fsuid != b->fsuid || a->rgid != b->rgid || a->egid != b->egid ||
        a->sgid != b->sgid || a->fsgid != b->fsgid ||
        a->ngroups != b->ngroups)
        return 0;
    sort_groups(a->groups, a->ngroups);
    sort_groups(b->groups, b->ngroups);
    for (int i = 0; i < a->ngroups; i++)
        if (a->groups[i] != b->groups[i])
            return 0;
    return 1;
}

static long real_set(long nr, long a0, long a1, long a2) {
    struct cng_cred was, c;
    int up, gp;
    if (real_ids(&was, &up, &gp) < 0) {
        cng_note_blocked((int)nr);
        return -ENOSYS;
    }
    memcpy(&c, &was, (unsigned long)&((struct cng_cred *)0)->groups);
    c.ngroups = 0;
    unsigned u0 = (unsigned)a0, u1 = (unsigned)a1, u2 = (unsigned)a2;
    long r;
    switch (nr) {
    case __NR_setuid:
        r = do_setuid(&c, up, u0);
        break;
    case __NR_setgid:
        r = do_setgid(&c, gp, u0);
        break;
    case __NR_setreuid:
        r = do_setreuid(&c, up, u0, u1);
        break;
    case __NR_setregid:
        r = do_setregid(&c, gp, u0, u1);
        break;
    case __NR_setresuid:
        r = do_setresuid(&c, up, u0, u1, u2);
        break;
    case __NR_setresgid:
        r = do_setresgid(&c, gp, u0, u1, u2);
        break;
    case __NR_setfsuid:
        r = do_setfsuid(&c, up, u0);
        break;
    case __NR_setfsgid:
        r = do_setfsgid(&c, gp, u0);
        break;
    case __NR_setgroups:
        /* Only a caller with CAP_SETGID gets past the first check, and only
         * then is there a list of the host's to compare with. */
        r = do_setgroups(&c, gp, (int)a0, (const unsigned *)a1);
        if (r == 0) {
            long n = reissue_cred(__NR_getgroups, CNG_NGROUPS_MAX,
                                  (long)was.groups, 0, 0, 0, 0);
            was.ngroups = n < 0 ? -1 : (int)n;
        }
        break;
    default:
        return -ENOSYS;
    }
    if (r < 0 || same_set(&was, &c))
        return r;
    /* Allowed, and not to be had: the platform's refusal, said once. */
    cng_note_blocked((int)nr);
    return (nr == __NR_setfsuid || nr == __NR_setfsgid) ? r : -EPERM;
}

/* A setter: run it against a copy of the set and publish the copy if it
 * succeeded, so the set changes as one object or not at all. */
#define CRED_SET(call)                                                        \
    do {                                                                      \
        struct cng_cred_write w;                                              \
        struct cng_cred *c = cng_cred_write_begin(&w);                        \
        long r_ = (call);                                                     \
        cng_cred_write_end(&w, r_ >= 0);                                      \
        return r_;                                                            \
    } while (0)

long cng_cred_handle(long nr, long a0, long a1, long a2, long a3, long a4,
                     long a5) {
    if (!cng_g_fake_id) {
        /* The host's set (see real_set): the kernel answers, or, for a setter
         * the host refuses, the kernel's rules do. */
        switch (nr) {
        case __NR_setuid:
        case __NR_setgid:
        case __NR_setreuid:
        case __NR_setregid:
        case __NR_setresuid:
        case __NR_setresgid:
        case __NR_setfsuid:
        case __NR_setfsgid:
        case __NR_setgroups:
            if (cng_blocked[nr])
                return real_set(nr, a0, a1, a2);
            return cng_syscall6(a0, a1, a2, a3, a4, a5, nr);
        default:
            return reissue_cred(nr, a0, a1, a2, a3, a4, a5);
        }
    }

    /* The getters read the published ids (cng_cred_ids), never the pointer's
     * buffer directly — see the top of this file. */
    struct cng_cred_ids id;
    switch (nr) {
    case __NR_getuid:
        cng_cred_ids(&id);
        return (long)id.ruid;
    case __NR_geteuid:
        cng_cred_ids(&id);
        return (long)id.euid;
    case __NR_getgid:
        cng_cred_ids(&id);
        return (long)id.rgid;
    case __NR_getegid:
        cng_cred_ids(&id);
        return (long)id.egid;
    /* getres*id take three out pointers and the kernel fills them in order,
     * one put_user each, stopping at the first that will not take a store: a
     * bad second pointer leaves the real id in the first and still answers
     * -EFAULT (measured on the host). Probing all three up front said the
     * opposite, and said it destructively — the write probe validates a range
     * by zeroing it (see uaccess.c) — so a bad third pointer zeroed the two
     * good ones the kernel would have filled. Each copyout is its own check,
     * in the kernel's order, and a NULL pointer is -EFAULT here too, unlike
     * the optional pointers elsewhere in this family. */
    case __NR_getresuid:
    case __NR_getresgid: {
        int u = (nr == __NR_getresuid);
        cng_cred_ids(&id);
        unsigned r_ = u ? id.ruid : id.rgid;
        unsigned e_ = u ? id.euid : id.egid;
        unsigned s_ = u ? id.suid : id.sgid;
        if (cng_user_copyout((void *)a0, &r_, sizeof r_) < 0 ||
            cng_user_copyout((void *)a1, &e_, sizeof e_) < 0 ||
            cng_user_copyout((void *)a2, &s_, sizeof s_) < 0)
            return -EFAULT;
        return 0;
    }
    case __NR_setuid:
        CRED_SET(do_setuid(c, cred_priv(c), (unsigned)a0));
    case __NR_setgid:
        CRED_SET(do_setgid(c, cred_priv(c), (unsigned)a0));
    case __NR_setreuid:
        CRED_SET(do_setreuid(c, cred_priv(c), (unsigned)a0, (unsigned)a1));
    case __NR_setregid:
        CRED_SET(do_setregid(c, cred_priv(c), (unsigned)a0, (unsigned)a1));
    case __NR_setresuid:
        CRED_SET(do_setresuid(c, cred_priv(c), (unsigned)a0, (unsigned)a1,
                              (unsigned)a2));
    case __NR_setresgid:
        CRED_SET(do_setresgid(c, cred_priv(c), (unsigned)a0, (unsigned)a1,
                              (unsigned)a2));
    case __NR_setfsuid:
        CRED_SET(do_setfsuid(c, cred_priv(c), (unsigned)a0));
    case __NR_setfsgid:
        CRED_SET(do_setfsgid(c, cred_priv(c), (unsigned)a0));
    case __NR_setgroups:
        CRED_SET(do_setgroups(c, cred_priv(c), (int)a0, (const unsigned *)a1));
    case __NR_getgroups:
        return do_getgroups((int)a0, (unsigned *)a1);
    case __NR_capget:
        return do_capget((struct cap_header *)a0, (struct cap_data *)a1);
    case __NR_capset:
        return do_capset((struct cap_header *)a0, (const struct cap_data *)a1);
    default:
        return -ENOSYS;
    }
}
