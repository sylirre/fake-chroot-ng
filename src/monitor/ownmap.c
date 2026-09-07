/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* The monitor's own mappings, and the walk that finds everything else.
 *
 * See include/cng/ownmap.h for what this is for. The short of it: an emulated
 * execve can only give the outgoing program's memory back if it can tell that
 * memory from ours, and this is where that question is answered.
 */
#include "cng/ownmap.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm/unistd.h>

/* Sized for the floor (about twenty-five mappings on a device: our own image,
 * the stack, heap, vdso/vvar, the first program and its stack, the pools the
 * loader made) plus every long-lived region the monitor maps afterwards, of
 * which there are a dozen. The scratch stacks are NOT in here — sigsys.c
 * already records all 256 of them with their bounds, and asking that table is
 * both cheaper and immune to the two drifting apart. */
#define OWN_MAX 96

/* lo is the claim (a mapping can never be at 0, so 0 means the slot is free)
 * and hi is the publication: a reader that sees a non-zero hi is guaranteed to
 * see the lo that goes with it. Slots are reused, because the argv snapshot
 * takes one per exec and gives it back again. */
static struct own_range {
    unsigned long lo, hi;
} g_own[OWN_MAX];

static int g_own_floored;
static int g_own_lost; /* a record did not fit, or the floor did not read */

static void own_lose(void) { __atomic_store_n(&g_own_lost, 1, __ATOMIC_RELEASE); }

static int own_add(unsigned long lo, unsigned long hi) {
    if (hi <= lo)
        return 0;
    for (int i = 0; i < OWN_MAX; i++) {
        unsigned long expect = 0;
        if (__atomic_load_n(&g_own[i].lo, __ATOMIC_RELAXED))
            continue;
        if (!__atomic_compare_exchange_n(&g_own[i].lo, &expect, lo, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&g_own[i].hi, hi, __ATOMIC_RELEASE);
        return 0;
    }
    /* Out of slots. Every later answer would be "not ours" for a region that
     * is, so the reclaim stops rather than acting on a table it has outgrown. */
    own_lose();
    return -1;
}

void *cng_own_map(void *p, unsigned long len) {
    if (!p || cng_is_err((long)p) || p == CNG_MAP_FAILED)
        return p;
    own_add((unsigned long)p, (unsigned long)p + len);
    return p;
}

void cng_own_drop(void *p, unsigned long len) {
    unsigned long lo = (unsigned long)p, hi = lo + len;
    for (int i = 0; i < OWN_MAX; i++) {
        if (__atomic_load_n(&g_own[i].hi, __ATOMIC_ACQUIRE) != hi ||
            __atomic_load_n(&g_own[i].lo, __ATOMIC_RELAXED) != lo)
            continue;
        __atomic_store_n(&g_own[i].hi, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_own[i].lo, 0, __ATOMIC_RELEASE);
        return;
    }
}

int cng_own_hit(unsigned long lo, unsigned long hi) {
    for (int i = 0; i < OWN_MAX; i++) {
        unsigned long h = __atomic_load_n(&g_own[i].hi, __ATOMIC_ACQUIRE);
        if (!h)
            continue;
        unsigned long l = __atomic_load_n(&g_own[i].lo, __ATOMIC_RELAXED);
        if (lo < h && l < hi)
            return 1;
    }
    return 0;
}

int cng_own_ready(void) {
    return g_own_floored && !__atomic_load_n(&g_own_lost, __ATOMIC_ACQUIRE);
}

/* ---- /proc/self/maps ----------------------------------------------------- */

static int hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* As much of a maps line as any caller here needs: the two addresses, and the
 * head of the pathname column. The kernel pads that column to 73, so 96 bytes
 * carry the bounds, the permissions and enough of the name to tell "[heap]"
 * from "[anon:scudo:primary]" — which is the whole distinction that matters,
 * since Android names ordinary anonymous mappings with PR_SET_VMA and those
 * belong to the guest like any other. A longer line is not an error: the tail
 * is a path we would only have looked at the first bytes of anyway. */
#define MAPS_LINE 96

static int maps_line(const char *line, unsigned long *lo, unsigned long *hi,
                     const char **path) {
    const char *p = line;
    unsigned long a = 0, b = 0;
    int n = 0, v;
    while ((v = hexval(*p)) >= 0) {
        a = (a << 4) | (unsigned)v;
        p++;
        n++;
    }
    if (!n || *p != '-')
        return -1;
    p++;
    for (n = 0; (v = hexval(*p)) >= 0; p++, n++)
        b = (b << 4) | (unsigned)v;
    if (!n || b <= a)
        return -1;
    /* Past the four remaining fixed fields (perms, offset, dev, inode) to the
     * pathname column, which is what is left once the run of spaces ends. */
    int field = 0;
    while (*p && field < 4) {
        while (*p == ' ')
            p++;
        while (*p && *p != ' ')
            p++;
        field++;
    }
    while (*p == ' ')
        p++;
    *lo = a;
    *hi = b;
    *path = p;
    return 0;
}

int cng_maps_walk(int (*fn)(unsigned long lo, unsigned long hi,
                            const char *path, void *ctx),
                  void *ctx) {
    long fd = sys_openat(CNG_AT_FDCWD, "/proc/self/maps",
                         CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[1024], line[MAPS_LINE];
    unsigned long fill = 0;
    int stopped = 0;
    for (;;) {
        long n = sys_read((int)fd, buf, sizeof buf);
        if (n <= 0)
            break;
        for (long i = 0; i < n && !stopped; i++) {
            if (buf[i] != '\n') {
                if (fill < sizeof line - 1) /* past that it is path tail */
                    line[fill++] = buf[i];
                continue;
            }
            line[fill] = '\0';
            fill = 0;
            unsigned long lo, hi;
            const char *path;
            if (maps_line(line, &lo, &hi, &path) == 0 && fn(lo, hi, path, ctx))
                stopped = 1;
        }
        if (stopped)
            break;
    }
    sys_close((int)fd);
    return stopped ? 1 : 0;
}

/* ---- the floor ----------------------------------------------------------- */

/* Contiguous mappings are merged as they arrive — an ELF image is three or four
 * VMAs that abut, and the table is small on purpose. */
static int floor_seen(unsigned long lo, unsigned long hi, const char *path,
                      void *ctx) {
    unsigned long *last = ctx;
    (void)path;
    if (last[1] == lo) { /* abuts the run we are accumulating: extend it */
        last[1] = hi;
        return 0;
    }
    if (last[1] && own_add(last[0], last[1]) != 0)
        return 1; /* out of slots: own_add has already disarmed the reclaim */
    last[0] = lo;
    last[1] = hi;
    return 0;
}

void cng_own_floor(void) {
    unsigned long last[2] = {0, 0};
    if (cng_maps_walk(floor_seen, last) != 0) {
        own_lose(); /* an incomplete floor is not a floor */
        return;
    }
    if (last[1] && own_add(last[0], last[1]) != 0)
        return;
    g_own_floored = 1;
}
