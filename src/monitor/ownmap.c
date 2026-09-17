/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* The monitor's own mappings, and the walk that finds everything else.
 *
 * See include/cng/ownmap.h for what this is for. The short of it: an emulated
 * execve can only give the outgoing program's memory back if it can tell that
 * memory from ours, and this is where that question is answered.
 */
#include "cng/monitor.h"
#include "cng/ownmap.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/tab.h"
#include "cng/uapi.h"

/* The registry grows as it is written to (cng_tab): the floor takes about
 * twenty-five records on a device, the monitor's long-lived regions a dozen
 * more, and the tables that grow — a shm attach list, the ptrace registry,
 * every chunk of every cng_tab including this one — add a record apiece with
 * no ceiling. There was one, at 96, and the 97th record disarmed the reclaim
 * for the rest of the process's life. The scratch stacks are NOT in here —
 * sigsys.c already records all 256 of them with their bounds, and asking that
 * table is both cheaper and immune to the two drifting apart.
 *
 * lo is the claim (a mapping can never be at 0, so 0 means the slot is free)
 * and hi is the publication: a reader that sees a non-zero hi is guaranteed to
 * see the lo that goes with it. Slots are reused, because the argv snapshot
 * takes one per exec and gives it back again. */
struct own_range {
    unsigned long lo, hi;
};

static struct cng_tab g_own = CNG_TAB_INIT(struct own_range);

static int g_own_floored;
static int g_own_lost; /* a record did not fit, or the floor did not read */

static void own_lose(void) { __atomic_store_n(&g_own_lost, 1, __ATOMIC_RELEASE); }

static int own_add(unsigned long lo, unsigned long hi) {
    if (hi <= lo)
        return 0;
    for (unsigned long i = 0;; i++) {
        struct own_range *r = cng_tab_at(&g_own, i);
        if (!r) {
            /* The host would not give the page. Every later answer would be
             * "not ours" for a region that is, so the reclaim stops rather
             * than acting on a table it has outgrown. */
            own_lose();
            return -1;
        }
        unsigned long expect = 0;
        if (__atomic_load_n(&r->lo, __ATOMIC_RELAXED))
            continue;
        if (!__atomic_compare_exchange_n(&r->lo, &expect, lo, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        __atomic_store_n(&r->hi, hi, __ATOMIC_RELEASE);
        return 0;
    }
}

void *cng_own_map(void *p, unsigned long len) {
    if (!p || cng_is_err((long)p) || p == CNG_MAP_FAILED)
        return p;
    own_add((unsigned long)p, (unsigned long)p + len);
    return p;
}

void cng_own_drop(void *p, unsigned long len) {
    unsigned long lo = (unsigned long)p, hi = lo + len;
    struct cng_tab_iter it;
    for (struct own_range *r = cng_tab_first(&g_own, &it); r;
         r = cng_tab_next(&g_own, &it)) {
        if (__atomic_load_n(&r->hi, __ATOMIC_ACQUIRE) != hi ||
            __atomic_load_n(&r->lo, __ATOMIC_RELAXED) != lo)
            continue;
        __atomic_store_n(&r->hi, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&r->lo, 0, __ATOMIC_RELEASE);
        return;
    }
}

int cng_own_hit(unsigned long lo, unsigned long hi) {
    struct cng_tab_iter it;
    for (struct own_range *r = cng_tab_first(&g_own, &it); r;
         r = cng_tab_next(&g_own, &it)) {
        unsigned long h = __atomic_load_n(&r->hi, __ATOMIC_ACQUIRE);
        if (!h)
            continue;
        unsigned long l = __atomic_load_n(&r->lo, __ATOMIC_RELAXED);
        if (lo < h && l < hi)
            return 1;
    }
    return 0;
}

int cng_own_ready(void) {
    return g_own_floored && !__atomic_load_n(&g_own_lost, __ATOMIC_ACQUIRE);
}

int cng_hits_monitor(unsigned long addr, unsigned long len) {
    if (!len)
        return 0; /* an empty range covers nothing */
    unsigned long end = addr + len;
    if (end < addr)
        end = ~0UL;
    return cng_hits_image(addr, len) || cng_own_hit(addr, end) ||
           cng_scr_hit(addr, end);
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
        return 1; /* no page for it: own_add has already disarmed the reclaim */
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
