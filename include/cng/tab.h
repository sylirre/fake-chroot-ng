/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* A table that grows: indexed storage for the monitor's own records, in
 * page-sized chunks mapped as they are first reached.
 *
 * The monitor has no allocator, and its fixed-size tables each had a ceiling
 * with a cliff behind it: the 97th mapping of its own disarmed the exec
 * reclaim for good, the 33rd executable mapping put every trapped syscall from
 * it back onto a read of /proc/self/maps, the 65th POSIX timer outlived the
 * exec, the fifth emulated netlink socket was refused. None of those counts
 * is a limit the kernel has, so none of them is a limit a guest can be told
 * about. This is the storage they use instead.
 *
 * Elements are fixed-size and zero when first reached — a chunk is a fresh
 * anonymous mapping — and never move: an element's address is good for the
 * life of the process, so a slot claimed with a compare-and-swap on one of its
 * fields stays claimed. Chunks are appended lock-free (a CAS on the last
 * chunk's link; the loser unmaps its page and takes the winner's) and never
 * given back, so a table only ever grows to its high-water mark. Every chunk
 * is registered as the monitor's own (cng_own_map), which is what keeps the
 * exec sweep off it. A fork child inherits the chunks with the rest of the
 * address space.
 *
 * Nothing here is a lock. What a table's elements mean, and which fields
 * claim one, is the owning module's business. */
#ifndef CNG_TAB_H
#define CNG_TAB_H

struct cng_tab_chunk;

struct cng_tab {
    unsigned esz;                 /* bytes per element */
    unsigned per;                 /* elements per chunk, settled at first use */
    struct cng_tab_chunk *head;
};

#define CNG_TAB_INIT(type) {sizeof(type), 0, 0}

/* Element i, mapping chunks as needed to reach it. 0 only when the host would
 * not give the page — the one bound there is. */
void *cng_tab_at(struct cng_tab *t, unsigned long i);

/* Element i if a chunk holding it exists, else 0. Maps nothing. */
void *cng_tab_peek(const struct cng_tab *t, unsigned long i);

/* Walk every element that exists, chunk by chunk:
 *     struct cng_tab_iter it;
 *     for (struct x *p = cng_tab_first(&t, &it); p; p = cng_tab_next(&t, &it))
 * A walk sees every element allocated before it started, and possibly some
 * appended during it. */
struct cng_tab_iter {
    struct cng_tab_chunk *c;
    unsigned i;
};
void *cng_tab_first(const struct cng_tab *t, struct cng_tab_iter *it);
void *cng_tab_next(const struct cng_tab *t, struct cng_tab_iter *it);

#endif
