/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* A table that grows in page-sized chunks. See include/cng/tab.h. */
#include "cng/tab.h"
#include "cng/loader.h" /* cng_page_size */
#include "cng/ownmap.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

struct cng_tab_chunk {
    struct cng_tab_chunk *next;
    unsigned long pad; /* keeps the elements 16-byte aligned */
    unsigned char data[];
};

static unsigned tab_per(const struct cng_tab *t) {
    return (unsigned)((cng_page_size - sizeof(struct cng_tab_chunk)) / t->esz);
}

/* Append a chunk after `*link` (which is 0), or take the one another thread
 * put there first. 0 when the host refuses the page.
 *
 * Registered as the monitor's own AFTER it is linked: for the one table that
 * is the registry itself, the registration is a record in the table, and it
 * lands in the chunk just linked — which is exactly one level of recursion,
 * ending in a chunk with free slots. */
static struct cng_tab_chunk *tab_grow(struct cng_tab_chunk **link) {
    unsigned long sz = cng_page_size;
    void *p = sys_mmap(0, sz, CNG_PROT_READ | CNG_PROT_WRITE,
                       CNG_MAP_PRIVATE | CNG_MAP_ANONYMOUS, -1, 0);
    if (p == CNG_MAP_FAILED || cng_is_err((long)p))
        return 0;
    struct cng_tab_chunk *none = 0;
    if (!__atomic_compare_exchange_n(link, &none, (struct cng_tab_chunk *)p, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        sys_munmap(p, sz); /* lost the append: theirs is the chunk we use */
        return none;
    }
    cng_own_map(p, sz);
    return (struct cng_tab_chunk *)p;
}

void *cng_tab_at(struct cng_tab *t, unsigned long i) {
    if (!t->per)
        t->per = tab_per(t); /* idempotent: every thread computes the same */
    struct cng_tab_chunk **link = &t->head;
    for (;;) {
        struct cng_tab_chunk *c = __atomic_load_n(link, __ATOMIC_ACQUIRE);
        if (!c && !(c = tab_grow(link)))
            return 0;
        if (i < t->per)
            return c->data + i * t->esz;
        i -= t->per;
        link = &c->next;
    }
}

void *cng_tab_peek(const struct cng_tab *t, unsigned long i) {
    unsigned per = t->per ? t->per : tab_per(t);
    for (struct cng_tab_chunk *c = __atomic_load_n(&t->head, __ATOMIC_ACQUIRE);
         c; c = __atomic_load_n(&c->next, __ATOMIC_ACQUIRE)) {
        if (i < per)
            return c->data + i * t->esz;
        i -= per;
    }
    return 0;
}

void *cng_tab_first(const struct cng_tab *t, struct cng_tab_iter *it) {
    it->c = __atomic_load_n(&t->head, __ATOMIC_ACQUIRE);
    it->i = 0;
    return it->c ? it->c->data : 0;
}

void *cng_tab_next(const struct cng_tab *t, struct cng_tab_iter *it) {
    unsigned per = t->per ? t->per : tab_per(t);
    if (!it->c)
        return 0;
    if (++it->i < per)
        return it->c->data + it->i * t->esz;
    it->c = __atomic_load_n(&it->c->next, __ATOMIC_ACQUIRE);
    it->i = 0;
    return it->c ? it->c->data : 0;
}
