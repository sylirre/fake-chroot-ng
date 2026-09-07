/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Which mappings in this address space are the monitor's own.
 *
 * A real execve throws the whole mm away. Ours keeps it — the monitor's code
 * and state are pages of the same address space — so the only way to give the
 * outgoing program's memory back is to be able to say which pages were never
 * its. Two answers together do that:
 *
 *  - the floor: everything mapped at the moment cng_run is about to load the
 *    first program. That is our image, our stack, the heap, the kernel's own
 *    pseudo mappings, and whatever we mapped on the way up. Nothing of any
 *    guest has been mapped yet, so nothing in it is a guest's;
 *  - the registry: every long-lived region the monitor maps after that —
 *    the broker's tables, the pid and IPC registries, the ptrace link table,
 *    the argv snapshot an exec is standing on. Each is recorded as it is made.
 *
 * Anything else is the guest's, and an exec is where it goes. Getting that
 * wrong unmaps the monitor out from under itself, so the registry is
 * fail-closed: if a record does not fit, or the floor could not be read,
 * cng_own_ready() answers no and the reclaim does not run at all.
 */
#ifndef CNG_OWNMAP_H
#define CNG_OWNMAP_H

/* Record [p, p+len) as the monitor's own. Returns p, so it can wrap an mmap:
 *     void *t = cng_own_map(sys_mmap(...), len);
 * A failed mmap (NULL or an errno) is passed through unrecorded. */
void *cng_own_map(void *p, unsigned long len);

/* Forget a region recorded above, before unmapping it. The range must be the
 * one that was recorded; a partial match is not dropped. */
void cng_own_drop(void *p, unsigned long len);

/* Does [lo, hi) touch anything of ours? */
int cng_own_hit(unsigned long lo, unsigned long hi);

/* Take the floor. Called once, from cng_run, immediately before the first guest
 * program is loaded — not merely before it runs, or the floor claims that
 * program's image and stack and goes on claiming those addresses after they are
 * given back. A `-t` self-test driver does not call it, so the reclaim stays
 * disarmed there, which is the safe direction. */
void cng_own_floor(void);

/* Is the answer trustworthy enough to unmap on? Zero until the floor is taken,
 * and zero forever after a record is lost. */
int cng_own_ready(void);

/* One pass over /proc/self/maps. `fn` is called for each mapping with its
 * bounds and the head of the pathname column ("" when the mapping is
 * anonymous) — the head, because the line is read into a fixed buffer and a
 * long path loses its tail; enough to tell one bracketed pseudo-name from
 * another, which is all any caller here asks. A non-zero return stops the walk
 * early. Returns 0 for a complete walk, 1 when `fn` stopped it, and -1 if the
 * file could not be read — which callers must treat as "nothing is known",
 * never as "nothing is there". */
int cng_maps_walk(int (*fn)(unsigned long lo, unsigned long hi,
                            const char *path, void *ctx),
                  void *ctx);

#endif /* CNG_OWNMAP_H */
