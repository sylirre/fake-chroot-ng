/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* The mmap(PROT_EXEC) hook: a file-backed executable mapping the host will not
 * grant, served from anonymous memory instead.
 *
 * chroot-ng's own loader never needs this — it reads a guest image with pread
 * and maps it anonymously, which is the whole `noexec` defeat. But a dynamic
 * guest's libraries are mapped by the guest's OWN ld.so, which asks for
 * PROT_EXEC straight from the file; on a true MNT_NOEXEC mount the kernel
 * refuses that, and every dynamically linked guest dies in its interpreter
 * before reaching main. There is no second entry point to fix it in: the
 * mapping request is the only place the failure is visible.
 *
 * So the refusal is caught and answered the same way the loader answers it:
 * anonymous RW pages, the file's bytes pread into them, `svc` sites rewritten
 * where -R asked for it, then mprotect to the protection the guest wanted.
 * Only MAP_PRIVATE can be served this way (a copy cannot carry MAP_SHARED's
 * visibility), and only where the kernel actually refused — an exec-permitted
 * mount keeps its real file mapping, its page-cache sharing and its identity
 * in /proc/self/maps.
 */
#ifndef CNG_EXECMAP_H
#define CNG_EXECMAP_H

/* CNG_MMAP_FORCE_ANON=1: take the anonymous route without asking the kernel
 * first, so the path can be exercised on a host that has no noexec mount to
 * offer. Same testing convention as CNG_SHM_FORCE_FILE / CNG_PROCREG_NONE. */
extern int cng_g_execmap_force;

/* Serve one mmap(2) whose prot has PROT_EXEC and whose flags do not have
 * MAP_ANONYMOUS. Returns the mapping address, or the kernel's own negative
 * errno — including when the anonymous route is not available or not
 * applicable, so the guest always sees a real answer. */
long cng_execmap(unsigned long addr, unsigned long len, long prot, long flags,
                 long fd, unsigned long off);

#endif /* CNG_EXECMAP_H */
