/* Freestanding runtime: mem/str helpers and minimal formatted output.
 * No libc — chroot-ng must run with no external dependencies so it behaves
 * identically for glibc, musl, static and Go/Rust guests, and so the SIGSYS
 * handler can call these helpers without re-entrancy hazards.
 */
#ifndef CNG_RT_H
#define CNG_RT_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* Compiler may emit calls to these; provide freestanding implementations. */
void *memset(void *d, int c, size_t n);
void *memcpy(void *d, const void *s, size_t n);
void *memmove(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);

size_t strlen(const char *s);
size_t cng_strnlen(const char *s, size_t max);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
size_t cng_strlcpy(char *dst, const char *src, size_t size);

/* I/O helpers */
long cng_write_all(int fd, const void *buf, size_t n);
void cng_puts(int fd, const char *s);

/* Minimal printf: %s %c %d %u %x %X %p %% ; length modifiers l, ll, z. */
void cng_dprintf(int fd, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void cng_vdprintf(int fd, const char *fmt, va_list ap);

/* Print "<msg>: <errno-name-or-number>\n" to stderr and exit(1). */
_Noreturn void cng_die(const char *msg, long err);

/* AArch64 cache maintenance (src/rt/cache.S): make [start,end) executable-
 * coherent after writing code into it. */
void cng_flush_icache(void *start, void *end);

#endif /* CNG_RT_H */
