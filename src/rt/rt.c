/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
#include "cng/rt.h"
#include "cng/syscall.h"

/* ---- mem/str ----------------------------------------------------------
 *
 * Word-at-a-time, on the general registers only: the Makefile builds the
 * monitor with -mgeneral-regs-only because on the -R tier this code runs on
 * the guest's own register file, so there is no SIMD to be had and the wide
 * loads and stores are 64-bit. A copy reads its source at whatever alignment
 * it arrives with — AArch64 takes an unaligned access of Normal memory in
 * stride — and aligns only its stores, which is what the prologue byte loops
 * are for. The string scans are stricter: a word is loaded only ALIGNED, and
 * only once some byte of the string is known to lie in it, so no load ever
 * reaches past the page that byte is on — a string ending on the last byte of
 * a mapping is read to its terminator and not one byte further. That is the
 * one rule an unaligned word load would break (a 2-byte string at the end of
 * a page has 6 bytes of the next page in its word), and why cng_strlcpy
 * aligns on the SOURCE, not on the destination like the copies do.
 */

/* An 8-byte access the compiler may make at any address (aligned(1)) and
 * through any pointer (may_alias); the aligned twin is for the scans. */
typedef u64 __attribute__((__may_alias__, __aligned__(1))) u64_ua;
typedef u64 __attribute__((__may_alias__)) u64_al;

#define RT_ONES  0x0101010101010101ULL
#define RT_HIGHS 0x8080808080808080ULL
/* Non-zero iff some byte of `w` is zero. Bits above the first zero byte may be
 * set spuriously, so a hit is followed by a byte scan of the word; a miss is
 * exact. */
#define RT_HAS_ZERO(w) ((((w) - RT_ONES) & ~(w)) & RT_HIGHS)

static inline int rt_unaligned(const void *p) { return (uintptr_t)p & 7; }

void *memset(void *d, int c, size_t n) {
    unsigned char *p = d;
    if (n >= 16) {
        u64 w = (unsigned char)c * RT_ONES;
        while (rt_unaligned(p)) {
            *p++ = (unsigned char)c;
            n--;
        }
        for (; n >= 8; n -= 8, p += 8)
            *(u64_al *)p = w;
    }
    while (n--)
        *p++ = (unsigned char)c;
    return d;
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *a = d;
    const unsigned char *b = s;
    if (n >= 16) {
        while (rt_unaligned(a)) {
            *a++ = *b++;
            n--;
        }
        for (; n >= 8; n -= 8, a += 8, b += 8)
            *(u64_al *)a = *(const u64_ua *)b;
    }
    while (n--)
        *a++ = *b++;
    return d;
}

/* Overlap is safe either way round with whole words: copying upwards for
 * d < s, a store lands below the next load; copying downwards for d > s, it
 * lands above it. */
void *memmove(void *d, const void *s, size_t n) {
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a == b || !n)
        return d;
    if (a < b) {
        if (n >= 16) {
            while (rt_unaligned(a)) {
                *a++ = *b++;
                n--;
            }
            for (; n >= 8; n -= 8, a += 8, b += 8)
                *(u64_al *)a = *(const u64_ua *)b;
        }
        while (n--)
            *a++ = *b++;
    } else {
        a += n;
        b += n;
        if (n >= 16) {
            while (rt_unaligned(a)) {
                *--a = *--b;
                n--;
            }
            for (; n >= 8; n -= 8) {
                a -= 8;
                b -= 8;
                *(u64_al *)a = *(const u64_ua *)b;
            }
        }
        while (n--)
            *--a = *--b;
    }
    return d;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    /* Whole words while they agree; the first that does not is left to the
     * byte loop, which finds the differing byte within it. */
    for (; n >= 8; n -= 8, x += 8, y += 8)
        if (*(const u64_ua *)x != *(const u64_ua *)y)
            break;
    while (n--) {
        if (*x != *y)
            return (int)*x - (int)*y;
        x++;
        y++;
    }
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    for (; rt_unaligned(p); p++)
        if (!*p)
            return (size_t)(p - s);
    const u64_al *w = (const u64_al *)p;
    while (!RT_HAS_ZERO(*w))
        w++;
    for (p = (const char *)w; *p; p++)
        ;
    return (size_t)(p - s);
}

size_t cng_strnlen(const char *s, size_t max) {
    size_t i = 0;
    for (; i < max && rt_unaligned(s + i); i++)
        if (!s[i])
            return i;
    /* A word is loaded only when all 8 of its bytes are within the bound,
     * so this is exactly the read the byte loop would have made. */
    for (; max - i >= 8 && !RT_HAS_ZERO(*(const u64_al *)(s + i)); i += 8)
        ;
    for (; i < max && s[i]; i++)
        ;
    return i;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n--) {
        if (*a != *b)
            return (int)(unsigned char)*a - (int)(unsigned char)*b;
        if (!*a)
            return 0;
        a++;
        b++;
    }
    return 0;
}

/* The scans for a byte look for two things per word — the byte and the
 * terminator — with the zero test applied to the word XORed with the byte
 * repeated, which turns every occurrence of the byte into a zero. */
char *strchr(const char *s, int c) {
    unsigned char ch = (unsigned char)c;
    if (!ch)
        return (char *)s + strlen(s);
    for (; rt_unaligned(s); s++) {
        if ((unsigned char)*s == ch)
            return (char *)s;
        if (!*s)
            return 0;
    }
    u64 pat = ch * RT_ONES;
    const u64_al *w = (const u64_al *)s;
    for (;; w++) {
        u64 v = *w;
        if (RT_HAS_ZERO(v) | RT_HAS_ZERO(v ^ pat))
            break;
    }
    for (s = (const char *)w;; s++) {
        if ((unsigned char)*s == ch)
            return (char *)s;
        if (!*s)
            return 0;
    }
}

char *strrchr(const char *s, int c) {
    unsigned char ch = (unsigned char)c;
    if (!ch)
        return (char *)s + strlen(s);
    const char *r = 0;
    for (; rt_unaligned(s); s++) {
        if ((unsigned char)*s == ch)
            r = s;
        if (!*s)
            return (char *)r;
    }
    u64 pat = ch * RT_ONES;
    for (const u64_al *w = (const u64_al *)s;; w++) {
        u64 v = *w;
        if (!(RT_HAS_ZERO(v) | RT_HAS_ZERO(v ^ pat)))
            continue;
        const char *p = (const char *)w;
        for (int i = 0; i < 8; i++, p++) {
            if ((unsigned char)*p == ch)
                r = p;
            if (!*p)
                return (char *)r;
        }
    }
}

/* One pass over the source: the bytes are copied as the terminator is looked
 * for, a word at a time while the source is aligned and the room admits a
 * whole word (the store is at whatever alignment `dst` has). Only what does
 * not fit is measured separately, for the return value. The destination is
 * NUL-terminated whenever `size` is non-zero, and `dst` may not overlap `src`
 * from above, exactly as before. */
size_t cng_strlcpy(char *dst, const char *src, size_t size) {
    size_t room = size ? size - 1 : 0, n = 0;
    while (n < room) {
        if (!rt_unaligned(src + n) && room - n >= 8) {
            u64 w = *(const u64_al *)(src + n);
            if (!RT_HAS_ZERO(w)) {
                *(u64_ua *)(dst + n) = w;
                n += 8;
                continue;
            }
        }
        char c = src[n];
        if (!c)
            break;
        dst[n++] = c;
    }
    if (size)
        dst[n] = '\0';
    return n + strlen(src + n);
}

/* ---- I/O -------------------------------------------------------------- */

long cng_write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t left = n;
    while (left) {
        long r = sys_write(fd, p, left);
        if (r < 0) {
            if (r == -EINTR)
                continue;
            return r;
        }
        if (r == 0)
            break;
        p += r;
        left -= (size_t)r;
    }
    return (long)(n - left);
}

void cng_puts(int fd, const char *s) { cng_write_all(fd, s, strlen(s)); }

/* ---- minimal printf --------------------------------------------------- */

/* One formatting run.
 *
 * `buf`/`cap` is where characters land, but when `fd` is >= 0 it is a *window*
 * rather than the destination: it is written out and reused each time it fills,
 * so a line longer than the buffer is delivered whole. That matters because the
 * lines this formats are not log lines — put_maps copies a mapping's path
 * through, put_mounts prints a bind's guest and host path on one row — and
 * cutting one at the window's width takes its trailing newline with it, running
 * two rows of a synthesized /proc file together.
 *
 * With `fd` < 0 nothing is flushed and the overflow is only counted, which is
 * what gives cng_snprintf the C return value: the length the format would have
 * produced, so a caller can tell that it did not fit. */
struct cng_fmt {
    char *buf;
    size_t cap;   /* bytes in buf, one of them reserved for a NUL */
    size_t len;   /* bytes held right now */
    size_t total; /* bytes the whole format produces */
    int fd;       /* >= 0: flush there when the window fills */
};

static void fmt_flush(struct cng_fmt *f) {
    if (f->len) {
        cng_write_all(f->fd, f->buf, f->len);
        f->len = 0;
    }
}

static void fmt_put(struct cng_fmt *f, char c) {
    f->total++;
    if (f->len + 1 >= f->cap) {
        if (f->fd < 0)
            return; /* snprintf: drop the byte, keep counting */
        fmt_flush(f);
    }
    f->buf[f->len++] = c;
}

/* A function call, so the argument is evaluated exactly once whether or not
 * there is room for it. Every caller below hands this an expression with a side
 * effect (`*s++`, `t[--i]`, `va_arg(...)`). */
static void fmt_run(struct cng_fmt *o, const char *fmt, va_list ap) {
#define PUT(ch) fmt_put(o, (char)(ch))

    for (const char *f = fmt; *f; f++) {
        if (*f != '%') {
            PUT(*f);
            continue;
        }
        f++;
        /* Flags/width: "0" (zero-pad) then a decimal field width. Needed by the
         * /proc synthesis, whose formats are fixed-width ("%02lu" in loadavg,
         * "%08llx" in maps) — a real reader parses them by column. */
        int zero = 0, width = 0;
        while (*f == '0') {
            zero = 1;
            f++;
        }
        while (*f >= '0' && *f <= '9') {
            width = width * 10 + (*f - '0');
            f++;
        }
        int lng = 0;
        while (*f == 'l') {
            lng++;
            f++;
        }
        if (*f == 'z') {
            lng = 2;
            f++;
        }
#define PAD(have)                                                              \
    do {                                                                       \
        for (int p_ = (have); p_ < width; p_++)                                \
            PUT(zero ? '0' : ' ');                                             \
    } while (0)
        /* The conversion specifier can be the terminator: stepping past the '%'
         * is unconditional and every scan above stops at '\0'. Falling into the
         * default arm below put that NUL in the output as a character and then
         * let the loop's own f++ walk past the end of the string, after which
         * this went on formatting whatever followed the literal in memory,
         * consuming a va_arg for every '%' it found there — an out-of-bounds
         * read in the one formatter every path shares, the SIGSYS handler's
         * included, where a fault is an unblockable kill.
         *
         * glibc calls an incomplete conversion an error and returns -1; this
         * returns a length and has nowhere to say that, so it keeps the stray
         * '%' (dropping nothing) and stops. */
        if (!*f) {
            PUT('%');
            break;
        }
        switch (*f) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            size_t sl = strlen(s);
            PAD((int)sl);
            while (*s)
                PUT(*s++);
            break;
        }
        case 'c':
            PUT((char)va_arg(ap, int));
            break;
        case '%':
            PUT('%');
            break;
        case 'd': {
            long v = lng ? va_arg(ap, long) : (long)va_arg(ap, int);
            unsigned long uv;
            int neg = 0;
            if (v < 0) {
                neg = 1;
                uv = (unsigned long)(-v);
            } else {
                uv = (unsigned long)v;
            }
            char t[24];
            int i = 0;
            if (uv == 0)
                t[i++] = '0';
            while (uv) {
                t[i++] = (char)('0' + uv % 10);
                uv /= 10;
            }
            if (zero) { /* sign first, then the zero fill: "-007" */
                if (neg)
                    PUT('-');
                PAD(i + neg);
            } else {
                PAD(i + neg);
                if (neg)
                    PUT('-');
            }
            while (i)
                PUT(t[--i]);
            break;
        }
        case 'u':
        case 'o':
        case 'x':
        case 'X':
        case 'p': {
            unsigned long uv;
            unsigned base = 10;
            const char *dig = "0123456789abcdef";
            if (*f == 'p') {
                PUT('0');
                PUT('x');
                uv = (unsigned long)va_arg(ap, void *);
                base = 16;
            } else {
                uv = lng ? va_arg(ap, unsigned long)
                         : (unsigned long)va_arg(ap, unsigned int);
                if (*f == 'o')
                    base = 8;
                else if (*f == 'x')
                    base = 16;
                else if (*f == 'X') {
                    base = 16;
                    dig = "0123456789ABCDEF";
                }
            }
            char t[24];
            int i = 0;
            if (uv == 0)
                t[i++] = '0';
            while (uv) {
                t[i++] = dig[uv % base];
                uv /= base;
            }
            PAD(i); /* %p pads its digits, after the "0x" */
            while (i)
                PUT(t[--i]);
            break;
        }
        default:
            PUT('%');
            PUT(*f);
            break;
        }
#undef PAD
    }
#undef PUT
}

/* Writes at most `cap - 1` bytes into `buf` plus a NUL, and returns the length
 * the format would have produced — so `>= cap` means it did not all fit. */
size_t cng_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
    struct cng_fmt f = {buf, cap, 0, 0, -1};
    fmt_run(&f, fmt, ap);
    if (cap)
        buf[f.len] = '\0';
    return f.total;
}

size_t cng_snprintf(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    size_t n = cng_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}

/* No length limit: the window below is refilled as often as the format needs. */
void cng_vdprintf(int fd, const char *fmt, va_list ap) {
    char buf[1024];
    struct cng_fmt f = {buf, sizeof buf, 0, 0, fd};
    fmt_run(&f, fmt, ap);
    fmt_flush(&f);
}

void cng_dprintf(int fd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cng_vdprintf(fd, fmt, ap);
    va_end(ap);
}

_Noreturn void cng_die(const char *msg, long err) {
    if (err)
        cng_dprintf(2, "chroot-ng: %s: errno %d\n", msg, (int)(err < 0 ? -err : err));
    else
        cng_dprintf(2, "chroot-ng: %s\n", msg);
    sys_exit_group(1);
}

/* ---- the monitor's own image ------------------------------------------ */

/* [addr, addr+len) against [__cng_image_start, __cng_image_end). `len` is
 * guest-supplied at both call sites, so a wrapping sum is a real input: treat
 * it as reaching the top of the address space rather than wrapping round to a
 * range that happens to miss us. */
int cng_hits_image(unsigned long addr, unsigned long len) {
    unsigned long lo = (unsigned long)__cng_image_start;
    unsigned long hi = (unsigned long)__cng_image_end;
    if (!len)
        return 0; /* an empty range covers nothing */
    unsigned long end = addr + len;
    if (end < addr)
        end = ~0UL;
    return addr < hi && end > lo;
}

/* ---- process bootstrap ------------------------------------------------ */

/* Actual page size, set from auxv AT_PAGESZ (declared in loader.h). Some
 * Android devices use 16 KiB pages, so never assume 4096. */
unsigned long cng_page_size = 4096;

int cng_main(int argc, char **argv, char **envp, unsigned long *auxv);

void cng_bootstrap(unsigned long *sp) {
    long argc = (long)sp[0];
    char **argv = (char **)&sp[1];
    char **envp = argv + argc + 1;
    char **p = envp;
    while (*p)
        p++;
    unsigned long *auxv = (unsigned long *)(p + 1);

    for (unsigned long *a = auxv; a[0] != 0; a += 2)
        if (a[0] == 6 /* AT_PAGESZ */ && a[1])
            cng_page_size = a[1];

    int rc = cng_main((int)argc, argv, envp, auxv);
    sys_exit_group(rc);
}
