#include "cng/rt.h"
#include "cng/syscall.h"

/* ---- mem/str ---------------------------------------------------------- */

void *memset(void *d, int c, size_t n) {
    unsigned char *p = d;
    while (n--)
        *p++ = (unsigned char)c;
    return d;
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--)
        *a++ = *b++;
    return d;
}

void *memmove(void *d, const void *s, size_t n) {
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a < b) {
        while (n--)
            *a++ = *b++;
    } else {
        a += n;
        b += n;
        while (n--)
            *--a = *--b;
    }
    return d;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
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
    while (*p)
        p++;
    return (size_t)(p - s);
}

size_t cng_strnlen(const char *s, size_t max) {
    size_t i = 0;
    while (i < max && s[i])
        i++;
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

char *strchr(const char *s, int c) {
    for (;; s++) {
        if (*s == (char)c)
            return (char *)s;
        if (!*s)
            return 0;
    }
}

char *strrchr(const char *s, int c) {
    const char *r = 0;
    for (;; s++) {
        if (*s == (char)c)
            r = s;
        if (!*s)
            break;
    }
    return (char *)r;
}

size_t cng_strlcpy(char *dst, const char *src, size_t size) {
    size_t len = strlen(src);
    if (size) {
        size_t n = len < size - 1 ? len : size - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return len;
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

/* The formatter. Writes at most `cap` bytes into `buf` (NUL-terminated when
 * cap > 0) and returns the byte count written, excluding the terminator. */
size_t cng_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap) {
    size_t n = 0;
/* `ch` is evaluated exactly once, and outside the room-to-store test — every
 * caller below hands this an expression with a side effect (`*s++`, `t[--i]`,
 * `va_arg(...)`), and guarding the evaluation stops the side effect the moment
 * the buffer fills. `while (*s) PUT(*s++)` then never advances `s`: a format
 * whose output overruns `cap` did not truncate, it spun forever. */
#define PUT(ch)                                                                \
    do {                                                                       \
        char c_ = (char)(ch);                                                  \
        if (n + 1 < cap)                                                       \
            buf[n] = c_;                                                       \
        n++;                                                                   \
    } while (0)

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
    if (cap) {
        if (n >= cap)
            n = cap - 1; /* truncated */
        buf[n] = '\0';
    }
    return n;
#undef PUT
}

size_t cng_snprintf(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    size_t n = cng_vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return n;
}

void cng_vdprintf(int fd, const char *fmt, va_list ap) {
    char buf[1024];
    size_t n = cng_vsnprintf(buf, sizeof buf, fmt, ap);
    cng_write_all(fd, buf, n);
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
