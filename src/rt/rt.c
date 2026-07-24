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

void cng_vdprintf(int fd, const char *fmt, va_list ap) {
    char buf[1024];
    size_t n = 0;
#define PUT(ch)                                                                \
    do {                                                                       \
        if (n < sizeof(buf))                                                   \
            buf[n++] = (char)(ch);                                             \
    } while (0)

    for (const char *f = fmt; *f; f++) {
        if (*f != '%') {
            PUT(*f);
            continue;
        }
        f++;
        int lng = 0;
        while (*f == 'l') {
            lng++;
            f++;
        }
        if (*f == 'z') {
            lng = 2;
            f++;
        }
        switch (*f) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
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
            if (neg)
                PUT('-');
            while (i)
                PUT(t[--i]);
            break;
        }
        case 'u':
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
                if (*f == 'x')
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
            while (i)
                PUT(t[--i]);
            break;
        }
        default:
            PUT('%');
            PUT(*f);
            break;
        }
    }
    cng_write_all(fd, buf, n);
#undef PUT
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

int cng_main(int argc, char **argv, char **envp, unsigned long *auxv);

void cng_bootstrap(unsigned long *sp) {
    long argc = (long)sp[0];
    char **argv = (char **)&sp[1];
    char **envp = argv + argc + 1;
    char **p = envp;
    while (*p)
        p++;
    unsigned long *auxv = (unsigned long *)(p + 1);

    int rc = cng_main((int)argc, argv, envp, auxv);
    sys_exit_group(rc);
}
