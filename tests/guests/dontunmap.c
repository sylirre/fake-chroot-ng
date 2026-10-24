/* mremap(MREMAP_DONTUNMAP) out of the program's own image (M23).
 *
 * DONTUNMAP moves the pages and leaves the old range mapped, so the next touch
 * of it faults in whatever backs it: the file's bytes for a file mapping,
 * zero-fill for anonymous memory. A kernel exec maps the image from the file;
 * chroot-ng's loader copies it into anonymous memory, and V8 — moving its
 * embedded builtins out of the text of the binary that carries them, then
 * CHECKing that the first word reads the same at both addresses — died of
 * the difference. The image has to move as the file mapping it stands in for.
 *
 * Three rows, each one page moved with MAYMOVE|FIXED|DONTUNMAP and the old
 * page compared with the new: anonymous memory (zero-fill, and nothing of
 * ours may change that), a private mapping of this program's own file (the
 * kernel's answer, which is the oracle), and a page of this program's
 * read-only data as it was loaded. The last must say what the second says —
 * moved with its bytes kept, or EINVAL from a 5.7-5.12 kernel that moves no
 * file mapping this way. A kernel (or qemu-user) with no DONTUNMAP at all
 * answers the first row EINVAL, and nothing else is asked.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

/* Read-only data of the image, aligned past the largest AArch64 page so that
 * a whole page of it lies in the middle whatever the page size. */
#define BLOB (3 * 65536)
static const unsigned char blob[BLOB] __attribute__((aligned(65536))) = {
    [0 ... BLOB - 1] = 0x5a};

static long pg;

/* Byte-wise through volatile: `blob` is const, and a compiler may otherwise
 * answer a read of it from the initializer rather than from memory. */
static int same(const void *a, const void *b) {
    const volatile unsigned char *x = a, *y = b;
    for (long i = 0; i < pg; i++)
        if (x[i] != y[i])
            return 0;
    return 1;
}

static int zeroed(const void *a) {
    const volatile unsigned char *x = a;
    for (long i = 0; i < pg; i++)
        if (x[i])
            return 0;
    return 1;
}

/* Move the page at `p` with DONTUNMAP and say how it went: whether the old
 * page still reads what moved, or reads zero-fill. */
static int row(const char *tag, void *p) {
    void *t = mmap(NULL, pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *r = mremap(p, pg, pg, MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP,
                     t);
    if (r == MAP_FAILED) {
        printf("%s r=%d\n", tag, errno);
        munmap(t, pg);
        return errno;
    }
    printf("%s r=0 kept=%d zeroed=%d\n", tag, same(p, r), zeroed(p));
    munmap(r, pg);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    pg = sysconf(_SC_PAGESIZE);

    char *a = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(a, 0x5a, pg);
    if (row("anon", a))
        return 0; /* no DONTUNMAP here */

    int fd = open("/proc/self/exe", O_RDONLY);
    void *f = fd >= 0 ? mmap(NULL, pg, PROT_READ, MAP_PRIVATE, fd, 0)
                      : MAP_FAILED;
    if (f == MAP_FAILED)
        printf("file setup errno=%d\n", errno);
    else
        row("file", f);

    row("image", (void *)(((unsigned long)blob + pg) & ~(pg - 1)));
    return 0;
}
