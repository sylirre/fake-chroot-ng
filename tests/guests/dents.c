/* Raw getdents64 of one directory, the way GNU ls -F / find -type read it:
 * every record's d_type, and whether its d_ino is the st_ino stat(2) reports
 * for the same name. Printed one entry per line, sorted by the caller.
 *
 * Busybox stats every entry it lists, so a listing that lies in d_type or
 * d_ino is invisible to it; this is the probe that sees what the dirent
 * itself says. Under chroot-ng -l a hardlink is a symlink to a hidden backing
 * file, and the kernel's record for it — DT_LNK, the symlink's own inode — is
 * not what stat() of the name answers. */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct dent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static const char *tname(unsigned t) {
    switch (t) {
    case DT_REG: return "REG";
    case DT_DIR: return "DIR";
    case DT_LNK: return "LNK";
    case DT_UNKNOWN: return "UNKNOWN";
    default: return "OTHER";
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: dents DIR\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    char buf[8192];
    for (;;) {
        long n = syscall(SYS_getdents64, fd, buf, sizeof buf);
        if (n < 0) {
            perror("getdents64");
            return 1;
        }
        if (n == 0)
            break;
        for (long o = 0; o < n;) {
            struct dent64 *d = (struct dent64 *)(buf + o);
            struct stat st, lst;
            int s = fstatat(fd, d->d_name, &st, 0) == 0;
            int l = fstatat(fd, d->d_name, &lst, AT_SYMLINK_NOFOLLOW) == 0;
            printf("%s type=%s ino=%s lino=%s\n", d->d_name, tname(d->d_type),
                   s ? (st.st_ino == d->d_ino ? "same" : "differs") : "nostat",
                   l ? (lst.st_ino == d->d_ino ? "same" : "differs") : "nostat");
            o += d->d_reclen;
        }
    }
    close(fd);
    return 0;
}
