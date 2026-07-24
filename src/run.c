/* `chroot-ng run [opts] -- PROG [args]` — load PROG with the userland loader
 * and transfer control to it.
 *
 * M3: static / static-PIE guests.
 * M4: dynamic guests — load PT_INTERP (ld.so) and jump to *its* entry with
 *     AT_BASE/AT_ENTRY/AT_PHDR set so it bootstraps the main program.
 *
 * `-L DIR` resolves the interpreter (and, once M5 lands, the whole guest
 * filesystem) under DIR. Later milestones replace it with -r rootfs + -b binds
 * and route ld.so's own opens through the SIGSYS path translator.
 */
#include "cng/loader.h"
#include "cng/rt.h"
#include "cng/syscall.h"

static const char *load_err(int rc) {
    switch (rc) {
    case CNG_LOAD_EOPEN:
        return "cannot open (missing or unreadable)";
    case CNG_LOAD_EFORMAT:
        return "not an AArch64 ELF64 executable";
    case CNG_LOAD_EIO:
        return "short/failed read";
    case CNG_LOAD_EMAP:
        return "mmap/mprotect failed (execmem denied?)";
    case CNG_LOAD_ETOOBIG:
        return "too many program headers / interp too long";
    default:
        return "unknown error";
    }
}

/* dst = a + b, truncating safely. Returns dst. */
static char *join2(char *dst, size_t size, const char *a, const char *b) {
    size_t n = cng_strlcpy(dst, a, size);
    if (n < size)
        cng_strlcpy(dst + n, b, size - n);
    return dst;
}

int cng_cmd_run(int argc, char **argv, char **envp, unsigned long *auxv) {
    int i = 1; /* argv[0] == "run" */
    const char *libprefix = 0;

    while (i < argc && argv[i][0] == '-' && strcmp(argv[i], "--") != 0) {
        if (!strcmp(argv[i], "-L") && i + 1 < argc) {
            libprefix = argv[i + 1];
            i += 2;
            continue;
        }
        cng_dprintf(2, "chroot-ng run: unknown option %s\n", argv[i]);
        return 2;
    }
    if (i < argc && !strcmp(argv[i], "--"))
        i++;
    if (i >= argc) {
        cng_dprintf(2, "chroot-ng run: missing program\n"
                       "usage: chroot-ng run [-L dir] -- PROG [args]\n");
        return 2;
    }

    char **gargv = argv + i;
    int gargc = argc - i;
    const char *path = gargv[0];

    struct cng_loaded prog;
    int rc = cng_load_elf(path, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        cng_dprintf(2, "chroot-ng: cannot load %s: %s\n", path, load_err(rc));
        return 1;
    }

    unsigned long sp, entry;
    if (prog.has_interp) {
        /* Resolve interpreter path (absolute), optionally under -L prefix. */
        char ipath[512];
        const char *ip = prog.interp;
        if (libprefix)
            ip = join2(ipath, sizeof ipath, libprefix, prog.interp);

        struct cng_loaded interp;
        int rc2 = cng_load_elf(ip, 0, &interp);
        if (rc2 != CNG_LOAD_OK) {
            cng_dprintf(2, "chroot-ng: cannot load interpreter %s: %s\n", ip,
                        load_err(rc2));
            return 1;
        }
        /* Jump to ld.so; it maps libraries and bootstraps the main program. */
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, &interp, path);
        entry = interp.entry;
    } else {
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, 0, path);
        entry = prog.entry;
    }

    cng_enter(sp, entry);
}
