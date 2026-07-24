/* `chroot-ng run [opts] -- PROG [args]` — load PROG with the userland loader
 * and transfer control to it.
 *
 * M3: static / static-PIE guests, no path virtualization yet. Later milestones
 * add the interpreter (M4), the seccomp/SIGSYS monitor + bind/rootfs
 * translation (M5), and option parsing for -r/-b.
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

int cng_cmd_run(int argc, char **argv, char **envp, unsigned long *auxv) {
    int i = 1; /* argv[0] == "run" */
    if (i < argc && !strcmp(argv[i], "--"))
        i++;
    if (i >= argc) {
        cng_dprintf(2, "chroot-ng run: missing program\n"
                       "usage: chroot-ng run [opts] -- PROG [args]\n");
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
    if (prog.has_interp) {
        cng_dprintf(2,
                    "chroot-ng: %s is dynamically linked (interp %s);\n"
                    "           dynamic loading arrives in M4\n",
                    path, prog.interp);
        return 1;
    }

    unsigned long sp =
        cng_build_stack(gargc, gargv, envp, auxv, &prog, 0, path);
    cng_enter(sp, prog.entry);
}
