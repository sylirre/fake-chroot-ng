/* `chroot-ng run [opts] -- PROG [args]` — load PROG with the userland loader,
 * install the path-translation monitor, and transfer control.
 *
 *   -r DIR   guest rootfs (host path); default "/" (identity)
 *   -b G:H   bind guest path G to host path H (repeatable)
 *   -L DIR   resolve the ELF interpreter under DIR (test aid; on real hardware
 *            the interpreter and libraries resolve through -r/-b + the monitor)
 *
 * PROG is a guest path resolved through the rootfs/bind map. The monitor traps
 * the guest's own path syscalls and translates them (see monitor.h). Under
 * qemu-user the seccomp filter is inert, so translation is only exercised on a
 * real AArch64 kernel (and via the `_dtest` self-test).
 */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"

static struct cng_fs g_fs; /* static: the monitor keeps a pointer after we jump */

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

static char *join2(char *dst, size_t size, const char *a, const char *b) {
    size_t n = cng_strlcpy(dst, a, size);
    if (n < size)
        cng_strlcpy(dst + n, b, size - n);
    return dst;
}

int cng_cmd_run(int argc, char **argv, char **envp, unsigned long *auxv) {
    int i = 1; /* argv[0] == "run" */
    const char *libprefix = 0;
    const char *rootfs = "/";
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int nb = 0;

    while (i < argc && argv[i][0] == '-' && strcmp(argv[i], "--") != 0) {
        if (!strcmp(argv[i], "-L") && i + 1 < argc) {
            libprefix = argv[++i];
        } else if (!strcmp(argv[i], "-0")) {
            cng_g_fake_id = 1;
            cng_g_fake_uid = 0;
            cng_g_fake_gid = 0;
        } else if (!strcmp(argv[i], "-R")) {
            cng_g_rewrite = 1;
        } else if (!strcmp(argv[i], "-F")) {
            cng_g_loader_file = 1;
        } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc && nb < CNG_MAX_BINDS) {
            char *spec = argv[++i];
            char *c = strchr(spec, ':');
            if (c) {
                *c = '\0';
                bind_g[nb] = spec;
                bind_h[nb] = c + 1;
                nb++;
            }
        } else {
            cng_dprintf(2, "chroot-ng run: bad option %s\n", argv[i]);
            return 2;
        }
        i++;
    }
    if (i < argc && !strcmp(argv[i], "--"))
        i++;
    if (i >= argc) {
        cng_dprintf(2, "chroot-ng run: missing program\n"
                       "usage: chroot-ng run [-r rootfs] [-b g:h] [-0] [-R]"
                       " [-L dir] -- PROG [args]\n"
                       "  -0   fake root (uid/gid 0, ownership, chown)\n"
                       "  -R   rewrite svc sites to trampolines (faster; also\n"
                       "       provides translation where seccomp is absent)\n"
                       "  -F   force file-backed segment mapping (auto-selected\n"
                       "       when anon exec memory is denied, e.g. Android NNP)\n");
        return 2;
    }

    char **gargv = argv + i;
    int gargc = argc - i;
    const char *prog_guest = gargv[0];

    /* Capture host auxv (for emulated execve) and the guest exe path
     * (for /proc/self/exe fixups). */
    cng_host_auxv = auxv;
    cng_g_exe_guest = prog_guest;

    /* Filesystem view. */
    cng_fs_init(&g_fs, rootfs);
    for (int j = 0; j < nb; j++)
        cng_fs_add_bind(&g_fs, bind_g[j], bind_h[j]);
    char cwd[CNG_PATH_MAX];
    if (sys_getcwd(cwd, sizeof cwd) > 0)
        cng_fs_set_cwd(&g_fs, cwd);

    /* The dispatcher (used by both the SIGSYS handler and M8 trampolines) needs
     * the fs view even if the seccomp monitor never installs (e.g. -R only). */
    cng_g_fs = &g_fs;

    /* Resolve the program itself through the map (following symlinks) to find
     * the host file. */
    char host_prog[CNG_PATH_MAX];
    if (cng_resolve(prog_guest, 1, host_prog, sizeof host_prog) != 0) {
        cng_dprintf(2, "chroot-ng: cannot resolve %s\n", prog_guest);
        return 1;
    }

    struct cng_loaded prog;
    int rc = cng_load_elf(host_prog, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        cng_dprintf(2, "chroot-ng: cannot load %s (%s): %s\n", prog_guest,
                    host_prog, load_err(rc));
        return 1;
    }

    unsigned long sp, entry;
    if (prog.has_interp) {
        char ipath[CNG_PATH_MAX];
        const char *ip;
        if (libprefix)
            ip = join2(ipath, sizeof ipath, libprefix, prog.interp);
        else if (cng_resolve(prog.interp, 1, ipath, sizeof ipath) == 0)
            ip = ipath;
        else
            ip = prog.interp;

        struct cng_loaded interp;
        int rc2 = cng_load_elf(ip, 0, &interp);
        if (rc2 != CNG_LOAD_OK) {
            cng_dprintf(2, "chroot-ng: cannot load interpreter %s: %s\n", ip,
                        load_err(rc2));
            return 1;
        }
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, &interp,
                             prog_guest);
        entry = interp.entry;
    } else {
        sp = cng_build_stack(gargc, gargv, envp, auxv, &prog, 0, prog_guest);
        entry = prog.entry;
    }
    /* (svc rewriting + its pool are handled inside the loader, per object.) */

    /* Install the monitor last, after all of our own path syscalls are done.
     * Only when translation was actually requested; identity needs none. */
    int want_xlate =
        (strcmp(rootfs, "/") != 0) || nb > 0 || cng_g_fake_id || cng_g_rewrite;
    if (want_xlate) {
        int mrc = cng_install_monitor(&g_fs);
        if (mrc < 0)
            cng_dprintf(2,
                        "chroot-ng: warning: could not install seccomp monitor "
                        "(errno %d); %s\n"
                        "           (seccomp is inert under qemu-user; a real "
                        "AArch64 kernel is required for the SIGSYS path)\n",
                        -mrc,
                        cng_g_rewrite
                            ? "svc-rewriting (-R) still handles located sites"
                            : "path translation is INACTIVE");
    }

    cng_enter(sp, entry);
}
