/* In-process execve/execveat emulation.
 *
 * A real kernel execve replaces the address space, wiping our SIGSYS handler
 * (the seccomp filter survives, but with no handler the next trap kills the
 * process). So we never let execve reach the kernel: we load the new program
 * ourselves and rewrite the trapped signal context to enter it, leaving the
 * monitor resident. This is the piece that makes the in-process model hold
 * together across program replacement.
 *
 * We do not tear down the previous program's mappings; the new program gets a
 * fresh stack and a kernel-chosen load base, so they don't collide. Repeated
 * execve leaks the old images (acceptable for now; noted in STATUS).
 */
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"
#include "cng/ucontext.h"

unsigned long *cng_host_auxv = 0;

void cng_emulate_execve(struct cng_ucontext *uc, int dirfd, const char *path,
                        char **argv, char **envp) {
    unsigned long long *r = uc->uc_mcontext.regs;

    if (!path) {
        r[0] = (unsigned long long)(long)-EFAULT;
        return;
    }

    /* Resolve the target through the rootfs/bind map (absolute or AT_FDCWD);
     * a real dirfd with a relative path is a rare case we pass through. */
    char host[CNG_PATH_MAX];
    const char *resolved = path;
    if (path[0] == '/' || dirfd == CNG_AT_FDCWD) {
        if (cng_fs_translate(cng_g_fs, path, host, sizeof host) != 0) {
            r[0] = (unsigned long long)(long)-ENAMETOOLONG;
            return;
        }
        resolved = host;
    }

    struct cng_loaded prog;
    int rc = cng_load_elf(resolved, 0, &prog);
    if (rc != CNG_LOAD_OK) {
        r[0] = (unsigned long long)(long)(rc == CNG_LOAD_EOPEN ? -ENOENT
                                                              : -ENOEXEC);
        return;
    }

    struct cng_loaded interp;
    int have_interp = 0;
    if (prog.has_interp) {
        char ip[CNG_PATH_MAX];
        if (cng_fs_translate(cng_g_fs, prog.interp, ip, sizeof ip) != 0 ||
            cng_load_elf(ip, 0, &interp) != CNG_LOAD_OK) {
            r[0] = (unsigned long long)(long)-ENOENT;
            return;
        }
        have_interp = 1;
    }

    int argc = 0;
    if (argv)
        while (argv[argc])
            argc++;

    unsigned long sp = cng_build_stack(argc, argv, envp, cng_host_auxv, &prog,
                                       have_interp ? &interp : 0, path);
    unsigned long entry = have_interp ? interp.entry : prog.entry;

    /* Rewrite the signal context to the new program's fresh entry state, then
     * return: rt_sigreturn resumes at `entry` with the new stack, handler and
     * filter still installed. */
    for (int i = 0; i < 31; i++)
        r[i] = 0;
    uc->uc_mcontext.sp = sp;
    uc->uc_mcontext.pc = entry;
}
