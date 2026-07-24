#include "cng/rt.h"
#include "cng/syscall.h"

#define CNG_VERSION "0.0.1"

static void usage(int fd, const char *prog) {
    cng_dprintf(fd,
        "chroot-ng %s - ptrace-free chroot/bind emulation for rootless Android\n"
        "\n"
        "usage: %s <command> [args]\n"
        "\n"
        "commands:\n"
        "  probe                 report kernel/seccomp/execmem/noexec capabilities\n"
        "  run [opts] -- PROG..  load and run PROG under path virtualization\n"
        "  version               print version\n"
        "  help                  show this help\n",
        CNG_VERSION, prog);
}

/* Forward declarations of subcommands (implemented in their own units as the
 * project grows). Stubs live here until then. */
int cng_cmd_probe(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_run(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_dtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_sigtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_jmptest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_faketest(int argc, char **argv, char **envp, unsigned long *auxv);

int cng_main(int argc, char **argv, char **envp, unsigned long *auxv) {
    const char *prog = argc > 0 ? argv[0] : "chroot-ng";

    if (argc < 2) {
        usage(2, prog);
        return 2;
    }

    const char *sub = argv[1];
    if (!strcmp(sub, "help") || !strcmp(sub, "--help") || !strcmp(sub, "-h")) {
        usage(1, prog);
        return 0;
    }
    if (!strcmp(sub, "version") || !strcmp(sub, "--version")) {
        cng_dprintf(1, "chroot-ng %s\n", CNG_VERSION);
        return 0;
    }
    if (!strcmp(sub, "probe"))
        return cng_cmd_probe(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "run"))
        return cng_cmd_run(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "_xlate"))
        return cng_cmd_xlate(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "_dtest"))
        return cng_cmd_dtest(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "_sigtest"))
        return cng_cmd_sigtest(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "_jmptest"))
        return cng_cmd_jmptest(argc - 1, argv + 1, envp, auxv);
    if (!strcmp(sub, "_faketest"))
        return cng_cmd_faketest(argc - 1, argv + 1, envp, auxv);

    cng_dprintf(2, "chroot-ng: unknown command '%s'\n", sub);
    usage(2, prog);
    return 2;
}

/* Temporary stubs; replaced in later milestones. */
__attribute__((weak)) int cng_cmd_probe(int argc, char **argv, char **envp,
                                        unsigned long *auxv) {
    (void)argc; (void)argv; (void)envp; (void)auxv;
    cng_dprintf(2, "probe: not implemented yet\n");
    return 1;
}
__attribute__((weak)) int cng_cmd_run(int argc, char **argv, char **envp,
                                      unsigned long *auxv) {
    (void)argc; (void)argv; (void)envp; (void)auxv;
    cng_dprintf(2, "run: not implemented yet\n");
    return 1;
}
