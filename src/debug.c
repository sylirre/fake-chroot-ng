/* Hidden debug subcommands for testing internals without a real kernel.
 *   _xlate -r ROOT [-b GUEST:HOST]... [-C CWD] PATH...
 * prints guest->host path translations. Used by the M5 unit tests (the path
 * core is pure logic, fully exercisable under qemu).
 */
#include "cng/path.h"
#include "cng/rt.h"

int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv) {
    (void)envp;
    (void)auxv;

    const char *rootfs = "/";
    const char *cwd = 0;
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int nb = 0;
    const char *paths[256];
    int np = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) {
            rootfs = argv[++i];
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
            char *spec = argv[++i];
            char *c = strchr(spec, ':');
            if (c && nb < CNG_MAX_BINDS) {
                *c = '\0';
                bind_g[nb] = spec;
                bind_h[nb] = c + 1;
                nb++;
            }
        } else if (!strcmp(argv[i], "-C") && i + 1 < argc) {
            cwd = argv[++i];
        } else if (np < 256) {
            paths[np++] = argv[i];
        }
    }

    struct cng_fs fs;
    cng_fs_init(&fs, rootfs);
    for (int i = 0; i < nb; i++)
        cng_fs_add_bind(&fs, bind_g[i], bind_h[i]);
    if (cwd)
        cng_fs_set_cwd(&fs, cwd);

    char out[CNG_PATH_MAX];
    for (int i = 0; i < np; i++) {
        if (cng_fs_translate(&fs, paths[i], out, sizeof out) == 0)
            cng_dprintf(1, "%s -> %s\n", paths[i], out);
        else
            cng_dprintf(1, "%s -> <overflow>\n", paths[i]);
    }
    return 0;
}
