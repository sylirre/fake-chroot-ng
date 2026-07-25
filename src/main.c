/* chroot-ng: ptrace-free chroot/bind emulation for rootless, SELinux-restricted
 * Android. Command-line front end.
 *
 *   chroot-ng [options] <rootfs> <program> [args...]   (normal use)
 *   chroot-ng --probe [path...]                         (capability probe)
 *   chroot-ng --help | --version
 *
 * The full option / environment reference lives in help() below (reachable via
 * -h/--help), which reflows it to the terminal width. Keep the option strings
 * there and the overview in README.md in sync.
 *
 * The runtime is freestanding (no libc), so the help renderer — ported from the
 * sibling arm64chroot project — is built on the cng_ I/O helpers plus a raw
 * ioctl(TIOCGWINSZ). cng_dprintf has fixed widths only (no "%*s"), so column
 * alignment is done with out_pad().
 */
#include "cng/l2s.h"
#include "cng/loader.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/rewrite.h"
#include "cng/rt.h"
#include "cng/syscall.h"


/* --- the run + probe + self-test entry points (own translation units) ----- */
int cng_run(const char *rootfs, const char *libprefix,
            const char *const *bind_g, const char *const *bind_h, int nb,
            int gargc, char **gargv, char **envp, unsigned long *auxv);
int cng_cmd_probe(int argc, char **argv, char **envp, unsigned long *auxv);

int cng_cmd_xlate(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_dtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_sigtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_jmptest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_faketest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_rwtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_nettest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_blocktest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_loadtwice(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_l2stest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_exectest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_cloexectest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_stackswtest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_clonetest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_clonestktest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_proctest(int argc, char **argv, char **envp, unsigned long *auxv);
int cng_cmd_bpftest(int argc, char **argv, char **envp, unsigned long *auxv);

/* Internal self-tests, exposed via `-t/--test NAME`. Hidden from --help; the
 * argument that would be a <rootfs> can never begin with '-', so there is no
 * ambiguity with the normal form. Each callee treats argv[0] as its own name
 * and parses its arguments from argv[1], exactly as when it was a subcommand. */
struct test_entry {
    const char *name;
    int (*fn)(int, char **, char **, unsigned long *);
};
static const struct test_entry g_tests[] = {
    {"xlate", cng_cmd_xlate},           {"dtest", cng_cmd_dtest},
    {"sigtest", cng_cmd_sigtest},       {"jmptest", cng_cmd_jmptest},
    {"faketest", cng_cmd_faketest},     {"rwtest", cng_cmd_rwtest},
    {"nettest", cng_cmd_nettest},       {"blocktest", cng_cmd_blocktest},
    {"loadtwice", cng_cmd_loadtwice},   {"l2stest", cng_cmd_l2stest},
    {"exectest", cng_cmd_exectest},     {"cloexectest", cng_cmd_cloexectest},
    {"stackswtest", cng_cmd_stackswtest}, {"clonetest", cng_cmd_clonetest},
    {"clonestktest", cng_cmd_clonestktest},
    {"proctest", cng_cmd_proctest},   {"bpftest", cng_cmd_bpftest},
};

static int dispatch_test(const char *name, int argc, char **argv, char **envp,
                         unsigned long *auxv) {
    for (unsigned k = 0; k < sizeof g_tests / sizeof *g_tests; k++)
        if (!strcmp(name, g_tests[k].name))
            return g_tests[k].fn(argc, argv, envp, auxv);
    cng_dprintf(2, "chroot-ng: unknown test '%s'\n", name);
    return 2;
}

/* --- freestanding output primitives for the help renderer ----------------- */

static void out(int fd, const char *s, int n) { cng_write_all(fd, s, (size_t)n); }
static void out_str(int fd, const char *s) { cng_write_all(fd, s, strlen(s)); }
static void out_ch(int fd, char c) { cng_write_all(fd, &c, 1); }
static void out_pad(int fd, int n) {
    static const char sp[] = "                ";   /* 16 spaces */
    while (n > 0) {
        int k = n < 16 ? n : 16;
        cng_write_all(fd, sp, (size_t)k);
        n -= k;
    }
}

/* --- terse synopsis + version (argument errors / -v) ---------------------- */

/* One- (or two-) line synopsis for argument errors, to *fd*. The full reference
 * lives in help(), reachable via -h/--help. */
static void usage(int fd) {
    out_str(fd,
        "usage: chroot-ng [options] <rootfs> <program> [args...]\n"
        "       chroot-ng --probe [path...]\n"
        "try 'chroot-ng --help' for details\n");
}

static void version(void) {
    cng_dprintf(1, "chroot-ng %s (built %s %s)\n", CNG_VERSION, __DATE__,
                __TIME__);
}

/* --- help renderer: reflow the reference to the terminal width ------------
 * Layout mirrors arm64chroot's proot-distro-style renderer: UPPERCASE sections
 * framed by blank lines, a two-column name/description table (one blank line
 * between entries) that collapses to a stacked layout on narrow PTYs. */

#define HELP_MIN_COLS 32   /* clamp for very narrow phone PTYs               */
#define HELP_MAX_COLS 92   /* clamp so wide terminals stay readable          */
#define HELP_NARROW   60   /* below this, name+description stack vertically  */

/* struct winsize / TIOCGWINSZ (asm-generic; AArch64 uses these values). */
struct cng_winsize { u16 ws_row, ws_col, ws_xpixel, ws_ypixel; };
#define CNG_TIOCGWINSZ 0x5413UL

/* A named entry (option / argument / env var) with its description. */
struct help_def { const char *name, *desc; };

/* Parse a leading run of decimal digits (COLUMNS); 0 on no digits. */
static int parse_uint(const char *s) {
    int v = 0;
    for (; *s >= '0' && *s <= '9'; s++) v = v * 10 + (*s - '0');
    return v;
}

/* Terminal width for help output, clamped to [HELP_MIN_COLS, HELP_MAX_COLS].
 * Help is written to stdout, so probe stdout first, then stdin/stderr, then
 * $COLUMNS (for redirected runs), finally a sane default. */
static int help_cols(char **envp) {
    struct cng_winsize ws;
    static const int fds[] = { 1, 0, 2 };   /* stdout, stdin, stderr */
    for (int i = 0; i < 3; i++) {
        if (sys_ioctl(fds[i], CNG_TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            int c = ws.ws_col;
            return c < HELP_MIN_COLS ? HELP_MIN_COLS
                 : c > HELP_MAX_COLS ? HELP_MAX_COLS : c;
        }
    }
    int c = 80;
    for (char **e = envp; e && *e; e++)
        if (!strncmp(*e, "COLUMNS=", 8)) {
            int v = parse_uint(*e + 8);
            if (v > 0) c = v;
            break;
        }
    return c < HELP_MIN_COLS ? HELP_MIN_COLS
         : c > HELP_MAX_COLS ? HELP_MAX_COLS : c;
}

/* Greedy word-wrap: emit *text* to *fd* wrapped to *width* columns, every line
 * prefixed with *indent* spaces. Words are never split; a blank line in the
 * source ("\n\n") starts a new paragraph. When *skip_first* is set the leading
 * indent of the very first line is suppressed — the caller has already placed
 * the cursor at column *indent* (used by the two-column table for line 1). */
static void help_wrap(int fd, const char *text, int width, int indent,
                      int skip_first) {
    int avail = width - indent;
    if (avail < 8) avail = 8;
    const char *p = text;
    int col = 0;                 /* chars used on the current line (past indent) */
    int need_indent = !skip_first;
    while (*p) {
        if (p[0] == '\n' && p[1] == '\n') {   /* paragraph break */
            if (col) out_ch(fd, '\n');
            out_ch(fd, '\n');
            col = 0;
            need_indent = 1;
            p += 2;
            while (*p == ' ' || *p == '\n') p++;
            continue;
        }
        if (*p == ' ' || *p == '\n') { p++; continue; }
        const char *e = p;                    /* one word: [p, e) */
        while (*e && *e != ' ' && *e != '\n') e++;
        int wlen = (int)(e - p);
        if (col == 0) {
            if (need_indent) out_pad(fd, indent);
            out(fd, p, wlen);
            col = wlen;
            need_indent = 1;      /* every subsequent line is indented */
        } else if (col + 1 + wlen <= avail) {
            out_ch(fd, ' ');
            out(fd, p, wlen);
            col += 1 + wlen;
        } else {
            out_ch(fd, '\n');
            out_pad(fd, indent);
            out(fd, p, wlen);
            col = wlen;
        }
        p = e;
    }
    if (col) out_ch(fd, '\n');
}

/* Render name/description pairs as an aligned two-column table, falling back
 * to a stacked layout (name on its own line, description indented below) when
 * the terminal is too narrow to give the description a usable column. Entries
 * are separated by one blank line. */
static void help_defs(int fd, const struct help_def *d, int n, int width) {
    int longest = 0;
    for (int i = 0; i < n; i++) {
        int l = (int)strlen(d[i].name);
        if (l > longest) longest = l;
    }
    int cap = width / 3; if (cap < 16) cap = 16;
    int opt_col = longest < cap ? longest : cap;
    int desc_col = width - opt_col - 4;
    int stacked = width < HELP_NARROW || desc_col < 24;

    for (int i = 0; i < n; i++) {
        if (stacked) {
            out_str(fd, "  ");
            out_str(fd, d[i].name);
            out_ch(fd, '\n');
            help_wrap(fd, d[i].desc, width, 4, 0);
        } else {
            int cont = 2 + opt_col + 2;   /* description column start */
            int nlen = (int)strlen(d[i].name);
            if (nlen <= opt_col) {
                /* Name and its pad place the cursor at column *cont*, so the
                 * first description line skips its own indent. */
                out_str(fd, "  ");
                out_str(fd, d[i].name);
                out_pad(fd, opt_col - nlen + 2);
                help_wrap(fd, d[i].desc, width, cont, 1);
            } else {
                out_str(fd, "  ");
                out_str(fd, d[i].name);
                out_ch(fd, '\n');
                help_wrap(fd, d[i].desc, width, cont, 0);
            }
        }
        if (i != n - 1) out_ch(fd, '\n');   /* one blank line between entries */
    }
}

/* Print shell examples, each prefixed with "  $ " and wrapped with a trailing
 * " \\" continuation so long command lines stay copy-pasteable. */
static void help_examples(int fd, const char *const *ex, int n, int width) {
    int avail = width - 6; if (avail < 8) avail = 8;   /* -4 prefix, -2 " \\" */
    for (int i = 0; i < n; i++) {
        const char *p = ex[i];
        int first = 1, col = 0;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            const char *e = p;
            while (*e && *e != ' ') e++;
            int wlen = (int)(e - p);
            if (col == 0) {
                out_str(fd, first ? "  $ " : "    ");
                out(fd, p, wlen);
                col = wlen;
            } else if (col + 1 + wlen <= avail) {
                out_ch(fd, ' ');
                out(fd, p, wlen);
                col += 1 + wlen;
            } else {
                out_str(fd, " \\\n");
                out_str(fd, "    ");
                out(fd, p, wlen);
                col = wlen;
                first = 0;
            }
            p = e;
        }
        out_ch(fd, '\n');
    }
}

/* Blank line, an UPPERCASE section heading, then a blank line beneath it. */
static void help_section(int fd, const char *title) {
    out_ch(fd, '\n');
    out_str(fd, title);
    out_str(fd, "\n\n");
}

/* Full reference help: purpose, usage, arguments, every option, environment
 * variables, and examples. Reflowed to the terminal width. Printed to stdout
 * on -h/--help. */
static void help(char **envp) {
    int fd = 1;
    int w = help_cols(envp);

    static const struct help_def args[] = {
        {"<rootfs>",  "Directory tree holding an AArch64 userland (e.g. an "
                      "Alpine or Debian ARM64 root filesystem); '/' runs "
                      "host-native aarch64 binaries directly (identity, no "
                      "translation). Guest paths resolve inside the rootfs."},
        {"<program>", "Guest program to execute, an absolute path inside the "
                      "rootfs."},
        {"args...",   "Arguments passed on to the guest program."},
    };
    static const struct help_def opts[] = {
        {"-b, --bind G:H", "Bind guest path G to host path H (repeatable, up to "
                      "64). Guest accesses under G resolve to H on the host. "
                      "Neither side may contain ':'."},
        {"-u, --fake-id[=ID]", "Present a fake user identity. ID is a uid or "
                      "uid:gid (a bare -u/--fake-id defaults to 0:0, root; a "
                      "single number sets both uid and gid). Credential syscalls "
                      "report and mutate this identity following POSIX rules, "
                      "and while its effective uid is 0 ownership/mode changes, "
                      "chown, and denied access() checks are faked as succeeding."},
        {"    --setuid-root", "Show setuid executables as owned by root (uid 0), "
                      "and on exec elevate the fake identity's effective uid to "
                      "0. Lets a setuid-root binary such as 'su' gain root under "
                      "a non-root identity. Implies --fake-id, defaulting to your "
                      "real uid/gid (not 0:0) unless -u/--fake-id sets one."},
        {"    --setgid-root", "As --setuid-root, but for setgid executables and "
                      "the group id (gid 0). Implies --fake-id (see above)."},
        {"-l, --link2symlink", "Emulate hardlinks with symlinks plus a hidden "
                      "backing file where the host refuses link(2) (Android / "
                      "SELinux answers EACCES/EXDEV/EPERM). Backing files live "
                      "in a per-rootfs store '<rootfs>/.l2s', invisible to the "
                      "guest; the group presents as ordinary regular files "
                      "sharing one inode — across directories, through mv and "
                      "rm — which lets package managers such as apk/dpkg "
                      "unpack. Off by default: without it the host's refusal "
                      "is reported to the guest unchanged."},
        {"-R, --rewrite", "Rewrite the guest's svc instruction sites to "
                      "trampolines ahead of time. Faster than trapping every "
                      "syscall, and also provides path translation where the "
                      "seccomp monitor is unavailable (e.g. under qemu-user)."},
        {"-F, --file-backed", "Force file-backed segment mapping. Auto-selected "
                      "when anonymous executable memory is denied (Android "
                      "no-new-privs / execmem); this forces it unconditionally."},
        {"    --no-proc", "Disable /proc emulation. By default the host /proc "
                      "is visible to the guest (a rootfs directory tree has "
                      "none, and mounting one needs privileges we lack), host "
                      "processes are hidden from it, and the files that would "
                      "describe chroot-ng rather than the guest — cmdline, "
                      "environ, auxv, maps, mounts, mountinfo, mountstats — are "
                      "served from the guest's own view, as are loadavg, uptime "
                      "and stat where the host denies them. With this flag the "
                      "guest sees only whatever /proc its rootfs (or an "
                      "explicit -b) provides."},
        {"-L, --lib-prefix DIR", "Resolve the ELF interpreter under DIR instead "
                      "of through the rootfs/bind map (test aid). On real "
                      "hardware the interpreter and libraries resolve through "
                      "the rootfs + monitor."},
        {"-t, --test NAME", "Run a built-in self-test (development). All "
                      "remaining arguments are passed to the test."},
        {"    --probe",   "Report kernel / seccomp / execmem / noexec "
                      "capabilities and exit. Optional trailing paths are "
                      "checked for the noexec mount flag (default '/' and '.')."},
        {"-h, --help",    "Show this help and exit."},
        {"-v, --version", "Show version and exit."},
        {"    --",        "Stop option parsing."},
    };
    static const struct help_def env[] = {
        {"CNG_DEBUG", "When set to a non-empty, non-zero value, log verbose "
                      "syscall-error diagnostics to stderr."},
        {"CNG_L2S_FORCE", "With -l: route every linkat through the emulation "
                      "without trying the real hardlink first. Test aid for "
                      "hosts whose filesystem allows link(2)."},
    };
    static const char *const examples[] = {
        "chroot-ng --probe",
        "chroot-ng -u ./rootfs /bin/sh",
        "chroot-ng --fake-id 1000:1000 --setuid-root --setgid-root ./rootfs /bin/su -",
        "chroot-ng -u -l ./rootfs /sbin/apk add busybox",
        "chroot-ng -R -b /tmp:/data/local/tmp ./rootfs /bin/busybox sh",
        "chroot-ng / /usr/bin/uname -a",
    };

    help_section(fd, "USAGE");
    help_wrap(fd, "chroot-ng [options] <rootfs> <program> [args...]\n\n"
                  "chroot-ng --probe [path...]", w, 2, 0);

    help_section(fd, "DESCRIPTION");
    help_wrap(fd,
        "Ptrace-free chroot / bind-mount emulation for rootless, "
        "SELinux-restricted Android without user namespaces. Instead of a "
        "ptrace tracer, chroot-ng intercepts the path-bearing syscalls "
        "in-process via seccomp RET_TRAP -> SIGSYS, and runs guest programs "
        "with its own userland ELF loader, so it can also execute binaries off "
        "'noexec' mounts.\n\n"
        "It works for glibc / musl (dynamic and static) and Go / Rust binaries "
        "without version pinning, where LD_PRELOAD tricks fail and proot's "
        "per-syscall ptrace overhead hurts.\n\n"
        "Run --probe on any target device FIRST: the whole in-process design "
        "depends on the SELinux execmem permission being granted.",
    w, 2, 0);

    help_section(fd, "ARGUMENTS");
    help_defs(fd, args, (int)(sizeof args / sizeof *args), w);

    help_section(fd, "OPTIONS");
    help_defs(fd, opts, (int)(sizeof opts / sizeof *opts), w);

    help_section(fd, "ENVIRONMENT");
    help_defs(fd, env, (int)(sizeof env / sizeof *env), w);

    help_section(fd, "EXAMPLES");
    help_examples(fd, examples, (int)(sizeof examples / sizeof *examples), w);
    out_ch(fd, '\n');   /* trailing blank line so output clears the prompt */
}

/* --- command-line parsing errors ------------------------------------------ */

static int err_unknown(const char *opt) {
    cng_dprintf(2, "chroot-ng: unknown option '%s'\n", opt);
    usage(2);
    return 2;
}
static int err_unknown_short(char c) {
    cng_dprintf(2, "chroot-ng: unknown option '-%c'\n", c);
    usage(2);
    return 2;
}
static int err_needarg(const char *opt) {
    cng_dprintf(2, "chroot-ng: option '%s' requires an argument\n", opt);
    usage(2);
    return 2;
}
static int err_noval(const char *opt) {
    cng_dprintf(2, "chroot-ng: option '%s' takes no value\n", opt);
    usage(2);
    return 2;
}
static int err_badid(const char *spec) {
    cng_dprintf(2, "chroot-ng: --fake-id '%s': expected UID or UID:GID\n", spec);
    usage(2);
    return 2;
}

/* Recognize a fake-id spec: "N" or "N:N" (decimal, non-empty on each side). */
static int is_id_spec(const char *s) {
    if (!s || !*s) return 0;
    int seen_colon = 0, digits = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ':') {
            if (seen_colon || !digits) return 0;
            seen_colon = 1; digits = 0;
        } else if (*p >= '0' && *p <= '9') {
            digits = 1;
        } else {
            return 0;
        }
    }
    return digits;
}

/* Parse a validated "N" (gid defaults to uid) or "N:M" spec into the fake-id
 * globals. Returns 0, or -1 if the spec is malformed. */
static int parse_id_spec(const char *s) {
    if (!is_id_spec(s)) return -1;
    unsigned u = 0;
    const char *p = s;
    for (; *p >= '0' && *p <= '9'; p++) u = u * 10 + (unsigned)(*p - '0');
    unsigned g;
    if (*p == ':') {
        g = 0;
        for (p++; *p >= '0' && *p <= '9'; p++) g = g * 10 + (unsigned)(*p - '0');
    } else {
        g = u;   /* a single value applies to both uid and gid */
    }
    cng_g_fake_uid = u;
    cng_g_fake_gid = g;
    return 0;
}

/* Register a "-b GUEST:HOST" spec into the (guest, host) bind arrays. Returns 0,
 * or -1 (with a diagnostic) on a full table or a malformed spec. */
static int add_bind(char *spec, const char **bind_g, const char **bind_h,
                    int *nb) {
    if (*nb >= CNG_MAX_BINDS) {
        cng_dprintf(2, "chroot-ng: too many --bind mounts (max %d)\n",
                    CNG_MAX_BINDS);
        return -1;
    }
    char *c = strchr(spec, ':');
    if (!c || c == spec || c[1] == '\0') {
        cng_dprintf(2, "chroot-ng: --bind '%s': expected GUEST:HOST\n", spec);
        return -1;
    }
    *c = '\0';
    bind_g[*nb] = spec;
    bind_h[*nb] = c + 1;
    (*nb)++;
    return 0;
}

/* --- entry point ---------------------------------------------------------- */

int cng_main(int argc, char **argv, char **envp, unsigned long *auxv) {
    const char *rootfs = 0;
    const char *libprefix = 0;
    const char *bind_g[CNG_MAX_BINDS];
    const char *bind_h[CNG_MAX_BINDS];
    int nb = 0;

    /* GNU-style options: single-letter short (-R), --word long. Value-taking
     * options accept "-b VAL"/"-bVAL" and "--bind VAL"/"--bind=VAL"; no-arg
     * shorts bundle ("-RF"). Parsing stops at the first non-option, at "--", or
     * at <rootfs>, so guest args are never consumed as options. The mode flags
     * --probe and -t hand the rest of argv to the probe / self-test verbatim. */
    int i = 1;
    for (; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0') break;   /* positional (or lone "-") */
        if (!strcmp(arg, "--")) { i++; break; }        /* explicit end of options */

        if (arg[1] == '-') {                           /* long option: --name[=val] */
            char *eq = strchr(arg, '='), *val = 0;
            if (eq) { *eq = '\0'; val = eq + 1; }      /* argv is writable */
            const char *n = arg + 2;
            if (!strcmp(n, "help")) {
                if (val) return err_noval(arg);
                help(envp);
                return 0;
            } else if (!strcmp(n, "version")) {
                if (val) return err_noval(arg);
                version();
                return 0;
            } else if (!strcmp(n, "probe")) {
                if (val) return err_noval(arg);
                argv[i] = (char *)"probe";             /* callee's argv[0] */
                return cng_cmd_probe(argc - i, argv + i, envp, auxv);
            } else if (!strcmp(n, "fake-id")) {
                cng_g_fake_id = 1;   /* default 0:0 unless a spec follows */
                cng_g_fake_id_explicit = 1;
                if (val) {
                    if (parse_id_spec(val) < 0) return err_badid(val);
                } else if (i + 1 < argc && is_id_spec(argv[i + 1])) {
                    parse_id_spec(argv[++i]);   /* "--fake-id 1000:1000" form */
                }
            } else if (!strcmp(n, "setuid-root")) {
                if (val) return err_noval(arg);
                cng_g_fake_id = 1;   /* implies the fake-id subsystem */
                cng_g_setuid_root = 1;
            } else if (!strcmp(n, "setgid-root")) {
                if (val) return err_noval(arg);
                cng_g_fake_id = 1;
                cng_g_setgid_root = 1;
            } else if (!strcmp(n, "link2symlink")) {
                if (val) return err_noval(arg);
                cng_g_l2s = 1;
            } else if (!strcmp(n, "rewrite")) {
                if (val) return err_noval(arg);
                cng_g_rewrite = 1;
            } else if (!strcmp(n, "file-backed")) {
                if (val) return err_noval(arg);
                cng_g_loader_file = 1;
            } else if (!strcmp(n, "no-proc")) {
                if (val) return err_noval(arg);
                cng_g_no_proc = 1;
            } else if (!strcmp(n, "bind")) {
                char *spec = val;
                if (!spec) {
                    if (i + 1 >= argc) return err_needarg("--bind");
                    spec = argv[++i];
                }
                if (add_bind(spec, bind_g, bind_h, &nb) < 0) return 2;
            } else if (!strcmp(n, "lib-prefix")) {
                if (val) libprefix = val;
                else {
                    if (i + 1 >= argc) return err_needarg("--lib-prefix");
                    libprefix = argv[++i];
                }
            } else if (!strcmp(n, "test")) {
                char *name; int k;
                if (val) { argv[i] = val; k = i; name = val; }   /* --test=NAME */
                else {
                    if (i + 1 >= argc) return err_needarg("--test");
                    k = i + 1; name = argv[k];                   /* --test NAME */
                }
                return dispatch_test(name, argc - k, argv + k, envp, auxv);
            } else {
                return err_unknown(arg);
            }
        } else {                                       /* short cluster: -RFb... */
            for (char *p = arg + 1; *p; ) {
                char c = *p++;
                if (c == 'h') { help(envp); return 0; }
                else if (c == 'v') { version(); return 0; }
                else if (c == 'u') {
                    cng_g_fake_id = 1;   /* default 0:0 unless a spec follows */
                    cng_g_fake_id_explicit = 1;
                    if (*p) {                                    /* -uID */
                        if (parse_id_spec(p) < 0) return err_badid(p);
                    } else if (i + 1 < argc && is_id_spec(argv[i + 1])) {
                        parse_id_spec(argv[++i]);                /* -u ID */
                    }
                    break;   /* -u takes the rest of the cluster / next token */
                }
                else if (c == 'l') { cng_g_l2s = 1; }
                else if (c == 'R') { cng_g_rewrite = 1; }
                else if (c == 'F') { cng_g_loader_file = 1; }
                else if (c == 'b') {
                    char *spec = *p ? p : (i + 1 < argc ? argv[++i] : 0);
                    if (!spec) return err_needarg("-b");
                    if (add_bind(spec, bind_g, bind_h, &nb) < 0) return 2;
                    break;
                } else if (c == 'L') {
                    char *v = *p ? p : (i + 1 < argc ? argv[++i] : 0);
                    if (!v) return err_needarg("-L");
                    libprefix = v;
                    break;
                } else if (c == 't') {
                    char *name; int k;
                    if (*p) { name = p; argv[i] = name; k = i; }  /* -tNAME */
                    else if (i + 1 < argc) { k = i + 1; name = argv[k]; }  /* -t NAME */
                    else return err_needarg("-t");
                    return dispatch_test(name, argc - k, argv + k, envp, auxv);
                } else {
                    return err_unknown_short(c);
                }
            }
        }
    }

    /* Normal form: <rootfs> <program> [args...]. */
    if (argc - i < 2) {
        usage(2);
        return 2;
    }
    rootfs = argv[i];
    char **gargv = argv + i + 1;
    int gargc = argc - i - 1;

    return cng_run(rootfs, libprefix, bind_g, bind_h, nb, gargc, gargv, envp,
                   auxv);
}
