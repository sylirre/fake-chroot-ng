/* Userland ELF loader (ul_exec): map a guest program into this address space
 * from a read-only file descriptor — no kernel execve, no file-backed
 * PROT_EXEC — so it works off a true noexec mount and lets us instrument the
 * guest in-process. See docs/DESIGN.md.
 */
#ifndef CNG_LOADER_H
#define CNG_LOADER_H

#include <stddef.h>

/* Set from auxv AT_PAGESZ at startup (default 4096). */
extern unsigned long cng_page_size;

static inline unsigned long cng_page_down(unsigned long a) {
    return a & ~(cng_page_size - 1);
}
static inline unsigned long cng_page_up(unsigned long a) {
    return (a + cng_page_size - 1) & ~(cng_page_size - 1);
}

struct cng_loaded {
    unsigned long entry;   /* absolute entry point (bias + e_entry) */
    unsigned long phdr;    /* absolute address of program headers in memory */
    unsigned long phent;   /* e_phentsize */
    unsigned long phnum;   /* e_phnum */
    unsigned long base;    /* load bias (0 for ET_EXEC) */
    unsigned long load_lo; /* lowest mapped page (absolute) */
    unsigned long load_hi; /* highest mapped page end (absolute) */
    int is_dyn;            /* ET_DYN vs ET_EXEC */
    int has_interp;        /* PT_INTERP present */
    char interp[256];      /* interpreter path if has_interp */
};

/* Load result codes (negative). */
#define CNG_LOAD_OK        0
#define CNG_LOAD_EOPEN    -1
#define CNG_LOAD_EFORMAT  -2  /* not ELF64 / wrong arch / bad type */
#define CNG_LOAD_EIO      -3  /* short/failed read */
#define CNG_LOAD_EMAP     -4  /* mmap/mprotect failed */
#define CNG_LOAD_ETOOBIG  -5  /* too many phdrs / interp too long */
#define CNG_LOAD_EEXEC    -6  /* anon mprotect(RX) denied — retry file-backed */

/* Force file-backed segment mapping (mmap PROT_EXEC from the file) instead of
 * anon copy+mprotect. Set automatically after the first anon-exec denial (e.g.
 * NO_NEW_PRIVS revoking execmem on Android), or via `run -F`. Requires an
 * exec-permitted mount; anon is required to defeat a true noexec mount. */
extern int cng_g_loader_file;

/* Re-test anon executable memory after NO_NEW_PRIVS/seccomp are active; sets
 * cng_g_loader_file if it is now denied. Call once after installing the monitor. */
void cng_loader_check_execmem(void);

/* Load the ELF at `path` (opened read-only). On success fills *out and returns
 * CNG_LOAD_OK. `base_hint` is an mmap hint for ET_DYN (0 = let kernel choose).
 * Detects PT_INTERP but does not load it (see cng_load_interp). */
int cng_load_elf(const char *path, unsigned long base_hint,
                 struct cng_loaded *out);

/* Same, from an already-open fd (left open, and its file offset untouched —
 * everything is pread/mmap). Lets an exec of "/proc/self/fd/N" load the open
 * file description itself rather than reopening the magic link: the kernel
 * checks *execute* permission for execve where a reopen needs *read*, and the
 * file may have no readable name at all (memfd, O_TMPFILE, deleted). */
int cng_load_elf_fd(int fd, unsigned long base_hint, struct cng_loaded *out);

/* Size of the fixed anonymous stack each loaded program gets (see stack.c).
 * Exposed because the emulated execve bounds argv/envp against it, exactly as
 * the kernel bounds ARG_MAX against RLIMIT_STACK. */
#define CNG_GUEST_STACK_SIZE (64UL << 20)

/* Upper bound on -E/--env entries. The guest environment is assembled from those
 * plus the two inherited terminal variables (see cng_run), so a vector holding
 * the result needs CNG_MAX_ENV + 3 slots. */
#define CNG_MAX_ENV 128

/* Build the initial process stack (argc/argv/envp/auxv) for the loaded program
 * (and optional interpreter) and return the guest stack pointer, or 0 if
 * argv/envp do not fit the stack region (the caller answers -E2BIG, as the
 * kernel does). `envp` is the GUEST environment — for the initial program the
 * one cng_run assembled, not the host's; for an emulated execve whatever the
 * guest passed. */
unsigned long cng_build_stack(int argc, char **argv, char **envp,
                              unsigned long *host_auxv,
                              const struct cng_loaded *prog,
                              const struct cng_loaded *interp,
                              const char *execfn);

/* Transfer control: set sp, clear registers, jump to entry. Never returns. */
_Noreturn void cng_enter(unsigned long sp, unsigned long entry);

#endif /* CNG_LOADER_H */
