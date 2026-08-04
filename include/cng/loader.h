/* Userland ELF loader (ul_exec): map a guest program into this address space
 * from a read-only file descriptor — no kernel execve, no file-backed
 * PROT_EXEC — so it works off a true noexec mount and lets us instrument the
 * guest in-process. See docs/DESIGN.md.
 */
#ifndef CNG_LOADER_H
#define CNG_LOADER_H

#include <stddef.h>

#include "cng/elf.h"

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
#define CNG_LOAD_EACCES   -7  /* not a regular file, or no execute bit at all */

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

/* Program headers we are willing to look at. */
#define CNG_MAX_PHDR 64

/* The two halves of a load, so that everything which can be refused happens
 * before anything is mapped.
 *
 * Loading an ET_EXEC image is destructive: its segments go down MAP_FIXED at the
 * link-time vaddr, which for two binaries out of the same toolchain is the
 * calling program's own text. Once that mmap lands there is no caller left to
 * return an errno to — so an emulated execve must first *plan* the program AND
 * its ELF interpreter (headers read, span computed, everything validated), and
 * only then map them. This is the same line the kernel draws around
 * begin_new_exec(): refusals before it, and a fatal signal after.
 *
 * A plan holds the file it was read from; cng_elf_plan_release closes it if the
 * plan opened it (never a borrowed fd). Mapping needs it, so release only after
 * cng_elf_map — or after giving up on a plan that will not be mapped. */
struct cng_elf_plan {
    Elf64_Ehdr eh;
    Elf64_Phdr ph[CNG_MAX_PHDR];
    unsigned long lo;  /* page-aligned bottom of the PT_LOAD span */
    unsigned long hi;  /* page-aligned top of it */
    int is_dyn;
    int fd;            /* the file to map from, -1 once released */
    int own_fd;        /* set when the plan opened it and must close it */
    int err;           /* CNG_LOAD_EOPEN: the open's own errno, negative. An
                        * exec that fails has to answer with it — ENOENT and
                        * EACCES are different answers to a caller that lived
                        * to read them. */
};

/* Header pass: read and validate, map nothing. Fills *plan and the PT_INTERP
 * half of *out (interp/has_interp); the rest of *out is cng_elf_map's. */
int cng_elf_plan(const char *path, struct cng_elf_plan *plan,
                 struct cng_loaded *out);
int cng_elf_plan_fd(int fd, struct cng_elf_plan *plan, struct cng_loaded *out);

/* Map pass: the destructive half. `base_hint` is an mmap hint for ET_DYN
 * (0 = let the kernel choose); an ET_EXEC plan ignores it and goes MAP_FIXED. */
int cng_elf_map(const struct cng_elf_plan *plan, unsigned long base_hint,
                struct cng_loaded *out);

void cng_elf_plan_release(struct cng_elf_plan *plan);

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
