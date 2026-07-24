# chroot-ng — status & roadmap

Milestones are committed individually. Each builds on the previous.

## Verified on-device (Android 15, kernel 5.15, rootless, SELinux, no userns)
An Alpine aarch64 rootfs runs under `chroot-ng -0 <rootfs> <program>` with no ptrace and no
user namespaces, on an execmem-denied mount:
- interactive shell + coreutils/busybox, `su -l`
- `apk` (full package manager: add/fix, incl. hardlinked packages via
  link2symlink)
- `git clone` over https
- **Go** builds end-to-end, including **cgo** (`go build` drives `gcc`→`cc1`)
- **gcc** compiles and links a working binary
Getting the C/Go toolchains working shook out a chain of execve/clone-fidelity
gaps that only a real fork+exec of a compiler exposes — see the entries below on
handler-stack isolation, signal masking, the 0x400000 relocation, and the
vfork/`posix_spawn` child-stack handling.

## Legend
- [x] done and tested
- [~] in progress
- [ ] not started

## Milestones

- [x] **M1 — scaffolding + freestanding runtime + CLI skeleton**
  Cross build (aarch64-linux-gnu) + qemu run. Own `_start`, syscall gate
  (single `svc`), mem/str helpers, mini-printf, and a GNU-style option parser
  (`--version`/`--help`/`--probe`, positional `<rootfs> <program>`, `-t` for the
  internal self-tests). Verified under qemu-aarch64.

- [x] **M2 — capability probe** (`chroot-ng --probe [path...]`)
  Reports kernel version (uname parse), auxv/identity, seccomp filter
  availability (child-process RET_ERRNO functional test), `execmem` (anon
  `mmap` RW→RX→execute a thunk — the pivotal test, with AArch64 icache flush),
  and per-mount `noexec` (`statfs` f_flags). Emits a viability verdict. Verified
  under qemu; the seccomp path is inert under qemu and must be confirmed on real
  hardware. Live `RET_TRAP`+SIGSYS validation deferred to M5.

- [x] **M3 — `ul_exec` loader: static binaries**
  Parse ELF64, map `PT_LOAD` into anon RW→RX (via `pread`, no execve/file
  PROT_EXEC), build the initial stack + synthesized auxv, clear registers, jump
  to entry. A static-PIE glibc guest runs end-to-end under qemu: correct
  argc/argv/env, live syscall, glibc init + self-relocation, exit code. This is
  the `noexec` defeat (file only ever opened O_RDONLY + read).
  Known limitations (tracked for later):
  - ET_EXEC guests at a fixed vaddr that collides with the non-PIE loader
    (0x400000) are unsupported; Android guests are PIE so this is moot. Fixing
    needs a static-PIE self-relocating loader.
  - Per-segment `mprotect` is page-granular; assumes segments don't share a
    page (true for max-page-size-aligned AArch64 ELFs). Add per-page perm-union
    if a counterexample appears.

- [x] **M4 — `ul_exec` loader: dynamic binaries**
  Load `PT_INTERP` (`ld.so`) at its own base, set `AT_BASE`/`AT_ENTRY`/`AT_PHDR`,
  and jump to the interpreter's entry; ld.so then maps libraries and bootstraps
  the main program. Verified under qemu with a dynamic glibc guest (`-L` resolves
  the interpreter path; `LD_LIBRARY_PATH` lets ld.so find libc at a real host
  path until M5 redirects its opens into the guest rootfs).
  Note: on a real noexec mount, ld.so's own file-backed `PROT_EXEC` mmap of
  `.so`s will fail — M5's mmap hook must convert those to anon-exec. Under qemu
  the libs live on an exec-permitted mount so this isn't exercised yet.

- [x] **M5a — path-translation core**
  rootfs + longest-prefix component-aware binds, lexical `..` canonicalization
  (no rootfs escape), cwd-relative resolution. `-t xlate` debug cmd, 9 tests.

- [x] **M5b — seccomp filter + SIGSYS monitor + dispatcher**
  - `dispatch.c`: translate path args of the trapped syscall set (openat family,
    rename/link/symlink two-path forms, chdir/getcwd/chroot/truncate/statfs) and
    re-issue via the gate. In-process, so path pointers are read directly.
  - `seccomp.c`: BPF that KILLs non-AArch64, ALLOWs gate-IP syscalls, TRAPs the
    path set, ALLOWs the rest. Jump offsets verified by construction.
  - `sigsys.c` + `sig.S`: SIGSYS handler reading x0..x5/x8 from the AArch64
    sigcontext and writing x0; own rt_sigreturn restorer (no vDSO dependency).
  - `run.c`: sets up the fs view and installs the monitor before entering the
    guest (only when translation is requested).
  Validated under qemu via `-t dtest` (dispatch translate+reissue, escape block)
  and `-t sigtest` (signal round-trip + sigcontext offsets). The seccomp *trap*
  itself is inert under qemu-user and MUST be confirmed on a real AArch64 kernel
  (the `probe` filter test covers install permission there).

- [x] **M6 — execve/execveat emulation**
  The SIGSYS handler special-cases execve/execveat: load the new program with
  the loader, build its stack, and rewrite the trapped signal context (pc/sp,
  cleared regs) so rt_sigreturn resumes into it — keeping the seccomp filter and
  handler resident (a real execve would wipe the handler). Load failures set
  -errno for normal execve semantics. Validated: the redirect resume via
  `-t jmptest`; the load+stack half is the M3/M4 path. Real trap needs HW.
  Caveat: old program mappings are not torn down (leak across repeated execve);
  the emulation runs on the main thread's large stack (multi-threaded execve
  would want a sigaltstack — tracked with the M5 signal-stack hazard).

- [x] **M7 — fidelity: uid/gid faking, /proc self-path fixups, link2symlink**
  - `-0` credential faking: getuid/geteuid/getgid/getegid/getres[ug]id report 0,
    setuid-family succeed silently, fchownat is faked, and stat/statx ownership
    is rewritten to the fake uid/gid. Credential syscalls are trapped only when
    `-0` is active (kept out of the filter otherwise).
  - `/proc/self/{exe,cwd,root}` readlink fixups return guest-visible targets.
  - link2symlink (lightweight): linkat falls back to a symlink when the fs
    forbids hardlinks (EPERM/EMLINK/EXDEV/ENOSYS/EACCES/EOPNOTSUPP).
  Validated via `-t faketest` (getuid=0, stat ownership=0, /proc/self/exe). 45/45.
  Limitations (tracked): `/proc/<pid>/*` numeric form and open("/proc/self/exe")
  redirect not yet handled. (link2symlink was the lightweight form here — a
  same-directory symlink to the sibling name; superseded by M9's backing-file
  scheme, which fixes nlink/type/mtime fidelity.)

- [x] **M8 — performance: AoT `svc` rewriting (`-R`/`--rewrite`)**
  At load time (while segments are still writable) each `svc #0` is rewritten to
  `b <trampoline>`, skipping the kernel seccomp+SIGSYS round trip.
  - `tramp.S`: per-site trampoline reached by `b` (preserves x30), saving the
    syscall-preserved set (x0..x18 incl. Android's x18 SCS reg, and x30; x19..x29
    are AAPCS-preserved by cng_dispatch), marshaling args, calling the
    dispatcher, writing x0, and returning to S+4 via absolute literals (no ±128
    MiB veneer for the return). Two literals (dispatcher, return) patched per copy.
  - `rewrite.c`: scan + `b` encoding + emit. The pool is allocated **contiguous
    with the guest** by the loader over-allocating its mapping (mmap hints aren't
    honored, notably under qemu), so every site is within `b` reach; unreachable
    or pool-exhausted sites fall back to the SIGSYS floor.
  - Because a rewritten site needs **no seccomp**, `-R` also provides translation
    where seccomp is unavailable (old kernels, qemu-user).
  Validated under qemu: `-t rwtest` (register preservation + correct syscall) and
  an end-to-end run — a static-PIE glibc guest (101 svc sites rewritten) has its
  `open()` translated into the rootfs, 10/10 deterministic, with a no-`-R`
  negative control. This is also the first end-to-end proof of the full
  translation pipeline with a real glibc guest. 50/50 tests.
  Caveat: `svc`-immediate scan is exact (`0xD4000001`); rare data words equal to
  it in an executable segment would be mis-rewritten — none in the glibc we
  tested (101 words, all real svc), but `-R` stays opt-in for that reason.

- [x] **M9 — robust link2symlink (backing-file scheme)**
  Ported from `/home/sol/arm64chroot`. Where the host refuses `link(2)`
  (Android/SELinux → EACCES/EXDEV, some EPERM), a guest hardlink group is
  represented in the directory of the first-linked name by a hidden backing file
  `.l2s.<ino>` holding the real contents, with every "hardlink" name a
  same-directory **relative** symlink to it (never dangles, never leaks a host
  path), plus a `.l2s.<ino>.<count>` marker file encoding the live link count.
  - Transparency fixups so the group presents as ordinary regular files:
    `newfstatat`/`statx` redirect to the backing file with `st_nlink` = count;
    `readlinkat` on a name returns `EINVAL`; `utimensat` redirects to the backing
    (so apk's set-mtime-then-verify — the "failed to preserve mtime" case —
    succeeds); `unlinkat`/`renameat` decref and reclaim the backing on the last
    reference. `linkat` resolves both endpoints (incl. real dirfds via
    `/proc/self/fd`, and `/proc/self/fd/N` O_TMPFILE via a content copy) to host
    paths and falls back to `cng_l2s_link`.
  - All in `src/monitor/l2s.c`, freestanding (raw syscalls), gated by
    `cng_l2s_active` so there is **zero** extra cost until a hardlink actually
    falls back. Validated by `-t l2stest`: regular-file presentation, shared
    inode, nlink=2, `readlink`→EINVAL, shared content, EEXIST on a dup link,
    mtime preserved through the backing, dirfd-relative links, and
    decref/reclaim. 72/72 tests.
  Limitation (tracked): backing files are not yet hidden from `getdents64`
  (would require trapping it); they are dotfiles and unrecorded in apk's db, so
  cosmetic only. Cross-directory hardlinks fall back to a content copy.

- [x] **Handler stack isolation (Go/small-stack guests)**
  The SIGSYS handler's path dispatcher is deep (multiple PATH_MAX buffers:
  `cng_resolve` ~20 KiB, `cng_dispatch` ~16 KiB per `-fstack-usage`). C guests
  survive on their multi-MiB main-thread stacks, but Go runs syscalls on ~8 KiB
  goroutine stacks, so the handler smashed them — intermittent SIGSEGV, memory
  corruption, and monitor crashes under `go build`/`make`. Two parts:
  - **SA_ONSTACK** so the kernel delivers the ~4.5 KiB signal frame (siginfo +
    ucontext incl. the FP/SVE reserved area) on the thread's registered
    alt-stack (Go gives each thread one) rather than the tiny goroutine stack —
    the frame delivery itself was overflowing before the handler could run.
  - a large dedicated **per-thread scratch stack** (256 KiB, claimed lock-free
    by TID, allocated on first use; `stackswitch.S` switches SP) for the
    dispatcher, since it far exceeds a 32 KiB alt-stack. A per-thread busy flag
    detects nested gate-net traps (which under SA_ONSTACK arrive on the
    alt-stack, not the scratch stack) and runs them in place without
    re-switching; the gate-net also records the blocked syscall so a re-issue
    can't trap twice.
  - **all signals masked during the handler** (`sa_mask`, SIGSYS excepted).
    Once we switch SP to the scratch stack our frame is left behind on the
    alt-stack; a signal delivered in that window — notably Go's very frequent
    SIGURG async-preemption — would be placed by the kernel at the alt-stack top
    (SP is no longer on the alt-stack), clobbering that frame and crashing on
    return. Masking closes the window; the signals queue and fire on sigreturn.
  Validated by `-t stackswtest`. 80/80.

- [x] **vfork-style clone → real fork (Go `os/exec`, posix_spawn)**
  Go's `os/exec` (and musl `posix_spawn`) spawn with
  `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)`: the child shares the parent's address
  space and the parent is suspended until the child's `execve`. Our execve is
  emulated in-process — loading the new image into a *shared* VM corrupts the
  parent (and no real execve ever resumes the vfork parent) — which showed up as
  intermittent `exec format error`/`no such file` for a valid tool plus a
  monitor SIGSEGV during `go build`'s parallel compile. The seccomp filter now
  traps `clone` *only when `CLONE_VFORK` is set* (a small `args[0] & CLONE_VFORK`
  BPF test, so thread creation and plain fork run natively), and converts it to
  an ordinary COW fork so the emulated execve happens in a private copy and the
  parent continues (the child's execve closes the O_CLOEXEC notify pipe to
  signal success).
  - **Child stack.** The conversion is done in `cng_sigsys_body` (not just
    `cng_dispatch`) because it must touch the ucontext. musl's `__clone` /
    `posix_spawn` (which gcc uses to launch cc1) passes a *caller-allocated child
    stack* with the child fn/arg pre-stored on it. We must reissue the real
    clone with `child_stack=0` so the forked child inherits (COW) the parent's
    SP — the **scratch stack** our handler frames live on — and can unwind them
    and sigreturn; then set the child's `uc->sp` to the original child stack so,
    after sigreturn, it resumes where the clone wrapper expects. Passing the
    child stack straight through set the child's SP into a frameless buffer and
    it died with a Bus error before ever reaching execve — the gcc→cc1 crash.
  Validated by `-t clonetest` (private VM) and `-t clonestktest` (child resumes on
  its own stack, parent's untouched — driven through the real SIGSYS body). Gap:
  `clone3` with VFORK is not detected (flags live behind a pointer); Go/musl use
  `clone`, not `clone3`, for spawning.

- [x] **Relocate chroot-ng out of the guest ET_EXEC range (0x400000)**
  chroot-ng is `-static -no-pie`, so it defaulted to load address `0x400000` —
  the exact fixed address a non-PIE `ET_EXEC` guest uses. Loading such a guest
  (notably gcc's `cc1`, `Type: EXEC` at `0x400000`) MAP_FIXED-overwrote our own
  monitor code, crashing early with `SEGV_ACCERR`. PIE guests were unaffected
  (kernel-picked high base). Link chroot-ng at `0x1000000000` (64 GiB) via an
  explicit linker script (`scripts/chroot-ng.ld`) whose location counter starts
  the first segment there — clear of every guest's fixed vaddr and below the
  kernel's high mmap region. (A `-Ttext`/`-Ttext-segment`/`--image-base` flag
  does NOT relocate a `-no-pie` binary cleanly on lld: it keeps the segment at
  the default `0x200000` and pads it up to the base — a ~64 GiB segment that
  still covers 0x400000. The script sets the segment start directly, avoiding
  the pad. Small code model is fine: chroot-ng's span is < 4 GiB so intra-image
  `adrp` reaches; the SIGSYS gate allowlist and M8 trampolines use
  runtime/absolute addressing, unaffected by the base.)
  Regression test in m3: a `-static -no-pie` guest (ET_EXEC @ 0x400000) runs to
  exit 42 on both the anon and file-backed paths. 84/84.

  With this, Go builds run end-to-end (incl. cgo -> gcc -> cc1); pure-Go builds
  (`CGO_ENABLED=0`) were already working once the handler-stack and clone fixes
  landed.

- [ ] **M10 — (optional) user_notif supervisor tier for kernels >= 5.0**

## Testing notes
- `make` cross-compiles; `make run ARGS="..."` runs under qemu-aarch64.
- `make test` runs `tests/run.sh`.
- qemu-user does NOT emulate guest seccomp filters faithfully → M5's mechanism
  needs simulated-SIGSYS unit tests + real-hardware validation. Loader (M3/M4)
  and path logic are fully qemu-testable.
