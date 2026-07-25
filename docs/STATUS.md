# chroot-ng — status & roadmap

Milestones are committed individually. Each builds on the previous.

## Verified on-device (Android 15, kernel 5.15, rootless, SELinux, no userns)
An Alpine aarch64 rootfs runs under `chroot-ng -u <rootfs> <program>` with no ptrace and no
user namespaces, on an execmem-denied mount:
- interactive shell + coreutils/busybox, `su -l`
- `apk` (full package manager: add/fix, incl. hardlinked packages with
  `-l`/`--link2symlink`)
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

- [x] **M7 — fidelity: fake user identity, /proc self-path fixups, link2symlink**
  - `-u`/`--fake-id[=uid[:gid]]` fake user identity (default `0:0` root): the
    guest sees a synthetic per-process credential set (r/e/s/fs uid+gid, plus
    supplementary groups) that get/set uid/gid/groups syscalls read and mutate
    following real POSIX privilege rules — so a privilege drop actually changes
    what getuid() reports and a non-root fake id cannot regain uid 0. While the
    effective uid is 0 (fake-root), ownership/mode changes (chown/chmod), utime,
    and denied access() checks are faked as succeeding, capget reports the full
    capability set, and stat/statx ownership is remapped so files owned by the
    real invoking user appear owned by the fake id. Credential syscalls are
    trapped only when `--fake-id` is active (kept out of the filter otherwise).
  - `--setuid-root` / `--setgid-root` (imply `--fake-id`, defaulting to the real
    invoking id rather than 0:0 when no explicit `-u`): setuid/setgid executables
    are shown as owned by root (uid/gid 0) and, on exec, elevate the fake
    identity's effective/saved/fs id to 0 — so a setuid-root binary such as `su`
    gains root under a non-root identity (its own `setuid(0)` then sticks).
  - `/proc/self/{exe,cwd,root}` readlink fixups return guest-visible targets.
  - link2symlink (lightweight): linkat falls back to a symlink when the fs
    forbids hardlinks (EPERM/EMLINK/EXDEV/ENOSYS/EACCES/EOPNOTSUPP).
  Validated via `-t faketest` (fake ids, stat remap, groups, capget, privilege
  drop, setuid-root exec elevation, /proc/self/exe).
  Limitations (tracked): only the magic links are virtualized (see "apk package
  scripts" below); the contents of `/proc/<pid>/*` (`maps`, `mountinfo`, ...)
  still describe the host. (link2symlink was the lightweight form here — a
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

- [x] **M9 — robust link2symlink (backing-file scheme, `-l`/`--link2symlink`)**
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
  - Opt-in via `-l`/`--link2symlink` (`cng_g_l2s`), **off by default**: the
    scheme trades real hardlinks for symlinks plus hidden `.l2s.*` files in the
    guest's own directories, so it only runs where a guest actually needs it
    (apk/dpkg unpacking hardlinked packages). Without the flag `linkat` reports
    the host's refusal to the guest unchanged, and `l2stest` checks that too.
  Limitations at M9 (both resolved by M9b below): backing files were not
  hidden from `getdents64`, and cross-directory hardlinks fell back to a
  content copy.

- [x] **M9b — l2s central hidden store (full hardlink fidelity in a guest shell)**
  Reworked the on-disk scheme: new link groups keep data + marker in a
  per-rootfs object store `<rootfs>/.l2s/`, and every "hardlink" name is a
  symlink carrying the data file's **absolute host path**. The host kernel
  follows those natively (dirfd-relative passthrough stays zero-cost) and the
  guest resolver maps them back via `cng_l2s_untranslate_target` (self-healing
  the prefix if the rootfs tree was moved). Consequences: hardlinks work
  **across directories**, survive `mv` of names or whole directories, and
  `rm -rf`/`rmdir` behave like the real thing — user directories never hold
  l2s droppings. The first-link `rename` into the store keeps the original
  inode (stable `st_ino`, pinned against reuse); on `EXDEV` (bind mount from
  another filesystem) or an unusable store it falls back to the M9
  per-directory scheme. The legacy format (what arm64chroot writes) stays
  fully recognized: stat/decref/bump work on old groups, cross-dir links join
  them via absolute targets, and a legacy name mv'ed to another directory is
  repointed afterwards (`cng_l2s_rename_prep`/`_fixup`).
  - Fidelity fixups on top of M9 (each with an `-t l2stest` check asserted by
    `tests/m7_fidelity.sh`): `fstat` / `newfstatat(AT_EMPTY_PATH)` /
    `statx(AT_EMPTY_PATH)` patch `st_nlink` by fd; `statx` honors the guest's
    mask/flags and advertises `STATX_NLINK`; `readlinkat` refuses (`EINVAL`)
    through real dirfds too; `getdents64` hides data/marker entries everywhere
    plus the `.l2s` store dir at the root, re-reading when a whole batch was
    filtered (a fully-hidden batch must not read as EOF); paths naming the
    machinery return `ENOENT` from every path syscall including execve
    (`cng_l2s_deny`); `fchownat`/`faccessat2` with `AT_SYMLINK_NOFOLLOW` land
    on the backing file; `RENAME_EXCHANGE` no longer decrefs the surviving
    name; `linkat(fd, "", …, AT_EMPTY_PATH)` works (live file → group bump,
    O_TMPFILE → materialize); `openat(O_NOFOLLOW)` of a link name opens the
    backing instead of `ELOOP` (real guest symlinks still `ELOOP`). `-l` is
    active from startup (the on-disk state survives sessions) and installs the
    monitor by itself; `fstat` + `getdents64` are trapped only under `-l`
    (`l2s_syscalls[]` in seccomp.c). `CNG_L2S_FORCE=1` routes every `linkat`
    through the emulation (test aid mirroring arm64chroot's `A64_L2S_FORCE`).
  - Acceptance: `tests/m10_l2s_shell.sh` runs 13 shell scenarios in an Alpine
    rootfs under `chroot-ng -R -l` + `CNG_L2S_FORCE=1` and compares stdout +
    exit status **byte-for-byte** against stock arm64chroot creating REAL
    hardlinks from the same scripts: ln basics (nlink/inode equality),
    cross-dir ln, `ls -a` hiding, readlink refusal, write-through, cross-dir
    `mv`, rm-one/rm-all + `rmdir`, `rm -rf` over groups, dup-`ln` EEXIST,
    busybox tar round-trip, `cmp` on a linked binary, and two-session
    persistence. A Debian/GNU leg (`find -samefile`, GNU stat) is gated on a
    translation smoke test — it skips under qemu (ld.so-loaded libc.so has no
    rewritten svc sites; the seccomp tier covers it on devices).
  - Accepted divergences (deliberate, documented):
    `readlink("/proc/self/fd/N")` on a link-opened fd can show the store path
    when the guest has a live `/proc`; `ln -P` of a symlink copies the
    target's contents instead of linking the symlink itself; the marker
    read-modify-write is not atomic under concurrent link/unlink; a guest
    cannot create files matching the `.l2s.` name grammar (denied `ENOENT`);
    the rootfs root's own `st_nlink` is +1 once the store exists;
    `openat2(RESOLVE_NO_SYMLINKS)` fails on emulated links; a legacy per-dir
    group whose surviving names were all mv'ed away leaves its old dir
    non-rmdir'able, and per-dir-fallback links don't survive a rootfs move
    (store links self-heal); `/.l2s` stays reachable via dirfd `..`-walks;
    cross-dir + EXDEV still copies; an emulated cross-filesystem link (bind
    mount) *succeeds* where a real one would report `EXDEV`.

- [x] **-R: signal-return svc sites left intact**
  The AoT rewriter used to turn the sa_restorer's `mov x8,#139; svc 0` into a
  trampoline call like any other site — but `rt_sigreturn` must execute with
  sp still pointing at the kernel's signal frame, so the first delivered
  signal (e.g. a shell's SIGCHLD after fork) made the kernel restore a
  garbage context and SIGSEGV the process. `cng_rewrite_seg` now skips an
  `svc 0` immediately preceded by `movz x8, #139`: sigreturn carries no path
  and needs no translation. This is what makes forking shells (busybox ash
  spawning applets) usable under `-R`; the seccomp tier never trapped it.

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

- [x] **apk package scripts: /proc magic links + chroot() keeps the view**
  `apk fix` in an Alpine rootfs failed every package script with
  `execve: No such file or directory` → `exited with error 127`, because apk
  runs them as `execve("/proc/self/fd/N")` (after `fchdir(root_fd); chroot(".")`)
  and the resolver treated that magic link like any guest symlink: it
  `readlink`ed it and **re-rooted the host target into the rootfs**, producing
  `<rootfs>/data/data/com.termux/.../rootfs/lib/apk/exec/<script>` → ENOENT.
  Three parts, all on that path:
  - `cng_resolve` now recognizes the `/proc/<pid|self|thread-self>/` magic links
    (checked each round, so a guest symlink into them — Alpine's
    `/dev/fd` → `/proc/self/fd` — is covered too). An `fd/<n>` link resolves to
    **itself**: it is already a host path, and the kernel takes it straight to
    the open file description, including the anonymous/deleted files
    (memfd, `O_TMPFILE`) no re-rooted target could name at all. `exe`/`cwd`/
    `root` for our own process resolve to the guest-visible values `readlink`
    already reports (`proc_self_fixup`), so exec'ing or opening one lands where
    the guest expects instead of on chroot-ng's own binary or a host path.
    `resolve_at_host`'s private `/proc/self/fd/` special case is gone — one rule
    now covers `openat`/`stat`/… as well as `execve`, and the numeric-pid form.
    An exec through an fd path also names the file behind the fd for
    `/proc/self/exe`, as the kernel would.
  - `chroot(2)` **rebases** binds and the cwd onto the new root
    (`cng_fs_chroot`) instead of `cng_fs_init`-ing them away: a real chroot
    unmounts nothing, and apk chroots before *every* script — which used to
    strip that child of `/proc`, `/dev` and every other `-b`. Binds under the
    new root keep working, ones outside it fall out of the view (as they must),
    and the target is now stat'ed so a non-directory gets `ENOTDIR`.
  - l2s `materialize` keeps the **source's mode**: a real hardlink shares it, so
    the O_TMPFILE-publish copy that writes apk's database (`etc/apk/world`,
    `lib/apk/db/*`, reached through `linkat` → EXDEV → the `-l` fallback) no
    longer lands as 0755 instead of 0644.
  Regression tests: `m6` execs a shebang script and a plain ELF through
  `/proc/self/fd/N`, `m5b` opens through `/proc/self/fd` and `/proc/self/cwd`
  (both `errno 2` before), `m5a` covers the chroot rebasing (`_xlate -c`), and
  `l2s-tmpfile` asserts `mode=1`. 144/144.
  Accepted divergences: `/proc/self/fd/N` resolves even when the guest has no
  `/proc` mounted, where a real chroot would report ENOENT; and `readlink`ing
  one still reports the host path (the kernel renders it against our real root,
  which is not the guest's) rather than the guest path.

- [ ] **M10 — (optional) user_notif supervisor tier for kernels >= 5.0**

## Testing notes
- `make` cross-compiles; `make run ARGS="..."` runs under qemu-aarch64.
- `make test` runs `tests/run.sh`.
- qemu-user does NOT emulate guest seccomp filters faithfully → M5's mechanism
  needs simulated-SIGSYS unit tests + real-hardware validation. Loader (M3/M4)
  and path logic are fully qemu-testable.
