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
  `/proc` mounted, where a real chroot would report ENOENT. (`readlink`ing one
  used to report the host path; M11 maps it back to the guest view.)

- [x] **CNG_DEBUG must not change behaviour (wild read in the error log)**
  `dbg_path` picked the path to log by testing whether `a0`/`a1` "looks like a
  string" — `> 0x1000`, then dereference. The args of a *failing* syscall are
  not all pointers: `ioctl`'s request (`TCGETS` = 0x5401), `truncate`'s length,
  `fchown`'s uid all clear that bar, so logging one read a wild address. Inside
  the SIGSYS handler, where every signal but SIGSYS is masked, the resulting
  SIGSEGV is unblockable-fatal: the guest died. Reproduced 5/5 with a real
  `apk del` under `-R` (which dispatches *every* syscall, so `ioctl` reaches it)
  and 0/5 with `CNG_DEBUG` off — i.e. only debug runs were affected, which are
  exactly the runs used to chase device bugs. The candidate is now validated
  through the kernel (`faccessat` copies the path in from user space first, so
  EFAULT/ENAMETOOLONG mean "not a readable string"), skipped if Android blocks
  `faccessat`. `-t dtest dbgpath` drives a failing `truncate` with a
  pointer-sized length under debug and asserts the dispatch survives (SIGSEGV
  before the fix).
  - Every silent `-ENOENT` in `execve_core` now traces under `CNG_DEBUG`
    (l2s-hidden / unresolved / open errno / bad shebang / interp unresolved),
    plus the resolved host path on success — an exec failure on a device says
    which stage produced it. A failed open now returns its **real** errno
    (EACCES, ELOOP, ...) instead of a blanket ENOENT, as the kernel does.
  - `--version` and a `CNG_DEBUG` startup banner stamp the build time: this tree
    reaches devices by hand-copy, so traces must identify their build. 147/147.

- [x] **exec a file the guest may execute but not read (apk scripts, part 2)**
  With the magic links resolving, apk's scripts then failed as
  `execve open /proc/self/fd/7 -> errno=13`. `execve(2)` checks **execute**
  permission on the inode; reopening a path checks **read** — and apk's script
  fd names an inode granting exactly `--x`. Real root reopens it anyway through
  its DAC bypass; our `--fake-id` root cannot, so the userland loader (which
  must *read* the image) was strictly more restrictive than the kernel.
  - `cng_load_elf_fd()` splits the loader's fd core out of `cng_load_elf`, and
    an exec whose target names one of our own fds (`cng_proc_self_fd`) loads
    **from that fd** instead of reopening the magic link: we run in-process, so
    the guest's fds are ours. No permission check at all, and it covers the
    anonymous files (memfd, `O_TMPFILE`, deleted) that have no readable name.
    Everything reads through pread/mmap, so the file offset — shared with the
    parent across fork — is untouched.
  - The shebang interpreter then reopens that same path *itself* (busybox `sh`
    reading the script), which fails for the same reason. Under fake-root only,
    an `openat` refused with EACCES on a path naming one of our fds now lends
    the inode the owner-read bit **through the fd** (no path race), reopens, and
    restores the mode — the DAC bypass real root would have had.
  - A refusal that no DAC change can fix, seen next on the device: apk 3 keeps
    package scripts in a **memfd** (`mode=777 uid=<app>`), and Android's SELinux
    declines an app an `open` on that tmpfs inode — so the interpreter's reopen
    is denied even though the inode grants read. There we hand the guest a
    **duplicate of the descriptor we hold**, rewound to 0 (a fresh open starts
    there; the duplicate shares our offset). `cng_fd_reopen` picks between the
    two answers: inode grants the access → dup (any identity, the refusal was
    never about credentials); inode denies it → the fake-root mode borrow.
    Declined for `O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_APPEND`/`O_DIRECTORY`, whose
    semantics a dup cannot reproduce, and when our fd's access mode is too
    narrow.
  Verified end-to-end under qemu: a `#!/bin/sh` script made execute-only after
  opening, exec'd via `/proc/self/fd/N` in an Alpine guest, now runs and leaves
  the mode `---x--x--x`. Checks: `-t exectest` on an execute-only ELF via its
  fd, `fakeroot_reopen` in `-t faketest`, and `fd_reopen`, which drives the dup
  branch off a memfd with a simulated refusal (SELinux cannot be provoked on a
  devbox). 151/151.
  Still unsupported: a file we do **not** own and cannot read — there is no bit
  to borrow and no descriptor to copy.

- [x] **M11 — /proc emulation (ported from `/home/sol/arm64chroot`)**
  The host `/proc` now passes through to the guest automatically (a rootfs
  directory tree has none, and mounting one needs privileges we do not have),
  with two layers on top: a **hidden-process view** and **synthesized files**.
  Off with `--no-proc`; an explicit `-b DIR:/proc` still wins over the
  passthrough.
  - **Hidden-process view**, on both sides. A numeric `/proc/<pid>` that is not
    a guest process is redirected to `/proc/0`, which never exists (pid 0 is the
    idle task), so it reads as "no such process". The test is on the **resolved
    host path**, not the guest one, so it holds however the path got there — the
    passthrough, or an explicit `-b /proc:/proc`, which a proot habit makes
    common and which would otherwise hand back the host's whole process list.
    One choke point in `cng_fs_translate` covers open/stat/readlink/execve and
    the `*at` forms. The listing side is a `getdents64` filter keyed the same
    way (the fd's host path is `/proc`), because `ls /proc` and `ps` read the
    directory rather than probing names; it costs a readlink only for a batch
    that actually holds an all-digit name, which outside `/proc` is nothing.
  - **PID registry** (`src/monitor/procreg.c`, ported from `proctab.c`): a
    `MAP_SHARED` table in which each guest process publishes its argv, environ,
    auxv, exe and cwd. By default the backing is one anonymous region inherited
    across fork (one invocation's view); with **`--shared-proc`** it is served
    per-rootfs by arm64chroot's broker design — a detached daemon owning an
    anonymous memfd (the table) and an abstract-namespace socket (the
    rendezvous), handing the memfd to every joining invocation over
    `SCM_RIGHTS`, so `ps`/`top` in one session see the guest processes of
    another. Clients keep no persistent broker fd (host fd == guest fd here —
    the guest would see it); the daemon uses the registry itself as its
    liveness signal and exits ~10 s after the last guest of the rootfs dies,
    leaving no file and no socket name. Fallbacks mirror the oracle's tiers: a
    named 0600 file keyed by uid+rootfs in a writable dir (pre-memfd kernels),
    then the anonymous per-invocation region.
    Slots are claimed by CAS and written under a seqlock whose odd count is
    itself taken by CAS — a child's slot can see two writers, the parent
    publishing the fork while the child publishes its own exec, and the loser
    (always the parent: its copy is the older) backs off instead of
    interleaving stores. Every access happens inside the SIGSYS handler, where
    a sleeping lock could deadlock. A recycled host pid is caught by comparing
    the recorded `/proc/<pid>/stat` starttime **on every membership check**:
    exit is not a trapped syscall (and a SIGKILL never could be), so without
    that a foreign process reusing a dead guest's pid would inherit its
    visibility — this covers even the signal-killed case that arm64chroot's
    exit-hook unregister cannot. The starttime itself is read dir-then-
    `openat("stat")`: the same file on a real kernel, and under qemu-user (the
    dev workflow) the only spelling that dodges qemu's realpath'd
    interception, which otherwise serves the caller's own stat with a
    starttime frozen at emulator start — a fork inherits that, and the child's
    self-sample would disagree with everyone else's read of it. Publish points
    mirror the kernel's: the initial stack build, and every emulated `execve`.
    A fork is published **by the parent** — the seccomp filter now traps
    process-creating `clone` (no `CLONE_VM`) for that, since a forked child
    need not make another traced syscall before something reads its `/proc`
    entry; a slot the child already stamped with its own exec is left alone.
    Threads still run untrapped.
  - **Synthesized files** (`src/monitor/procfs.c`, from `sys_procfs.c`), served
    from an in-memory copy on a read-only open, for any guest pid:
    `cmdline`, `environ`, `auxv` (the kernel's copies describe the chroot-ng
    invocation — we never execve), `mounts`/`mountinfo`/`mountstats` plus
    `/proc/mounts` (the rootfs + `-b` binds, not the host's mount namespace),
    `loadavg`, `uptime` and — only where the host denies the real file, as
    Android does — `stat`, and under `--fake-id` the `Uid:`/`Gid:`/`Groups:`
    lines of `status`.
  - **Refresh on rewind.** procps opens `/proc/loadavg` once and `lseek(0)`
    +rereads it every cycle, so a snapshot would freeze `top`. The refreshable
    files are moved to a reserved high fd range (the top 16 below `RLIMIT_NOFILE`)
    and the filter traps the whole read family — `read`, `readv`, `pread64`,
    `preadv`, `preadv2`, the same set arm64chroot hooks — **only for fds in
    that range**, where the dispatcher regenerates content read from offset 0.
    Ordinary reads stay untrapped; a guest fd that lands in the range is just
    re-issued.
  - **`maps` is rewritten, not fabricated.** The guest's mappings are this
    process's real mappings, so addresses, protections, device and inode are all
    true; only the pathname column is mapped back to guest spelling, with
    file-backed lines outside the guest view (chroot-ng's own image) dropped and
    anonymous lines kept.
  - Two fixes that fall out of the same machinery: `readlink` of an fd link
    (`/proc/self/fd/N`, and Alpine's `/dev/fd`) or of a `map_files/<range>`
    entry now reports the **guest** path instead of leaking the host one, and
    `comm` is set with `PR_SET_NAME` on each exec, so `ps` names the guest
    program rather than `chroot-ng` — that one makes the kernel's own record
    correct rather than synthesizing anything.
  Validated by `-t proctest` (passthrough + hidden pids, registry-backed
  cmdline/environ, another process's files through a real fork, the
  fork-vs-exec publish ordering and the dead-pid invalidation, the mount
  table, loadavg/uptime/stat shape and the refresh-on-rewind path through both
  `read` and `readv`, no host path in `maps`, fd-link and map_files
  untranslation, the fake-id status remap, `--no-proc`) and by
  `tests/m11_proc.sh`, which reruns the same ground in an Alpine guest shell
  (`cat /proc/self/cmdline` shows the guest's argv, `ps` sees only guest
  processes, `/proc/1/stat` is absent, `comm` is `busybox`) and adds the
  two-invocation `--shared-proc` scenario: a backgrounded guest `sleep` shows
  up in a second invocation's `ps` with its registry cmdline, and stays hidden
  without the flag. `-t proctest` itself runs its registry broker-backed and
  asserts that the broker (not a fallback tier) engaged. The seccomp filter's
  new rules are covered by `-t bpftest`, which builds the program and runs it
  through a BPF interpreter — qemu-user does not honor guest filters, so that is
  the only pre-device check for them. 197/197.
  A later line-by-line parity audit against `sys_procfs.c`/`proctab.c`/
  `path.c`/`sys_file.c` closed the remaining gaps (the read-family refresh
  coverage, the pid-reuse and two-writer registry hardening, map_files
  untranslation, and an empty-cwd snapshot now answering `/` instead of
  falling through to the host readlink).
  Accepted divergences: `stat()` of a synthesized name reports the host file,
  which on Android is the one being denied; `readlink` of a synthesized fd shows
  `memfd:cng-proc`; `/proc/version` passes through (arm64chroot must keep it in
  step with the kernel identity its `uname` fakes; chroot-ng fakes neither);
  an explicit `-b DIR:/proc` outranks the synthesis (the user overriding the
  view — arm64chroot keys its synthesis on the guest path, so there it outlives
  a bind); and without `--shared-proc` two separate chroot-ng invocations over
  one rootfs do not share a registry, so each hides the other's processes
  (matching arm64chroot's default). One place chroot-ng is
  deliberately *stricter* than arm64chroot: there, a `-b /proc:/proc` bind wins
  over the `/proc` zone in the path layer, so a host process stays reachable by
  explicit path (only the listing is filtered); here the hidden view is keyed on
  the resolved host path, so both routes are closed.

- [x] **M12 — System V shared memory (ported from `/home/sol/arm64chroot`)**
  Android denies `shmget`/`shmat`/`shmdt`/`shmctl` outright — they are off the
  app seccomp allow-list and SELinux forbids the class — so any guest that uses
  them (PostgreSQL, X clients, dpkg's plumbing, anything linked against a stock
  libc's shm functions) died on the first call. All four are now trapped and
  served in-process from `src/monitor/shm.c`, with **no host SysV IPC syscall
  and no `/dev/shm` anywhere in the path**. Trapped unconditionally, as in
  arm64chroot: the guest gets one shm namespace whatever the host's own IPC
  would have allowed.
  - **The broker owns the segments** (`src/monitor/broker.c`). Somebody has to
    hold each segment's backing fd for its lifetime, and it cannot be a guest
    process — host fd == guest fd here, so a held fd would be visible to and
    closable by the guest. The daemon holds it (an anonymous memfd, or a 0600
    file in a writable dir where `memfd_create` is unavailable) and hands out
    duplicates over `SCM_RIGHTS`; `shmat` maps the fd it is given `MAP_SHARED`
    and closes it at once, so a process holds a segment only as a mapping. This
    is the same daemon M11's `--shared-proc` registry already used: its
    one-byte handshake became a tagged request protocol so one rendezvous
    serves the PID table and the segment registry, exactly as arm64chroot's
    `proctab.c` multiplexes them. It is spawned lazily on the first shm call —
    safe from inside the SIGSYS handler because everything it runs is our own
    gate-issued syscalls, which our filter allows by instruction pointer.
  - **Namespace scope** follows the process view: per invocation by default
    (keyed by a pid+clock nonce seeded in the root process and fork-inherited,
    so one launch's process tree shares a namespace and separate launches do
    not), widened to per-rootfs by **`--shared-proc`**.
  - **Attach addresses become mmap flags.** arm64chroot mapped into a synthetic
    guest address space; here the guest's address space is ours, so `shmaddr` is
    an `mmap` hint: `SHM_RND` rounds down to the page size (SHMLBA on arm64),
    `SHM_REMAP` is `MAP_FIXED`, and an occupied range is `MAP_FIXED_NOREPLACE`
    → `EINVAL`. Pre-4.17 kernels ignore that flag and treat the address as a
    hint, so a returned address that is not the requested one is unmapped and
    answered `EINVAL` — what `shmat` would have said.
  - **`nattch` without an exit hook.** arm64chroot detaches from its
    `exit`/`exit_group` handlers; chroot-ng traps neither (same reason the PID
    registry has no exit hook — a `SIGKILL` could never be trapped either), so
    process death is the *normal* way an attach goes away here. The broker
    tracks each attacher's pid and starttime and reclaims on any `STAT`, keyed
    on the incarnation **and** on the zombie state: a process that has exited
    but not been reaped still owns its pid, yet the kernel has already dropped
    its mappings. Without that, a guest reading `nattch` right after `waitpid`
    would see a count a real kernel never reports — the differential test
    catches exactly this. `fork` re-counts inherited attaches from the child;
    the emulated `execve` detaches them all at its commit point, since a real
    one tears down the address space.
  - **Two fidelity gaps the oracle also has**, found by diffing corner cases
    (`tests/guests/shm_edge.c`): `SHM_EXEC` is a *permission* request, so
    attaching a `0600` segment with it must fail `EACCES` the way the kernel
    checks `S_IXUGO` — the broker's permission triad grew an execute leg for
    it; and `SHM_LOCK`/`SHM_UNLOCK` succeed for the owner rather than answering
    `EINVAL` (there is nothing to pin here, but refusing is the wrong answer).
  - **Tested differentially.** `tests/guests/shm_sysv.c` and `shm_stat.c`
    (arm64chroot's own, written for exactly this comparison) plus `shm_exec.c`
    and `shm_edge.c` run once under the emulation and once straight under
    qemu-aarch64, where the same code gets the genuine article — the host
    kernel's `shmget`/`shmctl` and qemu's own `shmat`; stdout must match byte
    for byte, over both backing tiers. `-t shmtest` covers the dispatcher level
    in ten groups including a real fork and a real broker, and
    `tests/guests/shm_key.c` pins the namespace scope, which is the one part
    with no counterpart to diff against.

- [x] **M13 — `-b SRC:DST[:ro]`: oracle-compatible bind syntax + read-only binds**
  `-b` took `GUEST:HOST`; arm64chroot takes `SRC:DST` — host first. Same flag,
  same syntax, opposite meaning, and nothing diagnosed a swap. The order is now
  the oracle's, and `:ro` (which used to be parsed as part of the host path, so
  `-b /etc:/etc:ro` produced the host path `/etc:ro`) is a real read-only mount.
  - **Parse** (`add_bind`): first `:` splits SRC from DST, a trailing `:ro`/`:rw`
    is stripped, DST must be absolute and not `/`, SRC must exist and not be the
    host root. A missing SRC whose DST *does* exist on the host reports the
    likely swap (`-b now takes SRC:DST (host path first); did you mean …?`) —
    the failure is otherwise a bare ENOENT, and the inverted-but-valid case
    would have been silent. `CNG_VERSION` is 0.1.0 so a hand-copied device build
    identifies which convention it carries.
  - **Enforcement.** `struct cng_bind` grew an `ro` bit; `cng_fs_host_ro` matches
    the bound **host** prefix at a `/` boundary, mirroring the oracle's
    `host_ro`, so a guest symlink leading into a `:ro` bind is covered however
    the path got there. `ro_denied()` gates the nine mutating dispatch sites:
    `openat`/`openat2` (write intent only — non-`O_RDONLY`, or
    `O_CREAT`/`O_TRUNC`), `mkdirat`, `mknodat`, `unlinkat`, `fchmodat`,
    `fchownat`, `utimensat`, `symlinkat`, `truncate`, both ends of
    `renameat`/`renameat2`, and the **destination** end of `linkat` (linking
    *from* a read-only mount is allowed, as on Linux). The check runs before
    `chattr_result`, so fake-root does not paper over a read-only mount.
    `name_to_handle_at` shares the openat case block and never writes, so its
    a2 (a handle pointer) is never read as open flags.
  - `/proc/mounts` and `/proc/mountinfo` render a `:ro` bind as `ro,relatime`
    instead of hardcoding `rw`.
  - Tests: `-t dtest -b SRC:DST[:ro] robind` drives eleven calls through the
    real dispatcher and asserts EROFS for the ten mutators while the read
    succeeds — with the **rw bind as a negative control** in the same harness,
    so a blanket refusal cannot pass both legs. `m5_xlate` pins that `:ro` is
    stripped from the mount point rather than folded into the host path. Every
    `-b` invocation in the suite and the docs moved to the new order. 227/227.

- [x] **dirfd-relative paths are contained (rootfs escape) + `O_NOFOLLOW` honored**
  `xlate` translated a path only when it was absolute or `AT_FDCWD`-relative;
  a name relative to a **real dirfd** was handed to the kernel untouched, on the
  reasoning that the dirfd already points inside the rootfs. The kernel, though,
  has no rootfs: a `..` run climbs straight past it, and an absolute symlink
  target is resolved from the **host** root. `openat(fd, "../../etc/shadow")`
  read the host file, and `openat(fd_of_/bin, "sh")` with
  `<rootfs>/bin/sh -> /bin/busybox` opened the *host* busybox. Ordinary software
  issues exactly these — `find`, `rm -rf`, `tar -C`, anything on `fts(3)`.
  - `xlate_at` maps the dirfd's host directory back to its **guest** path
    (`cng_fs_untranslate`), joins the name, and resolves the result through the
    rootfs/bind map — the same containment an absolute path gets. It returns an
    absolute host path, which the kernel ignores the dirfd for, so no caller
    changed. A dirfd outside the guest view (a `/proc` dirfd) has no guest
    spelling and keeps the host namespace, which is what the `/proc` zone wants.
  - `resolve_at_host`'s dirfd branch had the identical hole and fed `linkat`'s
    reissue directly; it now goes through `xlate_at` too, keeping the old
    host-concat only for the outside-the-view case.
  - **Hot-path cost.** `at_needs_xlate` keeps the common cases free: only a `/`
    (an intermediate component the kernel would follow), a `..` component, or —
    for a single dereferenced component — a `readlinkat` that says it really is
    a symlink, triggers the walk. `EINVAL`/`ENOENT` there are safe to finish in
    the kernel.
  - **`O_NOFOLLOW`** had to be fixed with it, and was a bug in its own right:
    the resolver always dereferenced the final component, so the kernel received
    a path that was no longer a symlink and had nothing to refuse — the open
    succeeded where it must `ELOOP`. `deref` now honors it (for `openat2` too,
    read from its `open_how`). The l2s link-name exception still works, restored
    by the existing `ELOOP` retry, and the l2s suite's "real symlinks still
    ELOOP through a dirfd" assertion is what caught this.
  - Tests: `-t dtest atrel GUESTDIR RELPATH` opens a directory through the
    dispatcher and reads a name relative to that fd. Asserted three ways — a
    `..` run at a file planted outside the rootfs reports ENOENT (the pre-fix
    binary reads it, verified), a `..` run inside still reaches the real file,
    and an absolute symlink re-roots. 230/230.

- [x] **io_uring refused (the one bypass no path trap can see)**
  `io_uring` submits its operations by writing SQEs into a shared ring, not by a
  syscall per operation, so `IORING_OP_OPENAT`/`STATX`/`RENAMEAT`/`UNLINKAT`/
  `LINKAT`/`MKDIRAT` never execute an `svc`. Nothing traps, nothing translates,
  and a guest linked against liburing (recent Node, Tokio, fio) addresses the
  **host** filesystem directly. Unlike every other gap this is not a missing
  translation — there is no interception point to add — so the ring must not be
  created at all. arm64chroot reaches the same conclusion by `-ENOSYS`.
  - New **designed-ENOSYS set** (`enosys_syscalls[]`, arm64chroot's
    `quiet_enosys`): the one piece of policy chroot-ng needs that is not
    translation. Answered with `SECCOMP_RET_ERRNO`, so the kernel refuses them
    itself — no signal, no handler, and it holds where nested SIGSYS delivery
    does not. liburing has a documented non-ring fallback for exactly this.
  - The block sits **ahead of the gate allowlist**. The gate exists so our own
    re-issued syscalls are not re-trapped, but we never issue `io_uring`, so
    exempting it by instruction pointer would only leave a hole. `-t bpftest`
    asserts both: an in-gate `io_uring_setup` is still ERRNO while an in-gate
    `openat` re-issue is still ALLOW.
  - `cng_denied_syscall()` gives the **`-R` trampoline tier** the same refusal;
    a rewritten `svc` site has no filter and calls the dispatcher directly.
  - Filter is 70 of 128 instructions. 232/232.

- [x] **xattr family translated (host read *and* write)**
  None of the twelve xattr syscalls was trapped, so the eight path-bearing forms
  took the guest's absolute path straight to the host filesystem. The getters
  leaked host state and answered existence questions about it; `setxattr` and
  `removexattr` **wrote** it. The `f*` forms act on an fd and correctly need no
  translation.
  - `setxattr`/`lsetxattr`/`getxattr`/`lgetxattr`/`listxattr`/`llistxattr`/
    `removexattr`/`lremovexattr` join `path_syscalls[]` and get one dispatch case:
    the path is a0 with no dirfd, so it is a plain translate + reissue. The `l`
    forms pass `deref_final = 0`; the four mutators honor a `:ro` bind (matching
    the four sites the oracle guards). They also join the l2s deny set, so a path
    naming the `.l2s` machinery reports ENOENT here as everywhere else, and the
    block-list probe set, since Android may refuse to re-issue them.
  - Tested by errno separation: `/etc/passwd` exists on the host and not in the
    test rootfs, so `getxattr` on it answering ENODATA means a real file was
    reached and ENOENT means containment. The pre-fix binary answers ENODATA
    (verified); the fixed one answers ENOENT, while the rootfs's own file still
    answers ENODATA — so the syscall is translated, not merely blocked. 234/234.

- [x] **`clone3` refused (the vfork corruption, reopened by a second entry point)**
  The M8-era `CLONE_VFORK` → fork conversion is what stops an emulated `execve`
  from loading the new program over the address space its parent is still using.
  It hangs off `__NR_clone`, and `clone3` was never trapped — but glibc >= 2.34
  reaches `clone3` **first** from `posix_spawn` and `pthread_create`, falling back
  to `clone` only on ENOSYS. On any kernel with `clone3` (5.3+, so every Android
  target) a glibc guest's spawn therefore produced a genuine shared-VM vfork
  child that the monitor never saw, and whose `execve` then overwrote the parent —
  exactly the corruption STATUS records as fixed for `clone`. It also bypassed
  `cng_procreg_fork` (invisible in the guest `/proc` view) and
  `cng_shm_fork_child` (under-counted `nattch`).
  - BPF cannot help here: `clone3`'s flags live in a `struct clone_args` behind
    `args[0]`, and seccomp can only read scalars out of `seccomp_data`, so the
    filter cannot tell a thread from a vfork. `clone3` joins the designed-ENOSYS
    set instead, which puts every glibc spawn and thread creation back on the
    `clone` path that *has* the conversion. Cheaper and far more predictable than
    reimplementing the delicate child-stack handling for a second entry point,
    and it is what the oracle does. We never issue `clone3` ourselves
    (`sys_fork` uses `__NR_clone`), so refusing it ahead of the gate costs
    nothing.
  - `-t bpftest` asserts `clone3` → ERRNO while a `CLONE_VM|CLONE_VFORK` `clone`
    still TRAPs for the conversion. `-t dtest denied` covers the **`-R`
    trampoline tier**, which has no filter and must answer from the dispatcher —
    the only one of the two tiers qemu-user can run — with an ordinary syscall as
    the control. 236/236.

- [x] **M14 — the `/dev` zone, and directory-entry injection**
  There was no `/dev` handling at all: guest `/dev/null` resolved to
  `<rootfs>/dev/null` and ENOENT'd on a plain directory tree, because a rootfs
  ships no device nodes and `mknod(2)` needs privileges we lack. The workaround
  people reach for, `-b /dev:/dev`, is far coarser than the gap deserves — it
  hands the guest the host's entire `/dev`, block devices included.
  - **The zone** (`dev_zone` in `path.c`, mirroring the oracle's
    `special_host_path`): `null`, `zero`, `full`, `random`, `urandom`, `tty`,
    `ptmx` pass through; `console` → `/dev/tty`; `pts/*` and `shm/*` pass
    through; everything else under `/dev` falls into the rootfs, so
    `/dev/mem` and the host's disks stay unreachable (asserted). Binds are
    matched first, so an explicit `-b` still overrides the zone. `--no-dev`
    disables it.
  - **`fd` and the std\* aliases** are the `/proc` fd links, and are rewritten to
    that spelling by `dev_magic` **in the resolver**, one step before the
    component walk. Putting them in the zone alone would not do: the walk
    readlinks each prefix, so it would treat the fd link as an ordinary symlink
    and try to re-root whatever it names — and for a pipe or a memfd that is not
    a path at all (`pipe:[12345]`). Routed through the magic-link machinery they
    reach exactly the anonymous files no re-rooted name could describe.
  - **Directory-entry injection** (`inject_dents`). Both the device nodes and the
    `-b` mount points are pure resolution overlays with no dirent behind them, so
    `getdents64` returned neither: `ls /dev` showed an empty directory that
    nonetheless opened `/dev/null` fine, and a bind destination was reachable by
    name but invisible to everything that enumerates before opening — shell
    globbing, `find`, a package manager's tree walk. Entries are spliced on the
    first read of the stream (`lseek(SEEK_CUR) == 0`), deduped against both the
    batch and a real dirent (a rootfs shipping its own `null` is not doubled),
    and carry `d_ino`/`d_type` from an lstat of the real host target so `ls -l`
    and `find -type` agree with what opening the name gets. The decision is taken
    *before* the read so an empty directory still gets its entries, and a genuine
    end-of-directory still owes them.
  - The synthesized mount table gains `devtmpfs /dev`, `devpts /dev/pts` and
    `tmpfs /dev/shm` rows; mount IDs now come from a running counter, since the
    zone rows are conditional and a bind's id depends on what precedes it.
  - Tests: `m5_xlate` covers the access half (whitelist, `console`, subpaths, the
    fd aliases, the non-whitelisted device staying in the rootfs, a bind
    outranking the zone); new `tests/m14_dev.sh` covers the listing half in a
    real Alpine guest — all fourteen names in `ls /dev` where the rootfs
    physically has only `null`, no duplicate for that one, the nodes actually
    readable/writable, `/dev/mem` unreachable, a spliced bind point listed with a
    real `d_type` and usable, and `--no-dev` injecting nothing and dropping the
    mount rows. 273/273.
  - Accepted divergence: after `chroot(2)` chroot-ng rebases the whole view, so
    the guest's own `/dev` is spelled `/dev` again and the zone applies inside the
    chroot. The oracle matches its zones on the *namespace* path, so there `/dev`
    is not auto-provided and the guest must bind-mount it. This is the same
    trade already made for `/proc`, and for the same reason — apk chroots before
    every package script, and those scripts need `/dev/null`.

- [x] **M15 — AF_UNIX address containment**
  A pathname socket carries a filesystem path in `sun_path`, and **no socket
  syscall was trapped**, so it got no containment at all. A guest
  `bind("/run/foo.sock")` created the inode on the **host**;
  `connect("/run/dbus/system_bus_socket")` reached the **host** daemon with the
  guest's real credentials; and every readback handed back a raw host path, which
  both leaks where the rootfs lives and breaks any program that compares the
  readback against what it bound. Of the gaps this audit turned up, this was the
  only outright containment escape among the ones the user named.
  - **In** (`bind`/`connect`/`sendto`/`sendmsg`): `cng_sun_in` resolves `sun_path`
    through the rootfs/bind map into its own buffer, so the guest's address is
    never written. `bind` keeps the final component literal — it is the name being
    created — while `connect`/`sendto` follow it. `sendmsg` copies the 56-byte
    `msghdr` to swap `msg_name`, leaving the guest's struct alone.
  - **The 108-byte problem.** `sun_path` is fixed at 108 bytes and the rootfs
    prefix frequently overflows it. The socket is then bound relative to an
    `O_DIRECTORY` handle on its parent — `/proc/self/fd/<n>/<basename>` — so only
    the basename has to fit. The fd is closed by `cng_sun_done` *after* the
    syscall, since the kernel resolves through it.
  - **Out** (`getsockname`/`getpeername`/`accept`/`accept4`/`recvfrom`/`recvmsg`):
    `cng_sun_out` maps the host path back to guest spelling in place and rewrites
    the in/out `addrlen`.
  - **Abstract names** have no filesystem node, so the rootfs prefix cannot scope
    them and an unprivileged process cannot be handed its own netns. A short
    per-rootfs tag (`\x01cng<hash8>`, keyed by `cng_broker_key_hash` — the same
    primitive broker.c already used for its own rendezvous) is spliced in after
    the leading NUL and stripped on readback. Without it, two invocations over
    different rootfs collide on one name (two guest X or D-Bus daemons fighting
    over `@/tmp/.X11-unix/X0`) and a guest can reach host abstract services.
    `--share-abstract-sockets` opts out. A name too long to carry the tag, and an
    unnamed/autobind address, pass through untagged.
  - **`SO_PEERCRED`** is remapped under `--fake-id` (`getsockopt` joins the
    credential set): the kernel reports the real invoking uid for the peer, while
    the guest's own `getuid()` reports the fake id, so a daemon doing a peer-uid
    ACL check — tmux, polkit, gpg-agent, ssh-agent — rejected its own client. The
    pid is deliberately left alone; guest pid == host pid here.
  - `CNG_SECCOMP_MAX_INSNS` 128 → 256 for the ten new entries (filter is 89
    instructions; the kernel's own limit is 4096).
  - Tests (`tests/m15_unixsock.sh`, guest `tests/guests/uxsock.c`) lean on facts
    that make them self-proving rather than tautological: the host `/run` is
    root-owned and unwritable, so `bind: ok` there is only reachable *through* the
    rootfs (the pre-fix binary answers `Permission denied` — verified), and the
    readback is asserted to contain no host path. For abstract names the tag is
    read back out of the **host's** `/proc/net/unix` (proving it is on the wire
    while the guest still sees a bare `@name`), two different rootfs are shown
    taking the same name, and `--share-abstract-sockets` is the control that makes
    them collide — so the isolation cannot pass by luck. An over-long rootfs path
    exercises the `/proc/self/fd` fallback.
  - Not covered, deliberately: `sendmmsg`/`recvmmsg` are left native. They are
    array forms whose per-message addresses would need the same treatment; no
    guest we run uses them with pathname addresses, and trapping them costs two
    more filter entries plus a loop over guest memory. Noted rather than hidden.

- [x] **M16 — NETLINK_ROUTE emulation**
  Android denies app domains rtnetlink, and everything that asks the kernel about
  interfaces goes through it — `getifaddrs(3)` (so `apt`, `dnf`, Java and Go
  runtimes), iproute2 (`ip link/addr/route`), bubblewrap's `loopback_setup()`, and
  glibc's netlink-based source-address selection. Without a shim every one of
  them fails inside the guest. This was the largest pure functionality gap
  against the oracle, and it is on chroot-ng's own target platform.
  - **The insight that made it small: an unbound socket can still dump.** The
    SELinux denial is on `bind(2)`, not on the query, so `RTM_GETLINK`,
    `RTM_GETADDR` *and* `RTM_GETROUTE` can all be relayed through a host netlink
    socket we open, send on and read from without ever binding it — verified
    directly before committing to the design. arm64chroot relays only GETROUTE
    that way and rebuilds the other two from `getifaddrs`; relaying all three is
    both far less code (about 300 lines against its 1246) and **more faithful**,
    since every reply is the kernel's own rather than an approximation. It is
    also the only option here: chroot-ng is `-nostdlib` and has no `getifaddrs`.
  - The guest's fd is a real `AF_UNIX` datagram socket, so `close`/`dup`/`poll`
    behave, that we never transmit on. A send builds the reply; the matching recv
    drains it. Slot identity is pinned by the socket's **inode**, not the fd
    number — we cannot trap `close`, so without that a guest which closed this fd
    and opened something else on the same number would have its I/O diverted here
    (the staleness discipline `procfs.c` already uses).
  - Four things had to be right for a real libc to accept the replies, and each
    was found by driving glibc at it rather than by reading the spec:
    `MSG_PEEK`/`MSG_TRUNC` (glibc sizes the message before reading it, so PEEK
    must not consume and TRUNC must report the whole pending length); the reply's
    `nlmsg_pid` is the **destination** port id — the requesting socket's, matching
    what `getsockname` reports — not whatever the request carried; the *source*
    address of a reply must be `nl_pid == 0`, which is how a client knows a
    message came from the kernel (filling it with our own id made glibc discard
    the entire dump and then report the next empty read as an error); and each
    recv must return **whole messages only**, since a reader walks with
    `NLMSG_OK` and a record split across two reads desynchronizes it.
  - A dump truncated by our buffer ends in a partial record, and a client walking
    with `NLMSG_OK` stops dead there — so `nl_finish` rewinds to the last complete
    message and puts `NLMSG_DONE` at that offset, discarding the partial tail. The
    guest loses whatever the truncation dropped but always sees a finite,
    well-formed dump instead of hanging.
  - `getsockname`/`getpeername` report a 12-byte `sockaddr_nl`: the underlying
    AF_UNIX answer is 2 bytes and iproute2 rejects that outright. `bind` on an
    emulated socket is a silent success. A non-dump request gets a zero-error ack,
    which is what lets bubblewrap's `loopback_setup()` proceed.
  - Where even `socket(AF_NETLINK)` is refused, a dump degrades to an empty
    result: `getifaddrs` then succeeds with no interfaces instead of failing, and
    `ip addr` prints nothing instead of "Cannot open netlink socket".
  - Tested **differentially**: the same guest (`tests/guests/netif.c`, exercising
    `getifaddrs` plus a raw iproute2-style `RTM_GETLINK` dump) runs once straight
    under qemu against the real kernel and once under chroot-ng with
    `CNG_NETLINK_FORCE_BLOCK=1`, and the two must agree byte for byte. That is the
    only way to check this on a devbox, where the emulated path never engages on
    its own. The suite also asserts the reverse — that with rtnetlink working the
    emulation stays entirely out of the way (no emulated fd is created).
  - Not done, and separable: the `SIOCGIF*` interface ioctls. They arrive on an
    `AF_INET` socket rather than a netlink one, so the fd-based hook does not
    reach them, and trapping `ioctl` wholesale would put every terminal `TCGETS`
    through the handler. The clean approach is a BPF range test on `args[1]`
    (`0x8910`–`0x8970`), which is its own change.

- [x] **The remaining path-bearing enumeration gaps**
  With the filter's tail being `RET_ALLOW`, any path-bearing syscall not on the
  trapped list reaches the host with the guest's string verbatim. The audit's
  remaining entries are closed here.
  - **`fchmodat2`** (6.6+) is **translated**, not refused: glibc >= 2.39 reaches
    for it first, and it is the only way to chmod a symlink itself. It honors
    `AT_SYMLINK_NOFOLLOW`, respects a `:ro` bind, and joins the l2s deny and
    block-list probe sets like its predecessor. This was a live escape on any
    modern glibc guest — the ordinary `chmod` path.
  - **Refused** (designed-ENOSYS, the oracle's answer): `open_tree` — which needs
    no privilege at all without `OPEN_TREE_CLONE` and is otherwise just a
    path→fd lookup on the host — plus `move_mount`, `fsopen`, `fsconfig`,
    `fsmount`, `fspick`, `fanotify_mark`, and `open_by_handle_at` (the pair to the
    already-trapped `name_to_handle_at`). `statmount`/`listmount` are refused for
    a different reason: they would hand the guest the **host** mount tree,
    defeating the synthesized `/proc/self/mounts` outright.
  - **System V semaphores and message queues.** M12 gave the guest its own shm
    namespace, but `semget`/`semop`/`semctl`/`semtimedop` and
    `msgget`/`msgsnd`/`msgrcv`/`msgctl` were left running natively — so on a
    desktop host the guest operated in the **host's** sem/msg namespace: it could
    attach to host semaphores, and host `ipcs -s`/`ipcs -q` listed the guest's
    objects. That is precisely the isolation the shm broker exists to provide, and
    the largest thing the M11/M12 divergence lists had missed. Refused, which is
    the oracle's behaviour; a broker-backed emulation mirroring shm would be the
    richer answer and is the obvious follow-up.
  - `-t bpftest` pins the distinction that matters: `semget`/`msgget` answer
    ERRNO while `shmget` still TRAPs for emulation, and `fchmodat2` TRAPs for
    translation rather than being refused. `-t dtest denied` covers the same on
    the `-R` trampoline tier. Filter is 109 of 256 instructions.

- [x] **auxv fidelity: `AT_SECURE`, `AT_RANDOM`, the identity entries, `AT_MINSIGSTKSZ`**
  Four entries the loader was getting wrong, two of them security-relevant.
  - **`AT_SECURE` was hardcoded 0.** It is what makes glibc's
    `__libc_enable_secure` and musl's `libc.secure` sanitize `LD_PRELOAD`,
    `LD_LIBRARY_PATH` and `LD_AUDIT` — so a `--setuid-root` exec that really did
    elevate the fake identity ran **unguarded**, which is the one case where it
    matters most. Now computed from the transition the way the kernel does
    (`uid != euid || gid != egid`).
  - **The identity entries carried chroot-ng's own host ids** even under
    `--fake-id`, so `getauxval(AT_UID)` contradicted `getuid()`. musl derives
    `libc.secure` from exactly that comparison. They now come from the live
    credential set when a fake identity is active.
  - **`AT_RANDOM` was a copy of our own host value**, reused for every program.
    glibc and musl take the stack canary and pointer guard from it, and a real
    execve re-randomizes per exec — so the whole exec chain shared one canary,
    and it was predictable from any single leak. Drawn fresh from `getrandom(2)`
    now, falling back to the host value only if that is unavailable.
  - **`AT_MINSIGSTKSZ` was dropped** while `AT_HWCAP` was forwarded verbatim —
    so guests do enable SVE, then size `SA_ONSTACK` alt-stacks from glibc's small
    compile-time fallback rather than the kernel's real answer. That is in direct
    tension with the ~4.5 KiB frame our own SIGSYS handler is delivered on. Now
    passed through.
  - `tests/guests/auxprobe.c` asserts the identity entries agree with the
    credential syscalls under `--fake-id`, and that `AT_RANDOM` differs between
    two execs.

- [x] **`ip addr` on-device fix: iproute2's dump contract, and no more relay buffer**
  Reported from a device: `ip addr` printed `DONE truncated / Dump terminated` and
  nothing else, where arm64chroot listed every interface. Two defects, and the
  first explains the message exactly.
  - **`NLMSG_DONE` must carry a 4-byte error int.** iproute2's
    `rtnl_dump_done()` rejects a terminator shorter than
    `NLMSG_LENGTH(sizeof(int))` — 20 bytes — and prints precisely
    `DONE truncated`. We emitted 16 (`NLMSG_LENGTH(0)`). glibc's `getifaddrs`
    never looks at the length, which is why this passed every local test: the
    M16 differential guest only counted messages. And because `ip addr`
    collects the `RTM_GETLINK` dump into a list *before* printing anything, the
    rejection lost the entire listing rather than truncating it — matching the
    report of no output at all.
  - **Our own terminator only appeared when the dump was truncated** by the
    16 KB reply buffer, which is why a devbox with two interfaces never saw it
    and a phone with seven did. Rather than widen the buffer, the buffer is
    **gone**: each slot now keeps its unbound host netlink socket open and the
    guest's `recvfrom`/`recvmsg` reads the kernel's reply *straight into the
    guest's own buffer*, with the guest's `MSG_*` flags forwarded. That removes
    the cap, the message-boundary splitting, and the hand-rolled
    `MSG_PEEK`/`MSG_TRUNC` emulation in one move — the kernel does all of it —
    and it means a dump can no longer silently lose entries. Only `nlmsg_pid`
    still needs rewriting (our host socket is unbound, so the kernel addresses
    replies to port 0 while the client matches them against the port id
    `getsockname` reported).
  - `tests/guests/nldone.c` now applies **iproute2's** filter rather than
    glibc's: it asserts the terminator's length, that the source address is
    `nl_pid == 0`, that `nlmsg_pid` equals the port id from `getsockname`, that
    the sequence number matches, and that nothing was silently skipped — the
    checks whose absence let this ship. `CNG_NETLINK_NO_RELAY=1` exercises the
    relay-less degradation path on a working host, asserting an empty dump is
    still well-formed rather than a terminator a client rejects.
  - The M15/M16 guest invocations are wrapped in `timeout` now: a dump that
    never terminates should fail one check rather than wedge the suite.

- [ ] **M10 — (optional) user_notif supervisor tier for kernels >= 5.0**

## Testing notes
- `make` cross-compiles; `make run ARGS="..."` runs under qemu-aarch64.
- `make test` runs `tests/run.sh`.
- qemu-user does NOT emulate guest seccomp filters faithfully → M5's mechanism
  needs simulated-SIGSYS unit tests + real-hardware validation. Loader (M3/M4)
  and path logic are fully qemu-testable.
