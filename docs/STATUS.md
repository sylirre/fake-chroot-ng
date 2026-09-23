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
  - Final protections are applied per host page as the union of every segment
    touching it (RWX where text and data share a page). The counterexample is
    a 4 KiB-max-page-size object on a 16 KiB kernel — Android's 16 KiB
    migration — which the anonymous strategy is the only way to run at all.

- [x] **M4 — `ul_exec` loader: dynamic binaries**
  Load `PT_INTERP` (`ld.so`) at its own base, set `AT_BASE`/`AT_ENTRY`/`AT_PHDR`,
  and jump to the interpreter's entry; ld.so then maps libraries and bootstraps
  the main program. Verified under qemu with a dynamic glibc guest (`-L` resolves
  the interpreter path; `LD_LIBRARY_PATH` lets ld.so find libc at a real host
  path until M5 redirects its opens into the guest rootfs).
  Note: on a real noexec mount, ld.so's own file-backed `PROT_EXEC` mmap of
  `.so`s fails, and the loader cannot help — it never sees that mapping. Closed
  by **M23** below (the mmap hook), which converts it to anon-exec.

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
  The emulation runs on the handler's own scratch stack, and an execve from a
  multithreaded program is the kernel's: every other thread is killed first
  (a thread-directed SIGSYS, the one signal a guest can never block — the
  mask-taking waits are trapped so it cannot be parked out of reach either),
  and a non-leader thread hands its exec to the group leader to carry, so the
  program that comes out of it is one thread whose tid is its pid.
  The old program's mappings were kept too, at 66.8 MB of address space per
  generation — and, on a guest whose libc reserves address space of its own,
  gigabytes more. What the loader mapped for it is given back by M32, and what
  the program mapped for itself by M35.

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
  Caveat at M8: the `svc`-immediate scan is exact (`0xD4000001`), and a data
  word equal to it anywhere in the executable segment was rewritten with it —
  which stock rootfs images turned out to contain (see M33, where the scan
  learned to ask the object where its code is).

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
    filtered (a fully-hidden batch must not read as EOF), and rewrites each
    link's own record from the symlink's (`DT_LNK`, its inode) to the backing
    file's `d_type`/`d_ino` — what `stat` of the name answers — so the readdir
    fast path of GNU `ls -F`/`find -type f`/`ls -i` sees a regular file
    (`cng_l2s_dirent`: one `readlinkat` per symlink listed under `-l`, one
    `fstatat` more per link; `tests/guests/dents.c` diffs the raw records
    against real hardlinks in M10); paths naming the
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
    cannot create files matching the `.l2s.` name grammar, nor (M60) a
    symlink whose target's last component matches it (denied `ENOENT`);
    the rootfs root's own `st_nlink` is +1 once the store exists;
    `openat2(RESOLVE_NO_SYMLINKS)` fails on emulated links; a legacy per-dir
    group whose surviving names were all mv'ed away leaves its old dir
    non-rmdir'able, and per-dir-fallback links don't survive a rootfs move
    (store links self-heal); `/.l2s` stays reachable via dirfd `..`-walks;
    cross-dir + EXDEV still copies; an emulated cross-filesystem link (bind
    mount) *succeeds* where a real one would report `EXDEV` — except out of
    a `:ro` bind, which is `EXDEV` as it is natively (M65).

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
  which on Android is the one being denied — and so does the fd: `fstat`, the
  by-fd `newfstatat`/`statx`, `fstatfs`, the `/proc/self/fd` link and a stat
  through it all describe the real file (the memfd is named after it, so a
  dup'd, inherited or reopened fd finds its way back; a held entry of a
  process that is gone reads as a generic /proc regular file, where the kernel
  would still have the pinned inode); `mmap` of such an fd works read-only
  where the real file answers `ENODEV`, and `fsync` returns 0 where it is
  `EINVAL`; `/proc/version` passes through (arm64chroot must keep it in
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
    A third only a real kernel could show: `SHM_REMAP` without an address is
    `EINVAL` (nothing to replace; `do_shmat` refuses before it looks the
    segment up), where qemu's own `shmat` attaches anyway — and so did the
    emulation, until the first native run. The address rules now come first,
    in the kernel's order, ahead of the broker's lookup and permission check.
  - **Tested differentially.** `tests/guests/shm_sysv.c` and `shm_stat.c`
    (arm64chroot's own, written for exactly this comparison) plus `shm_exec.c`
    run once under the emulation and once straight under qemu-aarch64, where
    the same code gets the genuine article — the host kernel's
    `shmget`/`shmctl` and qemu's own `shmat`; stdout must match byte for byte,
    over both backing tiers. `shm_edge.c`, like the `SHM_REMAP` and
    attachment-table programs, is refereed by a host-native build instead,
    since its attach-side answers are the ones qemu makes up. `-t shmtest`
    covers the dispatcher level in ten groups including a real fork and a
    real broker, and `tests/guests/shm_key.c` pins the namespace scope, which
    is the one part with no counterpart to diff against.

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
    prefix frequently overflows it. A name under the rootfs is then spelled
    `/proc/self/fd/<root>/./<guest path>` — the rootfs directory as the handle
    and the guest's own canonical path beneath it — so the stored string
    carries the guest name and *any* reader (a peer's `getpeername`, an
    inherited socket) takes it straight off the string. A name under a bind, or
    one too long even so, is bound relative to a handle on its parent
    (`/proc/self/fd/<n>/<basename>`) and the binding process remembers the pair,
    keyed by the socket's inode for its own `getsockname` and by the spelling
    for other readers, in a table that grows. The fd is closed by
    `cng_sun_done` *after* the syscall, since the kernel resolves through it.
  - **Out** (`getsockname`/`getpeername`/`accept`/`accept4`/`recvfrom`/`recvmsg`):
    `cng_sun_out` maps the host path back to guest spelling in place and rewrites
    the in/out `addrlen`.
  - **Abstract names** have no filesystem node, so the rootfs prefix cannot scope
    them and an unprivileged process cannot be handed its own netns. A short
    per-rootfs tag (`\x01cng<hash16>` — 8 digits until M55 — keyed by
    `cng_broker_key_hash`, the same primitive broker.c already used for its own
    rendezvous) is spliced in after
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
  - Not covered here, deliberately: `sendmmsg`/`recvmmsg` were left native. They
    are array forms whose per-message addresses need the same treatment; no guest
    we run uses them with pathname addresses, and trapping them costs two more
    filter entries plus a loop over guest memory. Noted rather than hidden — and
    closed later, as **M15b** below.

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

- [x] **`ip addr` on-device, part 2: relay the minimal dump request form**
  After the terminator fix, `ip addr` still printed nothing on-device. The debug
  trace localized it exactly:

        nl send fd=3 type=18 -> empty (no relay)   <- RTM_GETLINK refused
        nl send fd=3 type=22 -> relayed            <- RTM_GETADDR accepted

  The relay socket existed (`relay fd 4`), so it was the `sendto` on it that
  failed, and only for `RTM_GETLINK`. That alone explains an empty listing:
  `ip addr` builds its output from the **link** dump and annotates it with
  addresses, so zero links prints nothing however well `RTM_GETADDR` went.
  - **Cause: the request *form*.** iproute2 asks for `RTM_GETLINK` with a
    `struct ifinfomsg` **plus an `IFLA_EXT_MASK` attribute**; Android refuses
    that, while accepting the bare `rtgenmsg` (family byte only) form that
    Bionic's `getifaddrs(3)` sends. Two pieces of evidence agree: the split
    between the two request types above, and the blank `link/ether` fields in
    arm64chroot's own output on the same device — the signature of Android's MAC
    scrubbing, which proves `RTM_GETLINK` data *is* obtainable there via
    getifaddrs. That is also why the oracle works: it never issues the rich form,
    because it builds link replies out of getifaddrs.
  - **Fix:** `relay_dump` rewrites the request to the minimal 20-byte form —
    nlmsghdr + one family byte — keeping the guest's type, flags and sequence.
    The family byte is at offset 16 in all three payloads we relay
    (`ifinfomsg.ifi_family`, `ifaddrmsg.ifa_family`, `rtmsg.rtm_family`), so it
    carries across without knowing which. Dropping the filter attributes means
    the kernel may return more than was asked, which is safe: netlink filtering
    is advisory and every client filters replies itself.
  - Forwarding the request verbatim looked obviously right and was the bug.
  - `SO_RCVTIMEO` is set on the relay socket, so a kernel that answers nothing
    cannot hang the guest.
  - **Test gap closed:** `tests/guests/nldone.c` now sends iproute2's request
    byte for byte, `IFLA_EXT_MASK` and all. It previously sent the bare form —
    the one form that already worked — which is precisely why the suite passed
    while the device failed.
  - The relay socket occupies a guest-visible fd (host fd == guest fd here),
    and so does the pair peer; what a `close_range()` sweep does to them is
    M47's.

- [x] **Fix: the startup probe ran its candidates against live fd 0.** The
  blocked-syscall probe (blocklist.c) invoked every candidate with all-zero
  arguments, believing them harmless. But a zero arg0 names stdin:
  `utimensat(0, NULL, ...)` is futimens and really stamped its timestamps,
  `fchown(0, 0, 0)` really ran against it — and once the probe set grew the
  socket syscalls (M15), `recvfrom(0, NULL, 0, 0)` **blocked startup forever**
  whenever stdin was a datagram socket with nothing queued, which is what ssh
  and CI harnesses hand a process. Probes now pass arg0 = -1: a seccomp filter
  matches on the syscall number before the kernel reads any argument, so a
  blocked call still traps, while an allowed one returns EBADF/EFAULT
  instantly, with no side effects on inherited fds.

- [x] **Fix: `ip addr` on-device, round three — synthesize the link dump and
  serve write()-submitted requests.** The previous fix (minimal request form)
  was not enough: the on-device trace showed `sendto=-13` on the relay socket
  for `RTM_GETLINK` *in the minimal form too*, while `RTM_GETADDR` relayed
  fine. That is Android's real policy: link dumps expose MAC addresses, so app
  domains are refused them under `nlmsg_readpriv` in **every** request form,
  while address and route dumps are plain `nlmsg_read`. Relaying GETLINK can
  never work there — and the oracle never tries: arm64chroot synthesizes its
  link replies out of getifaddrs (whose Bionic implementation has its own
  fallback for exactly this restriction).
  - **Synthesis (netlink.c):** a refused GETLINK is rebuilt the oracle's way,
    from raw syscalls since chroot-ng has no libc: interfaces enumerated from
    our own RTM_GETADDR relay (the same enumeration Bionic's fallback uses —
    so, like the oracle on-device, only interfaces carrying an address appear),
    fleshed out with SIOCGIFNAME/FLAGS/MTU/HWADDR ioctls, and rendered with
    the oracle's exact recipe: hardcoded txqlen 1000, operstate from IFF_UP,
    IFF_LOWER_UP from IFF_RUNNING, IFLA_ADDRESS absent when the host refuses
    the MAC (the blank `link/ether ` arm64chroot shows). Zero interfaces —
    including the no-relay degradation — presents loopback alone, as the
    oracle does; a non-dump GETLINK filters by ifindex/IFLA_IFNAME and answers
    ENODEV for a miss. A refused GETADDR falls back to loopback addresses.
  - **Second defect, found by running Alpine's actual `ip`:** busybox submits
    its netlink request with plain `write(2)` — a syscall deliberately left
    untrapped — which hit the AF_UNIX stand-in and died with ENOTCONN. The
    stand-in is now one end of a datagram **socketpair** whose peer the
    monitor holds: replies are pushed in as per-message datagrams (the kernel
    itself provides MSG_PEEK/MSG_TRUNC/blocking/poll semantics, and nothing is
    ever split or truncated by us), an untrapped write() queues its request on
    our end natively, and every trapped netlink call — plus dispatch's
    read/readv case under -R — drains and serves the queue first. Relayed
    dumps are pumped through datagram-for-datagram with the pid fixup, and a
    dump whose host goes quiet still ends in a proper NLMSG_DONE.
  - Known limitations, judged acceptable: a client that write()s a request and
    then poll()s with no trapped call in between would sleep (no known client
    does this — busybox recv's, everything else sendmsg's); a guest that never
    reads ~200 KB of replies has the tail dropped rather than deadlocking the
    monitor (logged under CNG_DEBUG).
  - **Tests:** `CNG_NETLINK_DENY_GETLINK` simulates the Android split on a
    working host (implies FORCE_BLOCK); nldone gained a `named>0` field
    (IFLA_IFNAME is what `ip addr` prints names from); the no-relay leg now
    expects the loopback-only dump (oracle parity, was: empty); and an
    acceptance leg runs busybox `ip addr` from the Alpine rootfs under the
    split, asserting real output. Suite: 310 passed, 0 failed.

- [x] **Fix: the emulated execve read its argv out of the image it had just
  replaced.** `execve_core` loaded the new program and only then had
  `cng_build_stack` copy the caller's argv/envp strings onto the new stack. For
  an ET_EXEC guest the image goes in **MAP_FIXED at its own link-time vaddr**,
  so when the program calling execve is itself ET_EXEC at that vaddr — which
  every binary a plain `-static` toolchain produces is, all of them at 0x400000
  — the load landed exactly on the `.rodata`/`.data`/heap holding those strings
  (and, under `-R`, the trampoline pool extended the fixed span over the old
  brk as well). The exec'd program came up with **garbage argv** while still
  running and still exiting with the right status, so only an argv assertion
  could see it. This is the M3 fixed-vaddr collision reaching the execve path:
  relocating chroot-ng itself out of 0x400000 protected the monitor, not one
  guest from the next.
  - `path`/`argv`/`envp` are now snapshotted into one anonymous mapping before
    anything is mapped, and the body works from that copy — so the resolution,
    the shebang rewrite and the stack build all read memory the load cannot
    reach (a kernel-placed mapping is in the high mmap region; no ET_EXEC vaddr
    goes near it). Released once the stack is built, on every path.
  - The snapshot is bounded and answers `-E2BIG`, which the emulation never did
    before — argv/envp were simply copied onto the guest stack unchecked (part
    of the M17-10 gap). The bound is the kernel's own formula, a quarter of
    `RLIMIT_STACK` floored at 32 pages, clamped to what our fixed 64 MiB guest
    stack can hold; being the kernel's own, it cannot refuse anything that
    reached this process through a real execve. Both the pointer slots and the
    string pool are bounds-checked on copy rather than trusted: the vectors are
    guest memory and another thread of the exec'ing process can grow them
    between the sizing pass and the copy.
  - **Tests:** M8 gained a leg that builds both programs `-static -no-pie`
    explicitly — the usual static-PIE guest gets a fresh base per image and
    hides the bug entirely — and asserts argv0/argv1 survive; verified to fail
    on the pre-fix binary and pass after. Suite: 317 passed, 0 failed.

- [x] **M17-16 — the guest environment is built, not inherited** (`-E/--env`)
  A guest received our whole environment, and almost none of it described the
  world it was about to run in: `PATH`, `HOME`, `LD_LIBRARY_PATH`, `XDG_*`,
  `TMPDIR`, `SHELL` all named host locations the rootfs has its own copies of,
  and chroot-ng's own `CNG_*` knobs went along for the ride. The guest now starts
  from a clean environment: `-E/--env VAR=VAL` entries (repeatable, up to
  `CNG_MAX_ENV` = 128) plus `TERM`/`COLORTERM`, the two that describe the
  terminal both sides share. Oracle parity — `busybox env` under `-E FOO=bar`
  prints the same three lines arm64chroot does.
  - The host/guest split is explicit in the code now: `cng_g_envp` — read by every
    `CNG_*` knob and by `cng_broker_env` — is `cng_g_host_envp`, and the guest's
    vector is assembled by `build_guest_env` (`src/run.c`) and handed to
    `cng_build_stack`. The emulated `execve` is untouched: it carries the guest's
    own `envp`, exactly as a real one does.
  - An `-E` entry *replaces* rather than shadows, both for a repeated name and for
    an override of an inherited `TERM`: `getenv()` takes the first duplicate while
    a shell re-exporting `envp` keeps the last, so emitting both would leave the
    two disagreeing about which value won.
  - A spec with no `=` is refused (exit 2) rather than passed through as an entry
    no `getenv` could ever match — the oracle passes that string straight into
    `envp`. Nothing is synthesized for the guest either: a shell supplies its own
    default `PATH`, and inventing a `HOME` would be guessing.
  - **Tests:** new `tests/m17_env.sh`, 30 legs. The entry *count* carries the
    scrubbing assertion (host `CNG_*`, `HOME` and `LD_LIBRARY_PATH` canaries are
    set on every run), and two exact-match legs make the Alpine guest's own
    `env(1)` and its `/proc/self/environ` agree on the same three entries. M3, M4
    and M8 proved env forwarding by setting a host variable and now use `-E` —
    M4's `LD_LIBRARY_PATH` for ld.so among them, which is the one place the
    scrubbing would otherwise have broken a working test rather than a leak.
    Suite: 347 passed, 0 failed.

- [x] **Fix: the initial program's `/proc/self/exe` was `<program>` verbatim.**
  Everything after the first program has its exe link republished by the emulated
  execve, from the resolved host path (`execve.c`); the first program — the one
  nothing republishes — kept whatever was typed on the command line. So
  `chroot-ng -R / build/tests/hello` **aborted the guest before `main`**: glibc
  does not merely tolerate an absolute `/proc/self/exe`, it asserts it
  (`_dl_get_origin`, `dl-origin.c:41`), and a relative `<program>` produced a
  relative link. Nothing outside `-R`/live-seccomp saw it, since without the
  monitor the host's own (absolute) link is what the guest reads.
  - `cng_run` now derives the link the same way the exec path does: the resolved
    host path untranslated back into the guest view, which is absolute and
    symlink-resolved by construction. That also fixes the quieter half — a
    symlinked `<program>` reported the link rather than the file it named — and
    `comm`, which is taken from the same recorded program.
  - Oracle parity in all four combinations (absolute/relative x file/symlink):
    arm64chroot answers `exe=/bin/exeprobe comm=exeprobe` for each, and so do we
    now; two of the four used to abort and one was wrong.
  - **Tests:** M7 gained five legs on a new `tests/guests/exeprobe.c` (reads its
    own exe link and comm), including the reported form — identity rootfs plus a
    relative `<program>` — and a rootfs form whose relative path resolves against
    the guest root instead. Verified to fail on the pre-fix binary (`rc 134`,
    SIGABRT, on the relative legs) and pass after. Suite: 354 passed, 0 failed.

- [x] **M17-17 — the guest's initial working directory is selectable** (`-w/--work-dir`)
  The cwd a guest starts in was fixed: the guest root `/` under a real rootfs (the
  host launch directory is never leaked — it names nothing inside the rootfs, and
  a relative `<program>` would resolve against it), the host cwd under an identity
  rootfs, and nothing could change either. `-w/--work-dir DIR` now names one, as
  the oracle's option of the same name does.
  - `DIR` is a guest path resolved through the rootfs and its binds by
    `cng_resolve`, following symlinks, so a symlinked work directory reports what
    it resolved to — which is what a real `chdir(2)` leaves `getcwd` reporting —
    and `..` is canonicalized inside the guest root, so it cannot climb out.
    Both the virtual cwd and the real one move (`cng_fs_set_cwd` + `chdir`): the
    second is what an untranslated relative path resolves against, and on a host
    where no monitor installs it is the only one there is.
  - Applied before `<program>` is resolved, since that resolution is relative to
    the cwd — `-w /a/b <rootfs> probe` runs `/a/b/probe`, exactly as it would from
    a shell that had `cd`'d there first.
  - A `DIR` that is empty, missing, or not a directory is fatal (exit 1, the same
    code the neighbouring resolve/load failures use; the oracle spells all of its
    setup failures 126). Quietly falling back to `/` would leave a guest running
    in the wrong tree, which nothing downstream can detect.
  - **Tests:** new `tests/m17_workdir.sh`, 33 legs on a new
    `tests/guests/cwdprobe.c` (prints `getcwd`, `/proc/self/cwd`, and the contents
    of a file opened relative to the cwd — a working directory that only *prints*
    right is no working directory at all). Identity-rootfs legs run on every host;
    the rootfs legs need a live translation tier (`guest_xlate_ready`) because
    `getcwd` must come from the virtual cwd. Four of them are byte-for-byte
    differentials against arm64chroot's own `-w`. Suite: 387 passed, 0 failed.

- [x] **M17-7 — a bad guest pointer answers `EFAULT` instead of killing the guest**
  The syscalls the monitor *emulates* rather than re-issues read and write the
  guest's own pointers, so the kernel never validates them for us — and they do it
  inside the SIGSYS handler, where every signal but SIGSYS is masked
  (`cng_sig_install`). A `SIGSEGV` there is unblockable: the kernel force-defaults
  it and the process dies. So `shmctl(id, IPC_SET, garbage)`,
  `capget(garbage, ...)`, `setgroups(n, garbage)`, `getres*id(garbage, ...)`,
  `getcwd(garbage, n)`, `rt_sigaction(sig, garbage, ...)` and
  `rt_sigprocmask(how, garbage, ...)` each turned an ordinary `-EFAULT` into the
  death of the guest, behind nothing more than a bare NULL check.
  - New `src/monitor/uaccess.c`: `cng_user_readable` / `cng_user_writable` ask the
    kernel whether a range is accessible rather than finding out by faulting —
    the move `dbg_str` already makes for the debug log, generalized from a C
    string to a byte range. The probe is a copy through a scratch memfd:
    `pwrite64` is a `copy_from_user` of exactly that range, `pread64` a
    `copy_to_user` of it, and both report `EFAULT` (or a short count, where the
    fault is partway in) without touching anything else.
  - The write probe's source region is never written, so it always delivers
    zeros, and every caller uses it immediately before filling the buffer — which
    is why `getcwd` decides `ERANGE` first, as the kernel does. The read probe's
    scratch region is written and never read back, so concurrent probes on
    different threads cannot disturb each other and no lock is needed.
  - The descriptor carries the staleness discipline `procfs.c` uses for its
    synthesized fds: we do not trap `close(2)`, so a guest can close ours and be
    handed the number back for a file of its own, after which a probe would write
    into it. The inode is recorded at creation and checked on every use; a stale
    number is abandoned, never closed. Where no memfd can be had the probes answer
    "accessible" and the old dereference stands — no protection, but no
    regression either.
  - Applied to the same class wherever it appears in these handlers, not only the
    audited list: `openat2`'s `open_how`, `sendmsg`/`recvmsg`'s `msghdr` and first
    iovec, and the `getcwd` output buffer. Path *strings* are a separate case (the
    resolver walks them component by component) and are left for their own change.
  - **Tests:** new `tests/m17_fault.sh` on a new `-t faulttest`, which drives the
    dispatcher directly — so the emulation is exercised on every host, not only
    where the seccomp tier is live. Eleven syscalls are called with a wild
    (non-NULL, unmapped) pointer and must answer `-EFAULT`; the test surviving to
    print at all is half the assertion. Valid pointers are asserted to still work,
    and the leg reports SKIP where no memfd backs the probe. Suite: 400 passed,
    0 failed.

- [x] **M17-9 — `seccomp(2)` and `prctl` are virtualized**
  `docs/DESIGN.md` has listed this as required since M5 and it was never done: a
  guest could install its own seccomp filter, and the kernel layers that filter
  over ours on the same thread — including over the syscalls the SIGSYS handler
  re-issues through the gate, which the guest's filter knows nothing about. A
  guest that refuses `openat`, or kills on an unlisted syscall, would have taken
  the monitor down with it. `PR_GET_SECCOMP` reported mode 2 — *our* filter — so
  a program that checks whether it is already confined concluded it was and
  installed nothing.
  - `seccomp(2)` joins the designed-ENOSYS set, refused by the filter itself
    (`RET_ERRNO`), which is the oracle's answer too; we never issue it (the
    filter goes in through prctl), so refusing it ahead of the gate allowlist
    costs nothing. `prctl(PR_SET_SECCOMP)` answers `EACCES` — what a kernel says
    when the caller may not install a filter, and a case libseccomp, systemd and
    browser sandboxes all have a path for.
  - `PR_GET_SECCOMP` reports 0, and the `NO_NEW_PRIVS` pair reports what the
    *guest* asked for rather than the bit `cng_install_seccomp` had to set to
    install a filter at all. That bit told a guest setuid-on-exec was dead while
    our emulated execve still honors it (`--setuid-root`).
  - Only those four ops are trapped: the op is a scalar in `args[0]`, so the BPF
    filter tests it, and `PR_SET_NAME`, `PR_SET_VMA`, `PR_SET_PDEATHSIG` and the
    capability bounding set keep running natively. That matters on the hot path —
    bionic's allocator calls `PR_SET_VMA` on every mapping. The filter is 119 of
    256 instructions.
  - **Tests:** new `tests/m17_seccomp.sh` on a new `-t prctltest`, which sets the
    real `no_new_privs` bit first so "the guest sees 0" asserts the
    virtualization rather than an untouched process, and checks an unowned op
    (`PR_SET_NAME`) still reaches the kernel. Seven filter legs in
    `m5b_monitor.sh` cover which ops trap. Suite: 412 passed, 0 failed.

- [x] **M17-10 — execve fidelity: nesting, `execveat` flags, and the state a real
      exec drops**
  Four separate gaps in the emulation, all of them things the kernel does that we
  did not.
  - **Shebang nesting.** `#!` was a single `if`, so a script whose interpreter is
    itself a script came out as "not an ELF" (`ENOEXEC`). It is a loop now,
    bounded at four levels like `fs/exec.c` with `ELOOP` beyond — and each level
    prepends its interpreter and pushes the previous script down, so the whole
    chain reaches the final argv in order, exactly as the kernel assembles it.
  - **`execveat`'s flags word was never read** (`sigsys.c` did not even pass it
    on). `AT_EMPTY_PATH` — the fd-only form Go's `os/exec` and any
    `open`-then-`exec` idiom use — was ignored, so an empty path was simply
    ENOENT; `AT_SYMLINK_NOFOLLOW` silently followed the link it was told to
    refuse; and undefined bits were accepted where the kernel answers `EINVAL`.
    All three are honored now, with `AT_EMPTY_PATH` routed through
    `/proc/self/fd/N` so it reuses the path that already loads from an open
    description (and so reaches an anonymous or deleted image).
  - **A real dirfd resolved against the cwd.** `execveat(dirfd, "prog", ...)`
    copied the relative name through verbatim, leaving the *kernel* to resolve
    it — against the host cwd, with no rootfs in sight. It goes through
    `cng_resolve_at` now, the same containment every other `*at` syscall gets, so
    a `..` is clamped at the guest root instead of climbing past it.
  - **`EFAULT` on argv/envp.** The vectors were walked with a bare `strlen`,
    so a wild pointer was a fatal SIGSEGV inside the handler rather than the
    `-EFAULT` execve(2) promises. Both the vector and every string it points at
    are measured with the M17-7 helpers, one probe per page rather than per
    element, with `E2BIG` at the kernel's own `MAX_ARG_STRLEN`.
  - **State that outlived the image.** A real execve drops POSIX timers, the
    `clear_child_tid` futex, the robust futex list, the rseq registration and
    the heap along with the address space. We keep the address space, so all
    five survived: a timer went on firing into a program that never armed it,
    and `clear_child_tid` still pointed at the dead libc's TCB — an address the
    kernel writes a zero to and futex-wakes on thread exit, landing in whatever
    the new program put there. Timer ids are recorded as they are handed out
    (`timer_create`/`timer_delete` join the trapped set; nothing enumerates a
    process's timers, and the id in `/proc/self/timers` is the kernel's, not
    the one a guest under an emulator holds). The break is wound back to what
    it was before the first guest program ran, which also stops an exec chain
    accumulating every heap in it. The rseq area is the same shape with a
    sharper edge — the kernel writes cpu ids into it on its own, on every
    return to user mode after a preemption, and once the heap it sat in was
    wound back that write was a forced `SIGSEGV` (`SI_KERNEL`, no address, no
    handler consulted) — and it went unseen for as long as every exec was
    measured under qemu-user, which has no rseq: the first native run killed
    a ptrace tracee parked at its exec stop. `rseq` joins the trapped set, the
    area/length/signature are recorded per thread as the guest registers, and
    the registration is dropped at the point of no return, before anything is
    unmapped.
  - **Tests:** 18 new legs in `m6_execve.sh` on an extended `-t exectest`, whose
    new flags (`-D` dirfd, `-e` AT_EMPTY_PATH, `-N` nofollow, `-B` bad flag,
    `-R` state probe) are the only way to reach the execveat forms under qemu. A
    five-deep chain asserts `ELOOP` and a four-deep one asserts the full argv;
    the `-R` leg arms a heap and a timer and checks both are gone at the commit
    point. Three EFAULT legs in `m17_fault.sh`. Suite: 432 passed, 0 failed.

- [x] **M17-11 — resolution is physical, the way the kernel does it**
  `..` was collapsed lexically by `cng_fs_abscanon` *before* any symlink was
  expanded — logical resolution, the shell's convention, not the kernel's. With
  `/bin` a symlink to `/usr/bin`, `"/bin/../lib"` is `/usr/lib` to every syscall
  and was `/lib` to us; nothing that walks a tree with symlinked directories
  (and every distro has them) could agree with the filesystem it was walking.
  - `cng_resolve` is now a component walk against a resolved prefix, like
    `fs/exec.c`'s and the oracle's: each component is appended, checked for
    being a symlink, and expanded in place, while `..` pops the prefix — so it
    backs out of where the link actually led. `..` at the guest root stays
    there, which is what keeps the rootfs closed. It is also cheaper than what
    it replaces: one `readlink` per component instead of one per prefix per
    restart.
  - The magic links keep their meaning inside the walk: `/dev/fd/N` and
    `/dev/std*` are rewritten to their `/proc` spelling as the component is
    reached, `/proc/<pid>/fd/N` ends resolution in the host namespace with the
    remaining components riding along, and `exe`/`cwd`/`root` splice their
    guest-visible target in like any other link.
  - **`chdir` records where it landed**, not what was typed. The cwd is what a
    relative path resolves against and what `getcwd` reports, and the kernel's
    is the directory itself — so `chdir("/link"); open("../x")` has to back out
    of the target's parent. It took the same derivation `-w/--work-dir` and the
    exec path already use: the resolved host path, mapped back to the guest view.
  - **`faccessat2 AT_SYMLINK_NOFOLLOW`** was ignored, so it answered for the
    target: a dangling symlink reported ENOENT where the flag says it exists.
    (`O_NOFOLLOW` was fixed with M17-1; this was the other half.)
  - **Tests:** 8 legs in `m5_xlate.sh` on a new `-t xlate -R/-n` (the real
    resolver, against a tree on disk, with and without final-symlink
    dereference), 2 in `m5b_monitor.sh` on a new `dtest accessnf` (dangling link:
    nofollow exists, follow ENOENT), and 1 in `m7_fidelity.sh` for the symlinked
    `chdir`. Suite: 443 passed, 0 failed.

- [x] **M17-12 — `fstat` and `stat` agree, and `fchmod` fails soft**
  Two holes in the fake identity, both where an operation names a descriptor
  instead of a path.
  - `fstat` was trapped **only under `-l`**, so under `--fake-id` alone
    `stat("f")` reported the fake owner and `fstat(open("f"))` reported the real
    one — for the same file. Comparing those two is exactly what an installer
    does before deciding whether to chown. It is now trapped whenever either
    feature needs it.
  - `fchmod(fd)` was never in the fail-soft set, so a guest that opens a file and
    chmods the descriptor (`tar`, `cp -p`, `install`) got `EPERM` from the
    unprivileged host where the identical `fchmodat` succeeded.
  - **Tests:** two legs in `m7_fidelity.sh` (the `fchmod` fail-soft, and a
    stat/fstat ownership differential on one file) and one in `m5b_monitor.sh`
    that rebuilds the filter with the identity on and off — the only place the
    conditional trap set is visible. Suite: 446 passed, 0 failed.

- [x] **M17-13 — `chroot(2)` is privileged again**
  It was ungated: any guest could move its own root, where a real kernel demands
  `CAP_SYS_CHROOT`. That is a check guest code relies on the other way round too
  — a daemon that drops privileges and then expects `chroot` to fail was told it
  had succeeded. It now needs the same thing every other privileged operation
  here needs: a fake identity whose effective uid is 0 (`cng_fake_root`), and
  answers `EPERM` otherwise. The documented use (apk, which chroots before every
  package script) runs under `--fake-id` already.
  - The `/proc` and `/dev` zones surviving into the new root stays a **deliberate**
    divergence, now written down where the gate is: a real chroot leaves them
    unmounted, but a guest that cannot see `/proc` cannot run those same package
    scripts. Same trade as the M14 note above, for the same reason.
  - **Tests:** one leg in `m5b_monitor.sh` on a new `dtest chroot`, which asks
    both ways in one run — unprivileged `EPERM`, fake-root success — since the
    gate is the whole point.

- [x] **M17-14 — one kernel identity, told the same way twice**
  `uname(2)` passed the host's release straight through. Inside a rootfs that
  describes nothing the guest can act on, and on the target platform it is a
  device fingerprint: Android releases carry `-android14-11-<sha>`/`-perf`
  vendor suffixes. The guest now sees `6.1.0-chroot-ng` / `#1 SMP chroot-ng`
  (`CNG_KREL`/`CNG_KVER`), matching the oracle's choice of a fixed modern
  release — which also lifts the effective floor for a glibc rootfs that refuses
  to start below its build-time minimum.
  - `/proc/version` is synthesized from the same two strings and joins the
    existing `procfs` machinery. This is the half that makes the change worth
    anything: faking the syscall while the host file passed through would leave
    the two contradicting each other, and a distro install script reads whichever
    one it was written against.
  - `nodename` and `domainname` stay the host's. They name the machine the guest
    is really on — `hostname` reports it either way, and inventing one would only
    confuse the user reading it.
  - **Tests:** new `tests/m17_uname.sh`, 9 legs on a new `dtest uname`. Both
    readers are asserted to carry the fixed identity, and both to contain no
    occurrence of the *host's* actual release, which is the leak the change is
    about. Suite: 457 passed, 0 failed.

- [x] **M17-15 — the registry holds 4096 processes, and our own identity needs
      no registry at all**
  - **Capacity 256 → 4096**, the oracle's number. 256 concurrent guest processes
    is a lot for a phone, but it is a *shared* table under `--shared-proc` and
    slots are only reclaimed lazily (there is no exit hook), so a busy session
    could reach it — and past the cap a process is simply invisible.
  - Raising it would have made every lookup 16× more expensive, because a miss
    walks the whole table and "is this pid a guest?" is asked once per numeric
    name in a `/proc` listing — several hundred times for one `ps`. So the claim
    array is now kept apart from the payload: interleaved, each of those loads
    landed on its own cache line ~6.5 KiB from the last; dense, the whole
    4096-slot scan is 16 KiB, which is *less* work than the old 256-slot table
    cost.
  - **`/proc/self/cmdline` no longer falls back to our own argv.** The registry
    can be missing (no memfd) or full, and the fallback was the host file —
    which for a guest process describes the chroot-ng invocation that started
    it, so `cat /proc/self/cmdline` read back `chroot-ng -u /rootfs /bin/sh`.
    Anything that identifies itself by its own cmdline (busybox multi-call
    applets, a daemon writing a pid file) was told the wrong program was
    running. For our own pid the answer now comes from the live guest stack,
    which is where the kernel reads it from too — no shared table needed to
    describe the process doing the asking. Only *another* process's identity
    still requires the registry.
  - **Tests:** new `-t selfproc` and 7 legs in `m11_proc.sh`, run twice — once
    normally and once with a new `CNG_PROCREG_NONE=1`, which makes the registry
    unavailable so the degraded tier is reachable at all on a working host (the
    same testing convention as `CNG_SHM_FORCE_FILE`). Suite: 464 passed, 0
    failed.

- [x] **M16b — the `SIOCGIF*` ioctls answer from the same enumeration as the dumps**
  Split out of M16 because it needs a different trap key. These arrive on an
  ordinary `AF_INET` socket, so there is no fd range to filter on the way the
  synthesized `/proc` files have — and trapping `ioctl` wholesale would put every
  terminal `TCGETS` through the handler. The filter tests the *request* instead:
  `0x8910..0x8970` is the `SIOCxIF` band, two BPF instructions, and everything
  else stays untrapped.
  - They ask the same questions the netlink dumps do (`ifconfig`, and
    `getifaddrs`'s oldest fallback), so they are answered from the same
    enumeration: `SIOCGIFCONF` lists exactly the interfaces the link dump
    describes, and `SIOCGIF{NAME,INDEX,FLAGS,ADDR,NETMASK,BRDADDR,DSTADDR,MTU,
    METRIC,HWADDR,TXQLEN,MAP}` describe them the same way. Where the emulation
    degrades to loopback alone — no relay at all — the ioctl view degrades with
    it, instead of `ifconfig` listing the host's whole network while `ip addr`
    showed only `lo`.
  - The address dump now also yields each interface's first IPv4 address and
    prefix length, which is all this family can express; the netmask and
    broadcast follow from the prefix.
  - An interface the host knows but our enumeration did not is **left to the
    host**, not refused. Refusing would be the tidier story, but a guest can
    learn a name from `/proc/net/dev` (a passthrough) and busybox `ifconfig`
    reads exactly that — an `ENODEV` there stops it on its first interface. This
    emulation answers where the host will not; it does not take away answers the
    host is willing to give. Where the host's own rtnetlink works nothing is
    emulated on either side and the ioctls pass straight through.
  - `SIOCSIF*` stays unemulated: it changes the host's network configuration,
    and the host refuses it to an unprivileged process anyway.
  - **Tests:** `tests/guests/netif.c` gained the whole family, so the existing
    byte-for-byte differential against the real kernel covers it; plus 7 legs in
    `m16_netlink.sh` (including a relay-less run asserting the ioctl view is the
    same single interface `ip addr` shows) and 6 in `bpftest` pinning the band's
    two edges, `TCGETS`, and the requests just outside it. Suite: 469 passed,
    0 failed.

- [x] **M16c — the audit interface: the refusal `libaudit`'s callers recognise**
  The other netlink protocol Android's policy takes away, and the one that stops
  a whole package of ordinary software. Nothing is emulated — a guest has no
  business seeing the host's audit log, and asks for none — but the *refusal*
  has to be one the caller recognises, because it branches on which one it gets.
  - `libaudit`'s `audit_open()` is a bare `socket(PF_NETLINK, SOCK_RAW,
    NETLINK_AUDIT)`, and shadow-utils wraps it in `audit_help_open()`, which
    treats `EINVAL`/`EPROTONOSUPPORT`/`EAFNOSUPPORT` as "this kernel was built
    without audit" and carries on — and anything else as fatal:
    `useradd: Cannot open audit interface - aborting.` SELinux refuses the app
    domain a `netlink_audit_socket` with `EACCES`, which is not one of the
    three. In a Debian/Ubuntu rootfs that is 22 binaries — the whole of
    shadow-utils: `useradd`, `usermod`, `userdel`, `passwd`, `chage`, `chsh`,
    `chfn`, `gpasswd`, `groupadd`, `groupdel`, `groupmod`, `newusers`,
    `chpasswd`, `chgpasswd`, `vipw`, `vigr`, `pwck`, `grpck`, `pw{,un}conv`,
    `grp{,un}conv` — plus `su` on the distributions where `su` is shadow's
    rather than util-linux's.
  - So a refused audit socket answers `EPROTONOSUPPORT` — literally what
    `netlink_create` returns for a protocol nobody registered, i.e. a kernel
    with `CONFIG_AUDIT` off. Two conditions, in the `socket()` case that already
    exists for `NETLINK_ROUTE` (`cng_nl_audit_refusal`, `netlink.c`). A host
    that grants the socket is untouched, and no other family or protocol is
    looked at.
  - **Divergence from the oracle, deliberate:** arm64chroot gates the same shim
    on `fake_id && euid == 0`, framing it as part of the pretend-to-be-root
    story (`src/sys_net.c`). Here it is gated on the host's refusal alone. The
    refusal is the policy's and does not depend on the guest's credentials —
    real or synthetic — so "this container has no audit subsystem" is equally
    true for every guest in it; the rest of `netlink.c` already answers the same
    policy's rtnetlink denial without asking who the guest claims to be; and the
    gate's only live effect would be to leave `useradd` aborting in a rootfs
    whose files the invoking user already owns, which is the one case where it
    would otherwise have worked.
  - **Tests:** `tests/guests/auditsock.c` prints `audit_help_open()`'s decision
    rule, not just the errno, so a run is judged the way the tools judge it.
    3 legs in `m16_netlink.sh`: the forced refusal reads as `errno=93
    survives=1`; it is that narrow (a `NETLINK_ROUTE` and an `AF_INET` socket in
    the same run are untouched); and where the host grants the socket the guest
    sees exactly what an unemulated run saw. The host split is M16's — a devbox
    asserts passthrough, a device asserts the unforced rescue.
    `CNG_NETLINK_DENY_AUDIT=1` synthesizes the refusal (it does **not** imply
    `CNG_NETLINK_FORCE_BLOCK`; the two subjects are unrelated). Suite: 521
    passed, 0 failed, 1 skipped.
  - Not reachable end-to-end on a cross host: `useradd` is dynamically linked
    and its `socket()` lives in `libaudit.so.1`, which the guest's `ld.so` maps
    itself — and `cng_rewrite_seg` only rewrites images *our* loader maps, so
    under qemu-user (seccomp inert) that call escapes untranslated, as its
    `openat("/etc/.pwd.lock")` already does. On a device the filter traps
    `socket` from any object. The static guest above is what pins the behaviour
    here.

- [x] **M18 — guest `ptrace(2)`: strace, gdb and proot inside the rootfs**
  Until now `ptrace` was neither trapped nor refused, so a guest tracer reached
  the host kernel — which is worse than nothing here: the tracer saw *our*
  re-issued syscalls interleaved with the guest's, the path arguments it read
  were host paths with the rootfs prefix attached, exit-stop return values
  described the re-issue rather than the guest's call, and there was no
  post-`execve` `SIGTRAP` at all, because our execve never enters the kernel's
  exec path. It is now emulated end to end, in-process, needing no host ptrace
  permission (Android denies it), no `/proc/pid/mem` and no `process_vm_readv`.
  Model ported from arm64chroot's `ptracetab.c`, with the register file coming
  from the frame the kernel hands us at a stop rather than from an emulated CPU:
  - **The registry** (`src/monitor/ptrace.c`): one `MAP_SHARED` anonymous
    mapping created before the guest's first fork, so every guest process has it
    at the same address. One link per traced *task* (keyed by tid, as the kernel
    keys tracing), holding the relationship, the current stop, and a futex
    mailbox. Lock-free throughout — all of it runs inside the SIGSYS handler,
    where a sleeping lock could deadlock against the thread it interrupted.
  - **The tracee answers for itself.** It is parked in our code at the stop, so
    its memory is our memory (guest VA == host VA) and its registers are the
    frame we are holding: `PEEK`/`POKE`/`GETREGSET`/`SETREGSET`/`CONT`/
    `SYSCALL`/`DETACH` are mailbox messages it services while stopped. The
    AArch64 sigcontext's `regs/sp/pc/pstate` tail *is* a `struct user_pt_regs`,
    so the tracer reads and writes the real thing.
  - **Stops:** syscall entry/exit (with the tracer able to rewrite arguments,
    redirect the call via `NT_ARM_SYSTEM_CALL`, or cancel it outright — proot's
    whole method), signal-delivery and fault stops, `PTRACE_EVENT_`
    `FORK`/`VFORK`/`CLONE`/`VFORK_DONE`/`EXEC`/`EXIT`/`STOP`, group-stops,
    the initial attach stop, and synthetic exits for a tracee the tracer cannot
    host-reap. `PTRACE_ATTACH`/`SEIZE`/`INTERRUPT`/`LISTEN` reach a *running*
    task through a reserved kick signal (SIGRTMAX where it can be queued; probed
    downwards, because qemu-user refuses the top of the range).
  - **Seeing every syscall** needs more than the base filter's path set, so a
    task that becomes a tracee stacks a filter that traps everything
    (`cng_install_seccomp_traceall`), and a task that becomes a tracer stacks a
    narrow one over `wait4`/`waitid`/`kill`/`process_vm_*`. Both are installed
    on demand, so a guest that never traces — every guest — pays nothing, and in
    particular keeps a native, interruptible `wait4`.
  - **Signals are mediated while traced** (`src/monitor/ptsig.c`): our handler is
    installed for every catchable signal, mirroring the flags and mask the guest
    asked for (so `SA_RESTART`, `SA_ONSTACK` and the blocked set behave as it
    expects), the stop is reported, and only then is the signal handed to the
    guest's own disposition — its handler, or the default action emulated in
    place, including dying with the right `WIFSIGNALED` status. This is what
    makes gdb work: a breakpoint is a `brk` poked into read-only text (we
    mprotect, write, flush the icache and put the mapping back), and it arrives
    as a `SIGTRAP` stop.
  - **The regsets gdb needs, not just the ones we needed.** `GETREGSET`
    answers `NT_PRSTATUS`, `NT_PRFPREG` (from the signal frame's FP record, so
    `sigreturn` writes back what a tracer sets), `NT_ARM_TLS` and
    `NT_ARM_SYSTEM_CALL`. gdb also asks for `NT_ARM_PAC_MASK` whenever
    `AT_HWCAP` advertises pointer authentication — which we forward from the
    host verbatim — and treats a failure as fatal ("unable to fetch pauth
    registers"), which is what an on-device session first hit. The kernel's
    answer is `GENMASK(54, vabits_actual)` and nothing exports the VA size, so
    ours is *measured*: sign one pointer under 96 modifiers and OR the
    differences, since every bit of the PAC field flips in about half of them
    and every bit outside it never moves (bits above 54 are then dropped, as the
    kernel's mask never includes the top byte). `NT_ARM_TAGGED_ADDR_CTRL` — the
    same fatal ask on an MTE device — is answered from the task's own
    `prctl(PR_GET_TAGGED_ADDR_CTRL)`, and settable the same way. Everything else
    stays `-EINVAL`, which is what the kernel says for a regset the machine does
    not have and what gdb expects for the ones it merely probes (`NT_ARM_SVE`,
    `NT_ARM_HW_BREAK`/`WATCH` — so hardware watchpoints are unavailable and
    software breakpoints carry debugging).
  - **`PTRACE_SINGLESTEP` in software** (`src/monitor/ptstep.c`), because
    hardware single-step is `PSTATE.SS` and only the kernel's own ptrace can arm
    it: decode the instruction at pc, evaluate the condition against the frame's
    NZCV and register-form branches against its registers, plant a `brk` at the
    single resulting next PC, and report the `SIGTRAP` as a step. A step over a
    syscall reports once the syscall returns, where `TIF_SINGLESTEP` reports it.
    An instruction it cannot decode (a pointer-authenticated branch) reports the
    step in place rather than let a "stepping" tracee run away.
  - **`-R` tier parity:** `tramp.S` now builds a full `struct user_pt_regs` on
    its own stack and restores every register from it, including `sp` and `pc`,
    so a tracer's edits take effect on the rewriting tier too. That is also what
    makes any of this testable on a cross host, where no guest filter runs.
  - `--no-ptrace` refuses guest `ptrace` with `EPERM` and leaves the registry
    unmapped.
  - Fixed along the way: the SIGSYS tier's `clone` never published the child
    into the PID registry (only the `-R` tier did), so a forked guest process was
    invisible in `/proc` on the tier that runs on devices.
  - **Tests:** `tests/guests/pt_probe.c` is built twice — as the AArch64 guest
    and for the host — and 15 scenarios must print the same lines both ways, so
    the oracle is the real kernel's ptrace: stops and resumption, syscall stops,
    `GET_SYSCALL_INFO`, cancellation with a substituted return value, memory
    read/write, signal stops suppressed and delivered, the fork event with its
    auto-attached child, exec with and without `TRACEEXEC`, `TRACEEXIT`, a
    poked breakpoint, single-stepping, and attach/detach to a running process.
    One of them (`patharg`) pins the specific thing native host ptrace got
    wrong: the path a tracer reads is the guest's own string, asserted again
    with a real rootfs in the way. Plus the next-PC decoder in `-t ptracetest`
    (18 encodings) and both stacked filters simulated in `-t bpftest` — neither
    can be observed any other way on a cross host. Suite: 493 passed, 0 failed.
  - Accepted divergences (deliberate, documented):
    `rt_sigreturn` is never reported (it must execute with `sp` on the kernel's
    signal frame, so it cannot be re-issued from the handler); thread-creating
    `clone` is likewise left native, so `strace -f` follows forks but not new
    threads; a stacked filter cannot be removed, so a task keeps trapping after
    `PTRACE_DETACH` (a cost, not a correctness problem); a `SIGSTOP` sent to a
    tracee by a process that is neither its tracer nor traced itself is a real
    host stop, which freezes it inside its service loop; single-stepping is one
    thread at a time; an exit stop is only reported for a syscall whose entry
    stop was; and tracing spans one chroot-ng invocation's process tree, not
    independent invocations.

- [x] **M15b — the AF_UNIX array forms: `sendmmsg`/`recvmmsg`**
  M15 trapped the ten single-message socket calls and left the array forms
  native, which is the one hole it knowingly left open: `sendmmsg` and
  `recvmmsg` carry a `msg_name` **per message**, so a pathname `sun_path` sent
  through one went to the host untranslated and a source address returned by the
  other came back as a raw host path. The same escape as M15's, one loop further
  in. Closed here, with no new machinery — `cng_sun_in`/`cng_sun_out` per
  element, as the plan said it would take.
  - **`recvmmsg` needs no decomposition.** `msg_name` is an *output* buffer, so
    the batch is re-issued whole and only the messages the kernel actually
    filled — `[0, r)` — have their source addresses mapped back in place.
  - **`sendmmsg` is re-issued whole too, unless a message really carries an
    AF_UNIX address.** The call exists to spend one syscall on a batch, and
    taking a 1024-message UDP send apart into 1024 `sendmsg` calls to look for a
    `sun_path` that cannot be there would be a real regression. The socket is
    asked instead — one `getsockopt(SO_DOMAIN)` — and a batch on anything but an
    `AF_UNIX` socket goes straight to the kernel. On an `AF_UNIX` socket the
    array is scanned (free: a NULL `msg_name`, which is what a stream socket
    sends, is rejected without touching guest memory) and only a batch that
    really does carry an address is decomposed.
  - **The decomposition is the kernel's own loop**, so it answers the way the
    kernel does: send until one fails, write each `msg_len` back as it goes,
    report the count if any went out and the error only if none did — including
    not counting a message whose length writeback faults, even though it has
    already gone out. `vlen` is clamped to `UIO_MAXIOV` first, as the kernel
    clamps it. Each translated header is a copy; the guest's array is never
    rewritten.
  - **An emulated netlink socket** (M16) had to be taken apart per message on
    the receive side, and this is the part that was silently broken before rather
    than merely uncontained: the stand-in is an `AF_UNIX` socketpair, so a native
    `recvmmsg` filled each `msg_name` with an unnamed `AF_UNIX` address — and a
    netlink client discards any reply whose source is not `nl_pid == 0`. The
    per-message path fills a `sockaddr_nl` from `cng_nl_srcaddr`, drains pending
    requests first, and implements `MSG_WAITFORONE` itself (without it a batch
    larger than the pending replies blocks on a socket nothing else will feed).
    The send side needs nothing: a native `sendmmsg` puts the request datagrams
    into the pair, which is the same route an untrapped `write(2)` takes.
  - **Fault safety** (the M17-7 property) came with it. `cng_sun_in` copies
    `sun_path` before any kernel call would have validated the pointer, and it
    was doing so unprobed — so `bind(fd, (void *)0x10, 110)` was a SIGSEGV inside
    the handler, where SIGSEGV is masked and therefore fatal, rather than the
    `EFAULT` the kernel answers. One `cng_user_readable` in `cng_sun_in` fixes
    that for every caller (`bind`/`connect`/`sendto`/`sendmsg` as well as the new
    array forms); an unreadable address is passed through untouched so the kernel
    faults on the guest's own pointer. The array walk is probed the same way —
    once for the whole vector where it is all readable, per element otherwise,
    since the kernel stops at the first unreadable element rather than refusing
    the batch. Also fixed: `sendmsg` with a NULL `msghdr` ran `cng_sun_done` on
    an uninitialized `cng_sun_xlate`, which could close an arbitrary fd.
  - Two more filter entries (130 → 132 instructions of 256) and two more
    entries in the Android block-probe, since both are re-issued.
  - **Tests:** `tests/guests/uxmmsg.c` binds a datagram socket at a guest path,
    sends a batch to it with `sendmmsg` from a second named socket, and reads it
    back with `recvmmsg` — asserting the source of the **last** message as well
    as the first, because the containment is per element and a loop that only
    looked at the first would leak every message after it. The host `/run` is
    unwritable, so the batch arrives at all only if every address was translated;
    5 of the 9 legs fail against the pre-change binary. The abstract-name leg
    proves the per-rootfs tag is stripped per message too, and two legs pin the
    other half of the bargain — a socketpair batch and a loopback UDP batch,
    neither of which has an address to contain, must come back exactly as they
    would unemulated. `netif.c` gained a `recvmmsg` dump leg, so the emulated
    netlink source address is covered by M16's byte-for-byte differential
    against the real kernel (it reads `src_nl=0` without the fix). `-t faulttest`
    gained the bad-sockaddr case, which segfaults the run without the probe.

- [x] **M20 — POSIX message queues: the last host IPC namespace the guest could
  reach**
  The sweep that closed the System V sem/msg leak stopped one namespace short.
  `mq_open`/`mq_unlink`/`mq_timedsend`/`mq_timedreceive`/`mq_notify`/
  `mq_getsetattr` were in no trapped and no refused list, so they ran natively
  and a guest `mq_open("/x")` created its queue in the **host's** POSIX mqueue
  namespace — visible to every process on the machine, listed by
  `ls /dev/mqueue`, and charged against the host's `RLIMIT_MSGQUEUE`.
  - **Nothing here can be translated.** An mq name is not a filesystem path: it
    names an entry in the per-IPC-namespace mqueue mount, which an unprivileged
    process cannot be given one of. So the path traps have nothing to rewrite and
    the rootfs prefix nothing to scope — the same shape as abstract sockets,
    without the option of splicing a tag in (the guest would still share the
    host's queue limits and show up in its `/dev/mqueue`).
  - **Refused** with `SECCOMP_RET_ERRNO(ENOSYS)`, which is the oracle's answer
    (arm64chroot has no handler at all) and what the guest already sees on
    Android, where all six are off the app allow-list. The four
    descriptor-taking calls are refused with the two name-taking ones: with no
    queue there is nothing to send on, and a bare `mq_getsetattr` on some other
    fd must not half-work. `cng_denied_syscall` covers the `-R` trampoline tier,
    which has no filter.
  - Tests: three `-t bpftest` cases and one `-t dtest denied` case, mirroring how
    the sem/msg refusal was pinned before it became an emulation.

- [x] **M21 — AF_UNIX readback into a buffer too small for the address**
  Every readback call reports the address's **untruncated** length while copying
  only as much as the caller's buffer holds (`move_addr_to_user`, and 1003.1g:
  "fromlen shall refer to the value before truncation"). M15 read that length
  back *after* the syscall and translated the address in the guest's own buffer,
  so a guest with a short buffer left the emulation a truncated **host** path
  plus a length describing bytes that were never written. Three consequences,
  all real:
  - `cng_sun_out` walked up to 108 bytes past the guest's buffer. A fault there
    is not an `-EFAULT` — the SIGSYS handler runs with SIGSEGV masked, so it is
    the death of the process, reachable from a guest that merely passed
    `sizeof(struct sockaddr)` to `accept`.
  - The shortened guest path was written back at the buffer's start regardless of
    its size, so it could overflow a buffer the kernel had only partly filled.
  - The length handed back was the **host** one, which both breaks the caller's
    arithmetic and tells it how long the rootfs prefix is.
  - **Fixed by bouncing the address**, which is what the oracle does and what
    removes the reconstruction problem entirely: the kernel writes into a
    128-byte buffer of ours (`sockaddr_storage` is its own upper bound), the
    translation runs on a whole address, and `addr_out` reproduces the kernel's
    truncation rule over the *guest-view* result. `accept`/`accept4` close the
    new descriptor if that writeback fails, as the kernel does. `recvmsg` bounces
    `msg_name` inside a copied header and carries `msg_controllen`/`msg_flags`
    back to the guest's own — without which a caller loses `MSG_TRUNC`/
    `MSG_CTRUNC` and the length of the control data it is about to walk.
    `recvmmsg` takes an **AF_UNIX** batch apart into per-message `recvmsg` calls
    to do the same (one `getsockopt(SO_DOMAIN)` keeps every other family on the
    whole-batch path, as `sendmmsg` already did).
  - **A trap worth naming:** `cng_user_writable()` validates a range by *zeroing*
    it (uaccess.c). The first cut of this probed the address-length pointer
    before reading it and got 0 back, and probed the guest's `msghdr` before
    copying it and sent the kernel a zeroed one. Anything that must be read out
    of a range now happens before the range is probed for writing.
  - The empty abstract name (`addrlen == offsetof(sun_path) + 1`) was passing
    through untagged, so a guest could meet the host on it. It is a name two
    processes can rendezvous on like any other and is now tagged; only a genuinely
    unnamed (autobind) address, whose `addrlen` stops at `sun_family`, is left
    alone.
  - **Tests** (`tests/guests/uxtrunc.c`): the address buffer sits at the end of a
    page whose successor is `PROT_NONE` and the bytes in front of it are poisoned,
    so an overread dies and an overwrite shows. The pre-fix binary segfaults
    before printing a line. With an abstract name the guest-visible address is
    the same string with and without a rootfs, so that leg is a byte-for-byte
    differential against the real kernel; the pathname leg asserts the guest-view
    length and that the four bytes which fit are `/run`, not the rootfs prefix.

- [x] **M22 — System V semaphores and message queues, broker-backed**
  The richer answer M12's follow-up note asked for, replacing the ENOSYS refusal:
  `semget`/`semop`/`semtimedop`/`semctl` and `msgget`/`msgsnd`/`msgrcv`/`msgctl`
  are emulated from the same per-namespace daemon shm uses. Ported from
  arm64chroot's `sys_ipc.c` and the sem/msg half of its `proctab.c`. This is also
  the only way the guest has them at all on Android, where the whole SysV family
  is off the app seccomp allow-list.
  - **All state lives in the daemon** (`src/monitor/ipcreg.c`), unlike shm, whose
    payload is a memfd the guest maps. Every operation is an RPC, so mutation is
    single-threaded and needs no locking, a multi-operation `semop` is atomic for
    free, and a guest that dies mid-call cannot leave the registry torn. The
    daemon is freestanding like everything else here, so the variable-sized
    allocations — a value vector per set, an adjustment vector per undo row, a
    block per queued message — come from a small boundary-tagged arena rather
    than the `malloc` the original could lean on.
  - **Blocking operations park.** The connection stays open in a waiter slot and
    the poll loop watches it alongside the listener, so one sleeper does not wedge
    the daemon for everyone else. Parked operations are retried in arrival order
    after every state change, repeating until a pass makes no progress — which is
    also what reproduces the kernel's pipelined `msgsnd` → parked-receiver handoff,
    as an enqueue and a dequeue inside one pass. A `semtimedop` deadline bounds the
    poll directly, so it expires on time rather than at tick granularity.
  - **Interruption is the part chroot-ng has to work hardest for.** The client half
    runs inside the SIGSYS handler, which masks every signal but SIGSYS — so a
    sleeping `semop` is never woken by a signal *arriving*. The wait polls in
    100 ms slices and asks whether a signal the guest would take delivery of has
    become pending, judged against the mask the signal frame will restore and
    against the disposition (a signal the guest ignores would not have interrupted
    a real `semop` either, and neither would one that is only pending because
    *we* blocked it and whose default action is to discard it). On interruption a
    cancel goes down the same connection and the next message is definitive — the
    daemon's grant if it won the race, else the cancel-ack. The ordered stream is
    what makes that exact: a granted operation is never reported as EINTR, and a
    cancelled one was never applied. On the `-R` trampoline tier, which runs with
    the guest's own mask, the delivery itself is the interruption and `ppoll`'s
    EINTR is taken as one directly.
  - **SEM_UNDO with no exit hook anywhere.** chroot-ng traps neither `exit` nor
    `exit_group` (a `SIGKILL` could never be trapped either), so a dead process's
    adjustments are applied from its pid incarnation — and applied *when the set
    is next touched*, not on a timer, because the observation that catches a lazy
    implementation is exactly `waitpid(child); semctl(GETVAL)`. The same principle
    settles shm's `nattch`, including the zombie test: a process that has exited
    but not been reaped still owns its pid, yet the kernel has already run its
    exit.
  - **Protocol.** `struct cng_breq`/`cng_bresp` grew the fields the three object
    types share and eight new operations; the payloads that cannot fit a
    fixed-size request (an operation vector, a message's bytes, a `GETALL`/
    `SETALL` array) stream behind it on the same connection. The rendezvous tag
    went `cng-ipc.v1` → `v2`, so a differently versioned build never joins an
    incompatible daemon. `semctl`'s vector is the one unbounded array, and it is
    streamed through a 1024-value window rather than sized by `SEMMSL` — the
    handler's scratch stack has no room for 32000 of them.
  - **Namespace scope** is shm's: per invocation by default, widened to
    per-rootfs by `--shared-proc`.
  - **Tested two ways, for two reasons.** `-t ipctest` drives the dispatcher
    directly in thirteen groups — including a real fork, a blocking wake, and
    SEM_UNDO across a child's death — so it runs on a host with no working SysV
    IPC of its own, which is exactly the target platform. The guest programs
    (`tests/guests/sem_sysv.c`, `sem_block.c`, `sem_undo.c`) run once under the
    emulation and once straight under qemu, and must agree byte for byte; unlike
    the shm differential, which leans on qemu's own `shmat`, nothing is emulated
    on the reference side here — every call is forwarded to the host kernel, so
    the comparison is against the genuine article. Between them they pin the
    atomic rollback, the whole `msgrcv` selection rule, `MSG_EXCEPT`,
    `E2BIG`/`MSG_NOERROR`, the keyed-lookup and error orders, every way a sleeper
    can end (grant, wait-for-zero, timeout, EINTR, EIDRM, an *ignored* signal
    that must **not** interrupt), and SEM_UNDO through both an ordinary exit and
    a SIGKILL. `sem_key.c` pins the namespace scope, which is the one part with
    no oracle — the host has exactly one IPC namespace — and the suite also
    asserts the point of the whole exercise: the guest's keyed objects never
    appear in the host's `ipcs`.
  - Filter is 138 of 256 instructions (158 once M23's mmap band lands).

- [x] **M23 — the mmap hook: a library mapping a noexec mount will not grant**
  The loader defeats `noexec` for everything *it* loads, by reading the image
  with `pread` and mapping it anonymously. A dynamic guest's libraries are not
  in that set: they are mapped by the guest's OWN `ld.so`, which asks for
  `PROT_EXEC` straight from the file, and on a true `MNT_NOEXEC` mount the
  kernel refuses. Every dynamically linked guest died in its interpreter, and
  there was no second place to fix it — the mapping request is where the
  failure is visible. (`docs/DESIGN.md` has described this hook since M4; it
  was the last piece of the design that had no code.)
  - `execmap.c`: on `EPERM`/`EACCES`, map the range anonymously RW, `pread` the
    file's bytes into it, and `mprotect` to what the guest asked for. Only
    `MAP_PRIVATE` (a copy cannot carry `MAP_SHARED`'s visibility) and only after
    the kernel has actually refused, so an exec-permitted mount keeps its real
    file mapping, its page-cache sharing and its `/proc/self/maps` identity.
    Past end-of-file the copy reads as zeroes where the real thing would
    `SIGBUS` — the same forgiving edge the loader's own anon strategy has.
  - The filter tests the arguments, not the syscall: `PROT_EXEC` set and
    `MAP_ANONYMOUS` clear. Every anonymous allocation a guest makes — nearly all
    of them — stays untrapped; a handful of mappings per `dlopen` do not.
  - **-R now reaches library code**, which it never could before: the copy is
    still writable when it arrives, so the `svc` sites go through the M8
    rewriter on the way. Only the PF_X `PT_LOAD`s are scanned (read from the
    file, since the mapping may start past the headers), and since M33 only the
    parts of them the section headers call code — a library's `.rodata` and its
    unwind tables live inside that segment and do contain words equal to `svc
    #0`. The trampoline pool cannot be
    over-allocated here the way the loader does it, because the span belongs to
    the guest's linker, so it goes immediately outside the object's own load
    span (`MAP_FIXED_NOREPLACE`, both sides tried), and failing that wherever
    the kernel puts one; a pool nothing could reach is handed straight back.
  - Validated by `tests/m23_execmap.sh`: the BPF band (four shapes of `mmap`,
    through the interpreter), and a deliberately **dynamic** guest run with
    `CNG_MMAP_FORCE_ANON=1` — it starts with every library served from a copy,
    and its own libc `openat` lands in the rootfs. That last one is the case
    `guest_xlate_ready` used to skip as unreachable ("seccomp inert here and the
    guest links dynamically, so neither tier reaches libc's svc sites"). The
    control is the same run unforced, which on a cross host is not translated.
  - `CNG_MMAP_FORCE_ANON=1` takes the anonymous route without asking the kernel
    first, since no dev host has a true noexec mount to offer. Same testing
    convention as `CNG_SHM_FORCE_FILE` / `CNG_PROCREG_NONE`.
  - Filter is 158 of 256 instructions.

- [x] **M24 — `openat2`'s `open_how.resolve` describes OUR resolution**
  `openat2` was translated like `openat` and re-issued with the guest's own
  `open_how` — carrying a `resolve` word that constrains the very walk the
  translation had just performed, and that the kernel then re-applied to an
  absolute host path the guest never wrote. Every bit of it landed in the wrong
  namespace:
  - `RESOLVE_BENEATH` rejects an absolute pathname (`EXDEV`), and the
    translated one always is — so a relative name that must open was `EXDEV`,
    every time;
  - `RESOLVE_IN_ROOT` re-roots an absolute pathname at `dirfd`, so the host path
    was re-rooted at the guest's directory and named a file nobody asked for;
  - `RESOLVE_NO_SYMLINKS` was simply violated: the resolver had already followed
    the links the guest asked it not to, and handed the kernel the target;
  - `RESOLVE_NO_XDEV` was judged against the *host* mount list, where the
    rootfs prefix is a crossing the guest cannot see.

  Two answers, split by what the constraint is relative to:
  - **`BENEATH` / `IN_ROOT` scope the resolution to `dirfd`**, which the guest
    can only hold because we handed it over — so it already names a directory
    inside the view, and the kernel's own scoping contains the call at least as
    tightly as the rootfs does. The call goes over untranslated and is answered
    exactly, absolute symlinks and escaping `..` included. Two policies that
    were keyed on a path get re-expressed against the directory, which is sound
    because the answer must lie under it: a `:ro` bind covering the dirfd covers
    everything the open can reach (the ENOENT-vs-EROFS half is asked with the
    guest's own scoping, so it describes the same file), and a dirfd already
    inside `/proc` is the only way to reach a hidden pid, so that case asks the
    descriptor afterwards where it landed.
  - **The rest constrain the walk itself**, so they are answered during it —
    `cng_resolve_lim`, the same function every translation goes through — and
    then stripped from the copy of `open_how` that is re-issued. `NO_SYMLINKS`
    and `NO_MAGICLINKS` are `ELOOP` on the guest's own links (a `/proc` magic
    link counts, and `NO_SYMLINKS` implies `NO_MAGICLINKS`); `NO_XDEV` is
    `EXDEV` on leaving the guest mount the walk started in — the rootfs, a bind,
    the `/proc` or `/dev` zone, which is the same table the synthesized
    `/proc/self/mounts` is built from. The re-issue never writes to the guest's
    struct: it gets our copy.
  - `build_open_flags()` runs before any resolution, so a `how` the kernel
    refuses is `EINVAL` whatever the path says — ahead of any constraint we
    would answer ourselves. Asked of the kernel directly, with a name that
    resolves to nothing. The `size` rules are the kernel's own too: below the
    struct is `EINVAL`, above it a non-zero tail is `E2BIG`, and a zero tail
    makes the call identical to a sized one (which is what makes it safe to
    re-issue as one).
  - Validated by `tests/m24_openat2.sh`. `-t o2test` drives everything decided
    before the re-issue, which is where all the new judgement is, and so runs on
    every host — no qemu-user build implements `openat2`, and a cross host
    cannot reach the syscall at all. On a host that has it, the differential
    runs `tests/guests/openat2.c` twice, once with no emulation, and demands the
    host kernel's answers for all 21 cases byte for byte.

- [x] **M25 — the three objects chroot-ng leaves where everyone can reach them**
  `cng_broker_shared_dir()` is `/dev/shm`, `$XDG_RUNTIME_DIR`, `$TMPDIR`,
  `/data/local/tmp` or `/tmp` — on a normal machine, a directory every user may
  create names in. Two files and one socket lived there under names anybody
  could work out, and none of them checked who it was talking to.
  - **The System V shm backing file** (the fallback where `memfd_create` is
    unavailable) was `chroot-ng-shm.v1.<uid>.<shmid>`, opened
    `O_CREAT|O_TRUNC` with neither `O_EXCL` nor `O_NOFOLLOW`. A symlink left on
    that name had the `O_TRUNC` destroy whatever it pointed at; a file left on it
    was read back by its owner with the guest's shared memory in it. Nothing
    outside the daemon ever needs to find it — attachers are handed the
    descriptor over `SCM_RIGHTS`, and the path is kept only to unlink again — so
    the name now carries nothing but 64 random bits and the creation is
    `O_EXCL|O_NOFOLLOW`, which makes taking the name the whole test.
  - **The process registry's named-file tier** cannot do that: its name *is* how
    separate `--shared-proc` invocations find each other. So it proves the file
    is its own after opening it — `O_NOFOLLOW`, then a regular file, owned by us,
    with no group or other permission — and declines anything else rather than
    `ftruncate`ing it and mapping it shared. Declining costs a shared namespace
    (it degrades to the per-process anonymous table); adopting cost the guest's
    pid table, cwd and exe path, which `/proc` then answers from.
  - **The broker rendezvous is an abstract socket**, so it has no inode and no
    directory permission stands between the name and anyone else on the machine
    — and the `--shared-proc` name is a plain hash of the rootfs path, which
    anybody can compute. Both ends now ask `SO_PEERCRED`, which reports
    credentials the peer had at `connect()` and cannot forge: a daemon refuses a
    client that is not us, and a client refuses to join a daemon that is not
    ours (and does not retry or spawn — the name is held, so `--shared-proc`
    degrades to the file tier instead). The identity is the uid the socket name
    is keyed on, so the two always agree.
  - Validated by `-t sharedtest` (a symlink and a world-readable file planted on
    the registry's exact name, each declined with the planted file left intact,
    against a control that shows the tier does engage) and a `shmtest` leg that
    weighs every backing file in the shared directory against the shape it must
    now have — asserted in both directions, since the memfd tier must leave no
    file at all. `CNG_PROCREG_FORCE_FILE=1` reaches the registry's file tier,
    which is otherwise only used on a host without `memfd_create`.
  - Not covered by the suite: the peer-credential *refusal*, which needs a
    second uid to produce. What the suite does hold is the other direction —
    every broker-backed leg in M11/M12/M20/M22 goes through the check.
  - Which *rootfs* a same-uid client is from was not asked until M55: the
    daemon now compares the client's full path (the hello) rather than
    trusting that two rootfs never hash alike.

- [x] **M26 — the span that could not carry its own trampoline pool**
  `elf_read_headers` checks each `PT_LOAD` for a `p_vaddr + size` that wraps,
  but not the aggregate: what `map_anon` reserves is `hi - lo` **plus**
  `CNG_TRAMP_POOL` under `-R`, and that sum is a mapping length. Two segments —
  one at vaddr 0, one at `0xFFFFFFFFFFF80000`, each perfectly well formed on its
  own — make a span within a pool's distance of the top of the address space, so
  the addition wraps: the `mmap` then succeeds at a few pages while `read_exact`
  preads at `bias + p_vaddr` and `cng_rewrite_seg` writes trampolines at
  `seg + span`, both far outside the mapping. Measured: without the check the
  load returns `CNG_LOAD_OK`.
  Refused in the header pass, which maps nothing, and against the pool
  unconditionally — whether `-R` is running is not a property of the header, and
  a span nothing can map describes nothing either way. Gated by an `-t elfspan`
  leg that builds exactly that object and asserts the refusal with `-R` off and
  on alike (with it on there would be nothing left to report the failure with).

- [x] **M27 — a `PT_INTERP` too long to hold was dropped, and the object called
  static**
  `elf_read_headers` took the interpreter path only when `p_filesz` fit
  `out->interp` and the pread came back whole. Everything else — a path past 255
  characters, a `p_filesz` of 0 or 1, a file too short to hold the bytes the
  header points at — left `has_interp` at 0 and returned `CNG_LOAD_OK`, so the
  caller loaded a dynamic object as if it were static and entered it at its own
  `e_entry`: the `_start` `ld.so` was supposed to have relocated, which dies on
  the first GOT reference with no errno anywhere. The header file already
  documented `CNG_LOAD_ETOOBIG` as "too many phdrs / interp too long"; nothing
  ever returned it for the second half.
  Refused now where `fs/binfmt_elf.c` refuses: `p_filesz` under 2 or past what
  the buffer holds is `ENOEXEC` (`ELIBBAD` in the interpreter role), a string
  whose last byte is not a NUL is `ENOEXEC`, and a short read is `EIO` — that one
  through a code of its own (`CNG_LOAD_EINTERP`), because the kernel reads this
  string with `elf_read()` rather than out of the 256-byte header buffer, so it
  is `EIO` for the program role too. The 256-byte bound stays and is a refusal
  rather than a silent reclassification (the same bound `SHEB_WORD` puts on a
  `#!` word; glibc's and musl's loaders carry no `PT_INTERP` of their own, so the
  interpreter role loses nothing by being judged the same way). Gated by
  `-t elfinterp`, which builds five headers no toolchain emits and judges them in
  the pass that maps nothing.

- [x] **M28 — the arguments were validated in one pass and read again in the
  next**
  `exec_args_take` measures `argv`/`envp` with the probes and `copy_vec` then
  walked the same guest memory a second time with a bare `strlen`/`memcpy` — one
  pass asking the kernel whether the bytes are there, the next assuming the
  answer still holds. It does not have to: `execve` is called by one thread while
  the rest of the process keeps running, so a thread that unmaps the strings
  between the passes turns the `-EFAULT` `execve(2)` promises into a `SIGSEGV`
  inside the `SIGSYS` handler, where every signal but `SIGSYS` is masked and the
  fault is unblockable. The vector itself was walked a slot at a time with the
  same exposure.
  Two primitives in `uaccess.c` close it. `cng_user_copyin` takes a range through
  `process_vm_readv`, where the kernel does the copy and reports the fault
  instead of raising it — check and copy in one act, no gap to race (the memfd
  fallback has no such form, since staging through the descriptor would need a
  landing area private to the call, so there it stays probe-then-copy as before).
  `cng_user_strcopyin` measures and takes a string together, searching for the
  terminator in *our* copy: a `strlen` that finds the NUL and a `memcpy` that
  trusts it are two readings of a string that can change in between.
  `copy_vec` now takes the whole pointer array in one act, into the very slots
  the strings' own pointers replace as it goes, and holds the entry count to the
  sizing pass's — which is how `fs/exec.c` holds it too (`count()` fixes
  `bprm->argc`, `copy_strings()` copies exactly that many). A race answers
  `-E2BIG` or `-EFAULT` now, which is what `execve(2)` answers for those inputs.
  Gated by a `faulttest` leg driving both primitives against two pages with the
  second unmapped, on the `process_vm` and memfd tiers alike.

- [x] **M29 — the `/proc` self-snapshot walked a stack the guest owns**
  When the registry cannot answer (never mapped, or its table full),
  `/proc/self/{cmdline,environ,auxv}` are answered from the live guest stack —
  we are the process being described, so no shared table is needed. But that
  stack is the guest's: `argc`, both vectors and every string they name are the
  program's to rewrite (`setproctitle` does exactly that), and it is read long
  after it was built. The walk was raw — a dereference of `*(long *)sp`, an
  unbounded `while (*p) p++` over the environment and another over the auxv pairs
  — so a stack that had been rewritten to run off the end of its mapping faulted
  inside the `SIGSYS` handler, where `SIGSEGV` is masked and the process dies
  instead of answering a file it opened on itself.
  Every step goes through the probes now: `argc` is copied in, the environment is
  counted with `cng_user_veclen`, the auxv is copied pair by pair to its
  `AT_NULL` and dropped whole if it runs past what an entry holds (half a vector
  is not one), and `flatten_vec` takes each slot and each string with the
  copy-in pair rather than a `strlen`/`memcpy` over memory that can change
  between the two. What will not come across ends the vector where it stands, and
  only an unreadable `argc` — with which nothing below can be located — declines
  the snapshot: everything else is answered from what the stack does hold, since
  declining hands the question to the host file, which for a guest process is the
  chroot-ng invocation and the reason any of this exists.
  `cng_procfs_publish_stack` keeps its raw
  walk: it runs in the one moment the stack is certainly ours, on the vector we
  have just built and no guest instruction has yet touched, and the registry
  publish it feeds is deliberately syscall-free inside its seqlock window.
  Gated by three `selfproc` legs that publish a well-formed stack at the edge of
  a mapping and then rewrite it the three ways that used to walk off the end.

- [x] **M30 — the mount table named the directory each bind came from**
  `/proc/mounts`, `/proc/self/mountinfo` and `/proc/self/mountstats` are
  synthesized from the rootfs and the `-b` binds, and every bind row put
  `cng_g_fs->binds[i].host` in the source field: the host directory the bind was
  taken from, spelled out in the three files `df`, `mount`, `findmnt` and every
  container runtime read — inside a view whose whole purpose is that the guest
  cannot name a host path. It is the same leak already closed in `maps`, the fd
  links, `/proc/self/exe` and the AF_UNIX readback, left open in the one place
  that describes the mounts themselves.
  It was not the faithful rendering either: a real table names a **device** in
  that field — `/proc/mounts` has nothing else, and mountinfo puts the source
  filesystem in field 10 with the bound subtree in field 4, which for us is
  already `/`. Every row now says `/dev/root`, the name the rootfs row has always
  carried and the only device name the guest is ever shown; several mounts off
  one device name is a shape real tables have. The per-bind major:minor stays
  real, so anything cross-referencing `stat().st_dev` — which is what actually
  identifies a filesystem — still finds its row.

- [x] **M31 — a relative name appended to a cwd with no room left for it**
  `cng_fs_abscanon` joins `fs->cwd` and a relative path with `cng_strlcpy` and
  ignored what it reported, and `cng_strlcpy` truncates. A cwd within a
  component's length of `CNG_PATH_MAX` had the name appended to a buffer with no
  room for it, and what came back was **the cwd itself**: under an identity root
  a 4094-byte cwd made `open("x")` name the directory the guest was standing in.
  It is guest-reachable through the ordinary syscall path — `xlate_lim` falls
  back to `cng_fs_translate` on the raw guest name when `cng_resolve_lim`
  declines, and that is the join — so an `unlink` or an `O_CREAT` acted on the
  cwd instead of answering `ENAMETOOLONG`. Exactly the failure the comment in
  `cng_fs_translate_mnt` already forbids one join later, where a rootfs prefix
  that does not fit is a refusal rather than a shorter name.
  Both joins are checked now, absolute names included, and return -1 — which
  every caller already turns into the `-ENAMETOOLONG` a kernel whose `PATH_MAX`
  the name exceeded would have given. Pinned on both sides of the boundary: 4093
  bytes of cwd still has room for `/x`, 4094 does not.

- [x] **M32 — an exec chain kept every program it had already replaced**
  A real `execve` throws the whole mm away. The emulated one cannot — the
  monitor's code, its gate and its state are pages of the same address space —
  so the previous program's mappings were simply left behind: measured, a static
  guest exec'ing itself, **66.8 MB of address space per generation**, 64 MiB of
  it the stack the loader builds. A wrapper-script chain paid it per level.
  What is given back is exactly what the loader itself mapped for the program
  being replaced — its image, its interpreter's image (each one reservation with
  a recorded extent, so nothing is inferred from `/proc/self/maps`) and its
  stack. What was *not*, until M35, is what the previous program mapped for
  itself: the libraries its `ld.so` loaded, its arenas, its allocator's
  reservations. Following those was taken to mean a VMA table of our own
  maintained on every `mmap`/`munmap`/`mremap`, which is the per-syscall cost the
  `-R` tier exists to avoid; the brk heap, the one such region with a handle on
  it, was already wound back.
  Two conditions hold it up. The process must be single-threaded — a real execve
  kills the other threads, and since the de_thread emulation so does ours; the
  check is that it succeeded, since a thread it could not reach would go on
  running the old code on the old stacks. And the outgoing stack cannot be
  freed at the exec itself, because
  the SIGSYS tier returns into the new program through a signal frame that lives
  on it: a generation is retired and handed back at the new program's first
  dispatched syscall. An ET_EXEC image lands at its link-time vaddr, so a range
  the incoming program already occupies is dropped rather than unmapped.
  Measured after: 516 kB over eight execs, against the kernel's own 0 — for a
  guest whose libc reserves nothing of its own. M35 is the other half.

- [x] **M33 — the rewriter scanned data and called it code**
  The M8 scan matched a bare `0xD4000001` word anywhere in a `PF_X PT_LOAD`,
  on the reasoning that an executable segment holds instructions. It does not:
  a musl/Alpine link puts the whole read-only image — `.rela.dyn`, `.dynstr`,
  `.rodata`, `.eh_frame`, `.gcc_except_table` — in the one R+E segment, and
  even a `-z separate-code` link leaves `.rodata` and the unwind tables in
  there. Measured over 1717 aarch64 objects (an Alpine 3.x rootfs, the Debian
  trixie aarch64 rootfs, the Debian cross libraries): **58% of the bytes the
  scan walked were not instructions**, and ten data words in those stock images
  equal `svc #0` exactly.
  Every one of the ten is in `.gcc_except_table`, and not by chance: an LSDA
  call-site record with no landing pad and no action emits `01 00 00`, and the
  next entry's first byte lands on the `d4` — a rate some 10^5 times what a
  uniformly random word would give. They are in `libstdc++` (both
  distributions), `libapt-pkg`, `libicuuc`, `sqv`, `libgo` and `libgphobos`.
  In Debian's `libstdc++.so.6.0.33` and `libapt-pkg.so.7.0.0` that word is the
  **only** match in the entire executable segment — neither library contains an
  `svc` of its own — so under `-R` every site rewritten in them was a data
  word. What follows is a corrupted LSDA: the C++ personality routine reads it
  during an unwind and takes a wrong landing pad or none, and nothing between
  the store and `std::terminate` reports a thing. The failure is silent,
  deferred and workload-dependent, which is why nothing had caught it.
  The section headers separate the two exactly: all 1837 real `svc` words in
  that corpus are inside `SHF_EXECINSTR` sections and all ten data words are
  outside, and the headers survive `strip` — not one of the 1717 objects was
  without them (the 896 with no executable section at all are `.o` files, which
  nothing loads). So `cng_code_ranges` reads them from the fd the loader and
  the mmap hook already hold, merging contiguous ones (`.init`/`.plt`/`.text`/
  `.fini` become one range; three is the most a real object needs, against a
  table of 16), and `cng_rewrite_seg` scans the intersection of the mapping
  with that map. They are guest-controlled input, but a code map can only ever
  *narrow* what is scanned, so nonsense there costs rewriting and never
  correctness. The scan is also 2.4x cheaper for no longer walking the data.
  An object with no usable headers does not get the old behaviour back; it gets
  the old behaviour behind a syscall-context filter, which rewrites a candidate
  only if one of the eight instructions before it writes x8. On the same corpus
  97.1% of real sites set x8 that close (the rest keep the SIGSYS floor, which
  is correct and only slower), and not one of the ten data words has anything
  resembling it.
  What this does not reach is data *inside* a code section — a literal pool or
  a jump table. Measured with `$d`/`$x` mapping symbols on the objects that
  still carry a `.symtab`, that is 0.71% of code-section bytes, with no
  collision in 38 MB. Closing it exactly would mean patching lazily from the
  SIGSYS floor instead of ahead of time (`si_call_addr - 4` is a word the CPU
  really did execute), which is a different tier and would not serve the case
  `-R` also exists for: hosts where seccomp never traps at all.
  Validated by `-t rwtest`: the code map built from a synthetic section table
  (contiguous sections merged, allocated-but-not-executable and `SHT_NOBITS`
  ones skipped, an object with no section headers answering "no map"), and four
  scan decisions over 44 bytes taken verbatim from Debian's `libstdc++` at file
  offset `0x249b8c` — with the code map only the instruction is taken; with a
  map stretched to cover the data as well the LSDA word is taken too (the
  control, which reproduces the corruption on demand); with no map at all the
  filter keeps the real site and rejects the data word; and the data alone
  yields nothing.
  Measured end to end against the previous build, on an Alpine guest whose
  libraries all arrive through the mmap hook's anonymous copy
  (`CNG_MMAP_FORCE_ANON=1`, `/usr/bin/node`): before, `libstdc++.so.6.0.32` and
  `libicuuc.so.74.2` each had exactly one "site" rewritten, and in both it was
  the `.gcc_except_table` word; after, all fourteen libraries report none, and
  the real objects keep every site they had — a static-PIE glibc guest still
  rewrites its 101, and `ld-musl-aarch64.so.1` its 477 (478 candidates, less
  the sigreturn restorer the M8 guard already skipped). `CNG_DEBUG=1` now says
  both numbers per object: `rewrote N svc site(s), ranges=M`, where `ranges=0`
  is the headerless fallback. 813/813 tests.

- [x] **M34 — `-R`: the site the floor just trapped from, patched on the spot**
  The ahead-of-time pass has to decide what is code by reading bytes, which is
  why M33 had to give it the section headers and a filter behind them. A SIGSYS
  trap needs neither: `si_call_addr - 4` is a word the CPU fetched and executed
  as `svc #0`, so patching it cannot be wrong about what it is. `-R` now does
  both — the scan at load time, and this on the first trap from any site that
  scan could not reach.
  What it reaches is the coverage `-R` never had. On the target platform the
  guest's libraries are mapped **natively** (Termux app data forbids `execve`
  but permits file-backed `PROT_EXEC`), so the mmap hook hands back the kernel's
  own mapping and there is no copy for the rewriter to walk — measured on the
  device, `cat` under `-R` gets 222 sites rewritten ahead of time in the bionic
  linker and **not one** in libc, whose `svc` sites are in that natively mapped
  text. Those are the sites this tier takes: five for `cat`, ten for `ls -lR`.
  Also JIT'd code, and anything the scan left behind — a pool exhausted, a
  branch out of reach, an object whose headers named no code.
  Measured on the device (Android 13, 5.15), `ls -lR $PREFIX/lib` through a
  natively mapped bionic, five runs each: **2010/2028/2026/2033/2042 ms without
  the lazy tier against 1890/1881/1903/1855/1891 ms with it** — every run
  separated, ~7%, for ten sites patched once each.
  How it holds together:
  - A table of mappings, keyed by what `/proc/self/maps` says. That file is read
    **once per mapping** — never per site and never per trap — and answers three
    things at once: whether the word may be loaded at all (an execute-only
    mapping would fault on the load, in a handler that runs with SIGSEGV
    masked), whether the store lands in our copy or in a file on disk (a shared
    mapping is not ours to write), and what to put the page back to.
  - The same survey finds the nearest hole big enough for the pool, which is
    what makes the branch reach: the addresses either side of a loaded library
    are the ones its linker has already taken. A pool that cannot be reached
    from the whole mapping is refused outright — that is not a missed
    optimization but a trap-time cost, and it was measured as one: before the
    check, a pool the kernel placed outside ±128 MiB left every trapped syscall
    reading `/proc/self/maps` and the same `ls -lR` took **3.9 s**.
  - Anything that stops one site stops the mapping — no pool in reach, the pool
    full, a refused `mprotect` (the SELinux `execmod` denial a device may answer
    for file-backed text) — so the entry is kept with no pool and every later
    trap out of it is answered from the table without a syscall.
  - Nothing is ever made unexecutable. The pool is `r-x` from the start and a
    page of it gains `w` only while a trampoline is written; the site's own page
    gains `w` only while the branch is stored. A thread executing either page
    throughout neither faults nor has to be stopped — and `svc` to `b` is one of
    the substitutions the architecture explicitly permits while another PE is
    executing them (B, BL, BRK, HVC, ISB, NOP, SMC, SVC), so a racing thread
    sees the old word or the new one, and the old one simply traps again.
  - `rt_sigreturn` is never patched (the filter does not trap it; this is where
    that would stop being true), the table is taken with a try-lock so a nested
    trap can never meet it, and an emulated `execve` hands the pools back — the
    sites they branch from are gone, and an exec chain must not accumulate them
    the way M32 stopped it accumulating images.
  Two things it does not do. The protection to restore is remembered with the
  mapping rather than re-read, so a guest that changes its own text protections
  after a site there is patched gets back what the mapping had when we first saw
  it; re-reading would cost `/proc` per trap, which is the whole thing this tier
  avoids. And a guest that `MAP_FIXED`s over a pool unmaps the trampolines its
  own code branches into — the same exposure the M8 and M23 pools have always
  had, and the same answer: see the threat-model note in `docs/DESIGN.md`.
  Validated by `-t rwtest`, which calls the patcher with the address a SIGSYS
  would have handed it — a copy of the test function mapped `r-xp`, both of its
  sites patched through the maps lookup, the pool placement and the `mprotect`
  dance, then run, with the register sentinels intact and an already-patched
  site and a non-`svc` word both declined. That leaves three lines in the
  handler untested on a cross host, where no filter ever fires; the device
  covers those. 814/814 tests on the dev host, and on the device 777 passed with
  the same 11 pre-existing failures as the commit before it.

- [x] **M35 — an exec chain kept every allocator its programs had started**
  M32 gave back what the loader mapped and said the program's own mappings were
  not ours to follow. On Android they are most of the bill. Measured on the
  device, a **static bionic** guest exec'ing itself: **8,667,232 kB per
  generation**, almost all of it one
  `mmap(NULL, 8858370048, PROT_NONE, MAP_NORESERVE)` that scudo makes at libc
  init and that the next generation makes again; a **dynamic** one cost
  **10,790,480 kB**, its libraries on top. Sixty-four execs exhausted the address
  space outright — `Scudo ERROR: internal map failure (error desc=Out of memory)
  requesting 8650752KB`, SIGABRT, after 21 seconds spent mapping it. A musl guest
  hid the whole thing at 20 kB a generation, which is why the dev host never saw
  it and M32's leg passed there for four milestones.
  The fix does not build the per-`mmap` table M32 ruled out. It asks the question
  the other way round — not *what did our loader map*, which cannot see a guest's
  own `mmap`, but *what in this address space was never the guest's* — and gives
  back everything else. Two records answer it, in `src/monitor/ownmap.c`: a
  **floor**, every mapping that exists at the moment `cng_run` is about to load
  the first program (our image, our stack, the heap, the kernel's pseudo
  mappings), and a **registry** of the dozen long-lived regions the monitor maps
  after that — the broker tables, the pid and IPC registries, the ptrace link
  table, the argv snapshot an exec is standing on. The 256 scratch stacks are
  asked of `sigsys.c`, which already records their bounds.
  Where the floor stands is the whole of its accuracy: taken after the first
  program was loaded, it claimed that program's image and its 64 MiB stack, and
  once those were given back the kernel handed the same addresses to the next
  generation's allocator — which the sweep then read as ours and kept, at 16 MB
  a generation, with no way to say why. It goes in front of the load.
  The sweep runs inside M32's single-threaded gate, and at the point where the
  incoming image and stack are mapped but the new program has not executed an
  instruction — deferring it the way the reap is deferred would not do, since by
  the new program's first dispatched syscall its `ld.so` has mapped libraries and
  an anonymous `mmap` does not trap on the seccomp tier. `[heap]`, `[stack]`,
  `[vdso]`, `[vvar*]` and friends are kept; Android's `[anon:...]` names are not
  (`PR_SET_VMA` puts them on ordinary guest memory, which is the memory this is
  for). It is fail-closed: no floor, a lost record or an unreadable
  `/proc/self/maps` leaves the address space exactly as every build before it.
  One thing it must keep that is not ours: **the signal frame**. The SIGSYS tier
  returns into the new program through `rt_sigreturn`, and what that reads sits
  on the guest's alternate signal stack whenever the guest registered one —
  bionic registers one per thread, so the first version of this segfaulted an
  Android guest on its first exec. `cng_scr_hit` now keeps the mapping the live
  frame lies in; it is dead one generation later, so this costs one alternate
  stack rather than a chain of them.
  Measured after: **0 kB over 8 execs** for the static guest and 0 over 64
  (against 69,337,856 kB over 8 before), and for the dynamic one a chain of 64
  that finishes in 0.2 s where it used to abort after 21. Both are legs of
  `tests/m6_execve.sh`; the dynamic one asserts survival plus a bound rather than
  a kernel differential, because a dynamic bionic guest's `VmSize` swings ±80 MB
  between runs of the same binary and one leaked generation is three orders of
  magnitude above that. 814 passed and 0 failed on the dev host, where the
  dynamic leg needs a live filter and skips; 788/0 on the device.

- [x] **M36 — the guest's /dev/shm was a mount that was not there**
  POSIX shared memory has no syscall behind it. `shm_open()` is an `open()`
  under `/dev/shm` with the name checked, and `sem_open()` is the same — so a
  guest has POSIX shm exactly when it has a writable `/dev/shm`, and nothing
  else about it can be emulated. Android has no such directory at all, and no
  privilege we hold can mount one, so every `shm_open` in an Alpine or Debian
  rootfs came back ENOENT.
  Worse than absent, it was *advertised*. The synthesized mount tables
  (`/proc/mounts`, `/proc/self/mountinfo`, `/proc/self/mountstats`) emitted a
  `tmpfs /dev/shm` row whenever the `/dev` zone was on, unconditionally, so a
  program that checked before it acted — which is what a mount table is for —
  was told tmpfs and then refused. Measured on the device, before:
  `tmpfs /dev/shm tmpfs rw,nosuid,nodev,relatime 0 0`, then
  `sh: can't create /dev/shm/probe: nonexistent directory`.
  Where the host has a `/dev/shm` nothing changes: the whitelist passes it
  through, and a real one is a single tmpfs global to the machine, which is
  what the guest should see. Where it has none, the node is served from
  `$TMPDIR/chroot-ng-shm.v1.<uid>` — created on demand, then `$XDG_RUNTIME_DIR`,
  `/data/local/tmp` and `/tmp` behind it. One directory per uid rather than per
  rootfs, deliberately: a passthrough `/dev/shm` is already shared by everything
  on the machine, and scoping only the stand-in would make POSIX shm behave
  differently depending on a property of the host the guest cannot see.
  (`cng_broker_shared_dir()` is not reused for this — its list *starts* at
  `/dev/shm`, which is the one place this cannot use.)
  The mount row now follows the node: `cng_dev_shm_ok()` gates it, so a host
  with neither a real `/dev/shm` nor a writable temporary directory anywhere
  stops claiming one. `struct cng_dev_node` also gained a `dir` flag, since the
  "may a guest name a path under this?" test used to compare `host` against the
  string `"/dev/shm"` — which the day that path became a variable would have
  quietly stopped matching.
  Validated three ways: a busybox guest in the Alpine rootfs creates, reads,
  lists and removes an object under `/dev/shm` (M14), the same guest proves the
  mount table's claim and the node agree, and a compiled glibc guest does a full
  `shm_open` → `ftruncate` → `mmap` → reopen-by-name → read-back → `shm_unlink`
  round trip against the stand-in (M12, `tests/guests/shm_posix.c`). All of it
  runs on a host that has a real `/dev/shm` too, through `CNG_DEVSHM_FORCE_TMP`,
  and the last leg checks the objects landed under `$TMPDIR` and *not* in the
  host's own `/dev/shm`. The compiled leg skips on Termux, bionic having no
  `shm_open` at all — Android uses ashmem — which is the same reason the guests
  that need this are the rootfs ones.

- [x] **M37 — the trapped set was a property of the build host**
  Every syscall number in the tree came from `<asm/unistd.h>`, and every
  number younger than the headers on the machine doing the build sat behind an
  `#ifdef __NR_*`: forty of them, over openat2, execveat, clone3, the io_uring
  three, the mount API, statmount/listmount, the mqueue six, fchmodat2 and
  more. A binary built against old headers — an old NDK, an old distro
  sysroot — simply had no entry for those, and the filter's default action is
  ALLOW, so a guest on a newer kernel reached the host filesystem by the raw
  number: untranslated, unrefused, and with nothing to say so. The numbers are
  the stable ABI (arm64 takes the asm-generic table unchanged, and a number is
  never reused), so they now live in `include/cng/unistd.h` beside the rest of
  the local UAPI constants, generated from the 6.17 kernel's
  `scripts/syscall.tbl` and cross-checked against the cross toolchain's own
  header and the running kernel. Nothing else includes the system header; the
  gates are gone, and `src/rt/unistd_check.c` holds the table against the
  build host's `<asm/unistd.h>` where there is one — a differing value is a
  build error (`-Werror` on that one unit), a missing one is silence, which is
  exactly the host the table exists for.
  Doing that turned up the same hole with nothing to do with headers: the
  table's own last entry was 461, and 6.13 added the dirfd-relative xattr
  family (`setxattrat`, `getxattrat`, `listxattrat`, `removexattrat`), 6.15
  `open_tree_attr`, 6.17 `file_getattr`/`file_setattr` — seven path-bearing
  syscalls, live on the dev host's kernel, that no table here named. The six
  that take (dirfd, path) are translated like their predecessors (an
  `AT_SYMLINK_NOFOLLOW` l2s name lands on the backing file, a setter under a
  `:ro` bind is EROFS, `AT_EMPTY_PATH` read from each family's own slot — a2
  for the xattr four, a4 for the file-attribute pair); `open_tree_attr` joins
  `open_tree` in the designed-ENOSYS set.
  Validated by `-t bpftest` (each of the new numbers traps or is refused, and
  the previously gated ones are asserted the same way), `-t dtest newat` (the
  decisions taken on the guest's own spelling before any kernel is asked:
  `..` through a file, the empty name with and without the flag) and the
  `:ro`/l2s mutator tables. A kernel that has `getxattrat` also runs the
  contained-vs-reached differential the plain `getxattr` leg runs; without one
  it skips by name.

- [x] **M38 — the ET_EXEC preflight guarded the image and nothing else of ours**
  An ET_EXEC goes down MAP_FIXED at its link-time vaddr, and the header pass
  refused the one collision it knew about: chroot-ng's own image. But the
  image is not the only mapping of the monitor's a file can name. The
  scratch stack the emulated execve is itself running on, the signal frame
  it returns through, the own-map registry's regions (the floor, the pid and
  IPC registries, the argv snapshot the exec stands on) are all kernel-placed
  mappings at addresses just as spellable — and the exec sweep knows to leave
  every one of them alone, but the sweep runs *after* the map pass, and the
  map pass had already put the guest over them, past the point of no return
  where a failure is fatal and a success is a monitor with no stack.
  `cng_hits_monitor()` (ownmap.c) now asks the three questions the sweep
  asks — image, registry, scratch stacks with their frames — and every
  guest-chosen MAP_FIXED of ours asks it: the ET_EXEC header pass (ENOEXEC
  with the caller alive), the map pass again at the last moment before the
  MAP_FIXED (a registry can grow a chunk and a thread can claim a stack
  between the plan and the map; a stale yes there would replace the monitor,
  a refusal is at worst a fatal exec that says why), `shmat(SHM_REMAP)`
  (EINVAL) and the mmap hook's anonymous stand-in (the kernel's own answer).
  The sweep uses the same helper, so the two can no longer drift apart.
  The extent asked about is the whole of what `map_anon` reserves: under `-R`
  that is the span plus the trampoline pool on top of it, MAP_FIXED alike, so
  an ET_EXEC whose span ends exactly where a mapping of ours begins would have
  put its pool over that mapping.
  `-t imgtest` gained four legs against live addresses: an ET_EXEC over a
  region recorded with `cng_own_map` (refused, and the region's contents
  intact afterwards), one over this thread's scratch stack, one planned over
  a free page that becomes ours between the plan and the map, and one whose
  pool would land on a region of ours — refused with `-R` on, loaded with it
  off.

- [x] **M39 — the close-on-exec pass did nothing without `/proc/self/fd`**
  A real execve closes every FD_CLOEXEC descriptor; ours reads
  `/proc/self/fd` and closes what it finds — and when that directory could
  not be opened, returned quietly, so every close-on-exec descriptor of the
  outgoing program survived into the next one. Not an exotic host: a
  descriptor table filled to RLIMIT_NOFILE refuses the open with EMFILE, in
  exactly the program with the most descriptors to lose, with a launcher
  blocked on the O_CLOEXEC notify pipe that was supposed to close. A host
  with no `/proc` to read was the same silence.
  Where the directory will not open, the pass now asks about every
  descriptor number there can be: F_GETFD on each, one syscall per number, a
  miss being EBADF. The bound is the larger of the two RLIMIT_NOFILE values
  (the soft limit is checked at open time, so a descriptor can sit above the
  limit in force now if that was lowered after it was opened), floored at
  64K, with RLIM_INFINITY read as the kernel's own `fs.nr_open` default of
  2^20 — which cannot be read without `/proc` either. Tens of thousands of
  EBADFs is tens of milliseconds, once per exec, on the path that used to
  leak.
  `-t cloexectest` reproduces the trigger rather than a stand-in for it: the
  soft limit is brought down to the table's top, `/dev/null` is opened until
  EMFILE, and the pass is run — the CLOEXEC descriptors below and at the very
  top of the fill have to go, the plain ones have to stay.

- [x] **M40 — the guest stack had no guard under it**
  A real main stack has `stack_guard_gap` — 256 pages — of nothing beneath
  it, and a stack that grows into the gap faults. The stack `cng_build_stack`
  mapped was one 64 MiB RW mapping, writable to its last byte, with whatever
  the kernel had happened to place beneath it next in line: top-down
  allocation's most recent mapping, a library the guest loaded or a scratch
  stack of ours. A recursion that ran off the end wrote into that and went on
  running, where the kernel gives SIGSEGV.
  The same 256 pages are now reserved with the stack and made PROT_NONE:
  nothing else can be mapped there, the first store past the bottom is the
  fault a real overflow is, and it costs address space only. The usable size
  is unchanged (`CNG_GUEST_STACK_SIZE` still bounds argv/envp the way the
  kernel bounds ARG_MAX), the argv address scratch at the bottom of the
  region sits just above the guard, and the extent the exec reclaim is told
  covers the guard, so an emulated execve gives the whole region back.
  `-t stackguardtest` probes the guard and the usable bottom from a child (a
  store one word below the bottom dies of SIGSEGV, one at the bottom does
  not, the guard's own base faults, the sp lies above both, the recorded
  extent is stack plus guard); `tests/guests/recurse.c` is the end-to-end
  half — 48 MiB of recursion returns, so the guard took nothing from the
  stack, and an unbounded one dies of SIGSEGV where it used to write into its
  neighbour.

- [x] **M41 — the mmap hook's copy read on past the end of the file**
  A file mapping longer than its file answers a fault on any page wholly
  past EOF with SIGBUS (the kernel checks `i_size` at fault time, page by
  page), and only the partial last page reads as zeroes past the end — so a
  truncated object dies at the first touch past its end. The anonymous copy
  `cng_execmap` makes in place of a refused PROT_EXEC file mapping pread what
  the file had and left the rest zero, and the same object ran on: a page of
  zero words is `udf #0`, so code reached a SIGILL some way past the
  truncation, and data read as zero with no word said. Measured with
  `-t execmaptest` before the fix: a page past EOF read 0 from the copy where
  the kernel's own mapping of the same file died of SIGBUS.
  The tail goes back under the file: a file mapping without PROT_EXEC is one
  no mount and no policy refuses for a file we could pread, so the pages
  wholly past EOF are MAP_FIXED from the file at the same offset with the
  guest's protection minus execute — every one faults exactly as the
  kernel's would, and stops faulting if the file grows, as the kernel's
  would. Where even that is refused the tail is PROT_NONE: SIGSEGV for
  SIGBUS, at the same place. A mapping that begins past EOF is the tail
  entire; the partial last page already matched.
  `-t execmaptest` is a differential: the same three-page mapping of a
  one-and-a-bit-page file, once from the hook (forced onto the anonymous
  route) and once as the kernel's own PROT_READ mapping, probed page by page
  from a child — the marker page, the partial page's head and zero tail, the
  page past EOF and a mapping that begins past EOF must answer alike, and the
  kernel's answer for the pages past EOF is checked to be SIGBUS, so an
  agreement is not two mappings that both merely died.

- [x] **M42 — a monitor that could not be installed was a warning, not a refusal**
  `cng_run` installs the monitor last, when the invocation asked for
  something only a monitor delivers: a rootfs that is not `/`, a bind, `-u`,
  `-l`, `--no-ptrace`, `--shared-proc`. When `cng_install_monitor` failed it
  printed one line on stderr and entered the guest anyway — and without a
  filter nothing intercepts, so the rootfs ran against the host's own paths,
  `-u` reported the real identity, `-l` made no hardlink, `--no-ptrace`
  refused nothing and `--shared-proc` published nothing. Every one of those
  is the thing the invocation asked for, and none of them was delivered; a
  launcher script never reads the line, and a guest that wrote, wrote where
  the host keeps its files. Under qemu-user that was every run, since
  qemu rejects `PR_SET_SECCOMP` (EINVAL); on a device it is a policy that
  forbids the filter (EACCES — what `--probe` calls a hard blocker).
  Now the failure is the end of the run: chroot-ng says it cannot install
  the monitor, with the errno, and that nothing else would intercept, and
  exits 1 before the guest has run an instruction. `-R` is the one exception,
  and a deliberate one — a rewritten `svc` site calls the dispatcher directly
  and needs no filter, which is what makes it the interception tier for hosts
  that have none (`docs/DESIGN.md`). With `-R` the run goes ahead, and the
  warning now names exactly what it cannot reach: the `svc` sites in a
  library the guest's own ld.so maps from a mount that grants PROT_EXEC, and
  code no object carries.
  Three suite legs observed the old behaviour and now assert the new one:
  M8's no-`-R` control (rc 1 and the message on an inert host, the
  seccomp-translated open on a live one) and M18's `--no-ptrace /` and
  `--shared-proc /` legs (the refusal on an inert host, `nnp=1` on a live
  one). M8 also checks that `-R` on an inert host runs and warns.

- [x] **M43 — a directory descriptor was a place to resolve names from, wherever it pointed**
  The kernel resolves a name relative to a dirfd with no rootfs in the way,
  so every directory descriptor the guest holds has to be on a directory
  inside its view. The dispatcher assumed that instead of establishing it: a
  plain name against a dirfd went to the kernel on the strength of "the dirfd
  already points inside the guest view", and a dirfd it could not map back to
  a guest path had *every* name passed through — on the grounds that such a
  dirfd is one inside `/proc`, which wants the host namespace anyway. Three
  things followed. `openat(dirfd("/proc"), "../etc/passwd")` read the host's
  file, and so did a name through a dirfd on `/dev/pts` (measured both). The
  components after an fd magic link "rode along, as they do for a real
  dirfd": the resolver stopped at `/proc/self/fd/<n>` and handed the rest to
  the kernel, which walked `..` out of the rootfs from the directory the fd
  named and followed a symlink under it from the host root. And a directory
  descriptor the launcher leaked across the exec that started chroot-ng was
  inherited as it was — nothing looked at the table — and was a door out of
  the view by any relative name at all.
  - **Every directory the guest can hold a descriptor on is named**
    (`host_dir_guest`): inside the view by the reverse translation; the
    `/proc` zone under its own name, so the walk applies the hidden-process
    view and the synthesized files to `openat(dirfd("/proc"), "1/status")`
    exactly as to `"/proc/1/status"`; the `/dev` zone through the whitelist
    entry the host node stands for (`/dev/pts`, the `/dev/shm` stand-in under
    `$TMPDIR`). A zone answer must translate back to the same host directory,
    or a bind shadows the zone there. `xlate_at`, `cng_resolve_at`, the
    scoped `openat2` route, `fchdir`'s cwd resync and the `/proc` hooks'
    `at_canon` all go through it — the last now lexically, so `exe` against a
    dirfd on `/proc/self` is still the link the fixup recognizes.
  - **What follows a directory's fd link is walked, not ridden.** The fd
    directory itself is walked through like the directory it is; at the link
    the resolver reads where it points, and a directory of the view replaces
    it by its guest name the way `exe`/`cwd`/`root` are expanded, so the
    rest of the name gets the `..` and symlink handling every name gets. A
    file, or a description with no path (a pipe, a memfd), is handed over as
    before. Judged only where the link is followed: `O_NOFOLLOW` and `lstat`
    on the link itself are the kernel's to answer.
  - **A directory the guest has no name for is not a place to resolve from,
    and never enters its table.** A name walked against one, a reopen of it
    or a name through its magic link, a scoped `openat2` under it and an
    `fchdir` into it are all `EACCES` — the guest may not search a directory
    it cannot name — and the walk's refusal is carried past the lexical
    fallbacks that used to paper over a failed resolution (`xlate`,
    `cng_resolve_at`, the AF_UNIX address translation). What makes the
    walk-free path sound is that no such descriptor exists to take it:
    `cng_fd_admit` closes one, and it is run over everything the launcher
    handed down before the first program loads (`cng_fds_sanitize`; our own
    descriptors are close-on-exec and skipped), over every `SCM_RIGHTS`
    record a `recvmsg`/`recvmmsg` delivers, and over what `pidfd_getfd`
    imports (closed again, `EPERM`). Files are let in: a redirected stdin, a
    pipe, a socket handed over at launch are what an inherited descriptor is
    for, and a file is not a place to resolve a name from. One of the
    standard three that goes (`chroot-ng ... < /`) is replaced by `/dev/null`
    rather than left closed, as a setuid program treats them. The one descriptor
    that can still point above the guest's root is one opened before an
    emulated `chroot(2)` — bounded by the launcher's own view, and exactly
    what a real chroot leaves a process holding; a walk from it is refused
    where the kernel would have allowed the climb.
  - `fchdir(open("/proc"))` used to leave the virtual cwd where it was, so
    `getcwd` answered `/` while `self/status` resolved under it; the zone's
    name now carries the cwd along.
  - Validated by `tests/m25_fdview.sh`: `-t dtest outside` drives the
    dispatcher without the startup sanitization, so the refusals against an
    outside directory are observable (walk, `..`, `fchdir`, the magic link,
    a socket-delivered copy closed, `pidfd_getfd` refused) beside the file
    that keeps the kernel's answers; `tests/guests/fdescape.c` runs as a
    guest with a leaked host directory and file in its table and takes every
    route out — `..` from the zones' dirfds, `..` and an absolute symlink
    through a dirfd's magic link and its `/dev/fd` spelling — landing on the
    rootfs's marker each time, with the reopen, the `fchdir` and the
    in-view socket trip as the controls that still work.

- [x] **M44 — a `:ro` bind was read-only to every name but `/proc/self/fd/<n>`**
  The `:ro` refusal is keyed on the resolved host path, and an fd magic link
  resolves to a host path that names no bind of ours: `/proc/self/fd/<n>`
  is the path the kernel is handed, and `cng_fs_host_ro` had nothing to say
  about it. So a guest opened a file under the bind read-only (or `O_PATH`),
  reopened its fd link with `O_WRONLY` or `O_TRUNC`, and the host file was
  written — emptied, in the `O_TRUNC` case (measured, through both the
  `/proc` and the `/dev/fd` spellings). A real read-only mount refuses the
  reopen: the description was opened through the mount, and the reopen
  inherits its vfsmount. Here the mount is a prefix of the description's own
  path — which the link reports — so that is what `ro_denied` now asks about
  (`fd_link_ro`): the link is read, and the file it stands for is judged like
  any other host path. Anonymous descriptions (a pipe, a memfd) are on no
  mount of ours. A link with components after the fd is already the walk's
  business (M43): it arrives here as the file's own host path.
  - The link2symlink emulation is the one case the path cannot settle. A
    descriptor opened through an l2s name is on the group's data file, in
    the store under the rootfs where no bind covers it, and which name it
    was opened through is not something a description remembers. Its access
    mode is: a writable descriptor came through a writable name (a
    write-open under a `:ro` name is refused by name), so it may be
    reopened; a read-only or `O_PATH` one is judged as the `:ro` name's
    whenever the view has a `:ro` bind at all. That over-refuses exactly one
    shape — a read-only descriptor on a hardlinked file that was opened
    through a writable name and is reopened for writing through its fd link
    while some `:ro` bind exists — and nothing else.
  - Validated by new legs of `-t dtest robind` and `l2sro` in
    `tests/m5b_monitor.sh`: the fd link of a read-only and of an `O_PATH`
    descriptor under the bind, reopened `O_WRONLY`, `O_TRUNC`, through
    `/dev/fd`, and named to `truncate` and `chmod`, all `EROFS` where the
    read-only reopen still works; the same through an l2s name; the rw
    control run reopens every one of them.

- [x] **M45 — a `:ro` bind refused mutation by name and not by descriptor**
  A read-only mount refuses the calls that reach a file by its descriptor as
  surely as the ones that reach it by name — `mnt_want_write_file()` is the
  same test either way — and a descriptor on a file under a `:ro` bind is
  what the bind's read-only open hands out. `fchmod`, `fchown`, `futimens`
  (`utimensat` with a NULL path), `fsetxattr`, `fremovexattr`, the
  `AT_EMPTY_PATH` spellings of `fchownat`, `fchmodat2`, `setxattrat`,
  `removexattrat` and `file_setattr`, and the ioctl requests that write the
  mount (`chattr`'s `FS_IOC_SETFLAGS` on a read-only descriptor, for one)
  all went to the kernel with nothing in the way: they carry no path for the
  refusal to key on. Measured: a guest changed the mode, owner, times,
  xattrs and inode flags of a file it could only open read-only.
  - What they carry is the descriptor, whose own path the kernel reports:
    `fd_ro` puts the question to its fd link, which `ro_denied` resolves
    (M44) exactly as for a guest that spells `/proc/self/fd/<n>` out. The
    fd forms are trapped only with a `:ro` bind in the view — the trap is for
    the refusal alone — and `fchmodat2` learns `AT_EMPTY_PATH`, which the
    kernel has accepted since the syscall appeared and the dispatcher had
    been answering `ENOENT` for. `AT_EMPTY_PATH` with `AT_FDCWD` names the
    working directory, which the translation has already spelled out.
  - The ioctl requests are an explicit table (`cng_ioctl_mnt_write`, one
    table for the filter and the dispatcher): the generic flag, fsxattr,
    version, encryption-policy and verity setters, and the ext4, btrfs and
    f2fs private requests an owner may issue on a read-only descriptor (a
    snapshot into a directory, a subvolume's flags, a pin, a migration).
    Each is one `JEQ` in the ioctl block, behind the `SIOCxIF` band test,
    present only with a `:ro` bind; a terminal `TCGETS` and every getter stay
    native. `FIDEDUPERANGE` names its targets in the argument and is answered
    per destination as the kernel does: the argument is copied, a destination
    under the bind is replaced by a descriptor that is not open, and its
    status comes back `EROFS` with the guest's own `dest_fd` restored. The
    kernel orders a few of the private requests the other way (an owner
    check, a copy of the argument) and would answer `EPERM` or `EFAULT`
    ahead of `EROFS` for a call refused either way; that precedence is not
    reproduced.
  - `CNG_SECCOMP_MAX_INSNS` goes to 320: the largest configuration measures
    247 with the table in.
  - Validated by new `-t dtest robind` legs in `tests/m5b_monitor.sh` (each
    fd form `EROFS` under the bind and not under the rw control; the dedupe
    destination judged where the kernel has dedupe at all) and `-t bpftest`
    legs that simulate the filter with and without a `:ro` bind.

- [x] **M46 — the hidden-process view hid a process by path and not by pid**
  `/proc` hides a host process from the guest — by path, and from listings —
  but `process_vm_readv`, `process_vm_writev` and `pidfd_open` name a
  process by pid and carry no path, and all three ran native (the first two
  trapped only for a ptrace tracer). With a ptrace policy that permits
  same-uid access, a guest read and wrote the memory of a process its
  `/proc` said did not exist, and a pidfd on it reaches everything a pidfd
  reaches: signals, its descriptors through `pidfd_getfd`, `waitid`.
  - A pid the view does not show answers `ESRCH` from all three, which is
    what `/proc/<pid>` answers for it (`pid_hidden`); a task of a guest
    process counts, as the kernel finds a task by any tid it has
    (`cng_procreg_has_task`). Trapped only while there is a view — `--no-proc`
    hides nothing, and they run native there. A pid the kernel would refuse
    before it looked anything up (zero, negative) is left to it, so the
    `EINVAL`/`ESRCH` it gives stays its own. `pidfd_getfd` is M43's: what it
    imports is judged whatever the view.
  - Out of scope, and deliberately: the signal family (`kill`, `tgkill`,
    `pidfd_send_signal` on a pidfd the guest could only have got from a
    process it may see) and the scheduler and priority calls name a pid too
    and stay native — trapping `kill` for every guest is the cost the ptrace
    emulation stacks its filter on demand to avoid, and a signal to a hidden
    same-uid process is what a real chroot allows.
  - Validated by the last section of `tests/guests/fdescape.c` in
    `tests/m25_fdview.sh` (pid 1 `ESRCH` from both, a forked child reachable
    by both — the latter sits out where the host has no `process_vm_readv`
    for the guest at all, as qemu-user has not) and a `-t bpftest` leg that
    simulates the filter with and without the view.

- [x] **M47 — the emulated netlink socket's hidden descriptors were the guest's to lose**
  An emulated `NETLINK_ROUTE` socket is three descriptors in the one table
  the guest and the monitor share — the guest's end of a socketpair, our
  end, and an unbound relay socket — and the slot checked the identity of
  the first alone. `close(2)` is not trapped: a close-all loop before an exec
  (`daemon(3)`, `closefrom(3)`, every service manager's child setup) closed
  the two the program never knew about, its next opens were handed the
  numbers back, and the slot's reclaim — a trapped socket call on the old
  number, whose inode had changed — then *closed the two hidden numbers
  again*: two files of the program's. The relay socket was also the one of
  the three opened close-on-exec, so an emulated execve carrying a netlink
  socket without `SOCK_CLOEXEC` (the pair peer carries the guest's flags and
  survived with it) left the slot relaying through, and reading from,
  whatever the next program opened on that number: a guest socket there
  would have had its datagrams read by the monitor, blocking inside the
  handler with no timeout of its own.
  - Every descriptor of the slot now carries the identity of the file it was
    opened as, and the number is neither used nor closed without it checked
    (`cng_fdid`: device and inode both — the inode alone is per filesystem,
    and a guest file elsewhere carries the same number as freely as a memfd
    or a socket does). A stale pair peer is abandoned, never
    closed: the pair is broken, which is what the guest did to it. A stale
    or closed relay socket is opened again on the next relay, since the
    ordinary way to lose it is the exec sweep and not the guest.
  - `tests/guests/nlstale.c` in `tests/m16_netlink.sh`: sixteen files opened
    onto the freed numbers survive the reclaim, and a socket inherited across
    an exec still dumps — relayed, on a relay socket of ours, counted in the
    debug trace where the host relays at all.

- [x] **M48 — a synthesized `/proc` file was known by its inode number alone**
  The refreshable synthesized files (`loadavg`, `uptime`, `stat`) are memfds
  kept by descriptor number, and since `close(2)` is not trapped the entry
  is checked against the file behind the number before every refresh — by
  `st_ino` only. An inode number is per filesystem: a guest file carrying
  the memfd's number, moved onto the memfd's descriptor number, passed as
  the memfd, and the refresh reopened it for writing through the fd's magic
  link, truncated it and wrote `/proc/stat` into it — a write the monitor
  made on a file the guest may only have been able to read. The scratch
  memfd `uaccess.c` stages guest copies through carried the same
  inode-only check.
  - Both keep the `(st_dev, st_ino)` pair now (`cng_fdid`, M47's helper),
    and the refresh checks what its reopen actually returned against the
    recorded identity before it truncates a byte: the number is in the
    guest's table, and what the magic link names is decided the moment it
    is opened, not the syscall before.
  - `-t proctest` asks the helper the question no guest can be made to
    pose (the memfd's inode number on another device is not the memfd),
    then moves a file of its own onto the synthesized number and reads it
    back intact through the dispatcher.

- [x] **M49 — the resolved path was re-resolved by the kernel, from scratch**
  The walk turned a guest name into a host path and the syscall was made on
  that string, which the kernel resolves again, following whatever it finds:
  a directory on the way swapped for an absolute symlink between the walk
  and the call was followed from the HOST root, and the call landed outside
  the rootfs. Every path-bearing family had the window — open, stat,
  readlink, access, unlink, rmdir, mkdir, truncate, chdir all measured
  through it, thousands of times a second under a flipping thread — and so
  did every host path the monitor handled on its own account: the loader's
  open of the program, `-l`'s data files and markers, the `/proc` files a
  `-b DIR:/proc` serves, an AF_UNIX `sun_path`. It is the time-of-check to
  time-of-use of a string-based translator, and `proot` has it too.
  - No host path reaches the kernel as a string any more (`src/monitor/pin.c`,
    `cng/pin.h`). The directory the walk reached is opened `O_PATH` and held
    for the call, verified to be that directory — the kernel's own name for
    it (its fd link read back) against the walk's symlink-free spelling, the
    rootfs, bind and `/dev` directory prefixes being stored as the kernel
    spells them; a spelling that differs (a case-insensitive filesystem
    answers the stored case, and a `-b /sdcard` is one) is settled by a
    descriptor-by-descriptor walk from the prefix, each component
    `O_NOFOLLOW`, a symlink met there being the race and `ELOOP`. The call
    is then made against that descriptor with the last component as a plain
    name and the family's NOFOLLOW set, which the walk's own following
    makes a no-op for a tree at rest. `reissue()` does this for every
    dispatcher re-issue by table (`pin_args`); the loader, l2s, procfs and
    the fallback reopen take the whole-path forms.
  - An open is not given `O_NOFOLLOW`: the kernel keeps that on the
    description, `F_GETFL` and `fdinfo` report it, and the "reopen with the
    flags read back" idiom would then refuse a symlink the program never
    meant to avoid. It is made as an `openat2` with `RESOLVE_NO_SYMLINKS`
    — the how built as the kernel builds it for an `openat`, so the stricter
    call answers alike — where the host has `openat2`; a flag outside the
    known set, or a host that blocks the call (Android's filter), takes
    `O_NOFOLLOW`, and the bit on the description is the residue there.
  - `access` and `chmod` have no NOFOLLOW to set and take `faccessat2` and
    `fchmodat2` (remembered as absent on `ENOSYS`); `truncate`, `statfs`,
    `chdir` (an `fchdir`), the non-at xattr calls and `inotify_add_watch`,
    and any name with a trailing slash — which the kernel follows whatever
    the flag says — go through the last component's own `O_PATH`
    descriptor, checked not to be a symlink, by its fd link. The pinned
    pair spelled through the directory's fd link serves the l-form xattr
    calls and `bind`.
  - A pin that fails on the directory (`ENOENT`, `ENOTDIR`, `EACCES`) has
    skipped the checks the kernel makes before it resolves anything, so the
    call is made once more against a descriptor that is none and a name that
    needs one: `EBADF` means those checks passed and the pin's answer stands,
    anything else is the kernel's, in its order (`pin_errno`). Measured:
    `fstatat("/missing/x", badflags)` is `EINVAL`, as it was.
  - A pathname `bind` now carries "/proc/<pid>/fd/<n>/<name>" in `sun_path`
    — the binder's own pid, and the pinned directory kept open in it for as
    long as the socket is (given back on a later bind once the socket is no
    longer open here, the number's identity checked first: it is in the
    guest's table). That is what any process can read back: the binder by
    the record it made (the socket's own inode first), everything forked from
    it by the stored spelling, and a process with no record — a datagram
    service answering at the source address its `recvfrom` reported — by
    resolving the link to the host directory and that to its guest name. The
    self-describing "/proc/self/fd/<root>/./<guest path>" form is gone: the
    kernel resolved the guest path's components itself. A `connect`,
    `sendto` or `sendmsg` names the socket file by its own `O_PATH` link.
  - Cost, measured under qemu-user where a syscall is ~5 µs: an absolute
    `stat` 18 → 35 µs (open, readlink, close), an absolute `open` 28 → 39,
    a name against a dirfd 12.7 → 15.6 (the hot path pins nothing: the
    NOFOLLOW is all it gains).
  - `tests/m26_pinned.sh`: `tests/guests/pathrace.c` flips a directory
    against an absolute symlink to a host directory under nine families for
    four seconds (12,000–17,000 host answers before, the host's files
    unlinked, made and truncated; none now, all intact), and
    `tests/guests/uxreply.c` has two unrelated invocations exchange
    datagrams on their own bound names and read each other's back.

- [x] **M50 — a scoped `openat2` was pinned, and the pin undid the scope**
  `RESOLVE_BENEATH` / `RESOLVE_IN_ROOT` go to the kernel untranslated where
  the guest's namespace adds nothing under the dirfd (M24): the scoping is
  the kernel's to apply within one resolution, and there is no walk whose
  product a second resolution could move. M49's `reissue()` pinned the call
  all the same, and the pin is built for a walk's product: an absolute name
  was split at its last slash and re-aimed at the directory it spelled — the
  HOST root, where `BENEATH` had nothing left to refuse and `IN_ROOT` nothing
  to re-root, so both answered `ENOENT` for the `EXDEV` and the re-rooted
  open the kernel gives — and `RESOLVE_NO_SYMLINKS` was added to every open,
  which turned the relative and absolute links the scope would have followed
  or refused into `ELOOP`. Five legs of the `m24` differential, against a
  native kernel (the legs are host-gated: no qemu-user build has `openat2`,
  which is why the local suite never saw it). The scoped route makes the
  call raw now, the guest's name against the guest's own descriptor, with the
  `cng_blocked` check kept; the `:ro` refusal and the hidden-pid check around
  it are unchanged. Measured on 6.8: `beneath_abs=-18`, `inroot_abs=ok`,
  `beneath_abslink=-18`, `beneath_link=ok`, `inroot_abslink=ok`, as natively.

- [x] **M51 — `linkat` named the descriptor by its `/proc` link, whatever the kernel allowed**
  `linkat(fd, "", …, AT_EMPTY_PATH)` — the O_TMPFILE publish idiom — was made
  as a `linkat` of "/proc/self/fd/N" with `AT_SYMLINK_FOLLOW`, which every
  kernel follows for anyone. Whether the caller may name the source by
  descriptor is the kernel's question, and the kernels in the field answer it
  two ways: before 6.10 the flag takes `CAP_DAC_READ_SEARCH`, and without it
  the call is `ENOENT` ahead of everything but the flags check (a NULL name,
  a number that is no descriptor, the destination — all of it comes after);
  from 6.10 the descriptor's open-time credentials have to be the caller's
  own. So on 6.8 the emulation answered like a root's: `link_byfd=0` where
  the kernel says 2, and a NULL source under the flag `EFAULT` where the
  kernel says `ENOENT` first — the two differential legs (`m5b`, `m17`) that
  failed on that kernel alone. A flag bit outside the two the call knows was
  dropped on the way to the host, too, and the link made where the kernel
  answers `EINVAL` before either name.
  - The flagged call goes to the kernel as the guest made it, with the
    destination translated and pinned and nothing else: the empty name as a
    constant of ours (the guest's buffer could turn into a relative name
    between our read and the kernel's, and resolve untranslated against the
    descriptor), a NULL as a NULL, a NULL destination too — its `EFAULT`
    comes after the source's verdict, and the kernel never looks at the dirfd
    beside it. The flag beside a name that is not empty is kept on the
    re-issue as well: the older kernels refuse the call for the flag whatever
    the name says, and the pinned directory is one we opened, so the newer
    rule passes it as the guest's own would have.
  - Under fake root the capability is faked, as `chroot`'s `CAP_SYS_CHROOT`
    and the DAC bypass are: an `ENOENT` is retried through the descriptor's
    `/proc` link, which links the inode root's `AT_EMPTY_PATH` would have
    (`link_byfd=0`, and `AT_FDCWD` still `EPERM`, a number that is none still
    `EBADF`, as root has them on every kernel).
  - The `-l` fallback is taken for the filesystem's refusals of the flagged
    call as before (`EPERM`, `EACCES`, `EXDEV`, …), from the `/proc` link it
    always linked from; an `ENOENT` there is the flag's or the destination's
    and never a hardlink denial to paper over, so the "ENOENT is only
    believable when the source is absent" reading stays on the path route.
    `CNG_L2S_FORCE` still routes every `linkat` through the emulation.
  - `tests/guests/emptypath.c` gained `link_badflag` and `link_named_flag`;
    `m5b` runs it once more under `-u 0:0` for root's answers, and `m17`'s
    flagged-NULL needle is the oracle's own line.

- [x] **M52 — the de_thread listed its siblings once, into a table of 4096**
  The emulated `execve` kills every other thread of the process before
  anything is mapped (a thread-directed `SIGSYS` carrying a die request), and
  it found them with one read of `/proc/self/task` into a fixed table: the
  4097th sibling and everything after it was never told, and the exec went
  ahead beside them — old threads running the old program through the fd
  cleanup, the signal reset and the mapping reclaim — without a word, since a
  full table read the same as a complete one. A thread a sibling cloned
  between being listed and taking its request was missed the same way, at
  any thread count. The listing is the kernel's own now, read afresh every
  round until it is empty, and every listed sibling is told again each round
  (a request already pending is not queued twice, and the answer doubles as
  the existence probe — which also reaches a thread that took over the tid
  of one that died); a listing that takes more than one read can skip an
  entry while threads exit under it, so the kernel's own count (`Threads:`)
  has the last word. What cannot take the request — a zombie, or a thread
  that keeps `SIGSYS` blocked: qemu-user's own, or a guest that edited its
  signal frame — is given up on after a second as before, kept apart in a
  small table that grows, and looked at again once a second; a blocked
  thread is sampled ten times a millisecond apart first, so a writer of ours
  holding every signal off for a moment is not mistaken for one. The status
  fields are read by streaming the file: a `Groups:` line of a process with
  many supplementary groups runs past any one buffer, and every field wanted
  comes after it. `tests/guests/spawnexec.c` execs from 4500 parked threads
  and from sixteen chains that clone their successor at birth; the old
  binary reports 407 and ~20 threads after the exec, the kernel and the fix
  report 2 (qemu-user's own thread included) — the `m6` legs.

- [x] **M53 — the ptrace per-task table filled for good, and an attach was consumed before it could be kept**
  A traced or tracing task keeps its state (the frame it stopped on, its
  resume mode, its step breakpoint, the link to its tracer) in a tid-keyed
  slot, and the slots were 128 and never given back — a task's exit cleared
  its fields and left its tid in place — so the 129th task ever traced or
  tracing in a process found none. `PTRACE_ATTACH`/`SEIZE` had answered 0
  to the tracer by then (the kick and the pending flag are all it needs),
  and the tracee cleared the flag before asking for a slot: with none, it
  simply went on, and the tracer waited for a stop that never came. The
  table is a `cng_tab` now: a slot goes back at its task's own exit — the
  de_thread's die request reports the death first too, as the kernel's
  `SIGKILL` reaches a tracer — and one whose task died without passing there
  (`exit_group`, a fatal signal) is taken over by the next claimant once no
  free slot is left, with any step breakpoint it still had planted put back
  first, since its record is the only account of the original word; only
  then does the table grow. The pending flag is consumed after the slot is
  in hand, so a slot that cannot be had (the host refusing a page) leaves
  the attach pending for the next stop point rather than lost. `pt_probe`'s
  `attachmany` attaches to two hundred short-lived threads of one process in
  turn; the old binary hung at the 129th, and the leg is a kernel
  differential.

- [x] **M54 — a rootfs that could not be entered ran the guest anyway**
  With a real rootfs the guest starts at "/", and the real process is moved
  into the rootfs so that a relative name the monitor never sees — anything
  untrapped, and under `-R` every site the rewriter did not reach — resolves
  inside it. `--work-dir` has treated that chdir's failure as fatal since
  M17-17; the default path dropped it, so a rootfs that was not there, or
  had no search permission, ran the guest (from a bind, say) told it was at
  "/" with the real cwd still at the launch directory — the containment
  fallback missing and nothing said. It is refused now like `-w` is, with
  the errno, before the guest is entered; three `m17_workdir` legs, one with
  the program reachable through a bind, where the old binary ran it.

- [x] **M55 — a rootfs was its 32-bit hash, to the daemon, the registry file and the abstract tag alike**
  Everything that stands for a rootfs on the host was derived from one FNV-1a
  hash of its path: the `--shared-proc` rendezvous name (8 hex digits), the
  registry's named-file tier, and the tag spliced into every abstract AF_UNIX
  name. The peer check is by uid and nothing finer — deliberately, and a
  same-uid process can name any rootfs on its own command line, so a crafted
  collision buys an attacker nothing it did not have — but two rootfs of one
  user whose paths merely *happened* to hash alike met at one daemon: one
  `/proc` view, one System V namespace, one process table, one abstract
  socket scope, between guests that were meant to be apart, and nothing to
  say so. The hash is 64 bits now, and where there is something to compare
  the path is compared in full: the daemon is started for its path (or the
  session's nonce) and every connection opens with a hello carrying the
  client's, which the daemon reads ahead of the request and hangs up on if
  it is not its own — no round trip, and a mismatched client degrades as one
  refused by uid does; the registry file carries a sealed record of its path
  past the table's end, is made whole under a private name and moved onto
  the rendezvous name without replacing anything (`RENAME_NOREPLACE`, a
  `linkat` where that is refused), so exactly one creator wins and a joiner
  never sees a half-made file, and a file naming another rootfs is left as
  it was; the abstract tag, which has no daemon behind it, carries the whole
  key (12 → 20 bytes, so a name of up to 88 bytes carries it, 96 before). The
  rendezvous name is `v3` and the file `v2`, so no build joins the other's.
  Legs: `shmtest` reaches one daemon with its own key and with another's
  (answered, hung up on, answered again); `sharedtest` plants a file exactly
  as our own creation leaves it but naming another rootfs (declined, intact)
  and joins an unplanted one twice; `m15` reads the sixteen digits back off
  the wire.

- [x] **M56 — `timer_create` recorded whatever the guest's buffer held by then**
  The emulated `execve` deletes every POSIX timer the guest created, from a
  record of the ids as they were handed out (nothing enumerates them, and
  under qemu-user the ids in `/proc/self/timers` are the emulator's own, so
  the record is all the exec has there). The id was recorded by reading the
  guest's buffer back after the kernel had written it: another thread of the
  guest could rewrite or unmap the word in between, and the timer actually
  created outlived the program. The id is taken in a word of the
  dispatcher's now and handed to the guest afterwards; a copy-out that fails
  deletes the timer again and answers `-EFAULT`, which is what
  `do_timer_create()` does when its own put fails, so no timer is left behind
  that the guest knows nothing about. A `-t faulttest` leg: a bad pointer is
  `-EFAULT` and the count in `/proc/self/timers` does not move.

- [x] **M57 — a one-field credential reader took the pointer and read the buffer it named**
  The fake credential set is published as one object — two buffers, the
  active one never written, a writer copying it into the other and swapping
  the pointer, a reader re-checking the sequence after its read — and the
  header exempted "a reader of one field": `getuid`, `geteuid`, `getgid`,
  `getegid` and `cng_fake_root`, which every fake-root decision goes
  through, read `cng_g_cred->field` directly. With two buffers the one a
  pointer named a moment ago is the one the next writer fills, with a
  `memcpy` of the active set and then its edits, and the struct is four-byte
  aligned, so a uid could even come back torn — a value that was never any
  identity of the guest. `cng_cred_ids` takes the eight ids under the
  sequence and is the one way to read them; the getters and `cng_fake_root`
  (a function now) go through it, and `viewrace` reads `getuid`/`geteuid`
  beside `getresuid` in its identity race.

- [x] **M58 — the kernel wrote the host's answer into the guest's buffer first**
  Three answers the monitor rewrites after the kernel has produced them were
  produced straight into the guest's own buffer and corrected there a
  syscall later: an fd or `map_files` link's target (`readlinkat` — a host
  path, where the rootfs lives), a listing of `/proc` (`getdents64` — the
  host's pids, and under `-l` the l2s store's names) and a peer's
  credentials (`SO_PEERCRED` — the real invoking uid and gid). For the
  interval the host's answer sat in the guest's memory, readable by any
  other thread of it (a scanner thread finds it hundreds of thousands of
  times in a few seconds), and the correction read the buffer back, so a
  thread that rewrote it chose what was mapped, filtered or remapped. Each
  now fills a buffer of the monitor's and the guest's is written once, with
  the guest's answer — the rule the `uname` handler already stated.
  `readlinkat` decides an fd link before the call and answers it out of a
  `PATH_MAX` buffer (`rl_fdlink`), which also retires the second read for a
  short buffer and the scrub of the host tail; `getdents64` fills the batch
  buffer after the injected records and hands the final view over in one
  copy (`dents_out`), putting the stream back where it was if the guest's
  buffer will not take it, as the kernel leaves `f_pos` at the record it
  could not copy, and takes the count as the `unsigned int` the kernel
  does since the clamp now bounds a write into our buffer; `SO_PEERCRED`
  fills a ucred and a length word of ours with `sock_getsockopt`'s own
  length rules, so any length is remapped, not only a full one. Legs:
  `tests/guests/leakrace.c` (one thread calls, another scans the buffer for
  the host directory's name, a pid not its own, the real uid: 8k–5M
  sightings on the previous build, none now), `tests/guests/peercred.c`
  (the remap and the length rules against a plain run), and a `faulttest`
  leg for the put-back stream.

- [x] **M59 — a received descriptor was judged by the number the guest's buffer held**
  A descriptor arriving over a socket is judged on arrival (`cng_fd_admit`:
  a directory the guest has no name for is closed, its number left in the
  record), and the numbers judged were read back out of the guest's own
  control buffer after the kernel had written them — so another thread of
  the guest could rewrite the record in between and have some other number
  judged, keeping the descriptor the close was for; `recvmmsg` admitted the
  same way. `recvmsg` and `recvmmsg` now receive the control data into a
  buffer of the monitor's wherever the header asks for enough of it to
  hold a descriptor (`recvmsg_bounced`, which also carries the
  source-address bounce), judge the record there and hand it over in one
  copy. The bounce is exact: a buffer up to 8 KiB is taken at its own size;
  longer than that the socket's family is asked, and only then — AF_UNIX,
  the one family that can deliver descriptors, never fills more than an
  SCM_RIGHTS record of 253, a credentials record and a security label, so
  its buffer is taken at the bound with nothing lost, and any other family's
  stays the guest's own (a raw IPv6 socket's extension headers can run
  past it). A guest buffer that will not take the records is answered as
  the kernel answers one it cannot write: every descriptor of the record is
  closed again (`receive_fd()` installs nothing on a failed put) and the
  control data is reported truncated and empty; the copy-out comes before
  the judgement so a number the judgement closed is never closed a second
  time. What stays is the interval between the kernel's install and the
  close, which no in-process design can remove — `recvmsg`, `pidfd_getfd`
  and a scoped `openat2` landing on a hidden process all install first, and
  the table is the guest's; `docs/DESIGN.md` states it in the threat model
  and beside the fd-admission rule. `tests/guests/fdimport.c` receives from
  a host Python (`tests/send_fds.py`) a directory outside the rootfs, a
  file outside it and the rootfs itself — closed, file, dir — by `recvmsg`,
  by `recvmmsg`, and through a 16 KiB buffer that takes the family check,
  then an AF_INET `IP_PKTINFO` record through the same buffer (m25).

- [x] **M60 — an l2s link was whatever its target's text said it was**
  The emulation recognizes its links by their target, and took any target
  whose last component parsed as `.l2s.<digits>` at its word: an absolute one
  named the data file as it stood, wherever that was. A target is text the
  guest writes — `symlinkat` checked only the link's own name — so
  `ln -s /elsewhere/on/the/host/.l2s.1 x` made `lstat` of `x` describe a host
  file outside the rootfs, `chown -h`/`utimensat`/an `O_NOFOLLOW` open reach
  it, and `rm x` decref and delete it; another rootfs's store is exactly such
  a place. The same reading made a rootfs copied with `cp -a` operate on the
  original's store (its links still name it, and it is there), so the copy's
  `rm` deleted the original's data under names the copy never had. A link
  is the emulation's now only where its target is one the emulation could
  have written (`l2s_locate`, used by every recognition site — resolve,
  listing, rename fix-up, fd link count, the resolver's untranslation): a
  bare `.l2s.<ino>` with its data beside it, or a canonical absolute path to
  a data file in a place of the guest's own (the view, or the view the run
  started with, which a guest chroot narrows — `cng_l2s_home`), or a path
  into some other `…/.l2s` store, which self-heals onto this rootfs's store
  without the named file being looked at; the digits must be exactly the
  number's, and the data a regular file. Everything else is an ordinary
  symlink. The guest may no longer write such a target at all: `symlinkat`
  refuses one whose last component is in the grammar (data or marker) with
  `ENOENT`, as the names themselves are, judged on a copy of the target that
  is then the one the kernel gets. The `linkat(fd, "", …, AT_EMPTY_PATH)`
  fallback used to substitute the descriptor's real path for its `/proc`
  link whenever the file was live, and the first-link path then renamed a
  file outside the view into the store and left a symlink in its place; the
  substitution now needs a path the guest has a name for, and
  `cng_l2s_link` copies (materialize) rather than move a source that is not
  in a place of the guest's own. Legs: `-t l2stest` `l2s-spoof` (a planted
  outside target is a symlink to every call, the outside file untouched;
  the refusals; an outside descriptor linked by copy), `l2s-copied`,
  `l2s-home`; m10 differential "a copied rootfs leaves the original's groups
  alone" (fails on the previous build: the original's names dangle).

- [x] **M61 — the /dev/shm stand-in adopted whatever sat on its name**
  Where the host has no `/dev/shm` (Android), or `CNG_DEVSHM_FORCE_TMP=1` is
  set, the guest's `/dev/shm` is a per-uid directory of ours,
  `<candidate>/chroot-ng-shm.v1.<uid>`, with `/tmp` the last candidate — a
  name anyone can predict in a directory every user shares. `mkdirat`'s
  `EEXIST` was the end of the question and the check after it followed
  symlinks, so another user's directory made ahead of us, or a symlink to
  one where the host follows it, became the guest's `/dev/shm`: its POSIX
  shm objects and semaphores stored where that user could read, replace or
  delete them, or refused outright. One is adopted now only as procreg
  adopts its shared file: opened `O_PATH|O_DIRECTORY|O_NOFOLLOW`, a
  directory, owned by our uid and with no group or other bits
  (`shm_dir_ours`), in a candidate owned by us or root that nobody else can
  rename an entry out of — not writable by others, or sticky
  (`shm_parent_safe`). Anything else moves the search to the next
  candidate; a name squatted in every candidate leaves the guest without a
  `/dev/shm`, the degraded answer the stand-in already had, since nothing
  keeps a name in a shared directory from being taken first and a private
  name would split the directory every invocation shares. m14 legs: a
  0777 directory on the name, a symlink on it, and a 0777 non-sticky
  candidate are each passed over for the next candidate (all three were
  adopted by the previous build).

- [x] **M62 — an emulated netlink slot judged stale was claimed from its next occupant**
  The table of emulated `NETLINK_ROUTE` sockets retires a slot lazily — close
  is not trapped — whenever a thread finds one whose fd no longer names its
  socket, and finding, judging and claiming were three steps with nothing
  tying them to one occupant. Another thread could retire the slot and open
  a new socket in it between a judgement and the claim, and the claim, a
  compare-and-swap from the same "live" it had read, went through: the new,
  live socket was released under its owner, its pair peer closed and the
  slot handed to a third. The owner's next call reached the host as an
  AF_UNIX socket's — `bind` `EINVAL` — which is the four-thread leg of
  `nlmany` failing now and then under load (1–2 in 80 loaded runs, on the
  build before M60 too). A lookup that retired a stale slot holding the
  number it was asked about also stopped there, so a live socket a new
  owner had been given that number in another slot was taken for one that
  was not emulated. The state word counts the claims made on the slot above
  its two claim bits now; a live slot is judged on a snapshot of its fd and
  identity taken between two reads of one state (`slot_snap`) and claimed
  from exactly that state (`slot_claim`), the verdict asked once more under
  the claim (`slot_retire`); a slot retired for reuse stays claimed rather
  than passing through FREE, and a lookup goes on past a retired slot. m16
  leg: `tests/guests/nlchurn.c`, eight threads opening, binding, naming and
  closing 3600 sockets — about twenty went wrong a run, none now.

- [x] **M63 — two threads relaying on one netlink socket lost a descriptor**
  An emulated `NETLINK_ROUTE` socket relayed its dumps through a host
  netlink socket it kept for its life, replaced when the number stopped
  naming it (the exec sweep closes it; so does a guest's close-all loop).
  Two threads finding it gone at once each opened one and wrote its
  identity into the slot *before* the compare-and-swap that published it,
  so the loser could overwrite the winner's record: the published socket
  then failed its own identity check, was taken for stale by the next call
  and replaced without a close — a monitor descriptor lost per race, in the
  guest's table (`tests/guests/nlrace.c` measures ~270 over 60 rounds of
  eight threads on the previous build). Shared, the socket was also shared
  by the threads' dumps: the kernel runs one dump per socket (a second is
  `EBUSY`), each thread's reads took the other's replies, and a dump that
  timed out left its tail for the next request. The owner chose a socket
  per request over a guarded shared one: `relay_open`/`relay_close` give
  each relayed GET its own unbound socket, closed after the request where
  the number still names it (the identity discipline of M47; the address
  enumeration's throwaway socket closes the same way now), and the slot
  keeps only the guest's end and the pair peer — so there is no relay
  state to publish, and none to share. About three syscalls more per
  relayed request. m16 leg: `nlrace` (rounds=60 left=0 leaked=0).

- [x] **M64 — a refreshable /proc descriptor was published before its facts**
  A refreshable synthesized file (`/proc/uptime`, `loadavg`, `stat`) is a
  memfd in a small reserved descriptor range, tracked by an entry of three
  facts — the number, the kind of file it regenerates as, and the memfd's
  identity — so a read from offset 0 can regenerate it. The number was
  published by a compare-and-swap and the other two written after it, so
  a sibling thread reading the new descriptor in between (the range is
  small, its numbers easy to hit) judged it against the identity the entry
  had before: a mismatch that retired the entry, and the file never
  refreshed again — or, with ARM's ordering, a matching identity beside the
  previous kind. A stale verdict was retired with a plain store too, which
  could clear an entry another thread had just made there. Each entry
  carries a sequence now (even settled, odd being rewritten): readers take
  the three facts between two reads of an unchanged even sequence
  (`pf_snap`), and every writer — tracking, reclaiming, retiring — claims
  the entry by a compare-and-swap from the very sequence it judged
  (`pf_claim`), so what it replaces is what it looked at; nobody waits on a
  claim, which the `-R` tier's same-thread re-entry would make a deadlock.
  Tracking takes the entry the number itself had first (stale by the new
  file's identity; left beside the new entry it was what the next read
  retired, skipping that refresh), and a read that retires a stale entry
  goes on looking for the live one. Legs: `-t proctest` "synth fd reused
  by another kind" (a number moved from loadavg to uptime refreshes, as
  uptime), and `tests/guests/procrace.c` in m11 (reader threads pread the
  whole range while batches of uptime files are opened into it; a rewind
  that reads an unmoved clock is a lost refresh — the previous build loses
  one in some runs, the window being a few instructions wide).

- [x] **M65 — a link out of a :ro bind was a writable way into its file**
  A link cannot span mounts: the kernel answers `EXDEV` for one whose
  source is on another mount than the new name's directory, after the new
  name's own verdict (`EEXIST`, a missing directory) and before anything
  else about the source. A `:ro` bind is a mount of its own however the
  host has it, and only a destination under one was refused, "linking
  *from* a read-only mount is allowed, as on Linux" — which on Linux it is
  only within that mount, where the new name is `EROFS`. So `ln /ro/f
  /tmp/g`, the host's filesystem permitting (the bind and the rootfs on one
  filesystem), made a real hardlink, and writing through `/tmp/g` changed
  the `:ro` file; under `-l` the fallback went further and moved the file
  into the store, leaving a symlink in the bind. A source under a `:ro`
  bind is `EXDEV` now (`link_src_ro`): by name, through a followed name, by
  descriptor (asked of the path the kernel reports for it — the file's
  mount, not `fd_link_ro`'s reopen rule), and for an l2s name by where its
  data is; after the new name's verdict (`link_dst_verdict`), and never
  handed to the fallback. By descriptor the kernel's verdict on the source
  stays the kernel's (the flag's capability rule before 6.10, `EBADF`): it
  is asked with `/` for the new name, which `filename_create` answers
  `EEXIST` once the source has passed (measured on 6.17), so nothing is
  created. A group such a link already made — data under the bind, a
  writable name outside — is read-only through that name too: the no-follow
  mutators ask `:ro` of the data beside the name (`l2s_ro`), a link from it
  is `EXDEV`, and its unlink leaves the count on the `:ro` mount alone.
  `-t dtest rolink` in m5b, `:ro` and rw control: by name, followed, by
  descriptor and through the forced fallback, the destination's verdicts
  first, the bind's file untouched; and a planted pair refusing utimensat,
  a no-follow chown, a no-follow write open and a link, with its count
  kept (the previous build: ten failures, the bind's file turned into a
  symlink into the store).

- [x] **M66 — a hardlink of the emulation's own file was the host's to make**
  Where the host permits hardlinks, a `linkat` of an l2s name went to the
  host like any other: without `AT_SYMLINK_FOLLOW` it linked the
  emulation's *symlink* — a second name with the same target that the
  group's marker never counted, so after the counted names were removed
  the decref deleted the data under it (`ln a b` in a group `{a, c}`, then
  `rm a c`: `b` dangles). Followed, or by a descriptor opened through a
  name, it linked the backing file, which then counted its links apart
  from the group's. Groups meet such a host whenever a rootfs made on one
  that refuses links is used on one that does. The emulation's own file —
  one of its links named without following, its backing file however
  reached (`link_src_l2s`, i.e. `cng_l2s_stat` answering for it) — is now
  linked by the emulation whatever the host would allow, which joins the
  group; by descriptor, after the kernel's verdict on the source, asked as
  M65 asks it. `-t l2stest` `l2s-hostlink` with the host's link unblocked:
  by name, followed and by descriptor, each joins the group (nlink, inode),
  and the data outlives the removal of the other names.

- [x] **M67 — a segment whose end rounded up to nothing reserved nothing**
  The header pass refused a `PT_LOAD` whose `p_vaddr + p_memsz` wrapped,
  and one whose page-rounded end came out below its start. A sum within a
  page of the top of the address space is neither: it does not wrap, and
  `cng_page_up` turns it into 0 — which is not below a start of 0. So
  `p_vaddr` 0 with `p_memsz` a page short of 2^64 passed with a span of 0.
  Without `-R` that was an mmap of length 0 and an `EMAP`; with it, the
  trampoline pool on top of the span made the reservation a pool-sized
  mapping that succeeded, and the segment's whole file part was read into
  it — past the pool, into whatever the kernel had placed after it (an exec
  of such a file from a shell died "with the new image already mapped over
  the old one"). `cng_page_end` (loader.h) now answers both ways an end can
  fail to be an address, and the header pass refuses either with
  `CNG_LOAD_EFORMAT` (ENOEXEC, the caller alive); `execmap.c`'s span
  arithmetic, which had the same gap but only placed a pool with it, asks
  the same helper. `-t elfspan` `roundwrap` in m3, with `-R` off and on
  (the previous build: `plain=-4 rewrite=0`).

- [x] **M68 — a magic link's expansion was cut to fit, and named another path**
  The walk rewrites `/dev/fd[/…]` and `/dev/std*` to their `/proc/self/fd`
  spelling in place, and `/proc/<pid>/{exe,cwd,root}` to the guest-visible
  target plus whatever follows the link — both longer than what they
  replace, and both built with `cng_strlcpy` whose truncation nobody asked
  about. The `/dev/fd` one is reachable: a guest whose cwd is `/dev/fd`
  (chdir records it by that name) names `/dev/fd/<its whole relative
  path>` there, so a 4082-byte name lost its last byte and resolved as the
  4081-byte one — a run of zeros and the descriptor digit after it came
  out as descriptor 0, and a trailing tail of junk was dropped to leave a
  real descriptor number, which an exec then ran (measured: the host says
  ENOENT). `dev_magic` now answers -1 when the rewrite does not fit and
  `proc_magic` `PROC_MAGIC_LONG` — which also covers a canonicalization that
  overflowed, which used to fall through to an ordinary lookup with the
  walk's prefix half-overwritten — and the walk answers `-ENAMETOOLONG`, the
  `XLATE_TOOLONG` rule. A too-long exe/cwd/root is still a magic link to
  `RESOLVE_NO_MAGICLINKS` and to a scoped lookup, which refuse it first.
  m5 pins both sides of the boundary through the resolver with the cwd in
  `/dev/fd` (the previous build resolves the longer name to the shorter).

- [x] **M69 — a /proc number with a leading zero was the number to us**
  procfs looks its numbered entries up with `name_to_int()`, which refuses
  a leading zero: `/proc/self/fd/05` and `/proc/0<pid>/exe` do not exist,
  whatever descriptor 5 and process `<pid>` are (measured: ENOENT). Where
  the monitor answers such a name itself it read the digits as the number
  — `parse_int_run` for the fd links, exe/cwd/root, the fd shortcut an
  exec takes (`cng_proc_self_fd`), and procfs's `pid_tail` for the files it
  synthesizes — so an exec of `/proc/self/fd/0<n>` ran descriptor `<n>`, a
  readlink of `/proc/0<pid>/exe` reported the program, and
  `/proc/0<pid>/cmdline` opened. Found while fixing M68, where the zero run
  a truncation left behind was what made the wrong descriptor executable.
  Both parsers now take a number the way procfs names it (`0` itself, or
  no leading zero), and `proc_magic` asks `parse_int_run` too, so a digit
  run procfs has no entry for is an ordinary lookup rather than an fd link
  `RESOLVE_NO_MAGICLINKS` would refuse. `tests/guests/procnum.c` in m11,
  differential against the same guest with nothing in the way (the previous
  build reads the cmdline, exe and cwd of `/proc/0<pid>` and runs the
  program from `/proc/self/fd/0<n>`).

- [ ] **M10 — (optional) user_notif supervisor tier for kernels >= 5.0**

## Testing notes
- `make` builds (cross on x86_64, native on AArch64/Termux); `make run
  ARGS="..."` runs the result, under qemu-aarch64 only where the host needs it.
- `make test` runs `tests/run.sh`. It runs on x86_64 (cross + qemu), on native
  AArch64 Linux, and under Termux; `tests/lib.sh` resolves every host
  difference (emulator, guest toolchain and link mode, which translation tier is
  live, rootfs images) and the milestone scripts assert against what it found.
  See `tests/README.md`.
- M16 is the one milestone whose subject exists only on the target, so it asks
  the unemulated guest which host it is on and asserts a different thing on each:
  where raw rtnetlink works it must be reproduced byte-for-byte and must not
  engage unforced; where the kernel refuses it (a device) there is nothing to
  diff against, so the assertions are that the emulation engages *unforced* and
  turns each refusal into a working dump — which is the on-device acceptance bar
  and the one thing a devbox cannot check.
- qemu-user does NOT emulate guest seccomp filters faithfully → M5's mechanism
  needs simulated-SIGSYS unit tests + real-hardware validation. Loader (M3/M4)
  and path logic are fully qemu-testable. On an AArch64 host the harness detects
  the live filter (`CNG_SECCOMP_LIVE`) and flips the legs that depend on it —
  M8's no-`-R` control, for instance, expects chroot-ng to refuse to enter the
  guest under qemu (no filter and no `-R` means nothing intercepts; see M42)
  and a seccomp-translated open on a real kernel.
