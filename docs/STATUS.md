# chroot-ng — status & roadmap

Milestones are committed individually. Each builds on the previous.

## Legend
- [x] done and tested
- [~] in progress
- [ ] not started

## Milestones

- [x] **M1 — scaffolding + freestanding runtime + CLI skeleton**
  Cross build (aarch64-linux-gnu) + qemu run. Own `_start`, syscall gate
  (single `svc`), mem/str helpers, mini-printf, `version`/`help`/`probe`/`run`
  dispatch. Verified under qemu-aarch64.

- [x] **M2 — capability probe** (`chroot-ng probe [path...]`)
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
  (no rootfs escape), cwd-relative resolution. `_xlate` debug cmd, 9 tests.

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
  Validated under qemu via `_dtest` (dispatch translate+reissue, escape block)
  and `_sigtest` (signal round-trip + sigcontext offsets). The seccomp *trap*
  itself is inert under qemu-user and MUST be confirmed on a real AArch64 kernel
  (the `probe` filter test covers install permission there).

- [ ] **M6 — execve/execveat emulation**
  Re-run the loader in-process so filter + handler survive program replacement.

- [ ] **M7 — fidelity: uid/gid faking, /proc self-path fixups, link2symlink**

- [ ] **M8 — performance: AoT `svc` rewriting in the load/mmap hook**

- [ ] **M9 — (optional) user_notif supervisor tier for kernels >= 5.0**

## Testing notes
- `make` cross-compiles; `make run ARGS="..."` runs under qemu-aarch64.
- `make test` runs `tests/run.sh`.
- qemu-user does NOT emulate guest seccomp filters faithfully → M5's mechanism
  needs simulated-SIGSYS unit tests + real-hardware validation. Loader (M3/M4)
  and path logic are fully qemu-testable.
