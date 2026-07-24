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

- [ ] **M3 — `ul_exec` loader: static binaries**
  Parse ELF64, map `PT_LOAD` into anon RW→RX, build stack/auxv, jump to entry.
  Runs a static AArch64 binary loaded as *data* (the `noexec` defeat). Testable
  under qemu.

- [ ] **M4 — `ul_exec` loader: dynamic binaries**
  Load `PT_INTERP` (`ld.so`), set `AT_BASE`, hand control to the interpreter.
  glibc + musl dynamic guests.

- [ ] **M5 — seccomp filter + SIGSYS monitor + path-translation core**
  Install BPF (trap path syscalls, allow gate IP range), SIGSYS handler,
  bind/rootfs path translation. Handler unit-tested via simulated SIGSYS;
  end-to-end on real AArch64 kernel.

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
