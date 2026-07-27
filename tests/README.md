# chroot-ng test harness

```sh
make test          # or: sh tests/run.sh
```

The suite runs on three hosts. `tests/lib.sh` resolves every difference between
them at startup and prints what it found; the milestone scripts (`m*.sh`) assert
against that rather than against a hardcoded devbox.

| host | how binaries run | seccomp/SIGSYS tier | guest toolchain |
|---|---|---|---|
| Linux x86_64 | `qemu-aarch64[-static]` | **inert** — qemu-user does not apply a guest filter, so `-R` svc-rewriting carries translation | `aarch64-linux-gnu-gcc*`, static-PIE |
| Linux aarch64 | directly | **live** | native `gcc`/`cc`/`clang`, static-PIE |
| Termux (Android aarch64) | directly | **live** | `clang` (bionic); often dynamic-only |

Which tier is live is not inferred from `uname` — the harness runs
`chroot-ng --probe` and reads the answer. Legs whose expected outcome depends on
it (M8's no-`-R` control) flip accordingly.

## Skips

A leg a host genuinely cannot exercise prints `skip <reason>` and is counted
separately in the summary, so a partial run never reads like full coverage:

```
== summary: 312 passed, 0 failed, 1 skipped ==
```

Common reasons: no AArch64 guest toolchain; no Alpine/Debian rootfs image; no
host-native `arm64chroot` oracle (M10 is differential against it); the host has
no working SysV shm to diff against (Android drops it); the guest links
dynamically *and* the seccomp tier is inert, so neither tier reaches libc's own
`svc` sites.

## Environment knobs

| variable | meaning |
|---|---|
| `BIN` | binary under test (default `build/chroot-ng`) |
| `QEMU` | emulator command. Unset = auto-detect (none on an AArch64 host). Set **empty** to force direct execution on a cross host that runs AArch64 binaries another way (a `binfmt_misc` handler) |
| `GUESTCC` | compiler for `tests/guests/*.c`. Unset = probe a candidate list |
| `GUESTLD` | link mode for those guests: `-static-pie`, `-static`, or empty for dynamic. Unset = try each in that order and keep the first that both links an AArch64 binary and runs here |
| `GUEST_BINDS` | extra `-b SRC:DST` args a dynamic guest needs to find its ELF interpreter inside a synthetic rootfs. Auto-derived (`/system`, `/apex`, `/linkerconfig`, …) when the guest is not static |
| `CNG_ROOTFS_DIR` | directory holding `alpine/`, `debian-fresh/` rootfs images |
| `CNG_ALPINE`, `CNG_DEBIAN` | individual rootfs paths, overriding the search |
| `CNG_ORACLE` | `arm64chroot` binary for M10's real-hardlink differential. Dropped automatically if its machine does not match the host — it is a host-native emulator, not an AArch64 program |
| `CNG_SYSROOT` | sysroot holding the AArch64 ELF interpreter for M4 (cross host default `/usr/aarch64-linux-gnu`; empty on an AArch64 host, where it is on the system paths) |

Rootfs images are searched in `$CNG_ROOTFS_DIR`, `tests/.cache/rootfs/`,
`$HOME/arm64chroot/tests/.cache/rootfs/` and `$HOME/arm64-rootfs/`.

## Adding a milestone script

Source-level contract for a new `tests/mNN_*.sh`:

- `run` / `run_t SECS` — invoke chroot-ng; `emu` / `emu_t SECS` — invoke any
  other AArch64 program. Never spell `$QEMU` or `build/chroot-ng` directly.
- `guest_cc OUT SRC` (rc 2 = no toolchain) or `guest_cc_report OUT SRC`, which
  emits the right diagnosis on its own. Never invoke a compiler by name.
- `guest_xlate_ready WHAT` before any leg that needs a compiled guest's *own*
  path syscalls to be translated.
- `check`, `check_contains`, `skip` for reporting — `skip` keeps the count
  honest.
- `elf_type` / `elf_machine` / `elf_has_interp` instead of `file(1)`, which a
  bare Termux does not have.
- Prefer a directory you created over a host path (`/usr`, `/tmp`, `/run` and
  `/etc/passwd` are not universal), and derive an expected errno from a control
  run rather than pinning one that depends on the filesystem.
- When a leg is gated on a host capability, test *that* capability, not a proxy
  for it. M16 gated its rtnetlink differential on `getifaddrs` succeeding — but
  bionic has its own fallback for the very restriction being emulated, so on a
  device `getifaddrs` succeeds while `bind`/`sendto` on a NETLINK_ROUTE socket
  are refused; the gate took the devbox branch there and failed four legs for
  exactly the reason the emulation exists. Where a capability splits hosts,
  give each side its own assertions rather than skipping one.
- The `-t` debug subcommands that build their own filesystem view (`_dtest`,
  `_exectest`) accept `-b SRC:DST[:ro]`, so `$GUEST_BINDS` can be spliced into
  them exactly as into a real invocation.
