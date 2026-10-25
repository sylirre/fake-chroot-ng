# chroot-ng test harness

```sh
make test          # or: sh tests/run.sh
```

The suite runs on three hosts. `tests/lib.sh` resolves every difference between
them at startup and prints what it found; the milestone scripts (`m*.sh`) assert
against that rather than against a hardcoded devbox.

| host | how binaries run | seccomp/SIGSYS tier | guest toolchain |
|---|---|---|---|
| Linux x86_64 | `qemu-aarch64[-static]` | **inert** — qemu-user rejects the filter, so `-R` svc-rewriting carries translation; a run that needs a monitor and has no `-R` is refused | `aarch64-linux-gnu-gcc*`, static-PIE |
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

Common reasons: no AArch64 guest toolchain; an Alpine/Debian rootfs image that
could not be provisioned (no network, `CNG_ROOTFS_FETCH=0`); no
host-native `arm64chroot` oracle (M10 is differential against it); the host has
no working SysV shm to diff against (Android drops it); the guest links
dynamically *and* the seccomp tier is inert, so neither tier reaches libc's own
`svc` sites.

### On Termux (Android)

The device is the strictest host, and most of its skips are the platform
refusing something rather than a leg being unsound. A skip is only ever taken
for a fact the run observed — the driver or the shell says which — never for an
expected failure:

* **Android's seccomp filter blocks syscalls** that the kernel has (`openat2`,
  `faccessat2`, `name_to_handle_at`, `fchmodat2`, `rseq`, `set_robust_list`, the
  6.13 `*xattrat` family). The emulation answers `ENOSYS` as an older kernel
  would; a leg that needs the real call, or a host-built reference that issues
  it, skips. `openat2` is the exception: libc no longer falls back from it, so
  it is emulated, here and on any kernel without it, and m24 holds the
  emulation to the kernel's recorded answers (`CNG_OPENAT2_DENY=1` takes it as
  refused anywhere, so a native host diffs it against its own kernel). The uid
  and gid setters are refused too (all but `setresuid`), and
  answered from the real ids as the kernel would answer an app's process (m9;
  `CNG_SETID_DENY=1` takes them as refused anywhere, and
  `tests/guests/ambtrap.c` installs such a filter where seccomp is live).
* **SELinux hides or refuses what a kernel would allow**: hardlinks (`ln` is
  `EACCES`, so the l2s fallback is what runs), `stat` and `open` of
  `/proc/{loadavg,uptime,stat,version}` and `/proc/sys/kernel/overflow{u,g}id`
  (they are synthesized for that reason, and so is their `stat` —
  `CNG_PROC_DENY_STAT=1` forces that path elsewhere, `CNG_OVERFLOWID_SYNTH=1`
  the open of the sysctls),
  reopening a memfd through `/proc/self/fd/N` (so a synthesized fd's read-only
  view is an unlinked file in a private directory under `$TMPDIR` instead —
  `CNG_PROCFS_REOPEN_DENY=1` forces that elsewhere — and a guest's own
  read-only reopen of its memfd is refused, as there, except for the script a
  `#!` exec ran from one), and opening `/dev/pts`. The ioctls on a pty are a whitelist as
  well: `TCGETS2` and the other termios2 commands are `EACCES`, which the
  monitor answers from `TCGETS`/`TCSETS*` (m27; `CNG_TERMIOS2_DENY=1` forces
  that path on a host that serves them), and so is `TIOCGSID` on a slave and
  on a pipe, answered from `TCGETS`, `TIOCGPGRP` and `getsid`
  (`CNG_TIOCGSID_DENY=1`). qemu-user answers `TIOCGSID` with success and no
  session, so m27 asks the host once, outside the monitor, and judges only the
  forced rows there. Android 8's list lacks `TCSETSF` too (`tcsetattr` with
  `TCSAFLUSH`), answered from `TCFLSH` and `TCSETSW` (`CNG_TCSETSF_DENY=1`).
  Android 15's is shorter still for what is no terminal, where a kernel says
  `ENOTTY` to all of them: on a pipe `TCGETS` alone, on a directory none at
  all. The monitor's fallbacks take a refused `TCGETS` on what is no
  character device for `ENOTTY`, and m27's pipe and directory rows are where
  a native run on the device differs from the expected text.
* **The kernel is built without checkpoint/restore support**: no
  `/proc/self/timers`, and `PTRACE_O_SUSPEND_SECCOMP` is `EINVAL`.
* **`$TMPDIR` is inside `$PREFIX`, which the harness binds** for a guest's
  linker. A scratch directory the guest must *not* be able to name therefore has
  to be moved out of the binds (`cng_outside_binds`), and the arm64chroot oracle
  needs its rootfs there too, because it spells a guest path with the longest
  host prefix it finds.
* **`LD_PRELOAD` carries `libtermux-exec`**, which answers some `execve`
  failures itself. A host-built reference that stands for "the kernel" is run
  through `kref`, which drops it.
* **An older Android is older all the way down** (Android 8 on a 3.18
  kernel). There is no `/bin`, so a script the host kernel runs names the
  host's own `sh` (`$HOST_SH`); the ramdisk may carry a `/lib` of its own, so
  a guest's binds there are only the directories bionic's linker reads; its
  libc has no `posix_spawn` (API 28). The filter traps every syscall newer
  than itself — `statx`, the pidfd calls — and a leg that needs one skips on
  the `ENOSYS` (`-1 = not issuable here` in a driver's line). The kernel
  predates what some references are compared for — `execveat` (3.19), the
  `NoNewPrivs` status line (4.10), `PTRACE_O_SUSPEND_SECCOMP` (4.3, which the
  emulation then refuses as that kernel does), a recvmsg name of length 0
  and an iovec count past `UIO_MAXIOV` read as newer kernels read them — and
  those comparisons skip, the emulation answering as the 6.1 it advertises.
  SELinux refuses `accept` on a netlink socket before the family answers it.
  Termux ships `<sys/sem.h>` in a package of its own
  (`libandroid-sysv-semaphore`) and `libandroid-shmem` turns the shm calls
  into macros for an in-process emulation; `tests/guests/sysvipc.h` builds
  the SysV guests on raw syscalls either way.

## Environment knobs

| variable | meaning |
|---|---|
| `BIN` | binary under test (default `build/chroot-ng`) |
| `QEMU` | emulator command. Unset = auto-detect (none on an AArch64 host). Set **empty** to force direct execution on a cross host that runs AArch64 binaries another way (a `binfmt_misc` handler) |
| `GUESTCC` | compiler for `tests/guests/*.c`. Unset = probe a candidate list |
| `GUESTLD` | link mode for those guests: `-static-pie`, `-static`, or empty for dynamic. Unset = try each in that order and keep the first that both links an AArch64 binary and runs here |
| `GUEST_BINDS` | extra `-b SRC:DST` args a dynamic guest needs to find its ELF interpreter inside a synthetic rootfs. Auto-derived (`/system`, `/apex`, `/linkerconfig`, …) when the guest is not static |
| `CNG_ROOTFS_DIR` | where the `alpine/` and `debian/` rootfs images are provisioned (default `tests/.cache/rootfs`) |
| `CNG_ROOTFS_FETCH` | `0` = never download a rootfs tarball; one already in `$CNG_ROOTFS_DIR/downloads/` is still unpacked |
| `CNG_ALPINE`, `CNG_DEBIAN` | individual rootfs paths, used as they are instead of provisioning one |
| `CNG_ORACLE` | `arm64chroot` binary for M10's real-hardlink differential. Dropped automatically if its machine does not match the host — it is a host-native emulator, not an AArch64 program |
| `CNG_SYSROOT` | sysroot holding the AArch64 ELF interpreter for M4 (cross host default `/usr/aarch64-linux-gnu`; empty on an AArch64 host, where it is on the system paths) |

`cng_dyn_binds` sets `GUEST_DYN_BINDS`, the same list for a guest that is
dynamic even where the probed link mode is static — M23 builds one deliberately,
since the noexec `.so` path only exists for a guest whose own `ld.so` maps
libraries.

The suite provisions its rootfs images itself, under `$CNG_ROOTFS_DIR`. Each one
is a pinned tarball (`cng_rootfs_pin` in `tests/lib.sh`) that is downloaded
once into `downloads/`, checked against its sha256, and unpacked under its own
name:

* **`alpine/`** is the stock Alpine minirootfs (~3.5 MB), provisioned at
  startup. The suite only ever calls `bin/busybox` inside it.
* **`debian/`** is the arm64 layer of the official `debian:trixie-…-slim` image,
  fetched from Docker Hub (~30 MB). It is provisioned only when M10 reaches its
  Debian leg, which needs the arm64chroot oracle as well.

A tree is stamped with the hash it came from (`.alpine.sha256` beside it), so
bumping a pin replaces it on the next run. A tree that carries no stamp was
staged by hand, and is used as it is and never touched. Runs that share
`$CNG_ROOTFS_DIR` take turns provisioning. On a host without network access,
copy the tarball into `downloads/` yourself; with `CNG_ROOTFS_FETCH=0`, the
legs skip instead of trying the network. CI (`.github/workflows/tests.yml`, a
hosted Linux AArch64 runner) caches `downloads/` between runs.

## Adding a milestone script

Source-level contract for a new `tests/mNN_*.sh`:

- `run` / `run_t SECS` — invoke chroot-ng; `emu` / `emu_t SECS` — invoke any
  other AArch64 program. Never spell `$QEMU` or `build/chroot-ng` directly.
- `guest_cc OUT SRC` (rc 2 = no toolchain) or `guest_cc_report OUT SRC`, which
  emits the right diagnosis on its own. Never invoke a compiler by name.
- `guest_xlate_ready WHAT` before any leg that needs a compiled guest's *own*
  path syscalls to be translated.
- `check`, `check_contains`, `check_absent`, `skip` for reporting — `skip` keeps
  the count honest.
- A guest inherits no host environment (M17-16). What a guest program must see
  goes in with `-E VAR=VAL`; a `VAR=val run …` prefix reaches chroot-ng only,
  which is how the `CNG_*` knobs are set.
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
