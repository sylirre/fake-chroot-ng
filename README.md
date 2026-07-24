# chroot-ng

Ptrace-free `chroot`/bind-mount emulation for **rootless, SELinux-restricted
Android without user namespaces** — the environment where `proot` works but its
per-syscall `ptrace` overhead hurts, and where `LD_PRELOAD` tricks fail on
static / Go / Rust / raw-syscall binaries.

Instead of a ptrace tracer, chroot-ng intercepts only the path-bearing syscalls
in-process via **seccomp `RET_TRAP` → `SIGSYS`**, and runs guest programs with
its own **userland ELF loader** so it can also execute binaries off `noexec`
mounts. See [docs/DESIGN.md](docs/DESIGN.md) for the full rationale and
[docs/STATUS.md](docs/STATUS.md) for the milestone roadmap.

> Status: early development. See `docs/STATUS.md` for what works today.

## Target

- AArch64, Linux 3.5+ (real floor), rootless, SELinux-confined, no `user_ns`.
- Guest binaries on a true `noexec` mount.
- Works for glibc/musl (dynamic & static) and Go/Rust without version pinning.

## Build

Requires an `aarch64-linux-gnu` cross toolchain and `qemu-aarch64` for testing:

```sh
make                       # cross-compile -> build/chroot-ng
make run ARGS="--version"  # run under qemu-aarch64
make test                  # run the test harness
```

Override the compiler/emulator if needed:

```sh
make CC=aarch64-linux-gnu-gcc-12 QEMU=qemu-aarch64
```

## Usage (evolving)

```
chroot-ng [options] <rootfs> <program> [args...]   # run a guest program
chroot-ng --probe [path...]                        # report caps, then exit
chroot-ng --help                                   # full option reference
```

`<rootfs>` is a host directory holding an AArch64 userland (`/` runs
host-native binaries directly); `<program>` is an absolute path inside it.
Common options: `-0/--fake-root` (fake uid/gid 0), `-b/--bind G:H` (bind guest
path G to host H), `-R/--rewrite` (ahead-of-time `svc` rewriting).

```sh
chroot-ng -0 ./rootfs /bin/sh
```

Run `chroot-ng --probe` on any target device **first** — the whole in-process
design depends on the SELinux `execmem` permission being granted.

## License

Not yet chosen; to be decided by the project owner before any release.
