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

On an x86_64 host: an `aarch64-linux-gnu` cross toolchain plus `qemu-aarch64`
for running what it builds. On an AArch64 host (native Linux, or Termux with
`clang`): just the native compiler — no emulator is involved.

```sh
make                       # -> build/chroot-ng
make run ARGS="--version"  # run it (under qemu only where the host needs one)
make test                  # run the test harness
```

Override the compiler/emulator if needed:

```sh
make CC=aarch64-linux-gnu-gcc-12 QEMU=qemu-aarch64
```

The test harness runs on all three hosts and adapts to each: it picks the
emulator (or none), finds an AArch64 guest toolchain and the link mode that
works there, and asks the binary which translation tier is actually live —
the seccomp/SIGSYS tier only exists on a real AArch64 kernel, so on a cross
host `-R` svc-rewriting is what carries translation. Legs that a host cannot
support (no guest toolchain, no rootfs image, no SysV shm to diff against) are
reported as `skip` and counted separately from passes. See
[tests/README.md](tests/README.md) for the environment knobs.

## Usage (evolving)

```
chroot-ng [options] <rootfs> <program> [args...]   # run a guest program
chroot-ng --probe [path...]                        # report caps, then exit
chroot-ng --help                                   # full option reference
```

`<rootfs>` is a host directory holding an AArch64 userland (`/` runs
host-native binaries directly); `<program>` is an absolute path inside it.
Common options: `-u/--fake-id[=ID]` (fake user identity — `ID` is a `uid` or
`uid:gid`, defaulting to `0:0` root), `-b/--bind SRC:DST[:ro]` (expose host
directory SRC at guest path DST, read-only with `:ro`), `-E/--env VAR=VAL` (set a
guest environment variable — see below), `-l/--link2symlink` (emulate hardlinks where the host refuses `link(2)`),
`-R/--rewrite` (ahead-of-time `svc` rewriting), `--no-proc` (turn off the `/proc`
emulation described below), `--no-dev` (turn off the `/dev` passthrough),
`--share-abstract-sockets` (don't isolate abstract AF_UNIX names per rootfs), `--shared-proc` (share the process view between
independent invocations of the same rootfs, for both the process view and the
System V shm namespace).

`/proc` is visible to the guest without a bind, and describes the guest rather
than chroot-ng: host processes are hidden from it (by path and from listings,
including under an explicit `-b /proc:/proc`), `cmdline`/`environ`/`auxv`
report the guest program (no real `execve` ever happens, so the kernel's copies
would name the chroot-ng invocation), `mounts`/`mountinfo` describe the rootfs
and its binds instead of the host's mount namespace, `maps` and the `fd` links
are mapped back to guest paths, and `loadavg`/`uptime`/`stat` are synthesized
where the host denies them (as Android does). Separate invocations normally
hide each other's processes; `--shared-proc` keys the process registry by the
rootfs instead — served diskless by a per-rootfs broker daemon that exits by
itself once the last guest is gone — so `ps`/`top` in one session see the
guest processes of another.

`/dev` works the same way, and for the same reason: a rootfs directory tree
ships no device nodes and `mknod` needs privileges we lack. A fixed whitelist —
`null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx`, `console`, `pts/*`,
`shm/*`, `fd/*`, `std{in,out,err}` — resolves to the host's nodes, and everything
else under `/dev` comes from the rootfs, so the guest cannot reach the host's
block devices. This is deliberately narrower than the `-b /dev:/dev` people
otherwise reach for, which exposes the host's whole `/dev`. Because these nodes
and the `-b` mount points are pure path-resolution overlays with no directory
entry behind them, `getdents64` splices them into listings — otherwise `ls /dev`
shows nothing while `/dev/null` opens fine, and a bind destination stays
invisible to anything that enumerates before opening. `--no-dev` turns the zone
off.

**AF_UNIX sockets** are contained like any other path. A pathname socket carries
a filesystem path in `sun_path`, so `bind`/`connect`/`sendto`/`sendmsg` translate
it into the rootfs and `getsockname`/`getpeername`/`accept`/`recvfrom`/`recvmsg`
strip the prefix back off, so the guest never sees where its rootfs lives and a
program comparing the readback against what it bound still agrees. Where the
rootfs prefix pushes the name past `sun_path`'s 108 bytes, the socket is bound
relative to a `/proc/self/fd` directory handle instead, so only the basename has
to fit. Abstract names have no filesystem node to contain, so they are isolated
per rootfs by a short spliced tag (invisible to the guest, stripped on readback);
`--share-abstract-sockets` opts out into the host's global namespace.

**rtnetlink** is emulated where the host denies it, which Android does to app
domains — and everything that asks the kernel about interfaces goes through it:
`getifaddrs(3)`, iproute2, bubblewrap's `loopback_setup()`, glibc's
source-address selection. The guest's `socket(AF_NETLINK, …, NETLINK_ROUTE)` is
served by a stand-in fd whose dumps are relayed through an **unbound** host
netlink socket, which works because the denial is on `bind(2)`, not on the query.
Where even the socket is refused, dumps degrade to an empty result so
`getifaddrs` succeeds with no interfaces rather than failing outright. Nothing
engages where rtnetlink already works; `CNG_NETLINK_FORCE_BLOCK=1` forces the
emulated path for testing.

**System V shared memory** works too. Android denies `shmget`/`shmat`/`shmdt`/
`shmctl` outright, so chroot-ng serves them itself: the same broker daemon owns
each segment as an anonymous `memfd` (or a private file where `memfd_create` is
unavailable) and hands it to attachers over `SCM_RIGHTS`, which needs no host
SysV IPC and no `/dev/shm`. Segments are shared by every process of one
invocation and isolated between invocations, unless `--shared-proc` widens the
namespace to the rootfs.

**The environment** is built, not inherited. A host variable describes the host
rather than the rootfs — `PATH`, `HOME`, `LD_LIBRARY_PATH`, `XDG_*`, `TMPDIR`
would every one of them send a guest looking outside its own filesystem for
things the rootfs has its own copies of — so the guest starts from a clean
environment. Only `TERM` and `COLORTERM` are carried over, because they describe
the terminal both sides share, and everything else is spelled out with
`-E/--env VAR=VAL` (repeatable; an `-E` entry overrides an inherited
`TERM`/`COLORTERM`, and a repeated name keeps the last value). chroot-ng's own
`CNG_*` knobs are read from its own environment and are not part of the guest's.

```sh
chroot-ng -u ./rootfs /bin/sh              # fake root (uid/gid 0)
chroot-ng -u -E HOME=/root -E TZ=UTC ./rootfs /bin/sh -l
chroot-ng --fake-id 1000:1000 ./rootfs /bin/sh
# non-root, but setuid-root `su` still works (--setuid/--setgid-root imply -u):
chroot-ng --fake-id 1000:1000 --setuid-root --setgid-root ./rootfs /bin/su -
chroot-ng -u -l ./rootfs /sbin/apk add busybox   # hardlinked packages
```

Run `chroot-ng --probe` on any target device **first** — the whole in-process
design depends on the SELinux `execmem` permission being granted.

## License

Not yet chosen; to be decided by the project owner before any release.
