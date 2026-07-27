# chroot-ng — design

A `proot`-like tool that emulates a chroot environment and bind mounts for
**rootless, SELinux-restricted Android without user namespaces**, but without
paying `proot`'s per-syscall `ptrace` overhead.

## Target environment (locked)

- **Arch:** AArch64 only.
- **Kernel floor:** Linux 3.5+ is the real floor (seccomp-BPF needs 3.5). 3.4
  is best-effort at most (would require a pure-ptrace tier we are not building
  first).
- **Rootless**, SELinux-confined app domain, **no `CONFIG_USER_NS`**.
- **Binaries live on a true `MNT_NOEXEC` mount** (SD/USB/FUSE), so neither
  `execve` nor file-backed `PROT_EXEC` mmap works on them. The only in-process
  way to run such code is anonymous executable memory, which depends on the
  SELinux `execmem` permission (the W^X-compliant `mmap(RW)` → `mprotect(RX)`
  flow used by ART's JIT). **This is the pivotal prerequisite** — `probe`
  checks it.
- **Fidelity beyond chroot+bind:** fake user identity (`-u`/`--fake-id`), `/proc`
  emulation (`--no-proc` to disable), and `link2symlink` (`-l`/`--link2symlink`).

## Why not the obvious approaches

- **LD_PRELOAD / linker interception** (termux-exec): fails for static musl/glibc,
  Go, Rust, and any program issuing raw `svc` — exactly our constraint.
- **User namespaces** (bubblewrap-style): unavailable on Android.
- **Plain ptrace** (classic proot): works but is the overhead we are removing —
  two stops + a context switch to a separate tracer per syscall.

## Architecture: a layered, ptrace-free engine

Two hard shared components sit under a tiered interception mechanism.

### Shared component 1 — userland ELF loader (`ul_exec`)

Read the target ELF as *data* (works on `noexec`), map its `PT_LOAD` segments,
load its `PT_INTERP` (`ld.so`) the same way for dynamic binaries, build the
initial stack (`argv`/`envp`/`auxv`, `AT_PHDR`/`AT_ENTRY`/`AT_BASE`/`AT_RANDOM`),
set up TLS, and jump to the entry point — **no kernel `execve`**. Two mapping
strategies:

- **anonymous** — `mmap(RW)` → copy → `mprotect(RX)`. Defeats a true `noexec`
  mount, but needs `execmem`. **Gotcha found on device:** `PR_SET_NO_NEW_PRIVS`
  (mandatory for the unprivileged seccomp filter) *revokes* anon executable
  memory on Android — so this works at startup (before the monitor) but the
  `mprotect(RX)` is denied for programs started via emulated `execve` afterward.
- **file-backed** — `mmap` each segment `PROT_EXEC` straight from the file (+
  anon BSS). Needs no `execmem`; works on an exec-permitted mount (e.g. Termux
  app-data, which forbids `execve` but allows file-backed execute — the actual
  reason chroot-ng is needed there). Doesn't defeat a true `noexec` mount.

We probe anon exec memory right after installing the monitor and, if it's been
revoked, switch to file-backed for subsequent loads (with a per-load fallback as
a backstop). This single component also:

1. defeats `noexec` (the whole reason we can't just `execve`),
2. is libc-agnostic by construction (we are the loader — glibc/musl/static/
   dynamic all work with no version pinning),
3. lets the in-process interception survive `execve` (we emulate `execve` by
   re-running the loader while keeping our monitor resident).

### Shared component 2 — path translation core

The well-trodden `proot`-equivalent logic, independent of interception
mechanism: enumerate the ~40 path-bearing syscalls, canonicalize, apply the
bind list + guest rootfs, guard against symlink escape, and track the virtual
cwd/root. `/proc` is its own zone: it passes through to the host (a rootfs
directory tree has none), non-guest pids are hidden, the magic links
(`exe`/`cwd`/`root`, and the `fd` links' targets) are answered in guest terms,
and the files that would otherwise describe chroot-ng — `cmdline`, `environ`,
`auxv`, `maps`, the mount tables — are served from the guest's own view. Because
we run the guest in this process and never `execve`, those files are the kernel's
record of *our* invocation, so this is a correctness requirement, not polish.
See `src/monitor/procfs.c` (synthesis) and `src/monitor/procreg.c` (the
fork-inherited registry that tells a guest pid from a host one).

### Shared component 3 — the IPC broker

A detached per-namespace daemon (`src/monitor/broker.c`) that owns shared state
no guest process can hold itself, because **host fd == guest fd** here: anything
we keep open is visible to — and closable by — the guest. It serves two things
over one abstract-socket rendezvous: the `--shared-proc` PID table (as a memfd),
and the **System V shared-memory** registry, whose segments Android leaves us no
choice but to emulate (`shmget`/`shmat`/`shmdt`/`shmctl` are all denied, and
there is no writable tmpfs for `/dev/shm`). Each segment is an anonymous memfd
the daemon holds and hands to attachers over `SCM_RIGHTS`; `shmat` maps it
`MAP_SHARED` — into our own address space, which is also the guest's — and
closes the fd immediately, so a process holds a segment only as a mapping. The
daemon uses those registries as its own liveness signal and exits once nothing
is left, leaving no file and no socket name. See `src/monitor/shm.c`.

### Interception mechanism — tiered, auto-selected

| Tier | Mechanism | Min kernel | Notes |
|------|-----------|-----------|-------|
| primary | seccomp `RET_TRAP` → in-process `SIGSYS` | 3.5 | one signal per path syscall, no second process; handler translates into its own buffer and re-issues via the gate |
| perf    | AoT rewrite of `svc #0` sites in our own pages → trampoline | any | AArch64-clean because we own the (anon, RW→RX) pages; optimization on top of the SIGSYS floor |
| upgrade | seccomp `RET_USER_NOTIF` → supervisor | 5.0 | out-of-process, sheds SIGSYS/execve/clobber fragility where available |
| fallback| ptrace + seccomp `RET_TRACE` | 3.5 (3.4 plain) | correctness backstop; cannot defeat true `noexec` |

**Correctness floor = seccomp `RET_TRAP`/`SIGSYS`.** One BPF filter traps the
path-bearing syscalls unless the syscall's `instruction_pointer` is inside our
gate `[__cng_gate_start, __cng_gate_end)`. Every raw `svc` from anywhere —
glibc, musl, Go's runtime, Rust, JIT — traps synchronously, in-process, to the
`SIGSYS` handler, which reads args from the `ucontext`, translates the path into
its own buffer, re-issues the real syscall through the gate, and writes the
result back into the return register. Non-path syscalls run natively.

**The mmap hook is the choke point** for both `noexec`-defeat and rewriting of
dynamically-loaded code: when `ld.so` tries to `mmap(PROT_EXEC)` a `.so` from
the `noexec` rootfs (which fails natively), we intercept it, read+map the file
into anon RW→RX, and rewrite its `svc` sites before flipping to RX.

**Rewriting needs no seccomp** (a rewritten site is a plain `b` to a trampoline
that calls the dispatcher directly). So the rewriting tier is not only the speed
path — it is also a *seccomp-free interception mechanism*, extending translation
to kernels below the 3.5 seccomp-BPF floor (e.g. 3.4) and to environments where
seccomp is unavailable. Its limit is coverage: it only catches statically
locatable `svc` sites in objects we load (not JIT/self-modifying code, and not
`.so`s until the mmap hook lands), whereas the SIGSYS floor catches every raw
syscall. The two compose: rewrite what we can find, trap the rest.

### Coexisting with Android's own seccomp filter

On Android our process already carries the zygote's app seccomp filter, whose
action for non-allowlisted syscalls is `SECCOMP_RET_TRAP` (SIGSYS). Filters
stack and the most restrictive action wins, so we cannot un-block what Android
blocks (e.g. `setgid`/`setuid`/`setgroups` — apps may not change credentials).
Two consequences:

1. A guest syscall Android blocks traps to *our* SIGSYS handler (we own the
   disposition). We must not forward it — the real syscall is blocked.
2. When our handler re-issues a *translated* syscall through the gate, Android
   may block that too. Since the re-issue happens inside the handler, a naive
   design gets a masked seccomp SIGSYS → force-kill.

Two layers handle this:

- **Direct emulation (primary).** The SIGSYS handler passes `trapped=1` to the
  dispatcher. Since our filter only traps syscalls we have explicit handlers
  for, anything reaching the dispatcher's `default` was trapped by *Android* —
  so we emulate `-ENOSYS` directly instead of re-issuing. Credential setters are
  likewise emulated in place (against the fake-identity credential set under
  `--fake-id`, else `-ENOSYS`). Nothing is re-issued, so this does not depend on
  nested signal delivery. (The M8
  trampoline path passes `trapped=0`, where an unhandled syscall is an ordinary
  one to run, not a blocked one.)
- **Block-list probe (for re-issued path syscalls).** Some syscalls we *do*
  re-issue (translated path syscalls) are also Android-blocked — notably
  `fchownat` and `mknodat`. At monitor install we measure the ambient filter:
  fork a child that (with only Android's filter active) invokes each candidate
  with harmless NULL args and records which trap. The dispatcher then emulates
  the blocked ones as `-ENOSYS` instead of re-issuing. This runs in the child's
  normal flow (not nested), so it does not depend on nested SIGSYS delivery, and
  off Android nothing is blocked so everything re-issues normally.
- **Gate-net (last-resort backstop).** The `SA_NODEFER` gate-net still catches a
  re-issue that the probe missed, but it needs nested seccomp SIGSYS delivery,
  which some kernels don't honor — so it is only a backstop; correctness comes
  from the two mechanisms above.

**Keeping SIGSYS ours and deliverable.** A masked seccomp SIGSYS force-kills, so
the guest must never block SIGSYS or replace our handler. musl does exactly this
at startup (`rt_sigprocmask(SIG_BLOCK, ~[a few RT sigs])`), which neutered us
until we virtualized it. We trap `rt_sigprocmask` and `rt_sigaction`: mask
changes are applied with SIGSYS forced clear (in the SIGSYS handler we edit
`uc_sigmask`, which `sigreturn` restores — re-issuing there would be undone),
`sa_mask` on installed handlers has SIGSYS stripped, and `rt_sigaction(SIGSYS)`
is ignored so the guest can't take over our slot.

For a real container you want `-u`/`--fake-id` (fake user identity, default
`0:0` root), which emulates the credential syscalls against a synthetic
credential set instead of returning ENOSYS — mirroring proot's `-0`/`-i` and the
way the reference emulator recommends `--fake-id` for apt/dpkg.

### Guest ptrace

chroot-ng uses no ptrace, but guests do — `strace`, `gdb`, `proot` — and letting
those reach the host kernel is worse than refusing them: the tracer sees our own
re-issued syscalls, reads host paths with the rootfs prefix attached, and never
gets the post-`execve` `SIGTRAP`, since our execve is emulated and never enters
the kernel's exec path. So ptrace is emulated like every other kernel service
here, from inside the processes involved: a shared registry created before the
first fork holds one link per traced task, a tracee publishes its stop there and
then parks in a service loop answering `PEEK`/`POKE`/`GETREGSET`/`SETREGSET`/
resume *about itself* over a futex mailbox, and the tracer discovers stops from
its `wait4`. Nothing in that needs host ptrace permission, `/proc/pid/mem` or
`process_vm_readv`, all of which Android's policy can deny.

The stop points are exactly where the guest already reaches our code — the
SIGSYS trap, our signal handlers, the emulated execve, clone and exit — and at
each of them the full register file is addressable, because the AArch64
sigcontext's `regs/sp/pc/pstate` tail *is* a `struct user_pt_regs`. Two things
have to be added on top: a traced task stacks a second filter that traps every
syscall (the base filter only traps the path-bearing set, and strace must see
all of them), and while traced its signals are mediated by handlers of ours that
mirror the guest's own flags and mask — which is what makes a gdb breakpoint, a
`brk` poked into read-only text, arrive as a stop rather than kill the guest.
See `src/monitor/ptrace.c`, `ptsig.c` and `ptstep.c`.

### Known hazards (why the tiers exist)

- `execve` erases the in-process handler → emulate `execve` via the loader.
- The guest (notably Go) can clobber the `SIGSYS` handler or block the signal →
  virtualize `rt_sigaction`/`rt_sigprocmask`/`seccomp`/`prctl`. A guest filter is
  layered on top of ours by the kernel and governs the syscalls the handler
  re-issues through the gate as well, so `seccomp(2)` is refused `ENOSYS` and
  `prctl(PR_SET_SECCOMP)` `EACCES`; `PR_GET_SECCOMP` and the `NO_NEW_PRIVS` pair
  report the guest's own state rather than the bits we set to install the filter.
  The remaining prctl ops are real process state and stay untrapped (the filter
  tests `args[0]`).
- `SIGSYS` signal-stack correctness on guest-created threads → per-thread
  `sigaltstack`, validate against Go.
- `execmem` denied → no in-process path exists on a true `noexec` mount; only
  the ptrace fallback (from an exec-permitted location) remains.

## Build & test

Cross-compiled with `aarch64-linux-gnu-gcc`, exercised under `qemu-aarch64`.
Caveat: qemu-user does **not** faithfully run guest-installed seccomp filters,
so the SIGSYS mechanism is validated with simulated-SIGSYS unit tests plus real
AArch64-kernel integration; the loader and path logic are fully testable under
qemu.

The binary is freestanding (`-nostdlib`, own `_start`, own syscall gate) so it
never depends on libc and the SIGSYS handler has no re-entrancy hazards.
