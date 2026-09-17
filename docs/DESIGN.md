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

## Threat model — containment, not a sandbox

chroot-ng runs the guest **in its own address space**: the monitor's code, its
`svc` gate and the path-translation state are ordinary pages of the same
process. A guest that sets out to defeat translation needs no syscall to do it
— a store into the monitor's `.data`, or executable memory placed over the gate
range the seccomp filter allowlists, is enough, and neither is something a
syscall filter can see. Interception here is therefore **containment for guests
that are not attacking it**, which is the standing `proot` has and for the same
reason.

What that does and does not buy:

- A guest's *mistakes* are contained exactly: a path escaping the rootfs, a
  `..` run, an absolute symlink, a dirfd opened outside the view, an untranslated
  name reaching the host. Those are the bugs the path layer exists for.
- A guest's *malice* is not. Hostile code sharing an address space with its own
  monitor is not confined by it; put a kernel boundary — a container, a VM, a
  separate uid — around the whole invocation instead.

One rule follows for the implementation: chroot-ng must never be the instrument.
Wherever a **guest-chosen address** reaches a `MAP_FIXED` of ours — an `ET_EXEC`
guest's link-time vaddr (`src/loader/elf.c`), `shmat(SHM_REMAP)`
(`src/monitor/shm.c`) and the mmap hook's anonymous stand-in
(`src/monitor/execmap.c`) — the range is checked against everything that is the
monitor's and refused (`ENOEXEC` / `EINVAL` / the kernel's own answer):
`cng_hits_monitor()` covers the image `[__cng_image_start, __cng_image_end)`,
every region the own-map registry records (the floor, the registries, the argv
snapshot an exec stands on) and the scratch stacks with the signal frame a
dispatch returns through — the same three answers the exec sweep uses to tell
the monitor's memory from the outgoing program's. A monitor mapped over by its
own hand has nothing left to report the failure with. That is what the 64 GiB
link base (see the 0x400000 entry in `docs/STATUS.md`) moved out of the way of,
and `p_vaddr` is a field in a file, so the base alone is not a guarantee — and
the image is not the only mapping a file can name.

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

The walk produces a host path; the syscall is not made on it. A string handed
to the kernel is resolved again from scratch, following whatever is there by
then, and between the walk and the call the tree is the guest's to change: a
directory on the way swapped for an absolute symlink is followed from the host
root, and the call lands outside the rootfs — the time-of-check-to-time-of-use
of every string-based translator, `proot` included. So every host path is
*pinned* for its syscall (`src/monitor/pin.c`): the directory the walk reached
is opened `O_PATH` and verified to be that directory (the kernel's own name for
it, read back through its fd link, against the walk's symlink-free spelling;
where the two differ in spelling alone, as on a case-insensitive filesystem,
a descriptor-by-descriptor walk of the components from the rootfs or bind
prefix decides), and the call is made against that descriptor with the last
component as a plain name and the family's NOFOLLOW — an open as an `openat2`
with `RESOLVE_NO_SYMLINKS`, which leaves no flag on the description, where the
host has it. The walk followed everything that was to be followed, so NOFOLLOW
changes nothing for a tree at rest and refuses exactly the link that appeared
in the race. Families with no NOFOLLOW to give, and names with a trailing
slash (which the kernel follows regardless), go through the last component's
own `O_PATH` descriptor, checked not to be a symlink, by its fd link. A
pathname `bind` carries the pinned directory's link in `sun_path`, and the
binder keeps that descriptor open for as long as the socket is, so the stored
spelling reads back to the guest's name from any process (`unixsock.c`). The
loader's opens and `-l`'s own bookkeeping take the same route. What is not
pinned: a relative name against the guest's own dirfd (already a descriptor;
the NOFOLLOW is all it needs), the host's `/proc`, and a `/dev` whitelist
node named as itself.

Directory descriptors are part of the same containment: a name relative to a
dirfd is resolved by the kernel with no rootfs in the way, so every directory
the guest can hold a descriptor on must have a guest name — inside the view,
or one of the two zones — and the walk from it is ours. A descriptor on a
directory the guest cannot name is never let into its table: the launcher's
are closed before the first program loads, and one arriving later over a
socket or from `pidfd_getfd` is closed on arrival (`cng_fd_admit`,
`src/monitor/dispatch.c`). Files are let in for the I/O they carry; a file is
not a place to resolve a name from.

A file descriptor is the whole capability it is under `chroot(2)`, and
deliberately so. What the launcher hands over by descriptor — a redirected
stdin, a script or a data file on fd 3, one received over a socket — the
guest can read, write as the description's mode allows, execute
(`execveat(fd, "", AT_EMPTY_PATH)`, `fexecve`, `/proc/self/fd/N`) and give
a name of its own with `linkat(fd, "", …, AT_EMPTY_PATH)` where the kernel
lets an unprivileged process link by descriptor, exactly as a chrooted
process can with a descriptor it inherited. None of that resolves a name
against the host, so none of it is the walk's to refuse — and refusing it
would break every launcher that passes a program or its input by
descriptor. A launcher that must not let the guest execute, or keep, a
host file does not hand it the descriptor.

### Shared component 3 — the IPC broker

A detached per-namespace daemon (`src/monitor/broker.c`) that owns shared state
no guest process can hold itself, because **host fd == guest fd** here: anything
we keep open is visible to — and closable by — the guest. Over one abstract-socket
rendezvous it serves the `--shared-proc` PID table (as a memfd) and the whole of
**System V IPC**, which Android leaves us no choice but to emulate: every syscall
in the family is denied, and there is no writable tmpfs for `/dev/shm`.

Shared memory needs only an owner for the pages: each segment is an anonymous
memfd the daemon holds and hands to attachers over `SCM_RIGHTS`, and `shmat` maps
it `MAP_SHARED` — into our own address space, which is also the guest's — then
closes the fd at once, so a process holds a segment only as a mapping
(`src/monitor/shm.c`). Semaphore sets and message queues instead live *entirely*
in the daemon (`src/monitor/ipcreg.c`), because they need an arbiter rather than
a landlord: with every operation an RPC, all mutation is single-threaded, a
multi-operation `semop` is atomic for free, and a guest that dies mid-call cannot
leave the registry torn. An operation that must sleep parks its connection there
and is answered when it can proceed, when its deadline passes, when the object is
removed, or when the caller cancels it — which is how a blocking `semop` stays
interruptible even though our SIGSYS handler runs with every other signal masked.

The daemon uses those registries as its own liveness signal and exits once
nothing is left, leaving no file and no socket name.

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
into anon RW→RX, and rewrite its `svc` sites before flipping to RX
(`src/monitor/execmap.c`). The filter tests the arguments rather than the
syscall — `PROT_EXEC` set, `MAP_ANONYMOUS` clear — so every anonymous
allocation a guest makes stays untrapped and only a library's text mapping
reaches the handler. The conversion runs *after* the kernel has refused, so an
exec-permitted mount keeps its real file mapping, its page-cache sharing and
its identity in `/proc/self/maps`; only `MAP_PRIVATE` can be served this way,
since a copy cannot carry `MAP_SHARED`'s visibility.

**Rewriting needs no seccomp** (a rewritten site is a plain `b` to a trampoline
that calls the dispatcher directly). So the rewriting tier is not only the speed
path — it is also a *seccomp-free interception mechanism*, extending translation
to kernels below the 3.5 seccomp-BPF floor (e.g. 3.4) and to environments where
seccomp is unavailable. Its limit is coverage: it only catches statically
locatable `svc` sites in objects we load (not JIT/self-modifying code, and not
`.so`s until the mmap hook lands), whereas the SIGSYS floor catches every raw
syscall. The two compose: rewrite what we can find, trap the rest.

That composition is also the whole of what a run may fall back to. When the
filter cannot be installed and `-R` is on, chroot-ng enters the guest behind a
warning that names what stays untranslated; when `-R` is off there is nothing
left that intercepts, and the invocation — a rootfs, binds, `-u`, `-l`,
`--no-ptrace`, `--shared-proc` — cannot be delivered at all, so `cng_run`
refuses to enter the guest rather than run it against the host's own paths.

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
never reaches the kernel: it is answered from a per-process mirror of what the
guest asked for (with the kernel's own EINVAL/EFAULT checks, reset by the
emulated execve as `flush_signal_handlers` would), so the guest can't take over
our slot but sees its own disposition back. A SIGSYS that is not a seccomp trap
— `kill -SYS`, a `raise` — is delivered by our handler to that mirrored
disposition: the default action kills, SIG_IGN drops, a handler runs under its
`sa_mask` (SIGSYS itself being the one bit that stays unblocked).

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
- `execve` from a multithreaded program: the kernel's `de_thread` kills every
  other thread and gives a non-leader caller the leader's identity, and neither
  can be had from userspace directly → every sibling is sent a thread-directed
  `SIGSYS` carrying a die request (the one signal the guest can never block),
  and a non-leader caller hands its planned exec to the group leader over the
  same signal and exits, so the leader carries it and the new program is one
  thread whose tid is its pid. For that to reach every thread, the waits that
  install a mask of their own (`rt_sigsuspend`, `rt_sigtimedwait`, `ppoll`,
  `pselect6`, `epoll_pwait[2]`) and `signalfd4` are trapped when they carry a
  mask and `SIGSYS` is taken out of it; on the `SIGSYS` tier such a wait is run
  from the guest's own context through a stub in the gate, since the handler,
  which runs with every other signal blocked, cannot run it itself.
- The guest (notably Go) can clobber the `SIGSYS` handler or block the signal →
  virtualize `rt_sigaction`/`rt_sigprocmask`/`seccomp`/`prctl`. A guest filter is
  layered on top of ours by the kernel and governs the syscalls the handler
  re-issues through the gate as well, so `seccomp(2)` is refused `ENOSYS` and
  `prctl(PR_SET_SECCOMP)` `EACCES`; `PR_GET_SECCOMP` and the `NO_NEW_PRIVS` pair
  report the guest's own state rather than the bits we set to install the filter
  — and the `no_new_privs` half is kept per *task*, the way `task_struct` keeps
  it, so one thread setting it does not answer for its siblings.
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
never depends on libc and the SIGSYS handler has no re-entrancy hazards. Its
syscall numbers are its own table too (`include/cng/unistd.h`, the stable
AArch64 ABI spelled out) rather than the build host's `<asm/unistd.h>`: what
the filter traps and refuses must not depend on how old the headers were where
the binary happened to be built, and `src/rt/unistd_check.c` holds the table
against those headers at build time where the host has them.
