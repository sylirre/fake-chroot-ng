# M5b monitor tests (sourced by tests/run.sh). Exercises the dispatcher and the
# signal round-trip directly; the seccomp trap itself is inert under qemu-user
# and must be confirmed on a real AArch64 kernel.
echo "== M5b: syscall monitor (dispatch + signal) =="

ROOT=$(mktemp -d)
mkdir -p "$ROOT/etc"
printf 'HELLO-FROM-ROOTFS' > "$ROOT/etc/greeting"

check_contains "dispatch openat translated into rootfs" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /etc/greeting 2>&1)"

run -t dtest -r "$ROOT" access /etc/greeting >/dev/null 2>&1
check "dispatch faccessat: present file" 0 $?
run -t dtest -r "$ROOT" access /etc/nope >/dev/null 2>&1
check "dispatch faccessat: missing file" 1 $?

# faccessat2's AT_SYMLINK_NOFOLLOW asks about the link itself, so a dangling one
# exists while following it does not. Resolving the final component during
# translation answered for the target and lost the distinction.
ln -s /nowhere "$ROOT/dangling"
# chroot(2) is privileged. Ungated, an unprivileged guest could move its own
# root where a real kernel refuses -- a check the guest's own code may rely on
# (a daemon that drops privileges and expects chroot to fail afterwards).
mkdir -p "$ROOT/sub"
check_contains "chroot needs CAP_SYS_CHROOT (fake-root), else EPERM" \
    "chroot: unpriv=-1 root=0 cwd=/" \
    "$(run -t dtest -r "$ROOT" chroot /sub 2>&1)"

check_contains "faccessat2 AT_SYMLINK_NOFOLLOW answers for the link itself" \
    "accessnf: nofollow=0 follow=-2" \
    "$(run -t dtest -r "$ROOT" accessnf /dangling 2>&1)"
check_contains "...and for an ordinary file both forms agree" \
    "accessnf: nofollow=0 follow=0" \
    "$(run -t dtest -r "$ROOT" accessnf /etc/greeting 2>&1)"

# Plant a file OUTSIDE the rootfs; guest /../ must not reach it.
printf SECRET > "$ROOT/../esc_$$"
check_contains "dispatch blocks .. escape" \
    "open: errno 2" \
    "$(run -t dtest -r "$ROOT" open "/../esc_$$" 2>&1)"
rm -f "$ROOT/../esc_$$"

# /proc magic links live in the host namespace: an fd link names this process's
# own open file whatever the rootfs is, and /proc/self/cwd is the *guest* cwd,
# not the host one. Re-rooting either readlink target lands on nothing.
exec 7< "$ROOT/etc/greeting"
check_contains "dispatch openat through /proc/self/fd" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /proc/self/fd/7 2>&1)"
exec 7<&-
check_contains "dispatch openat through /proc/self/cwd" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /proc/self/cwd/etc/greeting 2>&1)"

# CNG_DEBUG error logging must not read a scalar syscall arg as a path pointer:
# truncate's length is large enough to look like one, and dereferencing it is a
# wild read inside the handler (SIGSEGV masked there => the guest is killed).
out=$(run -t dtest -r "$ROOT" dbgpath /etc 2>&1); rc=$?
check "debug logging survives a scalar syscall arg" 0 "$rc"
check_contains "debug logging still reports the real error" \
    "dbgpath: survived rc=-21 -> OK" "$out"

# A name resolved relative to a real dirfd must be contained exactly like an
# absolute one. It used to be passed to the kernel untouched, and the kernel has
# no rootfs: a ".." run climbed out (find/rm -rf/tar -C all issue these) and an
# absolute symlink target was taken from the host root.
mkdir -p "$ROOT/sub"
printf SECRET > "$ROOT/../atesc_$$"
check_contains "dirfd-relative .. cannot escape the rootfs" \
    "atrel: errno 2" \
    "$(run -t dtest -r "$ROOT" atrel /sub "../../atesc_$$" 2>&1)"
rm -f "$ROOT/../atesc_$$"
# ..-clamped, the same walk still reaches the real file inside the rootfs.
check_contains "dirfd-relative .. still resolves inside the rootfs" \
    "atrel: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" atrel /sub "../etc/greeting" 2>&1)"
# An absolute symlink target is a guest path, so it re-roots rather than
# reaching the host file of the same name.
ln -sf /etc/greeting "$ROOT/sub/lnk"
check_contains "dirfd-relative absolute symlink re-roots into the rootfs" \
    "atrel: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" atrel /sub lnk 2>&1)"

# The xattr family was never trapped, so a guest's absolute path reached the HOST
# filesystem: getxattr answered existence questions about it and setxattr wrote
# it. Translation shows up in the errno: a name that resolves inside the rootfs
# reaches a real file and answers "no such attribute", while an untranslated path
# lands on a host name that is not there -> ENOENT (2).
#
# Which errno "reached a real file" is depends on the filesystem holding it --
# ENODATA (61) where user.* xattrs are supported, EOPNOTSUPP (95) where they are
# not (tmpfs before 6.6), or an SELinux refusal on a device -- so take it from an
# identity-rootfs control run over the very same file instead of pinning a
# number. All that matters is that it is distinguishable from ENOENT.
xa_ctl=$(run -t dtest -r / getxa "$ROOT/etc/greeting" 2>&1)
xa_real=$(printf '%s\n' "$xa_ctl" |
    sed -n 's/.*getxa: errno \([0-9]*\).*/\1/p' | head -1)
# The host-only path is one we create outside the rootfs: absolute, present on
# the host, and absent from the rootfs, which is the shape of the pre-fix escape.
XAH=$(mktemp); printf x >"$XAH"
if [ -z "$xa_real" ] || [ "$xa_real" = 2 ]; then
    skip "xattr legs: no errno on this filesystem distinguishes reached from contained"
else
    check_contains "xattr on a host-only path is contained" \
        "getxa: errno 2" \
        "$(run -t dtest -r "$ROOT" getxa "$XAH" 2>&1)"
    check_contains "xattr reaches the rootfs file, so it is translated not blocked" \
        "getxa: errno $xa_real" \
        "$(run -t dtest -r "$ROOT" getxa /etc/greeting 2>&1)"
fi
rm -f "$XAH"

# A ":ro" bind must answer EROFS for every mutating path syscall while still
# serving reads. The rw run is the negative control: the same calls must NOT
# report EROFS there, so a blanket refusal cannot pass both legs.
RB=$(mktemp -d); printf 'RO-DATA' > "$RB/f"
out=$(run -t dtest -r "$ROOT" -b "$RB":/ro:ro robind /ro/f 2>&1); rc=$?
check ":ro bind refuses every mutating syscall" 0 "$rc"
check_contains ":ro bind still serves reads" "robind ro read: rc=" "$out"
check_contains ":ro bind refuses a write open" \
    "robind ro open-w: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses unlinkat" \
    "robind ro unlinkat: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses rename" \
    "robind ro renameat: rc=-30 -> OK" "$out"
out=$(run -t dtest -r "$ROOT" -b "$RB":/rw robind /rw/f 2>&1); rc=$?
check "a plain (rw) bind reports no EROFS" 0 "$rc"
rm -rf "$RB"

run -t sigtest >/dev/null 2>&1
check "signal round-trip + ucontext readable" 0 $?
check_contains "sigtest handler ran" "handler ran" "$(run -t sigtest 2>&1)"

rm -rf "$ROOT"

# symlink resolution: absolute guest-target symlinks re-rooted (Alpine busybox
# style), relative symlinks, and no escape via a symlink target.
SR=$(mktemp -d)
mkdir -p "$SR/bin"
printf REAL-BB > "$SR/bin/busybox"
ln -s /bin/busybox "$SR/bin/ls"
ln -s busybox "$SR/bin/cat"
ln -s /../../../etc/passwd "$SR/bin/esc"
check_contains "abs symlink re-rooted into rootfs" "read: REAL-BB" \
    "$(run -t dtest -r "$SR" open /bin/ls 2>&1)"
check_contains "relative symlink resolved" "read: REAL-BB" \
    "$(run -t dtest -r "$SR" open /bin/cat 2>&1)"
check_contains "symlink target cannot escape rootfs" "open: errno 2" \
    "$(run -t dtest -r "$SR" open /bin/esc 2>&1)"
rm -rf "$SR"

# The SIGSYS handler runs the (stack-hungry) dispatcher on a large per-thread
# scratch stack so it never smashes a small guest stack (e.g. Go's ~8 KiB
# goroutine stacks). Validate the stack-switch trampoline itself.
out=$(run -t stackswtest 2>&1); rc=$?
check "stackswtest exit 0" 0 "$rc"
check_contains "handler stack switch runs on scratch and preserves caller" \
    "stacksw: ran_on_scratch=1 ret=0xc0de caller_ok=1 -> OK" "$out"

# A vfork-style clone (CLONE_VFORK|CLONE_VM, as Go's os/exec and posix_spawn use)
# must be converted to a real COW fork, or the in-process emulated execve would
# load the new program over the shared parent's memory.
out=$(run -t clonetest 2>&1); rc=$?
check "clonetest exit 0" 0 "$rc"
check_contains "vfork clone converted to private-VM fork" \
    "clone: pid>0=1 child_exit7=1 private_vm=1 -> OK" "$out"

# A vfork-style clone carrying a caller-provided child stack (musl __clone /
# posix_spawn, as gcc uses to launch cc1) must resume the converted child on
# that stack — driven through the real SIGSYS body, which fixes uc->sp.
out=$(run -t clonestktest 2>&1); rc=$?
check "clonestktest exit 0" 0 "$rc"
check_contains "converted clone resumes child on its own stack" \
    "clonestk: pid>0=1 child_sp=childstk=1 parent_sp=orig=1 -> OK" "$out"

# The BPF filter itself: qemu-user does not honor a guest's seccomp filter, so
# its logic is verified by building it and running it through an interpreter —
# the only pre-device check available for it.
out=$(run -t bpftest 2>&1); rc=$?
check "bpftest exit 0" 0 "$rc"
check_contains "filter is structurally valid (jumps in range, ends in RET)" \
    "jumps_in_range=1 -> OK" "$out"
check_contains "path syscalls trap, others run native" \
    "bpftest openat traps: TRAP -> OK" "$out"
check_contains "in-gate reissue is allowed (no re-trap)" \
    "bpftest in-gate reissue allowed: ALLOW -> OK" "$out"
check_contains "fork traps (registry publish), threads do not" \
    "bpftest thread runs native: ALLOW -> OK" "$out"
check_contains "reads trap only for the reserved synthesized fd range" \
    "bpftest read of a synth fd traps: TRAP -> OK" "$out"
check_contains "an fd arg with a dirty upper half is judged on its low word" \
    "bpftest read with a dirty upper half is judged on the low word: ALLOW -> OK" \
    "$out"
check_contains "a foreign architecture is killed" \
    "bpftest foreign arch killed -> OK" "$out"
check_contains "the System V shm syscalls trap (M12 emulation)" \
    "bpftest shmat traps: TRAP -> OK" "$out"
# io_uring submits path operations through a ring, never an svc, so a created
# ring reaches the host filesystem with no trap and no translation. The filter
# must refuse it outright -- including from inside the gate, which exempts our
# own re-issues but must not become a hole for a call we never make.
check_contains "io_uring is refused ENOSYS by the filter" \
    "bpftest io_uring_setup is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "io_uring is refused even from inside the gate" \
    "bpftest in-gate io_uring is refused too: ERRNO -> OK" "$out"
# clone3's flags sit behind a pointer, so BPF cannot tell a thread from a vfork.
# Refusing it puts glibc's posix_spawn/pthread_create back on __NR_clone, where
# the CLONE_VFORK->fork conversion lives; otherwise a shared-VM child would
# reach the emulated execve and load the new program over its parent.
check_contains "clone3 is refused so spawns use the converted clone path" \
    "bpftest clone3 is refused ENOSYS: ERRNO -> OK" "$out"
# A guest-installed filter also governs the syscalls the SIGSYS handler
# re-issues through the gate, which that filter knows nothing about -- so
# seccomp(2) is refused outright. prctl carries the same capability under an op
# number it shares with process state we must not slow down (bionic's allocator
# calls PR_SET_VMA on every mapping), so the filter tests the op itself.
check_contains "seccomp(2) is refused ENOSYS by the filter" \
    "bpftest seccomp(2) is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "the prctl ops that describe our confinement trap" \
    "bpftest prctl PR_SET_SECCOMP traps: TRAP -> OK" "$out"
check_contains "PR_GET_SECCOMP traps, so it cannot report our mode 2" \
    "bpftest prctl PR_GET_SECCOMP traps: TRAP -> OK" "$out"
check_contains "the rest of prctl stays untrapped" \
    "bpftest prctl PR_SET_VMA runs native: ALLOW -> OK" "$out"
# fstat/fchmod are trapped only where they have something to do: under a fake
# identity, where fstat must remap ownership the way stat does and fchmod needs
# the same fail-soft. Off, an ordinary fstat must not pay for a trap.
check_contains "the fake-id set adds fstat and fchmod, and only then" \
    "bpftest fake-id: fstat_off=1 fstat_on=1 fchmod_on=1 -> OK" "$out"
# SysV sem/msg are emulated from the same broker as shm, so they trap rather
# than being refused -- and they trap unconditionally, so the guest gets its own
# namespace whatever the host's own IPC would have allowed.
check_contains "SysV semaphores trap for emulation" \
    "bpftest semget traps: TRAP -> OK" "$out"
check_contains "...including the blocking operation" \
    "bpftest semtimedop traps: TRAP -> OK" "$out"
check_contains "SysV message queues trap for emulation" \
    "bpftest msgget traps: TRAP -> OK" "$out"
check_contains "...including both ends of the queue" \
    "bpftest msgrcv traps: TRAP -> OK" "$out"
# POSIX mqueue: the same leak one namespace over. An mq name is not a filesystem
# path -- it names an entry in the per-IPC-namespace mqueue mount -- so no path
# trap can translate it and the rootfs prefix cannot scope it. Left native, a
# guest mq_open() created its queue in the HOST's namespace.
check_contains "POSIX message queues no longer reach the host namespace" \
    "bpftest mq_open is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "and the descriptor-taking mqueue calls are refused with them" \
    "bpftest mq_timedsend is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "shm is still emulated rather than refused" \
    "bpftest shmget still traps for emulation: TRAP -> OK" "$out"
check_contains "fchmodat2 is translated, not refused" \
    "bpftest fchmodat2 traps for translation: TRAP -> OK" "$out"
check_contains "plain clone still traps for the vfork conversion" \
    "bpftest plain clone still traps for the conversion: TRAP -> OK" "$out"

# The -R trampoline tier runs with no filter, so the designed-ENOSYS refusals
# cannot come from the kernel there -- the dispatcher must answer them itself.
# bpftest covers the filter; this covers the other tier, and is the only one of
# the two that qemu-user can actually run.
DR=$(mktemp -d)
out=$(run -t dtest -r "$DR" denied /x 2>&1); rc=$?
check "the trampoline tier refuses the designed-ENOSYS set itself" 0 "$rc"
check_contains "io_uring is refused on the -R tier" \
    "denied io_uring_setup: rc=-38 -> OK" "$out"
check_contains "clone3 is refused on the -R tier" \
    "denied clone3: rc=-38 -> OK" "$out"
check_contains "an ordinary syscall still runs on the -R tier" \
    "denied control getpid: rc=" "$out"
check_contains "POSIX message queues are refused on the -R tier" \
    "denied mq_open: rc=-38 -> OK" "$out"
rm -rf "$DR"
