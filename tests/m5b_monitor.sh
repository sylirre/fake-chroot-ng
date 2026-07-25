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
