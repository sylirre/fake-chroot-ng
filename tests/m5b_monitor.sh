# M5b monitor tests (sourced by tests/run.sh). Exercises the dispatcher and the
# signal round-trip directly; the seccomp trap itself is inert under qemu-user
# and must be confirmed on a real AArch64 kernel.
echo "== M5b: syscall monitor (dispatch + signal) =="

ROOT=$(mktemp -d)
mkdir -p "$ROOT/etc"
printf 'HELLO-FROM-ROOTFS' > "$ROOT/etc/greeting"

check_contains "dispatch openat translated into rootfs" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run _dtest -r "$ROOT" open /etc/greeting 2>&1)"

run _dtest -r "$ROOT" access /etc/greeting >/dev/null 2>&1
check "dispatch faccessat: present file" 0 $?
run _dtest -r "$ROOT" access /etc/nope >/dev/null 2>&1
check "dispatch faccessat: missing file" 1 $?

# Plant a file OUTSIDE the rootfs; guest /../ must not reach it.
printf SECRET > "$ROOT/../esc_$$"
check_contains "dispatch blocks .. escape" \
    "open: errno 2" \
    "$(run _dtest -r "$ROOT" open "/../esc_$$" 2>&1)"
rm -f "$ROOT/../esc_$$"

run _sigtest >/dev/null 2>&1
check "signal round-trip + ucontext readable" 0 $?
check_contains "sigtest handler ran" "handler ran" "$(run _sigtest 2>&1)"

rm -rf "$ROOT"
