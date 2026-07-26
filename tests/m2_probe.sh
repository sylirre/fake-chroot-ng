# M2 probe tests (sourced by tests/run.sh). The execmem/statfs/kernel paths are
# real on every host; the seccomp line is only meaningful on a real AArch64
# kernel (qemu-user does not apply a guest filter), so it is asserted against
# what tests/lib.sh detected rather than against a fixed expectation.
echo "== M2: probe =="
out=$(run --probe / 2>&1); rc=$?
# The verdict is "BLOCKED" — and the exit status 1 — exactly when a hard
# prerequisite fails, and execmem is the one that can legitimately fail on a
# device (SELinux denying anonymous RW->RX to the app domain).
if [ "$CNG_EXECMEM" = 1 ]; then
    check "probe rc (execmem permitted)" 0 $rc
    check_contains "execmem executed thunk" "RESULT    OK" "$out"
    check_contains "verdict is viable" "LIKELY VIABLE" "$out"
else
    check "probe rc (execmem denied)" 1 $rc
    check_contains "execmem denial reported" "RESULT    DENIED" "$out"
    check_contains "verdict is blocked" "BLOCKED" "$out"
fi
check_contains "kernel section" "kernel:" "$out"
check_contains "machine aarch64" "aarch64" "$out"
check_contains "noexec section present" "noexec mounts" "$out"
check_contains "verdict present" "verdict:" "$out"

# The seccomp functional test: a real AArch64 kernel must report the filter
# working, and under qemu-user it must report itself inert rather than silently
# claiming success.
if [ "$CNG_SECCOMP_LIVE" = 1 ]; then
    check_contains "seccomp RET_ERRNO works on this kernel" \
        "filter RET_ERRNO    WORKS" "$out"
else
    check_contains "seccomp filter reports itself unavailable here" \
        "filter test  " "$out"
fi
