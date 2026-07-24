# M2 probe tests (sourced by tests/run.sh). qemu-user cannot exercise the
# seccomp path, but the execmem/statfs/kernel paths are real.
echo "== M2: probe =="
out=$(run --probe / 2>&1); rc=$?
check "probe rc (execmem ok on host)" 0 $rc
check_contains "kernel section" "kernel:" "$out"
check_contains "machine aarch64" "aarch64" "$out"
check_contains "execmem executed thunk" "RESULT    OK" "$out"
check_contains "noexec section present" "noexec mounts" "$out"
check_contains "verdict present" "verdict:" "$out"
