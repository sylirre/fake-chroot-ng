# M7 fidelity tests (sourced by tests/run.sh). Drives the dispatcher directly so
# the fixups are exercised under qemu (no seccomp needed).
echo "== M7: fidelity (uid/gid faking, /proc, link2symlink) =="

ROOT=$(mktemp -d)
printf hi > "$ROOT/f"
out=$(run _faketest -r "$ROOT" /f 2>&1)

check_contains "getuid faked to 0"          "getuid=0"            "$out"
check_contains "geteuid faked to 0"         "geteuid=0"           "$out"
check_contains "stat ownership faked to 0"  "st_uid=0 st_gid=0"   "$out"
check_contains "/proc/self/exe fixup"       "exe=/bin/sh"         "$out"
check_contains "fchown faked to success" "fchown=0" "$out"

rm -rf "$ROOT"

# link2symlink (target is a guest/relative path, not a host path) + fchdir cwd
# tracking. Force the l2s fallback via the block-list (tmpfs allows hardlinks).
L2=$(mktemp -d); mkdir -p "$L2/w"
out=$(run _l2stest "$L2" 2>&1); rc=$?
check "l2stest overall (l2s + fchdir)" 0 "$rc"
check_contains "link2symlink target is relative (b -> a)" "target=a leak=0" "$out"
check_contains "fchdir updates virtual cwd" "fchdir: cwd=/w -> OK" "$out"
rm -rf "$L2"
