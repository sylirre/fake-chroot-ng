#!/bin/sh
# chroot-ng test harness. Runs the cross-built binary under qemu-aarch64 and
# checks behaviour. Extend per milestone.
set -u

BIN="${BIN:-build/chroot-ng}"
QEMU="${QEMU:-qemu-aarch64-static}"
pass=0
fail=0

run() { "$QEMU" "$BIN" "$@"; }

check() { # desc, expected_rc, actual_rc
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
        printf '  ok   %s\n' "$1"
    else
        fail=$((fail + 1))
        printf '  FAIL %s (rc want %s got %s)\n' "$1" "$2" "$3"
    fi
}

check_contains() { # desc, needle, haystack
    case "$3" in
    *"$2"*)
        pass=$((pass + 1))
        printf '  ok   %s\n' "$1"
        ;;
    *)
        fail=$((fail + 1))
        printf '  FAIL %s (missing: %s)\n' "$1" "$2"
        ;;
    esac
}

if [ ! -x "$BIN" ]; then
    echo "build first: make" >&2
    exit 1
fi

echo "== M1: CLI =="
out=$(run version 2>&1); check "version rc" 0 $?
check_contains "version string" "chroot-ng 0.0.1" "$out"
out=$(run help 2>&1); check "help rc" 0 $?
run >/dev/null 2>&1; check "no-args rc" 2 $?
run frobnicate >/dev/null 2>&1; check "unknown-cmd rc" 2 $?

# M2+ tests are appended as milestones land.
if [ -f tests/m2_probe.sh ]; then . tests/m2_probe.sh; fi
if [ -f tests/m3_loader.sh ]; then . tests/m3_loader.sh; fi
if [ -f tests/m4_dynamic.sh ]; then . tests/m4_dynamic.sh; fi
if [ -f tests/m5_xlate.sh ]; then . tests/m5_xlate.sh; fi
if [ -f tests/m5b_monitor.sh ]; then . tests/m5b_monitor.sh; fi
if [ -f tests/m6_execve.sh ]; then . tests/m6_execve.sh; fi
if [ -f tests/m7_fidelity.sh ]; then . tests/m7_fidelity.sh; fi
if [ -f tests/m8_rewrite.sh ]; then . tests/m8_rewrite.sh; fi
if [ -f tests/m9_androidnet.sh ]; then . tests/m9_androidnet.sh; fi

echo
echo "== summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
