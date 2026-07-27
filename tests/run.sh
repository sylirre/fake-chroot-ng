#!/usr/bin/env sh
# chroot-ng test harness. Runs the AArch64 binary — natively on an AArch64 host,
# under qemu-aarch64 on a cross host — and checks behaviour. Extend per
# milestone. Everything host-dependent (emulator, guest toolchain, which
# translation tier is live, rootfs images) is resolved in tests/lib.sh; see the
# header there for the environment knobs.
set -u

cd "$(dirname "$0")/.." || exit 1
. tests/lib.sh

if [ ! -x "$BIN" ]; then
    echo "build first: make" >&2
    exit 1
fi

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

check_absent() { # desc, needle, haystack
    case "$3" in
    *"$2"*)
        fail=$((fail + 1))
        printf '  FAIL %s (present: %s)\n' "$1" "$2"
        ;;
    *)
        pass=$((pass + 1))
        printf '  ok   %s\n' "$1"
        ;;
    esac
}

cng_platform_init
trap 'rm -rf "$CNG_TMP"' EXIT INT TERM
cng_platform_banner
if [ "$CNG_EMU_MISSING" = 1 ]; then
    echo "no qemu-aarch64 emulator found on a $HOST_ARCH host: install" \
        "qemu-user-static, or set QEMU= if AArch64 binaries run here anyway" >&2
    exit 1
fi
echo

echo "== M1: CLI =="
out=$(run --version 2>&1); check "version rc" 0 $?
check_contains "version string" "chroot-ng 0.1.0" "$out"
out=$(run -v 2>&1); check_contains "short -v version" "chroot-ng 0.1.0" "$out"
out=$(run --help 2>&1); check "help rc" 0 $?
check_contains "help usage line" "chroot-ng [options] <rootfs> <program>" "$out"
check_contains "help OPTIONS section" "OPTIONS" "$out"
out=$(run -h 2>&1); check "short -h rc" 0 $?
run >/dev/null 2>&1; check "no-args rc" 2 $?
run --frobnicate >/dev/null 2>&1; check "unknown-option rc" 2 $?
run / >/dev/null 2>&1; check "rootfs but no program rc" 2 $?
run -t frobnicate >/dev/null 2>&1; check "unknown test rc" 2 $?

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
if [ -f tests/m10_l2s_shell.sh ]; then . tests/m10_l2s_shell.sh; fi
if [ -f tests/m11_proc.sh ]; then . tests/m11_proc.sh; fi
if [ -f tests/m12_shm.sh ]; then . tests/m12_shm.sh; fi
if [ -f tests/m14_dev.sh ]; then . tests/m14_dev.sh; fi
if [ -f tests/m15_unixsock.sh ]; then . tests/m15_unixsock.sh; fi
if [ -f tests/m16_netlink.sh ]; then . tests/m16_netlink.sh; fi
if [ -f tests/m17_fault.sh ]; then . tests/m17_fault.sh; fi
if [ -f tests/m17_seccomp.sh ]; then . tests/m17_seccomp.sh; fi
if [ -f tests/m17_uname.sh ]; then . tests/m17_uname.sh; fi
if [ -f tests/m17_env.sh ]; then . tests/m17_env.sh; fi
if [ -f tests/m17_workdir.sh ]; then . tests/m17_workdir.sh; fi

echo
echo "== summary: $pass passed, $fail failed, $skipped skipped =="
[ "$fail" -eq 0 ]
