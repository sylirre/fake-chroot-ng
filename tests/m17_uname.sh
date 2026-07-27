# M17-14 kernel-identity tests (sourced by tests/run.sh).
#
# uname(2) used to hand the guest the host's own release. Inside a rootfs that
# describes nothing the guest can act on, and on the target platform it is a
# device fingerprint (`-android14-11-...`, `-perf`). The two places a guest
# reads it — uname and /proc/version — must agree, because anything that
# cross-checks them (distro install scripts do) otherwise sees a contradiction.
echo "== M17-14: kernel identity =="

UR=$(mktemp -d)
out=$(run -t dtest -r "$UR" uname / 2>&1)
check "uname rc" 0 $?
check_contains "release is the fixed identity, not the host's" \
    "rel=6.1.0-chroot-ng" "$out"
check_contains "version string is fixed too" "ver=#1 SMP chroot-ng" "$out"
check_contains "sysname and machine describe the guest ABI" \
    "sys=Linux" "$out"
check_contains "machine is aarch64" "mach=aarch64" "$out"
# nodename names the machine the guest is really on: `hostname` reports it
# either way, and faking it would only confuse a user.
check_contains "nodename stays the host's" "node_kept=1" "$out"
# The host release must not appear anywhere in what the guest was told.
check_absent "the host release does not leak through uname" \
    "$(uname -r 2>/dev/null || echo IMPOSSIBLE)" "$out"

vout=$(run -t dtest -r "$UR" open /proc/version 2>&1)
check_contains "/proc/version repeats the same release" \
    "Linux version 6.1.0-chroot-ng" "$vout"
check_contains "...and the same version string" "#1 SMP chroot-ng" "$vout"
check_absent "the host release does not leak through /proc/version" \
    "$(uname -r 2>/dev/null || echo IMPOSSIBLE)" "$vout"
rm -rf "$UR"
