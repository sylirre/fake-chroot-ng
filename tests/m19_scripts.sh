# M19 package-manager script tests (sourced by tests/run.sh).
#
# Both distros' package managers failed to run their maintainer scripts on a
# real device while every earlier milestone passed here, because each depended
# on a path answer this suite had no leg for.
#
#   - dpkg: `[ -x "" ]`. Every maintainer script dh_installmenu generates asks
#     `[ -x "$(command -v update-menus)" ]`, and for a program that is not
#     installed that is the empty string. The kernel answers ENOENT for an
#     empty pathname; resolving it as the working directory made the test true
#     and the script then ran a program that does not exist (exit 127).
#
#   - apk: fchdir(root_fd) followed by execve of a RELATIVE script name (its
#     apk_db_run_script, and the route it takes on any kernel without
#     /proc/sys/vm/memfd_noexec — below 6.3, so most devices). Only the
#     device's rootfs path exposed it: Android hands the app its data directory
#     as /data/user/0/<pkg>/..., a symlink to /data/data/<pkg>/.... getcwd(2)
#     reports the resolved name, the stored rootfs prefix was the unresolved
#     one, so the reverse map found nothing, the virtual cwd stayed where
#     --work-dir had left it, and the script resolved under that instead.
#
# The symlinked-rootfs leg is the one that reproduces the second: with the
# rootfs named directly, the reverse map matches and the bug is invisible.
echo "== M19: package-manager scripts =="

M19_ORACLE="${M19_ORACLE:-$CNG_ORACLE}"

GDIR=build/tests
mkdir -p "$GDIR"

# The guest tree, and a symlink naming it the way Android names the app's data
# directory. /root is somewhere for --work-dir to leave the cwd standing, so a
# fchdir that fails to move it is visible.
M19=$(mktemp -d)
mkdir -p "$M19/real/lib/apk/exec" "$M19/real/root"
ln -s real "$M19/link"

if ! guest_xlate_ready "M19 script legs"; then
    :
elif guest_cc_report "$GDIR/scriptprobe" tests/guests/scriptprobe.c; then
    cp "$GDIR/scriptprobe" "$M19/real/scriptprobe"
    cp "$GDIR/scriptprobe" "$M19/real/lib/apk/exec/scriptprobe"

    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    m19_run() { run -R $GUEST_BINDS "$@"; }

    # --- the empty pathname -------------------------------------------------
    out=$(m19_run "$M19/real" /scriptprobe 2>/dev/null)
    check_contains "an empty path is ENOENT to access(2)" \
        "empty-access=ENOENT" "$out"
    check_contains "an empty path is ENOENT to stat(2)" \
        "empty-stat=ENOENT" "$out"
    check_contains "an empty path is ENOENT to open(2)" \
        "empty-open=ENOENT" "$out"

    # --- fchdir to the root fd, then a relative execve ----------------------
    out=$(m19_run -w /root "$M19/real" /scriptprobe lib/apk/exec/scriptprobe \
        2>/dev/null)
    check_contains "fchdir to the root fd moves the guest cwd off -w" \
        "fchdir-cwd=/" "$out"
    check_contains "a relative execve after it finds the script" \
        "relexec=SCRIPT-OK" "$out"
    check_contains "and the script exits 0" "relexec-rc=0" "$out"

    # The same, with the rootfs named through a symlink — the device's spelling.
    out=$(m19_run -w /root "$M19/link" /scriptprobe lib/apk/exec/scriptprobe \
        2>/dev/null)
    check_contains "a rootfs named through a symlink still tracks fchdir" \
        "fchdir-cwd=/" "$out"
    check_contains "and a relative execve under it resolves" \
        "relexec=SCRIPT-OK" "$out"
    check_contains "and that script exits 0 too" "relexec-rc=0" "$out"
    check_absent "no host path reaches the guest through the symlink" \
        "$M19" "$out"

    # --- differential against arm64chroot -----------------------------------
    # The oracle is a whole-instruction emulator with a purely virtual cwd, so
    # it never had either bug; its answers are the reference for ours.
    if [ -n "$M19_ORACLE" ] && [ -x "$M19_ORACLE" ]; then
        m19_diff() { # desc, args...
            _d=$1
            shift
            # shellcheck disable=SC2086
            _got=$(run -R $GUEST_BINDS "$@" 2>/dev/null)
            # shellcheck disable=SC2086
            _want=$("$M19_ORACLE" $GUEST_BINDS "$@" 2>/dev/null)
            if [ -n "$_want" ] && [ "$_got" = "$_want" ]; then
                pass=$((pass + 1)); printf '  ok   oracle parity: %s\n' "$_d"
            else
                fail=$((fail + 1)); printf '  FAIL oracle parity: %s\n' "$_d"
                printf '    want: %s\n' "$(echo "$_want" | tr '\n' ' ')"
                printf '    got:  %s\n' "$(echo "$_got" | tr '\n' ' ')"
            fi
        }
        m19_diff "the empty pathname" "$M19/real" /scriptprobe
        m19_diff "fchdir + relative execve" -w /root "$M19/real" \
            /scriptprobe lib/apk/exec/scriptprobe
        m19_diff "the same through a symlinked rootfs" -w /root "$M19/link" \
            /scriptprobe lib/apk/exec/scriptprobe
    fi
fi

rm -rf "$M19"
