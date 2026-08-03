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

# A `#!` script well under the 64 bytes an Elf64_Ehdr occupies -- the shape of
# the .config scripts debconf extracts, and the one that must not be mistaken
# for a truncated ELF. Its interpreter is the probe itself: the synthetic
# rootfs has no shell. Beside it, a genuinely empty executable file, which is
# ENOEXEC on the kernel and has to be here too.
printf '#!/scriptprobe shortok\n' >"$M19/real/short.sh"
: >"$M19/real/empty.bin"
# A script to exec with an EMPTY argv: the kernel splices in the interpreter,
# the `#!` argument and the script path, and stops there. "argv[1] onwards" is
# then one past the vector's own terminator, and the snapshot lays envp
# directly behind argv -- so the walk ran into the environment.
printf '#!/scriptprobe argok\n' >"$M19/real/noargv.sh"
# ...and one whose `#!` line ends in a blank, which editors leave behind all the
# time. The kernel walks back over the line's trailing spaces and tabs before it
# parses anything, so the interpreter never sees them on its argument.
printf '#!/scriptprobe argok \n' >"$M19/real/trail.sh"
chmod 755 "$M19/real/short.sh" "$M19/real/empty.bin" "$M19/real/noargv.sh" \
    "$M19/real/trail.sh"

# That rule is the host kernel's own, so establish it here rather than claim it:
# a script whose interpreter is itself a script prints the argument it was
# handed, and the same trailing blank goes in.
KREF=$(mktemp -d)
printf '#!/bin/sh\nprintf "[%%s]" "$1"\n' >"$KREF/showarg"
printf '#!%s/showarg argok \n' "$KREF" >"$KREF/t.sh"
chmod 755 "$KREF/showarg" "$KREF/t.sh"
M19_KERN=$("$KREF/t.sh" 2>/dev/null)
rm -rf "$KREF"
check "the host kernel strips a #! line's trailing blanks" "[argok]" "$M19_KERN"

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

    # --- the two file shapes the exec path must tell apart -----------------
    out=$(m19_run -w /root "$M19/real" /scriptprobe lib/apk/exec/scriptprobe \
        /short.sh /empty.bin 2>/dev/null)
    check_contains "a shebang script shorter than an ELF header still runs" \
        "shortscript=SCRIPT-OK" "$out"
    check_contains "and exits 0" "shortscript-rc=0" "$out"
    check_contains "an empty file is ENOEXEC, as it is on the kernel" \
        "emptyfile=ENOEXEC" "$out"

    out=$(m19_run -w /root "$M19/real" /scriptprobe lib/apk/exec/scriptprobe \
        /short.sh /empty.bin /noargv.sh 2>/dev/null)
    check_contains "a script exec'd with an empty argv gets the three the kernel splices" \
        "shebargv=[argok][/noargv.sh]" "$out"
    check_absent "and not the environment behind it" "SHEBENV" "$out"

    out=$(m19_run -w /root "$M19/real" /scriptprobe lib/apk/exec/scriptprobe \
        /trail.sh 2>/dev/null)
    check_contains "the #! argument loses the line's trailing blanks, as it just did on the kernel" \
        "shebargv=$M19_KERN[/trail.sh]" "$out"

    # And it says so with the errno alone. A failed exec used to narrate itself
    # onto the guest's own stderr naming the resolved host path -- the one
    # thing the path layer exists to keep from the guest -- in a stream package
    # managers capture and log.
    err=$(m19_run -w /root "$M19/real" /scriptprobe lib/apk/exec/scriptprobe \
        /short.sh /empty.bin 2>&1 >/dev/null)
    check_absent "a failed exec leaks no host path to the guest" "$M19" "$err"
    check_absent "and narrates nothing at all, as the kernel does" \
        "chroot-ng: exec" "$err"

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
        m19_diff "a short shebang script and an empty file" -w /root \
            "$M19/real" /scriptprobe lib/apk/exec/scriptprobe /short.sh \
            /empty.bin
        m19_diff "the same through a symlinked rootfs" -w /root "$M19/link" \
            /scriptprobe lib/apk/exec/scriptprobe
    fi
fi

rm -rf "$M19"
