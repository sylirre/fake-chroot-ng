# M17-17 -w/--work-dir tests (sourced by tests/run.sh).
#
# The option names the directory the guest starts in. Two things have to hold,
# and both are asserted on every leg: the guest's own view of it — getcwd(2) and
# /proc/self/cwd come from different bookkeeping and must agree — and what
# relative paths actually resolve against, since a working directory that only
# prints correctly is no working directory at all. DIR is resolved like any
# other guest path, so the legs cover symlinks, binds, and a `..` that tries to
# climb out of the rootfs.
echo "== M17-17: -w/--work-dir =="

M17W_ORACLE="${M17W_ORACLE:-$CNG_ORACLE}"

GDIR=build/tests
mkdir -p "$GDIR"

# The guest tree, doubling as the rootfs for the legs below:
#   /a/b/marker   what a relative open under -w /a/b must find
#   /link -> /a/b  a symlinked work directory
#   /bindpt        a bind destination, backed by $M17WB
M17W=$(mktemp -d)
M17WB=$(mktemp -d)
mkdir -p "$M17W/a/b" "$M17W/bindpt"
echo INSIDE_AB >"$M17W/a/b/marker"
echo FROM_BIND >"$M17WB/bmarker"
ln -s /a/b "$M17W/link"

# --- option parsing ---------------------------------------------------------
run -w >/dev/null 2>&1
check "-w with no argument is refused" 2 $?
out=$(run -w 2>&1)
check_contains "the missing -w argument is diagnosed" \
    "option '-w' requires an argument" "$out"
run --work-dir >/dev/null 2>&1
check "--work-dir with no argument is refused" 2 $?
out=$(run --work-dir 2>&1)
check_contains "the missing --work-dir argument is diagnosed" \
    "option '--work-dir' requires an argument" "$out"
out=$(run --help 2>&1)
check_contains "-w is in the option reference" "-w, --work-dir DIR" "$out"

# A DIR that is not a usable directory is fatal, and says which of the three
# ways it was unusable. <program> is never reached, so it need not exist: the
# work directory is settled first, because a relative <program> resolves in it.
run -w "" / /no-such-program >/dev/null 2>&1
check "an empty -w path is refused" 1 $?
out=$(run -w "" / /no-such-program 2>&1)
check_contains "the empty -w path is diagnosed" \
    "chroot-ng: --work-dir: empty path" "$out"

run -w /no/such/directory / /no-such-program >/dev/null 2>&1
check "a nonexistent -w path is refused" 1 $?
out=$(run -w /no/such/directory / /no-such-program 2>&1)
check_contains "the nonexistent -w path is diagnosed" \
    "chroot-ng: --work-dir '/no/such/directory': not found" "$out"

run -w "$M17W/a/b/marker" / /no-such-program >/dev/null 2>&1
check "a -w path naming a regular file is refused" 1 $?
out=$(run -w "$M17W/a/b/marker" / /no-such-program 2>&1)
check_contains "the non-directory -w path is diagnosed" \
    "not a directory" "$out"

# ...and a directory that stats fine but cannot be entered. The real cwd moves
# with the guest's, because a relative path the monitor never sees — anything
# untrapped, and everything when no monitor installs at all — resolves against
# it; that chdir's failure used to be dropped, so the guest was told it was in
# one place while its untranslated names resolved from the launch directory,
# outside the view entirely. Reachable: no search permission is EACCES, and
# under --fake-id the guest believes it is root where the kernel does not.
if [ "$(id -u)" = 0 ]; then
    skip "a -w path that cannot be entered is refused: running as root, mode 0000 is still enterable"
else
    mkdir -p "$M17W/sealed"
    chmod 0000 "$M17W/sealed"
    run -u 0:0 -w /sealed "$M17W" /no-such-program >/dev/null 2>&1
    check "a -w path that cannot be entered is refused" 1 $?
    out=$(run -u 0:0 -w /sealed "$M17W" /no-such-program 2>&1)
    check_contains "the unenterable -w path is diagnosed with its errno" \
        "chroot-ng: --work-dir '/sealed': cannot enter (errno 13)" "$out"
    chmod 0755 "$M17W/sealed"
fi

# --- the identity rootfs ----------------------------------------------------
# Guest paths are host paths here, so these legs need no translation tier and
# run on every host — including the cross host, where getcwd is answered by the
# kernel from the real cwd rather than by the monitor from the virtual one. That
# the two spellings agree is the point: -w moves both.
m17w_probe=0
if guest_cc_report "$GDIR/cwdprobe" tests/guests/cwdprobe.c; then
    m17w_probe=1
    PROBE="$(pwd -P)/$GDIR/cwdprobe"
    cp "$GDIR/cwdprobe" "$M17W/probe"
    cp "$GDIR/cwdprobe" "$M17W/a/b/probe"

    out=$(run / "$PROBE" 2>/dev/null)
    check_contains "identity rootfs: the default cwd is the launch directory" \
        "cwd=$(pwd -P)" "$out"

    out=$(run -w "$M17W/a/b" / "$PROBE" marker 2>/dev/null)
    check_contains "-w sets the guest cwd" "cwd=$M17W/a/b" "$out"
    check_contains "/proc/self/cwd agrees with getcwd" \
        "proccwd=$M17W/a/b" "$out"
    check_contains "a relative path resolves in the work directory" \
        "rel=INSIDE_AB" "$out"

    out=$(run --work-dir="$M17W/a/b" / "$PROBE" marker 2>/dev/null)
    check_contains "--work-dir=DIR is the same option" "cwd=$M17W/a/b" "$out"

    out=$(run -w "$GDIR" / "$PROBE" 2>/dev/null)
    check_contains "a relative -w resolves against the default cwd" \
        "cwd=$(pwd -P)/$GDIR" "$out"
fi

# --- a real rootfs ----------------------------------------------------------
# Now the guest paths are not host paths, so the guest's getcwd has to be
# answered from the virtual cwd — which needs a live translation tier.
if ! guest_xlate_ready "-w rootfs legs"; then
    :
elif [ "$m17w_probe" = 1 ]; then
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    m17w_run() { run -R $GUEST_BINDS "$@"; }

    out=$(m17w_run "$M17W" /probe 2>/dev/null)
    check_contains "rootfs: the default cwd is the guest root" "cwd=/" "$out"
    check_absent "the host launch directory never reaches the guest" \
        "$(pwd -P)" "$out"

    out=$(m17w_run -w /a/b "$M17W" /probe marker 2>/dev/null)
    check_contains "rootfs: -w sets the guest cwd" "cwd=/a/b" "$out"
    check_contains "rootfs: /proc/self/cwd agrees with getcwd" \
        "proccwd=/a/b" "$out"
    check_contains "rootfs: a relative path resolves in the work directory" \
        "rel=INSIDE_AB" "$out"

    # A symlinked DIR reports what it resolved to, as a real chdir(2) leaves
    # getcwd reporting the directory rather than the link that named it.
    out=$(m17w_run -w /link "$M17W" /probe marker 2>/dev/null)
    check_contains "-w follows a symlink to the directory it names" \
        "cwd=/a/b" "$out"
    check_contains "and lands there: the relative open still works" \
        "rel=INSIDE_AB" "$out"

    # `..` is canonicalized inside the guest root, so it cannot climb out.
    out=$(m17w_run -w /a/../.. "$M17W" /probe 2>/dev/null)
    check_contains "-w cannot climb out of the rootfs with '..'" "cwd=/" "$out"

    out=$(m17w_run -b "$M17WB":/bindpt -w /bindpt "$M17W" /probe bmarker \
        2>/dev/null)
    check_contains "-w may name a bind destination" "cwd=/bindpt" "$out"
    check_contains "and relative opens land in the bind source" \
        "rel=FROM_BIND" "$out"

    # <program> is resolved against the cwd, so -w has to be settled first.
    out=$(m17w_run -w /a/b "$M17W" probe marker 2>/dev/null); rc=$?
    check "a relative <program> resolves in the work directory" 0 $rc
    check_contains "and runs there" "rel=INSIDE_AB" "$out"
fi

# --- differential against arm64chroot ---------------------------------------
# The oracle has the same option; its resolution is the reference for ours.
if [ "$m17w_probe" = 0 ]; then
    :   # guest_cc_report already said why there is nothing to run
elif ! guest_xlate_ready "-w oracle differential"; then
    :   # our side of the diff would fail for want of translation, not for -w
elif [ -z "$M17W_ORACLE" ] || [ ! -x "$M17W_ORACLE" ]; then
    skip "-w oracle differential: no arm64chroot oracle for this host"
else
    # m17w_diff <desc> <args...> — the same invocation both sides, stdout
    # compared whole. chroot-ng needs -R for translation on a cross host; the
    # oracle emulates every instruction and needs nothing.
    m17w_diff() {
        _d=$1
        shift
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        _got=$(run -R $GUEST_BINDS "$@" 2>/dev/null)
        # shellcheck disable=SC2086
        _want=$("$M17W_ORACLE" $GUEST_BINDS "$@" 2>/dev/null)
        if [ -n "$_want" ] && [ "$_got" = "$_want" ]; then
            pass=$((pass + 1)); printf '  ok   oracle parity: %s\n' "$_d"
        else
            fail=$((fail + 1)); printf '  FAIL oracle parity: %s\n' "$_d"
            printf '    want: %s\n' "$(echo "$_want" | tr '\n' ' ')"
            printf '    got:  %s\n' "$(echo "$_got" | tr '\n' ' ')"
        fi
    }
    m17w_diff "-w /a/b" -w /a/b "$M17W" /probe marker
    m17w_diff "-w /link (symlinked)" -w /link "$M17W" /probe marker
    m17w_diff "-w /a/../.. (clamped at the root)" -w /a/../.. "$M17W" /probe
    m17w_diff "no -w: the guest root" "$M17W" /probe
fi

rm -rf "$M17W" "$M17WB"
