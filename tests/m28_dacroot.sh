# M28: fake root's DAC bypass, lent (sourced by tests/run.sh).
#
# Root is not held back by permission bits: it creates and removes names in a
# directory whose mode forbids writing it, opens a file for an access its mode
# refuses, and searches a directory with no x bit. A fake root (-u) is the real
# uid underneath and had none of that, so tar could not fill a directory it had
# just made 0500 — GNU tar and busybox tar both create a directory with its
# final owner bits when they run as root, counting on exactly this — and
# `rm -rf` could not empty one. chroot-ng now lends the owner bits to the one
# inode the host refused, makes the call again, and puts the mode back.
#
# The guest program prints what root may do, case by case, ending with the
# modes everything was left with. Its reference is real root: the block below
# was recorded by running it natively with sudo on a 6.8 kernel, and it is
# what a fake root has to print, on every tier. The busybox tar leg is the
# scenario that was reported, end to end.
echo "== M28: fake root's DAC bypass =="

DAC_ROOT='mkdir_ro=0
create_in_ro=0
mkdir_in_ro=0
mkdir2_in_ro=0
mknod_in_ro=0
symlink_in_ro=0
link_in_ro=0
rename_in_ro=0
rename_dir_out=0
rmdir_in_ro=0
unlink_in_ro=0
unlink_link_in_ro=0
unlink_sym_in_ro=0
unlink_fifo_in_ro=0
tmpfile_in_ro=0
create_at_dirfd=0
unlink_at_dirfd=0
mkdir_rw=0
read_0000=zero
append_0400=0
trunc_0444=0
after_trunc=
truncate_0444=0
after_truncate=tr
mkdir_nr=0
readdir_0300=0
write_a_dir=21
exec_no_x=13
mkdir_nx=0
symlink_nx=0
mkdir_deep=0
stat_through=0
open_through=nxf
link_through=nxf
deep_through=deep
access_through=0
create_through=0
chmod_through=0
mode_after_chmod=640
chdir_nx=0
read_in_nx=nxf
mkdir_race=0
race failed=0 made=100
modes ro=500 sub=500 nr=300 nx=600 deep=600 race=500 z=0 w=400'

# dac_cases GOT PREFIX — each line of the reference looked for whole in GOT,
# so a failure names the case ("link_in_ro=0" is also the tail of
# "unlink_link_in_ro=0", which a substring test would take for it).
dac_cases() {
    printf '%s\n' "$DAC_ROOT" | while IFS= read -r _l; do
        if printf '%s\n' "$1" | grep -qxF -- "$_l"; then
            echo "  ok   $2${_l%%[= ]*}"
        else
            echo "  FAIL $2${_l%%[= ]*} (want: $_l)"
        fi
    done >"$CNG_TMP/dac_cases"
    pass=$((pass + $(grep -c '^  ok' "$CNG_TMP/dac_cases")))
    fail=$((fail + $(grep -c '^  FAIL' "$CNG_TMP/dac_cases")))
    cat "$CNG_TMP/dac_cases"
}

DRD=$(mktemp -d)
if guest_xlate_ready "fake-root DAC differential" &&
    guest_cc_report "$DRD/dacroot" tests/guests/dacroot.c; then
    # -l throughout: Android refuses an app's hardlinks, and link_in_ro is
    # then the l2s emulation's, whose first link writes the source's
    # directory too. Elsewhere the host's own link is made and -l never
    # steps in, so the forced run below is what exercises that lend there.
    for _run in -R plain l2s; do
        _label="fake root ($_run) is let through as root is"
        if [ "$_run" = plain ] && [ "$CNG_SECCOMP_LIVE" != 1 ]; then
            skip "$_label: the filter is inert here"
            continue
        fi
        _r=$(mktemp -d)
        cp "$DRD/dacroot" "$_r/"
        case $_run in
        -R)
            # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
            got=$(run_t 120 -R -l -u 0:0 $GUEST_BINDS "$_r" /dacroot / \
                2>/dev/null)
            ;;
        plain)
            # shellcheck disable=SC2086
            got=$(run_t 120 -l -u 0:0 $GUEST_BINDS "$_r" /dacroot / \
                2>/dev/null)
            ;;
        l2s)
            # shellcheck disable=SC2086
            got=$(CNG_L2S_FORCE=1 run_t 120 -R -l -u 0:0 $GUEST_BINDS "$_r" \
                /dacroot / 2>/dev/null)
            ;;
        esac
        check "$_label" "$DAC_ROOT" "$got"
        dac_cases "$got" "fake root ($_run): "
        # The modes as the host sees them, not through the dispatcher that
        # lent them: every one is back. (deep is in nx, which the host may
        # not search, and the guest's own line above already answers it.)
        _m=$(cd "$_r/dac" 2>/dev/null &&
            stat -c '%a' ro sub nr nx race rw/z rw/w 2>/dev/null | tr '\n' ' ')
        check "fake root ($_run): the host sees every lent mode given back" \
            "500 500 300 600 500 0 400 " "$_m"
        chmod -R u+rwx "$_r"
        rm -rf "$_r"
    done
fi
rm -rf "$DRD"

# The scenario reported: tar extracting a tree with read-only directories in
# it. busybox tar, like GNU tar, makes a directory with its final mode when it
# runs as root and fills it afterwards; the old fake root was refused every
# file in it ("can't open 'top/ro/a': Permission denied"). The archive is made
# by the guest too, so nothing depends on the host's own tar.
M28_ALPINE="${M28_ALPINE:-$CNG_ALPINE}"
if [ -z "$M28_ALPINE" ] || [ ! -x "$M28_ALPINE/bin/busybox" ]; then
    skip "tar into read-only directories: no alpine rootfs"
else
    for _tier in -R plain; do
        _label="tar under fake root ($_tier)"
        if [ "$_tier" = plain ] && [ "$CNG_SECCOMP_LIVE" != 1 ]; then
            skip "$_label: the filter is inert here"
            continue
        fi
        _t=$(mktemp -d)
        mkdir -p "$_t/src/top/ro/sub" "$_t/x" "$_t/a"
        echo a >"$_t/src/top/ro/a"
        echo b >"$_t/src/top/ro/sub/b"
        chmod 0555 "$_t/src/top/ro/sub" "$_t/src/top/ro"
        _opt=""
        [ "$_tier" = -R ] && _opt=-R
        # shellcheck disable=SC2086  # $_opt is empty or one flag
        out=$(run_t 60 $_opt -u 0:0 -b "$_t/src:/src" -b "$_t/x:/x" \
            -b "$_t/a:/a" "$M28_ALPINE" /bin/sh -c \
            'cd /src && tar cf /a/t.tar top && cd /x && tar xf /a/t.tar;
             echo "tar=$?"; cat top/ro/a top/ro/sub/b | tr "\n" " "; echo;
             stat -c "%a" top/ro top/ro/sub | tr "\n" " "; echo;
             rm -r top; echo "rm=$?"' 2>&1)
        check_contains "$_label extracts into a directory made 0500" "tar=0" \
            "$out"
        check_contains "$_label: ...every file in it" "a b " "$out"
        check_contains "$_label: ...with the modes the archive holds" \
            "555 555 " "$out"
        check_contains "$_label: ...and rm -r empties them again" "rm=0" \
            "$out"
        chmod -R u+rwx "$_t"
        rm -rf "$_t"
    done
fi
