# M27 terminal ioctls an Android app is refused (sourced by tests/run.sh).
#
# Android's SELinux policy whitelists the ioctls an app may issue on its pty,
# and the ones a libc builds its verdict about a terminal on are not all on the
# list: the host answers EACCES, and the guest -- which makes its ioctls itself
# -- took its terminal for none. The filter traps those requests (tty.c) and
# the dispatcher answers them from the commands the policy allows. Each guest
# here prints what a real kernel prints (the expected text was taken from a
# native build on one), so a host that serves the ioctl itself, a host that
# refuses it, and the knob that forces the refusal anywhere must all agree.
echo "== M27: terminal ioctls =="

TTY_DIR=$(mktemp -d)

# tty_check DESC GUEST KNOBS WANT [WHY] — run /GUEST on every tier this host
# has, once as the host serves it and once with each of KNOBS (a list) set to
# 1, which refuses the ioctls before the host is asked (the tier Android's
# policy serves). WHY, when given, is the reason the first of the two cannot be
# judged on this host.
tty_check() {
    _desc=$1
    _guest=$2
    _knob=$3
    _want=$4
    _why=${5:-}
    for _tier in -R plain; do
        if [ "$_tier" = plain ]; then
            if [ "$CNG_SECCOMP_LIVE" != 1 ]; then
                skip "$_desc, seccomp tier: the filter is inert here"
                continue
            fi
            _opt=""
        else
            _opt="-R"
        fi
        for _deny in 0 1; do
            _label="$_desc ($_tier)"
            [ "$_deny" = 1 ] && _label="$_desc, the host's refusal forced ($_tier)"
            if [ "$_deny" = 0 ] && [ -n "$_why" ]; then
                skip "$_label: $_why"
                continue
            fi
            # shellcheck disable=SC2086  # $_opt and $GUEST_BINDS are split on purpose
            _got=$(
                if [ "$_deny" = 1 ]; then
                    for _k in $_knob; do
                        export "$_k=1"
                    done
                fi
                run_t 60 $_opt $GUEST_BINDS "$TTY_DIR" "/$_guest" 2>/dev/null
            )
            case "$_got" in
            SKIP:*)
                skip "$_label: ${_got#SKIP: }"
                continue
                ;;
            esac
            if [ "$_got" = "$_want" ]; then
                pass=$((pass + 1))
                echo "  ok   $_label"
            else
                fail=$((fail + 1))
                echo "  FAIL $_label"
                printf '%s\n' "$_got" | sed 's/^/    /'
            fi
        done
    done
}

# TCGETS2/TCSETS2/TCSETSW2/TCSETSF2 over a real pty: the 44-byte struct comes
# back whole and no further, agrees with TCGETS on the first 36 bytes, each
# setter carries all of it in (c_ospeed too -- a copy that stopped at 36 reads
# back rate 0), a rate set through the master is read through the slave, an
# unmapped buffer is EFAULT both ways, and a pipe (to a getter and to a setter)
# and a directory are ENOTTY. A glibc since 2.42 builds isatty on them: on a
# device the original build answered EACCES here, and bash in an Ubuntu 26.04
# rootfs printed no prompt. Forced, TCSETSF is
# refused as well, as Android 8's policy refuses it, so TCSETSF2 reaches the
# pair that serves it (below) through the classic command's own fallback.
if guest_xlate_ready "termios2 ioctls" &&
    guest_cc_report "$TTY_DIR/termios2" tests/guests/termios2.c; then
    tty_check "termios2 ioctls agree with a kernel's" termios2 \
        "CNG_TERMIOS2_DENY CNG_TCSETSF_DENY" \
"get2=0 errno=0 whole=1 tail=1 prefix=1
set2=0 errno=0 readback=1
setsw2=0 errno=0 readback=1
setsf2=0 errno=0 readback=1
master_set2=0 errno=0 readback=1
master_get2=0 speed=1
get2_fault=-1 errno=14
set2_fault=-1 errno=14
pipe=-1 errno=25
pipe_set2=-1 errno=25
dir=-1 errno=25
done"
fi

# TCSETSF (tcsetattr(TCSAFLUSH): getpass, su, ssh's prompt) over a real pty:
# a line already typed is gone and the change made, the same line outlives a
# TCSETSW, an unmapped termios is EFAULT, and a pipe and a directory ENOTTY.
# Android 8's policy lets TCSETS, TCSETSW and TCFLSH through on a pty and
# answers this one EACCES; the forced tier serves it from TCFLSH and TCSETSW.
# Android 15's refuses all three on a pipe and TCGETS too on a directory, where
# what serves it must still tell a kernel's ENOTTY.
if guest_xlate_ready "TCSETSF" &&
    guest_cc_report "$TTY_DIR/tcsetsf" tests/guests/tcsetsf.c; then
    tty_check "TCSETSF agrees with a kernel's" tcsetsf CNG_TCSETSF_DENY \
"setsf=0 errno=0 readback=1 typed=1 left=-11
setsw=0 typed=1 left=6
setsf_fault=-1 errno=14
pipe=-1 errno=25
dir=-1 errno=25
done"
fi

# TIOCGSID (tcgetsid(3): login, script, agetty) over a real pty: ENOTTY with no
# session, a child that setsid()s and takes the pty reads its own pid from the
# slave and from the master, the parent reads it from the master and is ENOTTY
# of the slave it does not control, the leader's exit takes the session away, a
# pipe, /dev/null and a directory are ENOTTY, a null buffer is EFAULT, and a
# foreground group whose leader is gone still names its session (the members
# have to be looked through for it). Android's policy answers EACCES to it on a
# slave and on a pipe; the forced tier serves it from TCGETS, TIOCGPGRP and
# getsid and must say the same. The guest's own probe, run outside the monitor,
# says whether the host can be believed with the unforced rows: qemu-user's
# table lists the request as input only, so it answers success and writes no
# session.
if guest_xlate_ready "TIOCGSID" &&
    guest_cc_report "$TTY_DIR/tiocgsid" tests/guests/tiocgsid.c; then
    _host=$(emu_t 30 "$TTY_DIR/tiocgsid" probe 2>/dev/null)
    _why=""
    [ "$_host" = broken ] &&
        _why="the host answers TIOCGSID with success and no session (qemu-user)"
    tty_check "TIOCGSID agrees with a kernel's" tiocgsid CNG_TIOCGSID_DENY \
"slave_nosess=-1 errno=25
master_nosess=-1 errno=25
slave_foreign=-1 errno=25
slave_ctl=0 own=1
slave_fault=-1 errno=14
master_ctl=0 own=1
master_parent=0 kid=1
master_gone=-1 errno=25
pipe=-1 errno=25
null=-1 errno=25
dir=-1 errno=25
closed=-1 errno=9
master_orphan=0 sess=1
done" "$_why"
fi

rm -rf "$TTY_DIR"
