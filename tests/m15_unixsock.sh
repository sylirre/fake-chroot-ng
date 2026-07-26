# M15 AF_UNIX address containment (sourced by tests/run.sh).
#
# A pathname socket carries a filesystem path in sun_path, and no socket syscall
# was trapped, so it got no containment at all: a guest bind("/run/foo.sock")
# created the inode on the HOST and connect() reached host daemons with the
# guest's real credentials. Readback handed back raw host paths.
#
# The host /run is root-owned and not writable by the test user, which makes the
# pathname leg self-proving: a bind there can only succeed if it was translated
# into the rootfs. Abstract names have no filesystem node, so they are isolated
# by a per-rootfs tag instead; that leg is proven from the host's own
# /proc/net/unix (the tag must be on the wire) and by two rootfs taking the same
# name (they must not collide), with --share-abstract-sockets as the control.
echo "== M15: AF_UNIX containment =="

M15_GCC="${GCC:-aarch64-linux-gnu-gcc-13}"
M15_QEMU="${QEMU:-qemu-aarch64-static}"
# Wrapped in a timeout for the same reason as m16: a socket test that blocks
# should fail one check, not wedge the suite. The held-socket runs below sleep on
# purpose, so allow for that.
m15run() { timeout 60 "$M15_QEMU" "$@"; }
M15D=$(mktemp -d)

if ! $M15_GCC -static-pie -O2 -o "$M15D/uxsock" tests/guests/uxsock.c \
        2>"$M15D/build.log"; then
    echo "  skip: could not build tests/guests/uxsock.c"
else
    R1=$(mktemp -d); R2=$(mktemp -d)
    for d in "$R1" "$R2"; do
        mkdir -p "$d/run" "$d/bin"; cp "$M15D/uxsock" "$d/bin/uxsock"
    done

    # --- pathname sockets -------------------------------------------------
    # /run is not writable on the host, so "bind: ok" is only reachable by way
    # of the rootfs, and the readback must be the guest path, not the host one.
    out=$(m15run build/chroot-ng -R "$R1" /bin/uxsock /run/s.sock 2>&1)
    check_contains "m15 a pathname bind lands inside the rootfs" "bind: ok" "$out"
    check_contains "m15 getsockname reports the guest path" \
        "getsockname: /run/s.sock" "$out"
    check_contains "m15 getpeername reports the guest path" \
        "getpeername: /run/s.sock" "$out"
    case "$out" in
    *"$R1"*) fail=$((fail + 1))
        echo "  FAIL m15 readback leaked the host rootfs path"
        echo "    got: $out" ;;
    *) pass=$((pass + 1)); echo "  ok   m15 readback leaks no host path" ;;
    esac
    # The inode really is in the rootfs (the guest unlinks on exit, so bind a
    # name it leaves behind by killing the hold early is fragile — instead check
    # that the host never gained the name).
    if [ -e /run/s.sock ]; then
        fail=$((fail + 1)); echo "  FAIL m15 the host gained /run/s.sock"
    else
        pass=$((pass + 1)); echo "  ok   m15 the host filesystem is untouched"
    fi

    # An over-long translated name cannot fit sun_path's 108 bytes, so the
    # fallback binds relative to a /proc/self/fd directory handle instead.
    DEEP="$M15D/$(printf 'd/%.0s' $(seq 1 30))"
    mkdir -p "$DEEP/run" "$DEEP/bin" && cp "$M15D/uxsock" "$DEEP/bin/uxsock"
    out=$(m15run build/chroot-ng -R "$DEEP" /bin/uxsock /run/s.sock 2>&1)
    check_contains "m15 an over-long translated path still binds" "bind: ok" \
        "$out"

    # --- abstract namespace ----------------------------------------------
    out=$(m15run build/chroot-ng -R "$R1" /bin/uxsock myabs abstract 2>&1)
    check_contains "m15 an abstract bind works" "bind: ok" "$out"
    check_contains "m15 the per-rootfs tag is invisible to the guest" \
        "getsockname: @myabs" "$out"

    # ...but it IS on the wire: the host sees the tag, so the name is scoped.
    m15run build/chroot-ng -R "$R1" /bin/uxsock tagprobe abstract 4 \
        >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    hostview=$(grep -a 'tagprobe' /proc/net/unix 2>/dev/null | awk '{print $NF}' \
        | head -1)
    wait $m15bg 2>/dev/null
    case "$hostview" in
    *cng*tagprobe) pass=$((pass + 1))
        echo "  ok   m15 the abstract name is tagged on the wire" ;;
    "") echo "  skip: /proc/net/unix unreadable" ;;
    *) fail=$((fail + 1))
        echo "  FAIL m15 the abstract name is not tagged on the wire"
        echo "    got: $hostview" ;;
    esac

    # Two DIFFERENT rootfs must both be able to take the same abstract name.
    m15run build/chroot-ng -R "$R1" /bin/uxsock shared abstract 4 \
        >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    out=$(m15run build/chroot-ng -R "$R2" /bin/uxsock shared abstract 2>&1)
    wait $m15bg 2>/dev/null
    check_contains "m15 abstract names are isolated between rootfs" "bind: ok" \
        "$out"

    # --share-abstract-sockets opts out, and then they DO collide — the control
    # that proves the isolation above comes from the tag and not from luck.
    m15run build/chroot-ng -R --share-abstract-sockets "$R1" \
        /bin/uxsock shared2 abstract 4 >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    out=$(m15run build/chroot-ng -R --share-abstract-sockets "$R2" \
        /bin/uxsock shared2 abstract 2>&1)
    wait $m15bg 2>/dev/null
    check_contains "m15 --share-abstract-sockets shares the host namespace" \
        "Address already in use" "$out"

    rm -rf "$R1" "$R2"
fi
rm -rf "$M15D"
