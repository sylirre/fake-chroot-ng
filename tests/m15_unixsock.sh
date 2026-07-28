# M15 AF_UNIX address containment (sourced by tests/run.sh).
#
# A pathname socket carries a filesystem path in sun_path, and no socket syscall
# was trapped, so it got no containment at all: a guest bind("/run/foo.sock")
# created the inode on the HOST and connect() reached host daemons with the
# guest's real credentials. Readback handed back raw host paths.
#
# The guest path used below is /run/s.sock, and the host's /run is either
# root-owned and unwritable by the test user (a Linux devbox) or absent entirely
# (Android). Either way the pathname leg is self-proving: a bind there can only
# succeed if it was translated into the rootfs. Abstract names have no filesystem
# node, so they are isolated by a per-rootfs tag instead; that leg is proven from
# the host's own /proc/net/unix (the tag must be on the wire) and by two rootfs
# taking the same name (they must not collide), with --share-abstract-sockets as
# the control.
echo "== M15: AF_UNIX containment =="

# Runs are wrapped in a timeout for the same reason as m16: a socket test that
# blocks should fail one check, not wedge the suite. The held-socket runs below
# sleep on purpose, so allow for that.
# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m15run() { run_t 60 $GUEST_BINDS "$@"; }
M15D=$(mktemp -d)

if ! guest_xlate_ready "AF_UNIX containment scenarios"; then
    :
elif ! guest_cc_report "$M15D/uxsock" tests/guests/uxsock.c; then
    :
else
    R1=$(mktemp -d); R2=$(mktemp -d)
    for d in "$R1" "$R2"; do
        mkdir -p "$d/run" "$d/bin"; cp "$M15D/uxsock" "$d/bin/uxsock"
    done

    # --- pathname sockets -------------------------------------------------
    # The host /run is unwritable (or absent), so "bind: ok" is only reachable by
    # way of the rootfs; the readback must be the guest path, not the host one;
    # and the host must never gain the name. The last of the three holds even
    # when the suite runs as root, where the first proves less.
    out=$(m15run -R "$R1" /bin/uxsock /run/s.sock 2>&1)
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
    # Deep enough that the translated host path cannot fit sun_path on ANY host:
    # $TMPDIR is 4 characters on a devbox and ~40 under Termux, so count the
    # bytes rather than a fixed number of components.
    DEEP=$M15D
    while [ ${#DEEP} -lt 110 ]; do DEEP="$DEEP/d"; done
    mkdir -p "$DEEP/run" "$DEEP/bin" && cp "$M15D/uxsock" "$DEEP/bin/uxsock"
    out=$(m15run -R "$DEEP" /bin/uxsock /run/s.sock 2>&1)
    check_contains "m15 an over-long translated path still binds" "bind: ok" \
        "$out"

    # --- abstract namespace ----------------------------------------------
    out=$(m15run -R "$R1" /bin/uxsock myabs abstract 2>&1)
    check_contains "m15 an abstract bind works" "bind: ok" "$out"
    check_contains "m15 the per-rootfs tag is invisible to the guest" \
        "getsockname: @myabs" "$out"

    # ...but it IS on the wire: the host sees the tag, so the name is scoped.
    m15run -R "$R1" /bin/uxsock tagprobe abstract 4 >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    hostview=$(grep -a 'tagprobe' /proc/net/unix 2>/dev/null | awk '{print $NF}' \
        | head -1)
    wait $m15bg 2>/dev/null
    case "$hostview" in
    *cng*tagprobe) pass=$((pass + 1))
        echo "  ok   m15 the abstract name is tagged on the wire" ;;
    "") skip "abstract-tag-on-the-wire leg: /proc/net/unix unreadable" ;;
    *) fail=$((fail + 1))
        echo "  FAIL m15 the abstract name is not tagged on the wire"
        echo "    got: $hostview" ;;
    esac

    # Two DIFFERENT rootfs must both be able to take the same abstract name.
    m15run -R "$R1" /bin/uxsock shared abstract 4 >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    out=$(m15run -R "$R2" /bin/uxsock shared abstract 2>&1)
    wait $m15bg 2>/dev/null
    check_contains "m15 abstract names are isolated between rootfs" "bind: ok" \
        "$out"

    # --share-abstract-sockets opts out, and then they DO collide — the control
    # that proves the isolation above comes from the tag and not from luck.
    m15run -R --share-abstract-sockets "$R1" \
        /bin/uxsock shared2 abstract 4 >/dev/null 2>&1 &
    m15bg=$!
    sleep 2
    out=$(m15run -R --share-abstract-sockets "$R2" \
        /bin/uxsock shared2 abstract 2>&1)
    wait $m15bg 2>/dev/null
    check_contains "m15 --share-abstract-sockets shares the host namespace" \
        "Address already in use" "$out"

    # --- the array forms (sendmmsg/recvmmsg) -----------------------------
    # One address per message, so the containment is per element and a loop that
    # only looked at the first would leak every message after it. The proof is
    # the same one the pathname legs above make — the host /run is unwritable, so
    # a datagram only reaches the server if its address was translated — with the
    # readback asserted on the LAST message rather than the first.
    if ! guest_cc_report "$M15D/uxmmsg" tests/guests/uxmmsg.c; then
        :
    else
        cp "$M15D/uxmmsg" "$R1/bin/uxmmsg"
        out=$(m15run -R "$R1" /bin/uxmmsg /run/d.sock /run/c.sock 2>&1)
        check_contains "m15 mmsg both array-form sockets bind in the rootfs" \
            "bind: ok" "$out"
        check_contains "m15 sendmmsg translates every message's address" \
            "sendmmsg: 3" "$out"
        check_contains "m15 recvmmsg delivers the whole batch" "recvmmsg: 3" \
            "$out"
        check_contains "m15 recvmmsg strips the first source address" \
            "msg[0]: hello-0 from /run/c.sock" "$out"
        check_contains "m15 recvmmsg strips the last one too" \
            "msg[2]: hello-2 from /run/c.sock" "$out"
        case "$out" in
        *"$R1"*) fail=$((fail + 1))
            echo "  FAIL m15 an mmsg source address leaked the host rootfs path"
            echo "    got: $out" ;;
        *) pass=$((pass + 1))
            echo "  ok   m15 no mmsg source address leaks a host path" ;;
        esac
        if [ -e /run/d.sock ] || [ -e /run/c.sock ]; then
            fail=$((fail + 1))
            echo "  FAIL m15 the host gained an array-form socket"
        else
            pass=$((pass + 1))
            echo "  ok   m15 the host filesystem is untouched by the array forms"
        fi

        # The other half of the bargain: a batch with no address to contain must
        # come back exactly as it would unemulated. A socketpair has nowhere to
        # put one, and a UDP socket cannot be carrying a sun_path at all — which
        # is the case the emulation answers with one getsockopt rather than a
        # walk over every message.
        check_contains "m15 an address-less batch is untouched" \
            "pair: sent=3 got=3 ok=1" "$out"
        case "$out" in
        *"udp: skip"*)
            skip "m15 udp batch leg: no loopback UDP on this host" ;;
        *)
            check_contains "m15 an ordinary UDP batch is untouched" \
                "udp: sent=3 got=3 ok=1" "$out" ;;
        esac

        # An abstract source address carries the per-rootfs tag on the wire, and
        # recvmmsg has to strip it per message like recvmsg does for its one.
        out=$(m15run -R "$R1" /bin/uxmmsg /run/d.sock @uxmc 2>&1)
        check_contains "m15 recvmmsg strips the abstract tag per message" \
            "msg[2]: hello-2 from @uxmc" "$out"
    fi

    rm -rf "$R1" "$R2"
fi
rm -rf "$M15D"
