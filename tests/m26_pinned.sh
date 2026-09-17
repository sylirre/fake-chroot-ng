# M26: the resolved path is pinned for its syscall (sourced by tests/run.sh).
#
# The walk turned a guest name into a host path and the syscall was then made
# on that string, which the kernel resolved again from scratch: a directory on
# the way swapped for an absolute symlink between the two was followed from
# the HOST root, and the call landed outside the rootfs. Every path-bearing
# syscall had the window. Now the directory the walk reached is held open for
# the call and the last component is given to the kernel against it, with the
# family's NOFOLLOW; a link that appears in the race is refused, never
# followed (src/monitor/pin.c).
echo "== M26: pinned resolution =="

# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m26run() { run_t 120 $GUEST_BINDS "$@"; }
M26D=$(mktemp -d)

# The pin asked directly (-t pintest), on a tree under a rootfs of its own:
# the forms no guest can be made to produce to order — a spelling the
# readback does not agree with (the descriptor walk decides), the race held
# still (a link where the walk saw a directory, on the way and at the leaf),
# the trailing slash, what is left unpinned, and the kernel's order of
# refusals for a name whose directory cannot be pinned.
PTR=$(mktemp -d)
out=$(run_t 60 -t pintest -r "$PTR" 2>&1); rc=$?
check "m26 pintest overall" 0 "$rc"
for _leg in "plain: rc=0 names_dir=1" "respelled: rc=0 names_dir=1" \
    "trailing slash: dir leaf=0 file leaf=-20" \
    "link in the way: dir=-40 leaf=-40" \
    "unpinned and missing: missing=-2 notdir=-20" \
    "errno order: badflags=-22 missing=-2 unlink_badflags=-22 present=0"; do
    check_contains "m26 pin $_leg" "pintest $_leg -> OK" "$out"
done
rm -rf "$PTR"

if ! guest_xlate_ready "pinned-resolution legs"; then
    :
else
    # Two threads: one flips /w/d between a directory and a symlink to a host
    # directory the guest cannot name, the other loops over the families and
    # counts what each answered. A single answer from the host's files is
    # the escape. The mutating families aim at names only the host side
    # has, and leave their mark there if they ever get through.
    if guest_cc "$M26D/pathrace" tests/guests/pathrace.c -pthread; then
        R=$(mktemp -d); H=$(mktemp -d)
        mkdir -p "$R/bin" "$R/w/d" "$H/hostdir" "$H/sub"
        cp "$M26D/pathrace" "$R/bin/pathrace"
        printf 'guest\n' > "$R/w/d/x"; chmod 755 "$R/w/d/x"
        ln -s GUEST "$R/w/d/lnk"
        printf 'host\n' > "$H/x"; chmod 644 "$H/x"
        ln -s HOST "$H/lnk"
        : > "$H/victim"
        head -c 100 /dev/zero > "$H/big"
        out=$(m26run -R "$R" /bin/pathrace "$H" 4 2>/dev/null)
        check_contains "m26 the race never reaches the host: no family answers for it" \
            " host=0 " "$out"
        check_absent "m26 ...and the run exercised the families at all" \
            "iters=0 " "$out"
        check "m26 the host's file survived the unlinks" 0 \
            "$([ -e "$H/victim" ]; echo $?)"
        check "m26 the host's directory survived the rmdirs" 0 \
            "$([ -d "$H/hostdir" ]; echo $?)"
        check "m26 nothing was made in the host's directory" 1 \
            "$([ -e "$H/hostdir/made" ]; echo $?)"
        check "m26 the host's file kept its size" 100 \
            "$(wc -c < "$H/big" | tr -d ' ')"
        rm -rf "$R" "$H"
    else
        skip "pinned-resolution race leg: could not build tests/guests/pathrace.c with -pthread"
    fi

    # A pathname socket is bound through the pinned directory, so what the
    # kernel stores is the monitor's spelling of the name — and a datagram
    # service answers at the source address its recvfrom reports. Server and
    # client are two invocations, neither forked from the other, each with a
    # pathname of its own: the server must read the client's name back as
    # the guest bound it, and its reply must arrive.
    if guest_cc "$M26D/uxreply" tests/guests/uxreply.c; then
        R=$(mktemp -d); mkdir -p "$R/bin" "$R/run"
        cp "$M26D/uxreply" "$R/bin/uxreply"
        m26run -R "$R" /bin/uxreply server /run/srv.sock >"$M26D/srv.out" \
            2>/dev/null &
        m26bg=$!
        sleep 2
        cl=$(m26run -R "$R" /bin/uxreply client /run/srv.sock /run/cli.sock \
            2>/dev/null)
        wait $m26bg 2>/dev/null
        sv=$(cat "$M26D/srv.out")
        check_contains "m26 a server reads an unrelated client's bound name back" \
            "server: got=ping from=/run/cli.sock reply=1" "$sv"
        check_contains "m26 ...and its reply to that name arrives, from the server's" \
            "client: reply=pong from=/run/srv.sock" "$cl"
        check_absent "m26 ...with none of the monitor's spelling shown" \
            "/proc/" "$sv$cl"
        rm -rf "$R"
    else
        skip "pinned bind readback leg: could not build tests/guests/uxreply.c"
    fi
fi
rm -rf "$M26D"
