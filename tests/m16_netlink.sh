# M16 NETLINK_ROUTE emulation (sourced by tests/run.sh).
#
# Android denies app domains rtnetlink, and everything that asks the kernel about
# interfaces goes through it: getifaddrs(3), iproute2, bubblewrap's
# loopback_setup(), glibc's source-address selection. Without a shim they all
# fail inside the guest.
#
# What a host can prove splits in two, and the milestone asks the unemulated
# guest which case this one is:
#
#   raw rtnetlink WORKS here (a devbox) — then the emulation, forced on with
#     CNG_NETLINK_FORCE_BLOCK=1, must reproduce the real kernel byte for byte,
#     and must stay entirely out of the way when it is not forced.
#   the kernel REFUSES it (a device: the case the shim exists for) — then there
#     is nothing to diff against and the emulation is *supposed* to diverge.
#     What to assert instead is that it engages on its own and turns each refusal
#     into a working answer, which is the one thing a devbox cannot check.
#
# The deciding question is the raw path, not getifaddrs. Bionic carries its own
# fallback for exactly the restriction being emulated, so on a device getifaddrs
# succeeds while bind/sendto on a NETLINK_ROUTE socket are refused — and keying
# the gate on "getifaddrs: ok" took the devbox branch there and failed every
# differential leg for precisely the reason the emulation exists.
echo "== M16: NETLINK_ROUTE emulation =="

# Guest runs are wrapped in a timeout: a netlink dump that never terminates would
# otherwise wedge the whole suite instead of failing one check.
# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m16run() { run_t 60 $GUEST_BINDS "$@"; }
m16_has() { # needle, haystack
    case "$2" in
    *"$1"*) return 0 ;;
    esac
    return 1
}
M16D=$(mktemp -d)

if ! guest_xlate_ready "rtnetlink emulation scenarios"; then
    :
elif ! guest_cc_report "$M16D/netif" tests/guests/netif.c; then
    :
else
    R=$(mktemp -d); mkdir -p "$R/bin"; cp "$M16D/netif" "$R/bin/netif"

    # The reference: the same binary with no emulation at all, talking to
    # whatever this kernel is willing to do.
    base=$(emu_t 60 "$M16D/netif" 2>/dev/null)
    m16_raw=0
    if m16_has "bind: ok" "$base" && m16_has "sendto: ok" "$base" &&
        m16_has "dump: got>0=1" "$base"; then
        m16_raw=1
    fi

    if [ -z "$base" ]; then
        skip "rtnetlink legs: the unemulated guest produced no output at all"
    else
        em=$(CNG_NETLINK_FORCE_BLOCK=1 m16run -R "$R" /bin/netif 2>/dev/null)

        # --- 1. the emulation's own properties, assertable on any host ------
        check_contains "m16 getifaddrs works under the emulation" \
            "getifaddrs: ok" "$em"
        check_contains "m16 the loopback interface is visible" "lo=1" "$em"
        check_contains "m16 socket(AF_NETLINK) is served" "socket: ok" "$em"
        check_contains "m16 bind on an emulated socket succeeds" "bind: ok" "$em"
        # iproute2 refuses a getsockname answer that is not sockaddr_nl-sized;
        # the underlying AF_UNIX socket would report 2 bytes.
        check_contains "m16 getsockname reports a 12-byte sockaddr_nl" \
            "getsockname: len=12 family=16" "$em"
        # accept(2) does not apply to a datagram socket, and netlink is one.
        # The stand-in shares the getsockname branch, so it used to answer
        # success with a sockaddr_nl — handing back fd 0 as a connection.
        check_contains "m16 accept on a netlink socket is EOPNOTSUPP" \
            "accept: rc=-1 errno=95" "$em"
        # A dump the guest can parse: messages present, its own sequence number
        # echoed, and real RTM_NEWLINK records in it.
        check_contains "m16 an RTM_GETLINK dump is relayed and parseable" \
            "dump: got>0=1 msgs>0=1 seq_ok=1 newlink>0=1" "$em"
        # recvmmsg fills a source address per message, and a netlink client
        # discards any reply whose source is not the kernel — so the array form
        # has to answer sockaddr_nl with nl_pid 0, exactly as recvmsg does. The
        # underlying socketpair would report an unnamed AF_UNIX address instead.
        check_contains "m16 recvmmsg sources each reply from the kernel" \
            "mmsg: got>0=1 msgs>0=1 src_nl=1 src_pid0=1" "$em"
        # The SIOCGIF* family answers the same questions over an AF_INET socket
        # (`ifconfig`, getifaddrs's oldest fallback). It comes from the same
        # enumeration as the dump, so the two views cannot contradict each
        # other -- a guest told it has only loopback must not be shown the
        # host's whole interface list here.
        check_contains "m16 SIOCGIFCONF lists the same interfaces the dump did" \
            "ifconf: size_ok=1 entries>0=1 lo=1 lo_addr=1" "$em"
        check_contains "m16 the per-interface getters agree with it" \
            "ifget: lo idx=1 up=1 loopback=1 mtu=65536 mask8=1 byidx=1" "$em"
        # A name nobody has is still ENODEV. An interface the host DOES know but
        # our enumeration did not is deliberately left to the host: a guest can
        # learn a name from /proc/net/dev (a passthrough), and busybox
        # `ifconfig` reads exactly that, so refusing it would stop the tool on
        # its first interface. This emulation answers where the host will not;
        # it never takes away an answer the host is willing to give.
        check_contains "m16 an interface nobody has is ENODEV" \
            "ifget: nodev=1" "$em"
        # A non-dump RTM_GET* is a different request from the dump of the same
        # type: its payload *is* the request, and the kernel parses it with a
        # header length of its own before the handler runs. Relaying every
        # RTM_GET* in the minimal dump form — the shape that gets past Android's
        # refusal of the attribute-bearing dump — hands the kernel a message
        # four bytes short of that and it answers EINVAL, so `ip link show dev
        # eth0` and `ip route get 8.8.8.8` printed "Invalid argument" for
        # requests the host would have answered.
        check_contains "m16 a non-dump RTM_GETLINK is answered, not refused" \
            "getlink1: msgs>0=1 newlink=1 err=0" "$em"

        # --- 2. against the kernel, where there is a kernel to compare to ---
        if [ "$m16_raw" = 1 ]; then
            if [ "$em" = "$base" ]; then
                pass=$((pass + 1))
                echo "  ok   m16 emulated rtnetlink matches the real kernel"
            else
                fail=$((fail + 1))
                echo "  FAIL m16 emulated rtnetlink matches the real kernel"
                echo "    want: $base"
                echo "    got:  $em"
            fi

            # Without forcing, rtnetlink works here, so the emulation must stay
            # out of the way entirely rather than shadowing a working kernel.
            pt=$(m16run -R "$R" /bin/netif 2>/dev/null)
            if [ "$pt" = "$base" ]; then
                pass=$((pass + 1)); echo "  ok   m16 passthrough is unchanged"
            else
                fail=$((fail + 1)); echo "  FAIL m16 passthrough is unchanged"
                echo "    got: $pt"
            fi
            dbg=$(CNG_DEBUG=1 m16run -R "$R" /bin/netif 2>&1 \
                >/dev/null | grep -c 'netlink: emulating')
            check "m16 the emulation does not engage where rtnetlink works" \
                0 "$dbg"
        else
            # This host is the target. Nothing to diff against, so assert the
            # thing that actually matters here: the guest never asked to be
            # rescued, and still was.
            printf '  (this kernel refuses the raw path: %s)\n' \
                "$(printf %s "$base" | tr '\n' ' ')"
            pt=$(m16run -R "$R" /bin/netif 2>/dev/null)
            dbg=$(CNG_DEBUG=1 m16run -R "$R" /bin/netif 2>&1 \
                >/dev/null | grep -c 'netlink: emulating')
            if [ "$dbg" -gt 0 ]; then
                pass=$((pass + 1))
                echo "  ok   m16 the emulation engages unforced where the kernel refuses rtnetlink"
            else
                fail=$((fail + 1))
                echo "  FAIL m16 the emulation engages unforced where the kernel refuses rtnetlink"
                echo "    (no 'netlink: emulating' trace; guest got: $pt)"
            fi
            check_contains "m16 unforced: bind succeeds where the kernel refused it" \
                "bind: ok" "$pt"
            check_contains "m16 unforced: the refused dump is served and parseable" \
                "dump: got>0=1 msgs>0=1 seq_ok=1 newlink>0=1" "$pt"
            check_contains "m16 unforced: getifaddrs works" "getifaddrs: ok" "$pt"
            check_contains "m16 unforced: the loopback interface is visible" \
                "lo=1" "$pt"
            check_contains "m16 unforced: SIOCGIFCONF answers from the same view" \
                "ifconf: size_ok=1 entries>0=1 lo=1 lo_addr=1" "$pt"
            check_contains "m16 unforced: the per-interface getters agree" \
                "ifget: lo idx=1 up=1 loopback=1 mtu=65536 mask8=1 byidx=1" \
                "$pt"
        fi

        # --- 3. iproute2's dump contract, which glibc's getifaddrs does NOT
        #    check -- and which is why a malformed terminator passed every test
        #    here and still broke `ip addr` on a device with "DONE truncated".
        #    NLMSG_DONE must carry a 4-byte error int (nlmsg_len >= 20), and every
        #    reply must survive iproute2's pid/seq filter or the whole dump is
        #    dropped silently. `ip addr` buffers the link dump before printing, so
        #    any of these failing yields no output at all rather than a partial
        #    listing.
        if guest_cc "$M16D/nldone" tests/guests/nldone.c; then
            cp "$M16D/nldone" "$R/bin/nldone"
            kem=$(CNG_NETLINK_FORCE_BLOCK=1 m16run -R "$R" /bin/nldone \
                2>/dev/null)
            check_contains "m16 the dump satisfies iproute2's contract" \
                "nldone: done=1 done_len_ok=1 links>0=1 named>0=1 skipped=0" \
                "$kem"
            if [ "$m16_raw" = 1 ]; then
                kbase=$(emu_t 60 "$M16D/nldone" 2>/dev/null)
                if [ "$kem" = "$kbase" ]; then
                    pass=$((pass + 1))
                    echo "  ok   m16 the dump contract matches the real kernel"
                else
                    fail=$((fail + 1))
                    echo "  FAIL m16 the dump contract matches the real kernel"
                    echo "    want: $kbase"
                    echo "    got:  $kem"
                fi
            else
                # The on-device acceptance bar, and literally what makes `ip
                # addr` print anything there: unforced, over whatever the kernel
                # does allow, the contract still has to hold.
                knf=$(m16run -R "$R" /bin/nldone 2>/dev/null)
                check_contains "m16 unforced: the dump contract holds on a refusing kernel" \
                    "nldone: done=1 done_len_ok=1 links>0=1 named>0=1 skipped=0" \
                    "$knf"
            fi
            # Android refuses the link dump itself (nlmsg_readpriv), in every
            # request form, while the address dump relays fine — so a refused
            # RTM_GETLINK must be synthesized from the address dump plus
            # ioctls, not degraded to an empty dump that `ip addr` renders as
            # total silence. CNG_NETLINK_DENY_GETLINK simulates that split.
            kdg=$(CNG_NETLINK_DENY_GETLINK=1 m16run -R "$R" /bin/nldone \
                2>/dev/null)
            check_contains "m16 a refused RTM_GETLINK is synthesized" \
                "nldone: done=1 done_len_ok=1 links>0=1 named>0=1 skipped=0" \
                "$kdg"
            edg=$(CNG_NETLINK_DENY_GETLINK=1 m16run -R "$R" /bin/netif \
                2>/dev/null)
            check_contains "m16 getifaddrs works over a synthesized link dump" \
                "getifaddrs: ok" "$edg"
            check_contains "m16 loopback survives the synthesized link dump" \
                "lo=1" "$edg"
            # With no relay at all the guest still gets a well-formed dump
            # presenting loopback — the oracle's exact degradation when even
            # getifaddrs fails, and what bubblewrap/glibc want to see.
            knr=$(CNG_NETLINK_NO_RELAY=1 m16run -R "$R" /bin/nldone \
                2>/dev/null)
            check_contains "m16 a relay-less dump presents loopback only" \
                "nldone: done=1 done_len_ok=1 links>0=1 named>0=1 skipped=0" \
                "$knr"
            # ...and the ioctl view degrades with it, to the same one interface.
            # Without that, `ifconfig` would still be listing the host's real
            # network while `ip addr` showed loopback alone.
            enr=$(CNG_NETLINK_NO_RELAY=1 m16run -R "$R" /bin/netif 2>/dev/null)
            check_contains "m16 a relay-less SIOCGIFCONF presents loopback only" \
                "ifcount: 1" "$enr"
            check_contains "m16 that loopback carries 127.0.0.1" \
                "ifconf: size_ok=1 entries>0=1 lo=1 lo_addr=1" "$enr"

            # busybox ip submits its request with plain write(2) — a syscall
            # deliberately left untrapped — and that is what Alpine runs. The
            # socketpair stand-in queues the write; the trapped recv drains and
            # serves it. Real `ip addr` output is the acceptance bar: at least
            # one interface line and one inet line, under the Android split.
            M16_ALPINE="${M16_ALPINE:-$CNG_ALPINE}"
            if [ -n "$M16_ALPINE" ] && [ -x "$M16_ALPINE/bin/busybox" ]; then
                bb=$(CNG_NETLINK_DENY_GETLINK=1 run_t 60 -R \
                    "$M16_ALPINE" /bin/busybox ip addr 2>/dev/null)
                check_contains "m16 busybox ip addr lists loopback" \
                    ": lo: <LOOPBACK,UP" "$bb"
                check_contains "m16 busybox ip addr lists an address" \
                    "inet 127.0.0.1/8" "$bb"
            else
                skip "busybox ip leg: no alpine rootfs"
            fi
        else
            skip "iproute2 dump-contract legs: could not build tests/guests/nldone.c"
        fi
    fi

    # --- 4. M16c: the audit interface ---------------------------------------
    #
    # The other netlink protocol Android's policy takes away. Nothing is
    # emulated -- the guest has no business seeing the host's audit log -- but
    # the refusal has to be one libaudit's callers recognise, because they
    # branch on it: EINVAL/EPROTONOSUPPORT/EAFNOSUPPORT mean "no audit in this
    # kernel" and every shadow-utils tool carries on, while the EACCES the
    # policy actually returns is fatal ("Cannot open audit interface -
    # aborting", which is what `useradd` and shadow's `su` print in a rootfs on
    # a device). These legs do not depend on the rtnetlink probe above.
    if guest_cc "$M16D/auditsock" tests/guests/auditsock.c; then
        cp "$M16D/auditsock" "$R/bin/auditsock"
        # The reference: the same binary with no emulation, on this kernel.
        abase=$(emu_t 60 "$M16D/auditsock" 2>/dev/null | grep '^audit:')
        a_raw=0
        case "$abase" in *"open=1"*) a_raw=1 ;; esac

        # Forced: the refusal Android returns, turned into the one the tools
        # survive. EPROTONOSUPPORT is 93 -- what netlink_create itself returns
        # for a protocol nobody registered, i.e. a kernel built without audit.
        ad=$(CNG_NETLINK_DENY_AUDIT=1 m16run -R "$R" /bin/auditsock 2>/dev/null)
        check_contains "m16c a refused audit socket reads as 'no audit in this kernel'" \
            "audit: open=0 errno=93 survives=1" "$ad"
        # ...and it is that narrow: no other socket is touched by the answer.
        check_contains "m16c the audit answer leaves other sockets alone" \
            "other: route=1 inet=1" "$ad"

        if [ "$a_raw" = 1 ]; then
            # This kernel grants the socket (audit built in, no policy in the
            # way). Then there is no refusal to rephrase and the guest must see
            # exactly what it would have seen unemulated.
            apt=$(m16run -R "$R" /bin/auditsock 2>/dev/null | grep '^audit:')
            if [ "$apt" = "$abase" ]; then
                pass=$((pass + 1))
                echo "  ok   m16c a granted audit socket is passed through untouched"
            else
                fail=$((fail + 1))
                echo "  FAIL m16c a granted audit socket is passed through untouched"
                echo "    want: $abase"
                echo "    got:  $apt"
            fi
        else
            # This host is the target: the kernel (or its policy) refuses the
            # socket on its own, so the guest must be rescued without being
            # asked -- the on-device acceptance bar, and the whole reason
            # `useradd` aborts there today.
            printf '  (this kernel refuses the audit socket: %s)\n' "$abase"
            apt=$(m16run -R "$R" /bin/auditsock 2>/dev/null)
            check_contains "m16c unforced: the refusal is rephrased where the kernel refuses it" \
                "audit: open=0 errno=93 survives=1" "$apt"
        fi
    else
        skip "audit interface legs: could not build tests/guests/auditsock.c"
    fi

    rm -rf "$R"
fi
rm -rf "$M16D"
