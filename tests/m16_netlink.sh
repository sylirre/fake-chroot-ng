# M16 NETLINK_ROUTE emulation (sourced by tests/run.sh).
#
# Android denies app domains rtnetlink, and everything that asks the kernel about
# interfaces goes through it: getifaddrs(3), iproute2, bubblewrap's
# loopback_setup(), glibc's source-address selection. Without a shim they all
# fail inside the guest.
#
# Tested differentially. The same guest binary runs twice — once with no
# emulation, where it talks to the real kernel, and once under chroot-ng with
# CNG_NETLINK_FORCE_BLOCK=1, which makes the emulation engage on a host where
# rtnetlink actually works. The two must agree byte for byte. That is the only
# way to check this on a host that is not the target: the emulated path is the
# one that matters on a device and never engages elsewhere unless it is forced.
echo "== M16: NETLINK_ROUTE emulation =="

# Guest runs are wrapped in a timeout: a netlink dump that never terminates would
# otherwise wedge the whole suite instead of failing one check.
# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m16run() { run_t 60 $GUEST_BINDS "$@"; }
M16D=$(mktemp -d)

if ! guest_xlate_ready "rtnetlink emulation scenarios"; then
    :
elif ! guest_cc_report "$M16D/netif" tests/guests/netif.c; then
    :
else
    R=$(mktemp -d); mkdir -p "$R/bin"; cp "$M16D/netif" "$R/bin/netif"

    # The real kernel's answers, via the same binary with no emulation at all.
    base=$(emu_t 60 "$M16D/netif" 2>/dev/null)
    case "$base" in
    *"getifaddrs: ok"*)
        # 1. The emulation must reproduce the real kernel exactly.
        em=$(CNG_NETLINK_FORCE_BLOCK=1 m16run -R "$R" /bin/netif 2>/dev/null)
        if [ "$em" = "$base" ]; then
            pass=$((pass + 1))
            echo "  ok   m16 emulated rtnetlink matches the real kernel"
        else
            fail=$((fail + 1))
            echo "  FAIL m16 emulated rtnetlink matches the real kernel"
            echo "    want: $base"
            echo "    got:  $em"
        fi

        # 2. The individual properties, so a failure says which one broke.
        check_contains "m16 getifaddrs works under the emulation" \
            "getifaddrs: ok" "$em"
        check_contains "m16 the loopback interface is visible" "lo=1" "$em"
        check_contains "m16 socket(AF_NETLINK) is served" "socket: ok" "$em"
        check_contains "m16 bind on an emulated socket succeeds" "bind: ok" "$em"
        # iproute2 refuses a getsockname answer that is not sockaddr_nl-sized;
        # the underlying AF_UNIX socket would report 2 bytes.
        check_contains "m16 getsockname reports a 12-byte sockaddr_nl" \
            "getsockname: len=12 family=16" "$em"
        # A dump the guest can parse: messages present, its own sequence number
        # echoed, and real RTM_NEWLINK records in it.
        check_contains "m16 an RTM_GETLINK dump is relayed and parseable" \
            "dump: got>0=1 msgs>0=1 seq_ok=1 newlink>0=1" "$em"

        # 3. Without forcing, rtnetlink works on this host, so the emulation must
        #    stay out of the way entirely rather than shadowing a working kernel.
        pt=$(m16run -R "$R" /bin/netif 2>/dev/null)
        if [ "$pt" = "$base" ]; then
            pass=$((pass + 1)); echo "  ok   m16 passthrough is unchanged"
        else
            fail=$((fail + 1)); echo "  FAIL m16 passthrough is unchanged"
            echo "    got: $pt"
        fi
        dbg=$(CNG_DEBUG=1 m16run -R "$R" /bin/netif 2>&1 \
            >/dev/null | grep -c 'netlink: emulating')
        check "m16 the emulation does not engage where rtnetlink works" 0 "$dbg"

        # 4. iproute2's dump contract, which glibc's getifaddrs does NOT check --
        #    and which is why a malformed terminator passed every test here and
        #    still broke `ip addr` on a device with "DONE truncated". NLMSG_DONE
        #    must carry a 4-byte error int (nlmsg_len >= 20), and every reply must
        #    survive iproute2's pid/seq filter or the whole dump is dropped
        #    silently. `ip addr` buffers the link dump before printing, so any of
        #    these failing yields no output at all rather than a partial listing.
        if guest_cc "$M16D/nldone" tests/guests/nldone.c; then
            cp "$M16D/nldone" "$R/bin/nldone"
            kbase=$(emu_t 60 "$M16D/nldone" 2>/dev/null)
            kem=$(CNG_NETLINK_FORCE_BLOCK=1 m16run -R "$R" /bin/nldone \
                2>/dev/null)
            check_contains "m16 the dump satisfies iproute2's contract" \
                "nldone: done=1 done_len_ok=1 links>0=1 named>0=1 skipped=0" \
                "$kem"
            if [ "$kem" = "$kbase" ]; then
                pass=$((pass + 1))
                echo "  ok   m16 the dump contract matches the real kernel"
            else
                fail=$((fail + 1))
                echo "  FAIL m16 the dump contract matches the real kernel"
                echo "    want: $kbase"
                echo "    got:  $kem"
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
        ;;
    *)  skip "rtnetlink differential: this host denies rtnetlink, nothing to diff against" ;;
    esac

    rm -rf "$R"
fi
rm -rf "$M16D"
