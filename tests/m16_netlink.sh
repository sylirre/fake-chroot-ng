# M16 NETLINK_ROUTE emulation (sourced by tests/run.sh).
#
# Android denies app domains rtnetlink, and everything that asks the kernel about
# interfaces goes through it: getifaddrs(3), iproute2, bubblewrap's
# loopback_setup(), glibc's source-address selection. Without a shim they all
# fail inside the guest.
#
# Tested differentially. The same guest binary runs twice — once straight under
# qemu, where it talks to the real kernel, and once under chroot-ng with
# CNG_NETLINK_FORCE_BLOCK=1, which makes the emulation engage on a host where
# rtnetlink actually works. The two must agree byte for byte. That is the only
# way to check this here: the emulated path is the one that matters on a device
# and never engages on a devbox unless it is forced.
echo "== M16: NETLINK_ROUTE emulation =="

M16_GCC="${GCC:-aarch64-linux-gnu-gcc-13}"
M16_QEMU="${QEMU:-qemu-aarch64-static}"
# Guest runs are wrapped in a timeout: a netlink dump that never terminates would
# otherwise wedge the whole suite instead of failing one check.
m16run() { timeout 60 "$M16_QEMU" "$@"; }
M16D=$(mktemp -d)

if ! $M16_GCC -static-pie -O2 -o "$M16D/netif" tests/guests/netif.c \
        2>"$M16D/build.log"; then
    echo "  skip: could not build tests/guests/netif.c"
    sed 's/^/    /' "$M16D/build.log" | head -5
else
    R=$(mktemp -d); mkdir -p "$R/bin"; cp "$M16D/netif" "$R/bin/netif"

    # The real kernel's answers, via the same binary with no emulation at all.
    base=$(m16run "$M16D/netif" 2>/dev/null)
    case "$base" in
    *"getifaddrs: ok"*)
        # 1. The emulation must reproduce the real kernel exactly.
        em=$(CNG_NETLINK_FORCE_BLOCK=1 m16run build/chroot-ng -R "$R" \
            /bin/netif 2>/dev/null)
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
        pt=$(m16run build/chroot-ng -R "$R" /bin/netif 2>/dev/null)
        if [ "$pt" = "$base" ]; then
            pass=$((pass + 1)); echo "  ok   m16 passthrough is unchanged"
        else
            fail=$((fail + 1)); echo "  FAIL m16 passthrough is unchanged"
            echo "    got: $pt"
        fi
        dbg=$(CNG_DEBUG=1 m16run build/chroot-ng -R "$R" /bin/netif 2>&1 \
            >/dev/null | grep -c 'netlink: emulating')
        check "m16 the emulation does not engage where rtnetlink works" 0 "$dbg"

        # 4. iproute2's dump contract, which glibc's getifaddrs does NOT check --
        #    and which is why a malformed terminator passed every test here and
        #    still broke `ip addr` on a device with "DONE truncated". NLMSG_DONE
        #    must carry a 4-byte error int (nlmsg_len >= 20), and every reply must
        #    survive iproute2's pid/seq filter or the whole dump is dropped
        #    silently. `ip addr` buffers the link dump before printing, so any of
        #    these failing yields no output at all rather than a partial listing.
        if $M16_GCC -static-pie -O2 -o "$M16D/nldone" tests/guests/nldone.c \
                2>>"$M16D/build.log"; then
            cp "$M16D/nldone" "$R/bin/nldone"
            kbase=$(m16run "$M16D/nldone" 2>/dev/null)
            kem=$(CNG_NETLINK_FORCE_BLOCK=1 m16run build/chroot-ng -R "$R" \
                /bin/nldone 2>/dev/null)
            check_contains "m16 the dump satisfies iproute2's contract" \
                "nldone: done=1 done_len_ok=1 links>0=1 skipped=0" "$kem"
            if [ "$kem" = "$kbase" ]; then
                pass=$((pass + 1))
                echo "  ok   m16 the dump contract matches the real kernel"
            else
                fail=$((fail + 1))
                echo "  FAIL m16 the dump contract matches the real kernel"
                echo "    want: $kbase"
                echo "    got:  $kem"
            fi
            # With no relay available the dump must still be well-formed: an
            # empty interface list, not a terminator iproute2 rejects.
            knr=$(CNG_NETLINK_NO_RELAY=1 m16run build/chroot-ng -R "$R" \
                /bin/nldone 2>/dev/null)
            check_contains "m16 a relay-less dump is still well-formed" \
                "nldone: done=1 done_len_ok=1 links>0=0 skipped=0" "$knr"
        else
            echo "  skip: could not build tests/guests/nldone.c"
        fi
        ;;
    *)  echo "  skip: host rtnetlink unavailable, nothing to diff against" ;;
    esac

    rm -rf "$R"
fi
rm -rf "$M16D"
