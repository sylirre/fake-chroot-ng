# M11: /proc emulation (sourced by tests/run.sh).
#
# Two layers. First the dispatcher-level self-test (-t proctest), which needs no
# seccomp and so runs anywhere. Then guest-shell scenarios under -R with a real
# Alpine rootfs: those are the ones that would have caught a file describing
# chroot-ng instead of the guest, since a shell reads them the way a real tool
# does. Unlike M10 this is not differential against arm64chroot — the sibling
# emulator synthesizes a plausibly different mount table (its own pseudo-mount
# rows and mount IDs), so the assertions are structural instead.
echo "== M11: /proc emulation =="

M11_ALPINE="${M11_ALPINE:-/home/sol/arm64chroot/tests/.cache/rootfs/alpine}"

PT=$(mktemp -d)
out=$(run -t proctest -r "$PT" -b /usr:/usr 2>&1); rc=$?
check "proctest overall" 0 "$rc"
check_contains "the registry runs broker-backed (--shared-proc plumbing)" \
    "proctest shared-proc backing: 3 -> OK" "$out"
check_contains "/proc passes through, non-guest pids are hidden" \
    "proctest passthrough+hidden -> OK" "$out"
check_contains "a -b /proc:/proc bind does not reopen the host process list" \
    "proctest bound-proc hidden -> OK" "$out"
check_contains "a /proc listing drops host pids, keeps guest ones" \
    "proctest listing: self=1 own_pid=1 host_pids=0 -> OK" "$out"
check_contains "cmdline is the guest argv, not the chroot-ng invocation" \
    "proctest cmdline: 24 bytes argv0=/bin/busybox -> OK" "$out"
check_contains "environ is the guest environment" \
    "proctest environ: 30 bytes -> OK" "$out"
check_contains "another guest process is described from the registry" \
    "proctest other-pid: -> OK" "$out"
check_contains "a child's exec outranks the fork publish; a dead pid stops answering" \
    "proctest fork-guard+stale-pid: -> OK" "$out"
check_contains "mounts describes the rootfs and binds" "proctest mounts:" "$out"
check_contains "mountinfo carries the root device row" "proctest mountinfo:" "$out"
check_contains "loadavg has the kernel's five fields" "proctest loadavg:" "$out"
check_contains "a held loadavg fd refreshes on rewind (top's pattern)" \
    "proctest loadavg refresh:" "$out"
check_contains "the readv path takes the same refresh hook" \
    "proctest loadavg readv refresh:" "$out"
check_contains "uptime is synthesized" "proctest uptime:" "$out"
check_contains "stat falls back to synthesis where the host denies it" \
    "proctest stat:" "$out"
check_contains "maps leaks no host path" "proctest maps:" "$out"
check_contains "an fd link reports the guest path" \
    "proctest fdlink: / -> OK" "$out"
check_contains "a map_files link target is mapped into the guest view" \
    "proctest map_files:" "$out"
check_contains "status Uid/Gid remapped under --fake-id" \
    "proctest status remap:" "$out"
check_contains "--no-proc disables passthrough and synthesis" \
    "proctest no-proc -> OK" "$out"
rm -rf "$PT"

# --- guest-shell scenarios -------------------------------------------------
m11_ready=0
if [ -x "$M11_ALPINE/bin/busybox" ]; then m11_ready=1; else
    echo "  skip: alpine rootfs missing"
fi

# m11_sh <desc> <expected> <script>: run the script in an Alpine guest under -R
# and compare its (whitespace-trimmed) stdout.
m11_sh() {
    got=$(run -R -b /tmp:/tmp "$M11_ALPINE" /bin/busybox sh -c "$3" 2>/dev/null)
    if [ "$got" = "$2" ]; then
        pass=$((pass + 1)); echo "  ok   m11 $1"
    else
        fail=$((fail + 1)); echo "  FAIL m11 $1"
        echo "    want: $2"
        echo "    got:  $got"
    fi
}

if [ "$m11_ready" -eq 1 ]; then
    # The guest's own command line — the host file holds the chroot-ng argv.
    m11_sh "cmdline is the guest's own argv" "cat|/proc/self/cmdline|" \
        'cat /proc/self/cmdline | tr "\0" "|"'

    # The mount table is the guest's: rootfs, /proc, and the -b bind.
    m11_sh "mounts shows rootfs + proc + bind" "3" \
        'grep -c -e "^/dev/root / " -e "^proc /proc proc " -e " /tmp " /proc/mounts'

    # No host path may appear in the guest's view of its own mappings.
    m11_sh "maps leaks no rootfs host path" "0" \
        "grep -c '$M11_ALPINE' /proc/self/maps"

    # Host processes are invisible; the guest's own are not.
    m11_sh "a host pid is hidden" "hidden" \
        '[ -e /proc/1/stat ] || echo hidden'
    m11_sh "our own pid is visible" "visible" \
        '[ -e /proc/$$/stat ] && echo visible'
    m11_sh "ps sees only the guest's processes" "few" \
        'n=$(ps | wc -l); [ "$n" -lt 10 ] && echo few'

    # The magic links stay in guest terms.
    m11_sh "exe link is the guest path" "/bin/busybox" 'readlink /proc/self/exe'
    m11_sh "root link is the guest root" "/" 'readlink /proc/self/root'

    # loadavg / uptime shape (Android denies the real files to apps).
    m11_sh "loadavg has five fields" "5" 'wc -w < /proc/loadavg'
    m11_sh "uptime has two fields" "2" 'wc -w < /proc/uptime'

    # comm is the guest program, not chroot-ng (PR_SET_NAME, not synthesis).
    m11_sh "comm names the guest program" "busybox" 'cat /proc/self/comm'

    # Binding the host /proc at /proc is a common habit from proot; it must not
    # hand the guest the host's process list back. The hidden view keys on where
    # a path lands, not on which map rule put it there.
    got=$(run -R -b /proc:/proc "$M11_ALPINE" /bin/busybox sh -c \
        'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)
    own=$(run -R "$M11_ALPINE" /bin/busybox sh -c \
        'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)
    if [ -n "$got" ] && [ "$got" = "$own" ]; then
        pass=$((pass + 1)); echo "  ok   m11 -b /proc:/proc hides host pids like the default"
    else
        fail=$((fail + 1))
        echo "  FAIL m11 -b /proc:/proc hides host pids like the default"
        echo "    bound: $got  default: $own"
    fi
    got=$(run -R -b /proc:/proc "$M11_ALPINE" /bin/busybox sh -c \
        '[ -e /proc/1/stat ] || echo hidden' 2>/dev/null)
    check_contains "a host pid stays unreachable under a /proc bind" \
        "hidden" "$got"

    # An explicit -b DIR:/proc pointing somewhere else is the user overriding
    # the host view, and must outrank both the passthrough and the synthesis.
    BP=$(mktemp -d); printf 'bound\n' > "$BP/loadavg"
    got=$(run -R -b "$BP":/proc "$M11_ALPINE" /bin/busybox cat /proc/loadavg \
        2>/dev/null)
    check_contains "an explicit -b DIR:/proc outranks the synthesis" \
        "bound" "$got"
    rm -rf "$BP"

    # --no-proc turns the whole thing off: the rootfs has no /proc of its own.
    got=$(run -R --no-proc "$M11_ALPINE" /bin/busybox sh -c \
        'cat /proc/loadavg 2>/dev/null || echo none' 2>/dev/null)
    check_contains "--no-proc leaves the guest without /proc" "none" "$got"

    # --shared-proc: two INDEPENDENT invocations over one rootfs share the
    # process view through the per-rootfs broker — ps in the second lists the
    # first's guest process, with the cmdline the sleeper published. Without
    # the flag each invocation has its own registry and hides the other's
    # processes (the pre-flag behavior, still the default).
    run -R --shared-proc "$M11_ALPINE" /bin/busybox sleep 87.65 2>/dev/null &
    m11_bg=$!
    sleep 2
    got=$(run -R --shared-proc "$M11_ALPINE" /bin/busybox ps 2>/dev/null)
    case "$got" in
    *"sleep 87.65"*)
        pass=$((pass + 1))
        echo "  ok   m11 --shared-proc: ps sees the other invocation's guest" ;;
    *)
        fail=$((fail + 1))
        echo "  FAIL m11 --shared-proc: ps sees the other invocation's guest"
        echo "    got: $got" ;;
    esac
    solo=$(run -R "$M11_ALPINE" /bin/busybox ps 2>/dev/null)
    case "$solo" in
    *"sleep 87.65"*)
        fail=$((fail + 1))
        echo "  FAIL m11 without --shared-proc the other invocation stays hidden" ;;
    *)
        pass=$((pass + 1))
        echo "  ok   m11 without --shared-proc the other invocation stays hidden" ;;
    esac
    kill "$m11_bg" 2>/dev/null
    wait "$m11_bg" 2>/dev/null
fi
