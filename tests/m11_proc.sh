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

M11_ALPINE="${M11_ALPINE:-$CNG_ALPINE}"

# The bind source is a directory we make, not a host path like /usr: Android has
# no /usr at all, and all proctest wants is a bind whose guest mount point must
# then show up in the synthesized mount table.
PT=$(mktemp -d); PTB=$(mktemp -d)
out=$(run -t proctest -r "$PT" -b "$PTB":/usr 2>&1); rc=$?
check "proctest overall" 0 "$rc"
check_contains "the registry runs broker-backed (--shared-proc plumbing)" \
    "proctest shared-proc backing: 3 -> OK" "$out"
check_contains "/proc passes through, non-guest pids are hidden" \
    "proctest passthrough+hidden -> OK" "$out"
check_contains "a -b /proc:/proc bind does not reopen the host process list" \
    "proctest bound-proc hidden -> OK" "$out"
check_contains "a /proc listing drops host pids, keeps guest ones" \
    "proctest listing: self=1 own_pid=1 host_pids=0 -> OK" "$out"
# The hidden view keys on the resolved HOST path, and a /proc dirfd has no guest
# path to resolve against — so a relative name under one went to the kernel
# untouched and read the process the absolute spelling had just refused. Our own
# entry must still be reachable both ways, or the fix would hide everything.
# ...and the fd links, which are the sharp end of the same thing: they are
# answered as HOST paths, so the kernel takes one straight to the open file
# description it names. A hidden process's descriptors were readable by pid and
# number — the host file itself, wherever on the filesystem it lived. ENOENT is
# the required answer, not EACCES: that would mean we reached it and only DAC
# turned us away.
check_contains "a host pid stays hidden through a /proc dirfd and its fd links" \
    "prochide: abs=-2 rel=-2 bare=-2 own=1 self=1 fdlink=-2 fdopen=-2 ownfd=1 -> OK" \
    "$(run -t dtest -r "$PT" prochide / 2>&1)"
check_contains "cmdline is the guest argv, not the chroot-ng invocation" \
    "proctest cmdline: 24 bytes argv0=/bin/busybox -> OK" "$out"

# ...and that has to hold when there is no registry at all. It is a shared table
# and it can be missing (no memfd) or full; the fallback used to be the host
# file, which for a guest process is the chroot-ng invocation that started it.
# We are the process being described, so the live stack answers on its own.
# CNG_PROCREG_NONE=1 is the only way to reach the degraded tier on a working
# host (same convention as CNG_SHM_FORCE_FILE).
sout=$(run -t selfproc 2>&1)
check "selfproc with the registry" 0 $?
check_contains "our own cmdline is the guest's argv" \
    "selfproc /proc/self/cmdline: 22 bytes [/bin/guestprog] -> OK" "$sout"
check_contains "our own environ is the guest's" \
    "selfproc /proc/self/environ: 13 bytes [GUESTVAR=yes] -> OK" "$sout"
sout=$(CNG_PROCREG_NONE=1 run -t selfproc 2>&1)
check "selfproc with no registry at all" 0 $?
check_contains "the registry really was unavailable" \
    "selfproc registry=0: 0 failure(s)" "$sout"
check_contains "cmdline still answers from the live stack" \
    "selfproc /proc/self/cmdline: 22 bytes [/bin/guestprog] -> OK" "$sout"
check_contains "environ still answers from the live stack" \
    "selfproc /proc/self/environ: 13 bytes [GUESTVAR=yes] -> OK" "$sout"
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
# The p-variants take it too, and there the offset is the caller's argument, not
# the description's — which pread(2) is defined never to move. Measured: the
# kernel leaves a held /proc/uptime fd at 8 across a pread of the whole file.
check_contains "a pread that triggers the refresh leaves the offset alone" \
    "proctest pread keeps the offset: 8 then 8 -> OK" "$out"
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
# ...and it has to be the LIVE set. The ids in cng_g_cred are what getresuid,
# getresgid and getgroups answer, and every credential syscall writes them; the
# status lines were remapped from the host's instead, so a guest that dropped
# privilege was still described by the identity it started with, and its
# supplementary groups were the invoking user's — groups getgroups() never
# reported. One process, two answers, is a thing the kernel cannot do.
check_contains "status carries the live credential set, not the startup one" \
    "proctest status live: uid=11/12/13 gid=21/22/23 groups=3 -> OK" "$out"
check_contains "--no-proc disables passthrough and synthesis" \
    "proctest no-proc -> OK" "$out"
rm -rf "$PT" "$PTB"

# --- maps lines longer than the line reader ---------------------------------
# put_maps re-parses every chunk the line reader hands it, and a line longer
# than that reader's buffer arrives in pieces. Only the first piece carries the
# five fixed columns; the rest is bare path characters, which the five-field
# scan runs straight past, so the "no pathname column" branch printed the raw
# host tail — the one thing put_maps exists to prevent. Two legs, because the
# fix has two halves: a buffer that fits any path the kernel can print, and a
# refusal to re-parse a piece of a line when it does not.
#
# The length has to come from the guest side of a short rootfs: a bind's host
# path is capped at 512 bytes, so it cannot supply one. The rootfs prefix is
# then the only part of the host spelling the guest cannot also say, which makes
# the mktemp directory's own name the marker to count.
ML_DIR=$(mktemp -d)
ML_MARK=$(basename "$ML_DIR")
ML_ROOT="$ML_DIR/rootfs"
mkdir -p "$ML_ROOT"
if guest_xlate_ready "maps over-long-line legs" &&
    guest_cc_report "$ML_ROOT/mapslong" tests/guests/mapslong.c; then
    # (a) A host path long enough to have overrun the old 2 KiB line buffer,
    # which is an ordinary deep tree: a nested node_modules, a Java class
    # hierarchy. The mapping must still appear, under its guest name.
    ml_deep=""
    ml_i=0
    while [ "$ml_i" -lt 50 ]; do
        ml_deep="$ml_deep/cngdeepcngdeepcngdeepcngdeepcngdeepcngdeepcng"
        ml_i=$((ml_i + 1))
    done
    if mkdir -p "$ML_ROOT$ml_deep" 2>/dev/null &&
        printf 'x' > "$ML_ROOT$ml_deep/blob" 2>/dev/null; then
        out=$(run_t 60 -R "$ML_ROOT" /mapslong "$ml_deep/blob" "$ML_MARK" 2>&1)
        check_contains "maps a long host path survives whole" \
            "lines=1 hostleak=0 mapped=1 malformed=0" "$out"
    else
        skip "maps long-path leg: the host filesystem refused the path"
    fi

    # (b) Past any buffer, so the size alone cannot be the whole fix. The kernel
    # escapes '\n' in the pathname column as the four bytes \012, so a path made
    # of newlines prints four times its own length: measured, fourteen 251-byte
    # components print as a 14155-byte line, and PATH_MAX bounds only the path.
    # A guest can make such a directory inside its own rootfs. Nothing faithful
    # can be emitted for that line — but half of it is not the answer either,
    # and re-parsing the second half is what printed the raw host tail.
    ml_nl=$(printf 'a'; printf '%0249d' 0 | tr '0' '\n'; printf 'b')
    ml_wide=""
    ml_i=0
    while [ "$ml_i" -lt 14 ]; do
        ml_wide="$ml_wide/$ml_nl"
        ml_i=$((ml_i + 1))
    done
    if mkdir -p "$ML_ROOT$ml_wide" 2>/dev/null &&
        printf 'x' > "$ML_ROOT$ml_wide/blob" 2>/dev/null; then
        out=$(run_t 60 -R "$ML_ROOT" /mapslong "$ml_wide/blob" "$ML_MARK" 2>&1)
        # mapped=0 by construction: the guest names the path in raw bytes and
        # maps prints it escaped, so the row cannot be found by that spelling.
        check_contains "maps an unprintable-length path emits no half-line" \
            "hostleak=0 mapped=0 malformed=0" "$out"
    else
        skip "maps escaped-path leg: the host filesystem refused the path"
    fi
fi
rm -rf "$ML_DIR"

# --- guest-shell scenarios -------------------------------------------------
m11_ready=0
if [ -n "$M11_ALPINE" ] && [ -x "$M11_ALPINE/bin/busybox" ]; then
    m11_ready=1
else
    skip "guest-shell /proc scenarios: no alpine rootfs"
fi
# Bound at the guest's /tmp so the mount table has a third row to find. The host
# side is a directory of ours: /tmp is not a path Android has.
M11TMP=$(mktemp -d)

# m11_sh <desc> <expected> <script>: run the script in an Alpine guest under -R
# and compare its (whitespace-trimmed) stdout.
m11_sh() {
    got=$(run -R -b "$M11TMP":/tmp "$M11_ALPINE" /bin/busybox sh -c "$3" 2>/dev/null)
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
rm -rf "$M11TMP"
