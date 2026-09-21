# M25: descriptors and the guest view (sourced by tests/run.sh).
#
# A directory descriptor is a place to resolve names from, and the kernel
# resolves them with no rootfs in the way. The dispatcher passed a plain name
# against a dirfd to the kernel on the strength of "the dirfd already points
# inside the guest view", and for a dirfd it could not map back it passed
# every name — so `openat(dirfd("/proc"), "../etc/passwd")` read the host's,
# the components after an fd magic link were the kernel's to walk from wherever
# the descriptor pointed, and a directory fd the launcher leaked across the
# exec was an open door. Now a descriptor on a directory the guest has no name
# for never enters its table (closed at startup, on receipt over a socket, and
# after pidfd_getfd), the zones' directories are named so a walk from one is
# contained like any other, and what a name reaches through an fd link is
# walked by the resolver rather than by the kernel.
echo "== M25: descriptors and the guest view =="

# The driver, which runs without the startup sanitization: what a guest holding
# a descriptor on an outside directory may do with it (nothing that resolves a
# name), and that a copy arriving over a socket or from pidfd_getfd is closed.
# The file beside it keeps the kernel's own answers and survives both imports.
FVR=$(mktemp -d); FVO=$(mktemp -d)
printf 'HOST-LEAK' > "$FVO/file"
out=$(run -t dtest -r "$FVR" outside "$FVO" "$FVO/file" 2>&1); rc=$?
check "an outside directory descriptor resolves nothing" 0 "$rc"
for _leg in dir-walk dir-dotdot dir-stat-walk dir-fchdir dir-magic \
    dir-magic-below; do
    check_contains "outside dir: $_leg is EACCES" \
        "outside $_leg: rc=-13 -> OK" "$out"
done
check_contains "outside dir: a copy received over a socket is closed" \
    "outside dir-scm: rc=-9 -> OK" "$out"
case "$out" in
*"outside pidfd: unavailable"*)
    skip "pidfd_getfd import: no pidfd_open here" ;;
*)
    check_contains "outside dir: pidfd_getfd's copy is closed and the call is EPERM" \
        "outside dir-pidfd_getfd: rc=-1 -> OK" "$out"
    check_contains "outside file: pidfd_getfd imports it" \
        "outside file-pidfd_getfd: rc=" "$out"
    check_absent "outside file: pidfd_getfd import not refused" \
        "outside file-pidfd_getfd: rc=-" "$out" ;;
esac
check_contains "outside file: a name below it is the kernel's ENOTDIR" \
    "outside file-walk: rc=-20 -> OK" "$out"
check_contains "outside file: its magic link reopens it" \
    "outside file-magic: rc=" "$out"
check_absent "outside file: the reopen is not refused" \
    "outside file-magic: rc=-" "$out"
check_contains "outside file: a copy received over a socket is kept" \
    "outside file-scm: rc=" "$out"
check_absent "outside file: the socket copy is not closed" \
    "outside file-scm: rc=-" "$out"
rm -rf "$FVR" "$FVO"

# End to end: a guest with the launcher's leaks in its table (fd 7 a host
# directory, fd 8 a host file, both outside the rootfs), and every route a
# relative name used to take out of the view. The rootfs supplies the marker
# the escapes must land on instead, and a /dev so "/dev/pts/../.." has a
# parent to walk through.
FVR=$(mktemp -d); FVO=$(mktemp -d)
mkdir -p "$FVR/etc" "$FVR/sub" "$FVR/dev"
printf 'GUEST-MARKER' > "$FVR/etc/marker"
ln -s /etc/marker "$FVR/sub/lnk"
printf 'HOST-LEAK' > "$FVO/file"
if ! guest_xlate_ready "descriptor legs"; then
    :
elif guest_cc_report "$FVR/fdescape" tests/guests/fdescape.c; then
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run_t 60 -R $GUEST_BINDS "$FVR" /fdescape 7<"$FVO" 8<"$FVO/file" 2>&1)
    check_contains "a leaked directory fd is closed before the guest runs" \
        "inherited-dirfd=Bad file descriptor" "$out"
    check_contains "a leaked file fd stays, for the I/O it carries" \
        "inherited-file=ok(HOST-LEAK)" "$out"
    # One of the standard three on an outside directory (`< /`) is replaced
    # by /dev/null rather than left closed: a program is entitled to find 0,
    # 1 and 2 open, and its next open must not land on one of them.
    # shellcheck disable=SC2086
    out0=$(run_t 60 -R $GUEST_BINDS "$FVR" /fdescape <"$FVO" 2>&1)
    check_contains "stdin on an outside directory becomes /dev/null" \
        "stdin=/dev/null" "$out0"
    for _leg in proc-dotdot procself-dotdot devpts-dotdot; do
        check_contains "$_leg: a .. run from a zone dirfd stays in the rootfs" \
            "$_leg=ok(GUEST-MARKER)" "$out"
    done
    check_contains "a .. run through a dirfd's magic link stays in the rootfs" \
        "magic-dotdot=ok(GUEST-MARKER)" "$out"
    check_contains "an absolute symlink below a dirfd's magic link is re-rooted" \
        "magic-symlink=ok(GUEST-MARKER)" "$out"
    check_contains "...through the /dev/fd spelling too" \
        "devfd-symlink=ok(GUEST-MARKER)" "$out"
    check_contains "a directory of the view still reopens through its fd link" \
        "magic-reopen-dir=ok" "$out"
    check_contains "fchdir into /proc carries the cwd with it" \
        "getcwd=/proc" "$out"
    check_contains "...and relative names resolve there" \
        "rel-self-status=ok" "$out"
    check_contains "a directory of the view survives a trip over a socket" \
        "scm-view-dir=usable" "$out"
    check_contains "so does a file" "scm-view-file=usable" "$out"
    # ...and what arrives from OUTSIDE the view, which only a host process can
    # send: a directory the guest has no name for is closed on arrival, its
    # number left in the record; a file and a directory of the view are let
    # in. Judged out of the control data as the kernel wrote it into a buffer
    # of the monitor's — the guest's own buffer, read back a syscall later,
    # held whatever another of its threads had put there — and the records
    # then handed to the guest, by recvmsg and by recvmmsg alike. Sent from a
    # Python of the host's (send_fds, 3.9+); without one the leg sits out.
    if guest_cc "$FVR/fdimport" tests/guests/fdimport.c &&
        python3 -c 'import socket; socket.send_fds' 2>/dev/null; then
        rm -f "$FVR/sock"
        # shellcheck disable=SC2086
        run_t 60 -R $GUEST_BINDS "$FVR" /fdimport /sock >"$FVO/import.out" \
            2>/dev/null &
        _bg=$!
        _n=0
        while [ ! -S "$FVR/sock" ] && [ $_n -lt 100 ]; do sleep 0.1; _n=$((_n + 1)); done
        python3 tests/send_fds.py "$FVR/sock" "$FVO" "$FVO/file" "$FVR" \
            2>/dev/null
        wait $_bg 2>/dev/null
        imp=$(cat "$FVO/import.out")
        check_contains "an outside directory arriving over a socket is closed on arrival" \
            "round=0 n=1 ctrunc=0 closed file dir" "$imp"
        check_contains "...by recvmmsg as well" \
            "round=1 n=1 ctrunc=0 closed file dir" "$imp"
        # A control buffer longer than the monitor's own bound: an AF_UNIX
        # socket's is taken at the bound (it can never fill it), so the records
        # arrive whole and judged; an AF_INET socket's stays the guest's own,
        # and the record the kernel wrote there arrives untouched.
        check_contains "...and through a control buffer past the bounce bound" \
            "round=2 n=1 ctrunc=0 closed file dir" "$imp"
        case "$imp" in
        *"inet: setup:"*) skip "no loopback for the AF_INET control leg" ;;
        *) check_contains "a family that carries no descriptors keeps its own buffer" \
            "inet: n=1 ctrunc=0 pktinfo=1" "$imp" ;;
        esac
    else
        skip "descriptor import leg: no guest build or no python3 send_fds here"
    fi
    # The hidden-process view by pid. /proc hides a host process by path, and
    # process_vm_readv/writev and pidfd_open were the routes to a process that
    # carry no path: with a ptrace policy that permits same-uid access a guest
    # could read and write the memory of a process its /proc said did not
    # exist, and a pidfd reaches everything a pidfd reaches. ESRCH now, which
    # is what /proc/<pid> answers -- where a guest process stays reachable.
    # Where the host has no process_vm_readv or pidfd_open to reach a guest
    # process with (qemu-user implements neither for every guest; an old
    # kernel has no pidfd_open) the allowed leg says so and sits out; the
    # hidden one is answered before the kernel is asked, and is ESRCH either
    # way.
    check_contains "process_vm_readv on a hidden process is ESRCH" \
        "pvm-read-hidden=No such process" "$out"
    case "$out" in
    *"pvm-read-guest=Function not implemented"*)
        skip "process_vm_readv on a guest process: no process_vm_readv here" ;;
    *)
        check_contains "process_vm_readv on a guest process is allowed" \
            "pvm-read-guest=ok" "$out" ;;
    esac
    check_contains "pidfd_open on a hidden process is ESRCH" \
        "pidfd-open-hidden=No such process" "$out"
    case "$out" in
    *"pidfd-open-guest=Function not implemented"*)
        skip "pidfd_open on a guest process: no pidfd_open here" ;;
    *)
        check_contains "pidfd_open on a guest process is allowed" \
            "pidfd-open-guest=ok" "$out" ;;
    esac
fi
rm -rf "$FVR" "$FVO"
