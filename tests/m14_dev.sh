# M14 /dev zone + directory-entry injection (sourced by tests/run.sh).
#
# A rootfs directory tree ships no device nodes and mknod(2) needs privileges we
# do not have, so a fixed whitelist of harmless host devices passes through by
# name. Two halves matter and are asserted separately: the *access* half (the
# whitelist resolves, everything else stays in the rootfs) lives in m5_xlate,
# and the *listing* half is here — those nodes have no physical dirent, so
# getdents64 has to splice them in or `ls /dev` shows an empty directory that
# nonetheless opens /dev/null fine. The same splicing covers -b mount points,
# which are pure resolution overlays with no dirent either.
echo "== M14: /dev zone + dirent injection =="

M14_ALPINE="${M14_ALPINE:-$CNG_ALPINE}"

if [ -z "$M14_ALPINE" ] || [ ! -x "$M14_ALPINE/bin/busybox" ]; then
    skip "/dev zone scenarios: no alpine rootfs"
else
    # ls /dev must show the whitelist. The Alpine rootfs physically contains
    # only "null", so anything beyond it came from the injection.
    got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
        'ls /dev | tr "\n" " "' 2>/dev/null)
    for want in null zero full random urandom tty ptmx console pts shm fd \
                stdin stdout stderr; do
        case " $got " in
        *" $want "*) pass=$((pass + 1)); echo "  ok   m14 ls /dev shows $want" ;;
        *) fail=$((fail + 1))
           echo "  FAIL m14 ls /dev shows $want"; echo "    got: $got" ;;
        esac
    done

    # Deduped against the physical dirent: the rootfs ships a real /dev/null,
    # which must appear once, not twice.
    got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
        'ls /dev | grep -c "^null$"' 2>/dev/null)
    check "m14 a physically-present node is not duplicated" 1 "$got"

    # The nodes are usable, not just listed.
    got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
        'echo written-to-null > /dev/null && echo ok' 2>/dev/null)
    check_contains "m14 /dev/null is writable" "ok" "$got"
    got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
        'dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c' 2>/dev/null)
    check_contains "m14 /dev/zero reads" "4" "$got"

    # Containment: a device that is NOT on the whitelist must not be reachable,
    # even though it exists on the host. Which node that is has to be picked at
    # runtime — /dev/mem is there on a devbox but not on every Android device,
    # and a name the host does not have would make this pass for free.
    m14_dev=
    for d in mem kmsg loop-control hwrng snd input binder ashmem; do
        [ -e "/dev/$d" ] || continue
        [ -e "$M14_ALPINE/dev/$d" ] && continue
        m14_dev=$d
        break
    done
    if [ -n "$m14_dev" ]; then
        got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
            "[ -e /dev/$m14_dev ] && echo reachable || echo contained" \
            2>/dev/null)
        check_contains \
            "m14 a non-whitelisted host device (/dev/$m14_dev) is unreachable" \
            "contained" "$got"
    else
        skip "device-containment leg: this host has no non-whitelisted /dev node to try"
    fi

    # --no-dev turns the whole zone off: /dev is the rootfs directory only.
    got=$(run -R --no-dev "$M14_ALPINE" /bin/busybox sh -c \
        'ls /dev | tr "\n" " "' 2>/dev/null)
    check_contains "m14 --no-dev lists only the rootfs /dev" "null" "$got"
    case " $got " in
    *" zero "*) fail=$((fail + 1))
        echo "  FAIL m14 --no-dev still injected nodes"; echo "    got: $got" ;;
    *) pass=$((pass + 1)); echo "  ok   m14 --no-dev injects nothing" ;;
    esac

    # A -b mount point is a resolution overlay with no dirent in the rootfs, so
    # it was reachable by name but invisible to anything that enumerates first
    # (shell globbing, find, a package manager's tree walk).
    M14B=$(mktemp -d); printf x > "$M14B/marker"
    got=$(run -R -b "$M14B":/hostdir "$M14_ALPINE" /bin/busybox sh -c \
        'ls / | grep -c "^hostdir$"' 2>/dev/null)
    check "m14 a bind mount point appears in its parent's listing" 1 "$got"
    # d_type comes from an lstat of the bind source, so `find -type d` agrees
    # with what an open of the same name gets.
    got=$(run -R -b "$M14B":/hostdir "$M14_ALPINE" /bin/busybox sh -c \
        'find / -maxdepth 1 -name hostdir -type d | wc -l' 2>/dev/null)
    check "m14 the spliced entry carries a real d_type" 1 "$got"
    got=$(run -R -b "$M14B":/hostdir "$M14_ALPINE" /bin/busybox sh -c \
        'cat /hostdir/marker' 2>/dev/null)
    check_contains "m14 the spliced mount point is usable" "x" "$got"
    rm -rf "$M14B"

    # The synthesized mount table gains the zone rows.
    got=$(run -R "$M14_ALPINE" /bin/busybox sh -c \
        'grep -c -e " /dev devtmpfs " -e " /dev/pts devpts " -e " /dev/shm tmpfs " /proc/mounts' \
        2>/dev/null)
    check "m14 the mount table lists the /dev zone" 3 "$got"
    got=$(run -R --no-dev "$M14_ALPINE" /bin/busybox sh -c \
        'grep -c " /dev devtmpfs " /proc/mounts' 2>/dev/null)
    check "m14 --no-dev drops the /dev mount rows" 0 "$got"
fi
