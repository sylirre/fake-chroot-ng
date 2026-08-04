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

    # The zone is governed by --no-dev, not by --no-proc: `fd` and the std*
    # aliases name the host fd table, which is a host object whatever /proc the
    # guest has, and /dev/fd/N already resolved under --no-proc. The directory
    # itself did not — it fell through to the /proc zone and vanished with it,
    # taking its listing entry along (busybox lstats each name it prints).
    got=$(run -R --no-proc "$M14_ALPINE" /bin/busybox sh -c \
        '[ -d /dev/fd ] && echo have-dir; [ -e /dev/fd/1 ] && echo have-n' \
        2>/dev/null)
    check_contains "m14 --no-proc keeps /dev/fd a directory" "have-dir" "$got"
    check_contains "m14 --no-proc keeps /dev/fd/N" "have-n" "$got"
    got=$(run -R --no-proc "$M14_ALPINE" /bin/busybox sh -c \
        'ls /dev | grep -c "^fd$"' 2>/dev/null)
    check "m14 --no-proc still lists fd" 1 "$got"

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

# --- reaching an overlay entry through a dirfd ------------------------------
# The listing half above makes these names visible; this is the other half of
# the same question. An overlay has no dirent, so a *relative* name against the
# directory's own fd cannot be resolved by the kernel — it has to take the
# guest-side walk, even though a single plain component looks like nothing that
# could redirect. `ls -l` asks exactly this (fstatat against the fd it is
# listing), so without it an entry ls had just shown came back ENOENT.
# An overlay entry has to survive a directory whose real entries fill the
# guest's buffer. Spliced in after the kernel's own it had nowhere to fit, and
# since injection happens only on the first read of the stream, "did not fit"
# meant the guest never saw it at all -- decided by the guest libc's readdir
# buffer, which is 2 KiB in musl and 32 KiB in glibc. Read the same directory
# to the end at three buffer sizes: the set of names must not depend on it.
M14S=$(mktemp -d)
M14SB=$(mktemp -d)
i=0
while [ $i -lt 60 ]; do : >"$M14S/file_with_a_longish_name_$i"; i=$((i + 1)); done
m14_names() { # bufsz
    run -t dtest -r "$M14S" -b "$M14SB":/zzbind dents / "$1" 2>&1 |
        head -1 | tr ' ' '\n' | sort | tr '\n' ' '
}
m14_count() { echo "$1" | tr ' ' '\n' | grep -c .; }
m14_big=$(m14_names 65536)
m14_bign=$(m14_count "$m14_big")
check_contains "m14 an overlay entry is listed with a large read buffer" \
    " zzbind " "$m14_big"
for bufsz in 256 128; do
    m14_got=$(m14_names $bufsz)
    check_contains "m14 ...and with a $bufsz-byte one" " zzbind " "$m14_got"
    check "m14 ...listing the same names either way ($bufsz)" "$m14_bign" \
        "$(m14_count "$m14_got")"
done
rm -rf "$M14S" "$M14SB"

# ...and the room the injection leaves has to admit at least one of the kernel's
# own records. put_dent stops only when the *next* record does not fit, so what
# remained was routinely under the 24 bytes the smallest dirent (".") needs;
# filldir64 then refuses the whole batch with EINVAL and writes back an
# unchanged f_pos (measured on this kernel; qemu-user answers ENOMEM where we
# left it exactly nothing, which means the same thing). The injected bytes were
# reported as a short batch, so the next read decided "first read" from that
# same position and spliced the identical entries in again: `ls /dev` through a
# raw getdents64 of 184..407 bytes repeated the whitelist forever and never
# reached "." at all. Only the 32 KiB/2 KiB/4 KiB readdir buffers of glibc, musl
# and bionic kept every guest that has been tried out of it.
#
# The /dev whitelist is 14 entries totalling 384 bytes, so the sizes below
# bracket it: below it, across each cumulative record boundary, exactly at the
# first size that fits everything, and well above.
M14W=$(mktemp -d)
mkdir -p "$M14W/dev"
for bufsz in 32 64 128 184 200 256 376 400 408 512 65536; do
    m14w=$(run_t 30 -t dtest -r "$M14W" dents /dev $bufsz 2>&1 | head -1 |
        sed 's/^dents://')
    check "m14 a $bufsz-byte getdents64 of /dev repeats no entry" "" \
        "$(echo "$m14w" | tr ' ' '\n' | grep -v '^$' | sort | uniq -d |
            tr '\n' ' ')"
    check_contains "m14 ...and still reaches the directory's own entries ($bufsz)" \
        " .. " "$m14w "
done
# The buffer is what bounds how many overlay records a first read can carry;
# once one kernel record fits alongside the whole set, nothing is dropped.
check_contains "m14 a buffer that holds the whole overlay lists all of it" \
    " stderr " "$(run_t 30 -t dtest -r "$M14W" dents /dev 65536 2>&1 | head -1) "
rm -rf "$M14W"

M14D=$(mktemp -d)
M14DB=$(mktemp -d)
mkdir -p "$M14D/dev" # the zone overlays entries INTO it; the directory is real
printf x >"$M14DB/marker"
if ! guest_xlate_ready "dirfd-relative overlay legs"; then
    :
elif guest_cc_report "$M14D/atoverlay" tests/guests/atoverlay.c; then
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run -R $GUEST_BINDS -b "$M14DB":/hostdir "$M14D" /atoverlay \
        2>/dev/null)
    check_contains "m14 openat(dirfd(/dev), \"zero\") resolves" "dev-openat=ok" \
        "$out"
    check_contains "m14 fstatat(dirfd(/dev), \"urandom\") resolves" \
        "dev-fstatat=ok" "$out"
    check_contains "m14 faccessat(dirfd(/dev), \"null\") resolves" \
        "dev-faccessat=ok" "$out"
    check_contains "m14 fstatat(dirfd(/), \"<bind>\") resolves" \
        "bind-fstatat=ok" "$out"
    check_contains "m14 openat(dirfd(/), \"<bind>\") resolves" \
        "bind-openat=ok" "$out"
fi
rm -rf "$M14D" "$M14DB"
