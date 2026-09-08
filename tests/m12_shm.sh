# M12: System V shared memory (sourced by tests/run.sh).
#
# Three layers. First the dispatcher-level self-test (-t shmtest), which needs
# no seccomp and so runs anywhere, over both backing tiers (memfd, and the
# file-backed fallback forced with CNG_SHM_FORCE_FILE=1). Then a differential
# leg: the same guest binaries run once under chroot-ng's emulation and once with
# no emulation at all, where they get the host kernel's REAL SysV shm — stdout
# must match byte for byte, which is the strongest statement available that the
# emulation is indistinguishable. Finally the namespace scope, which
# has no kernel counterpart to diff against (that is the point) and is asserted
# directly.
#
# The programs print only semantic outcomes — never shmids, addresses or
# timestamps — since those legitimately differ between the host's global
# namespace and ours. See tests/guests/shm_sysv.c.
echo "== M12: System V shared memory =="

# --- dispatcher self-test ---------------------------------------------------
out=$(run -t shmtest 2>&1); rc=$?
check "shmtest overall" 0 "$rc"
check_contains "create, attach, and IPC_STAT agree" \
    "shmtest create+attach+stat -> OK" "$out"
check_contains "a fork child shares the memory; nattch drops when it dies" \
    "shmtest fork share=1 nattch-after-exit=1 -> OK" "$out"
check_contains "attach-address rules (unaligned, SHM_RND, occupied, SHM_REMAP)" \
    "shmtest attach-addr unaligned/rnd/occupied/remap -> OK" "$out"
# SHM_REMAP is MAP_FIXED, and chroot-ng shares the guest's address space: an
# attach aimed at the monitor's own image would replace the code performing it.
check_contains "a SHM_REMAP attach onto chroot-ng's own image is refused" \
    "shmtest remap over our own image refused=1 intact=1 -> OK" "$out"
# The memfd tier leaves nothing on disk at all; the leg below asserts the other
# direction, where a file does appear.
check_contains "the memfd tier leaves no file in the shared directory" \
    "shmtest backing files forced=0 found=0 malformed=0 -> OK" "$out"
check_contains "a read-only attach sees the same memory" \
    "shmtest rdonly attach -> OK" "$out"
check_contains "detach then IPC_RMID kills the id" \
    "shmtest detach+rmid -> OK" "$out"
check_contains "keyed lookup, IPC_EXCL and ENOENT" \
    "shmtest keyed lookup -> OK" "$out"
check_contains "the ipcs enumeration path (SHM_INFO, SHM_STAT, IPC_INFO)" \
    "shmtest shm_info+shm_stat+ipc_info -> OK" "$out"
check_contains "SHM_INFO/IPC_INFO succeed before any segment exists" \
    "shmtest empty-namespace shm_info+ipc_info -> OK" "$out"
check_contains "a truncated broker reply leaves no descriptor behind" \
    "shmtest short reply leaks no fd -> OK" "$out"
# The other direction, and the one the daemon actually reads on: an fd a peer
# attaches to a *request* is installed by the kernel whether or not the receiver
# asked for one, because the control buffer goes on the recvmsg regardless.
check_contains "a fd attached to a request is not left installed" \
    "shmtest an unwanted fd is not left installed -> OK" "$out"
# A peer that closed with nothing sent is the one broker failure a caller may
# retry: it neither answered nor half-answered, and the daemon's state died with
# it. A timeout and a truncated reply must not be confused with it — there the
# request may already have been served.
check_contains "the retryable broker failure is told from the others" \
    "shmtest gone/short/timeout told apart: 111 -> OK" "$out"
# ...and the retry itself: the daemon listens across its whole idle-exit
# teardown, so a connect landing there succeeds and only the reply never comes.
# Callers turned that into a fabricated ENOSPC/EIDRM instead of trying again.
check_contains "a daemon on its way out does not fail the caller's request" \
    "shmtest a daemon on its way out is retried past: OK" "$out"
# The rendezvous is an abstract name anyone on the machine can compute, so the
# daemon has to take the caller's identity from the kernel rather than from the
# request — and refuse a peer the kernel will not identify at all.
check_contains "a request cannot name a process other than its sender" \
    "shmtest a forged caller pid is not believed -> OK" "$out"
check_contains "an unidentifiable peer is refused by both ends" \
    "shmtest an unidentifiable peer is refused client=-28 daemon=-28 -> OK" "$out"
check_contains "IPC_SET writes the permission triad back" \
    "shmtest ipc_set -> OK" "$out"
check_contains "execve detaches every attachment" \
    "shmtest execve detach-all -> OK" "$out"
check_contains "bad ids, zero size and a stray address are refused" \
    "shmtest error cases -> OK" "$out"

# The file-backed tier: what the broker falls back to where memfd_create is
# unavailable (pre-3.17 kernel, or a seccomp filter blocking it).
out=$(CNG_SHM_FORCE_FILE=1 run -t shmtest 2>&1); rc=$?
check "shmtest over the file-backed backing tier" 0 "$rc"
check_contains "file-backed segments still share across a fork" \
    "shmtest fork share=1 nattch-after-exit=1 -> OK" "$out"
# That file lands in /dev/shm or /tmp, where every user on the machine may
# create names — and it used to be named after the shmid, so anyone could
# predict it, leave a symlink on it and have O_TRUNC destroy what it pointed at,
# or leave a file on it and read the guest's shared memory back out. Nothing
# outside the daemon needs to find it by name (attachers are handed the
# descriptor), so it now carries only random bits and is created O_EXCL.
check_contains "the backing file's name is unguessable and exclusively created" \
    "shmtest backing files forced=1 found=1 malformed=0 -> OK" "$out"

# --- differential against the host kernel's real SysV shm -------------------
# The reference side is the same binary run with no emulation at all, so it needs
# the host to actually provide SysV shm: Android does not (bionic drops the API
# and the app domain gets no IPC), so there the differential legs sit out and the
# dispatcher self-test above is what covers the emulation.
SG=$(mktemp -d)
# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m12run() { run $GUEST_BINDS "$@"; }

# --- what the guest can see of the broker's own startup ---------------------
# The daemon is started by a double fork from whichever guest process makes the
# first SysV IPC call, and the middle child of that fork is a child of the
# guest's process. Its exit used to send the guest a SIGCHLD for a process the
# guest never started (and could be reaped by a wait() on another thread). It is
# cloned with no exit signal now, which the kernel neither signals nor shows to
# an ordinary wait. Needs no host SysV shm — the emulation is the whole
# subject — so it sits outside the differential block below.
if ! guest_xlate_ready "broker spawn visibility"; then
    :
elif ! guest_cc_report "$SG/brokerchld" tests/guests/brokerchld.c; then
    :
else
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    bc_out=$(run_t 60 $GUEST_BINDS -R "$SG" /brokerchld 2>/dev/null)
    # The control: this run can see a SIGCHLD and reap a child at all.
    check_contains "m12 a guest's own child is still its own" \
        "own: chld=1 reaped=1 status=3" "$bc_out"
    check_contains "m12 the first SysV call starts the broker" \
        "broker: got=1" "$bc_out"
    case "$bc_out" in
    *"quiet: 1"*)
        check_contains "m12 starting the broker leaves the guest nothing to see" \
            "broker: got=1 chld=0 wait=-1 e=10" "$bc_out" ;;
    *)
        skip "m12 broker spawn visibility: no exit-signal-less clone here (qemu-user implements clone(SIGCHLD) and nothing else)" ;;
    esac
fi

# --- POSIX shm: the other shared memory, which is a directory ---------------
# shm_open() has no syscall behind it: it is an open() under /dev/shm, so a
# guest has POSIX shared memory exactly when it has a writable one. Android has
# no such directory at all, and the synthesized mount table said it did, so a
# glibc or musl guest was told tmpfs and then handed ENOENT. chroot-ng serves
# one from a per-uid directory under $TMPDIR there; this asks a real libc
# whether that is enough, and asks it against the stand-in specifically, so a
# host with its own /dev/shm exercises the same path.
#
# guest_cc rather than guest_cc_report on purpose: bionic has no shm_open at
# all (Android uses ashmem), so on a Termux host the program cannot build and
# that is a skip, not a failure. The rootfs guests this matters for — Alpine,
# Debian — are the ones that have it.
if ! guest_xlate_ready "POSIX shm"; then
    :
elif ! guest_cc "$SG/shm_posix" tests/guests/shm_posix.c; then
    skip "POSIX shm: no shm_open in this guest libc (bionic has none)"
else
    m12_want="posix: created
posix: read POSIX-SHM-OK
posix: after-unlink gone
posix: done"
    M12T=$(mktemp -d)
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
    m12_got=$(TMPDIR="$M12T" CNG_DEVSHM_FORCE_TMP=1 run_t 60 $GUEST_BINDS -R \
        "$SG" /shm_posix 2>/dev/null); m12_rc=$?
    check "m12 a POSIX shm round trip on the /dev/shm stand-in exits 0" 0 "$m12_rc"
    if [ "$m12_got" = "$m12_want" ]; then
        pass=$((pass + 1))
        printf '  ok   m12 ...create, map, reopen by name, read back, unlink\n'
    else
        fail=$((fail + 1))
        printf '  FAIL m12 POSIX shm round trip on the stand-in\n'
        printf '    want: %s\n' "$(echo "$m12_want" | tr '\n' '|')"
        printf '    got : %s\n' "$(echo "$m12_got" | tr '\n' '|')"
    fi
    # And it really was the stand-in: the object is created and unlinked inside
    # the run, so what is left behind is the directory chroot-ng made for it.
    if [ -n "$(find "$M12T" -maxdepth 1 -type d -name 'chroot-ng-shm.v1.*' \
        2>/dev/null)" ]; then
        pass=$((pass + 1))
        printf '  ok   m12 ...in the per-uid directory under $TMPDIR\n'
    else
        fail=$((fail + 1))
        printf '  FAIL m12 the stand-in directory was not made under $TMPDIR\n'
        find "$M12T" | sed 's/^/    /' | head -5
    fi
    rm -rf "$M12T"
fi

m12_kbase=
m12_ready=0
if guest_xlate_ready "SysV shm differential"; then
    m12_ready=1
    for p in shm_sysv shm_stat shm_exec shm_edge shm_key; do
        guest_cc "$SG/$p" "tests/guests/$p.c" || m12_ready=0
    done
    if [ "$m12_ready" = 0 ]; then
        skip "SysV shm differential: the guest programs do not build here ($(head -1 "$GUEST_CC_LOG" 2>/dev/null))"
    else
        # Android drops SysV IPC from bionic and denies it to app domains, so
        # there is no kernel reference to diff against there.
        m12_kbase=$(emu_t 60 "$SG/shm_sysv" 2>/dev/null)
        case "$m12_kbase" in
        *done*) ;;
        *)
            m12_ready=0
            skip "SysV shm differential: this host has no working SysV shm to diff against"
            ;;
        esac
    fi
fi
if [ "$m12_ready" = 1 ]; then
    # shm_diff <desc> <prog>: emulated vs the real kernel, stdout + rc.
    shm_diff() {
        out_k=$(emu_t 60 "$SG/$2" 2>/dev/null); rc_k=$?
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        out_e=$(run_t 60 $GUEST_BINDS -R "$SG" "/$2" 2>/dev/null); rc_e=$?
        if [ "$out_k" = "$out_e" ] && [ "$rc_k" = "$rc_e" ]; then
            pass=$((pass + 1)); printf '  ok   %s\n' "$1"
        else
            fail=$((fail + 1)); printf '  FAIL %s\n' "$1"
            printf '    kernel: %s (rc %s)\n' "$(echo "$out_k" | tr '\n' '|')" "$rc_k"
            printf '    cng   : %s (rc %s)\n' "$(echo "$out_e" | tr '\n' '|')" "$rc_e"
        fi
    }
    shm_diff "m12 shm_sysv matches the real kernel byte-for-byte" shm_sysv
    shm_diff "m12 shm_stat (ipcs enumeration) matches the real kernel" shm_stat
    # The emulated execve keeps the address space, so it has to drop attaches
    # itself; a real execve gets it for free by replacing the address space.
    shm_diff "m12 execve detaches attachments as a real one does" shm_exec
    # The corner cases, each of which had a divergence when this was ported:
    # SHM_EXEC's permission check, SHM_LOCK, SHM_RND's rounding. See shm_edge.c.
    shm_diff "m12 shmat/shmctl corner cases match the real kernel" shm_edge

    # SHM_REMAP has its own program because qemu-aarch64 cannot referee it: it
    # tracks attachments in a table of its own keyed by start address and
    # detaches the whole recorded region, which is the very mistake under test.
    # Measured with no chroot-ng in the picture — one page remapped over the
    # front of a 16-page attachment, then shmdt: the kernel keeps the covered
    # segment's nattch at 1 and leaves the tail mapped, qemu-user reports 0 and
    # unmaps all 64 KiB. So the reference side is a host build, as M18 does for
    # ptrace and M22 for msgsnd.
    RM_ORACLE=$SG/shm_remap
    rm_ready=1
    if ! guest_cc "$SG/shm_remap" tests/guests/shm_remap.c; then
        rm_ready=0
        skip "m12 SHM_REMAP: the guest program does not build here"
    elif [ -n "$QEMU" ]; then
        rm_ready=0
        for _c in ${HOSTCC:-} cc gcc clang; do
            have "$_c" || continue
            if "$_c" -O2 -o "$SG/rm_host" tests/guests/shm_remap.c 2>/dev/null
            then
                RM_ORACLE=$SG/rm_host
                rm_ready=1
                break
            fi
        done
        [ "$rm_ready" = 1 ] ||
            skip "m12 SHM_REMAP: no host compiler for the differential oracle"
    fi
    if [ "$rm_ready" = 1 ]; then
        if [ -n "$TIMEOUT" ]; then
            rm_k=$("$TIMEOUT" 60 "$RM_ORACLE" 2>/dev/null)
        else
            rm_k=$("$RM_ORACLE" 2>/dev/null)
        fi
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        rm_e=$(run_t 60 $GUEST_BINDS -R "$SG" /shm_remap 2>/dev/null)
        if [ "$rm_k" = "$rm_e" ]; then
            pass=$((pass + 1))
            printf '  ok   m12 SHM_REMAP retires what it replaced\n'
        else
            fail=$((fail + 1))
            printf '  FAIL m12 SHM_REMAP bookkeeping diverges from the kernel\n'
            printf '    kernel: %s\n' "$(echo "$rm_k" | tr '\n' '|')"
            printf '    cng   : %s\n' "$(echo "$rm_e" | tr '\n' '|')"
        fi
    fi

    # Both tables the emulation tracks attachments in used to be fixed-size, and
    # neither limit exists in the kernel: 128 attachments per process (past which
    # shmdt answered EINVAL for an address the kernel detaches) and 32 attaching
    # processes per segment (past which a dead attacher's count stayed on nattch
    # for good). qemu-aarch64 cannot referee this — its own shm bookkeeping is 32
    # regions wide — so the reference side is a host build, as SHM_REMAP's leg
    # above and M22's msgsnd ordering are.
    MANY_ORACLE=$SG/shm_many
    many_ready=1
    if ! guest_cc "$SG/shm_many" tests/guests/shm_many.c; then
        many_ready=0
        skip "m12 attachment tables: the guest program does not build here"
    elif [ -n "$QEMU" ]; then
        many_ready=0
        for _c in ${HOSTCC:-} cc gcc clang; do
            have "$_c" || continue
            if "$_c" -O2 -o "$SG/many_host" tests/guests/shm_many.c 2>/dev/null
            then
                MANY_ORACLE=$SG/many_host
                many_ready=1
                break
            fi
        done
        [ "$many_ready" = 1 ] ||
            skip "m12 attachment tables: no host compiler for the differential oracle"
    fi
    if [ "$many_ready" = 1 ]; then
        if [ -n "$TIMEOUT" ]; then
            many_k=$("$TIMEOUT" 120 "$MANY_ORACLE" 2>/dev/null)
        else
            many_k=$("$MANY_ORACLE" 2>/dev/null)
        fi
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        many_e=$(run_t 120 $GUEST_BINDS -R "$SG" /shm_many 2>/dev/null)
        if [ "$many_k" = "$many_e" ]; then
            pass=$((pass + 1))
            printf '  ok   m12 attachment tracking has no limit the kernel does not\n'
        else
            fail=$((fail + 1))
            printf '  FAIL m12 attachment tracking runs out where the kernel does not\n'
            printf '    kernel: %s\n' "$(echo "$many_k" | tr '\n' '|')"
            printf '    cng   : %s\n' "$(echo "$many_e" | tr '\n' '|')"
        fi
    fi

    # ...and again over the file-backed tier, which must be indistinguishable
    # from the memfd one (only the broker's backing differs).
    out_k=$m12_kbase
    out_e=$(CNG_SHM_FORCE_FILE=1 m12run -R "$SG" /shm_sysv 2>/dev/null)
    check_contains "m12 file-backed shm_sysv still matches" "$out_k" "$out_e"

    # The guest's calls really are being emulated, not passed to the host: the
    # dispatcher traces every one under CNG_DEBUG.
    n=$(CNG_DEBUG=1 m12run -R "$SG" /shm_sysv 2>&1 | grep -c 'sysv-shm')
    if [ "$n" -ge 8 ]; then
        pass=$((pass + 1)); printf '  ok   %s\n' "m12 the guest's shm syscalls reach the emulation ($n)"
    else
        fail=$((fail + 1)); printf '  FAIL %s\n' "m12 guest shm syscalls not emulated (traced $n)"
    fi

    # --- namespace scope ----------------------------------------------------
    # Default: one namespace per invocation, so a keyed segment does not leak
    # from one launch to the next (two containers do not share IPC).
    K=51ab0001
    m12run -R "$SG" /shm_key $K create first-invocation >/dev/null 2>&1
    out=$(m12run -R "$SG" /shm_key $K find 2>/dev/null)
    check_contains "m12 a keyed segment does not leak between invocations" \
        "found=0" "$out"

    # --shared-proc widens the namespace to the rootfs, the same way it widens
    # the guest process view.
    K=51ab0002
    m12run --shared-proc -R "$SG" /shm_key $K create shared-invocation >/dev/null 2>&1
    out=$(m12run --shared-proc -R "$SG" /shm_key $K find 2>/dev/null)
    check_contains "m12 --shared-proc shares segments between invocations" \
        "found=1 text=shared-invocation" "$out"
    m12run --shared-proc -R "$SG" /shm_key $K rmid >/dev/null 2>&1
fi
rm -rf "$SG"

# --- guest-shell smoke ------------------------------------------------------
# ipcs(1) is what a user reaches for; busybox's applet drives SHM_INFO/SHM_STAT
# exactly as shm_stat.c does, so this only has to show the tool runs and reports
# an empty namespace the way it would against a kernel with no segments.
M12_ALPINE="${M12_ALPINE:-$CNG_ALPINE}"
if [ -n "$M12_ALPINE" ] && [ -x "$M12_ALPINE/bin/busybox" ]; then
    SR=$(mktemp -d); cp -a "$M12_ALPINE/." "$SR"
    out=$(run -R "$SR" /bin/sh -c 'ipcs -m; echo rc=$?' 2>/dev/null)
    check_contains "m12 ipcs -m runs in a guest shell" "rc=0" "$out"
    rm -rf "$SR"
else
    skip "ipcs guest-shell scenario: no alpine rootfs"
fi
