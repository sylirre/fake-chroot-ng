# M12: System V shared memory (sourced by tests/run.sh).
#
# Three layers. First the dispatcher-level self-test (-t shmtest), which needs
# no seccomp and so runs anywhere, over both backing tiers (memfd, and the
# file-backed fallback forced with CNG_SHM_FORCE_FILE=1). Then a differential
# leg: the same guest binaries run once under chroot-ng's emulation and once
# straight under qemu-aarch64, where they get the host kernel's REAL SysV shm —
# stdout must match byte for byte, which is the strongest statement available
# that the emulation is indistinguishable. Finally the namespace scope, which
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
check_contains "a read-only attach sees the same memory" \
    "shmtest rdonly attach -> OK" "$out"
check_contains "detach then IPC_RMID kills the id" \
    "shmtest detach+rmid -> OK" "$out"
check_contains "keyed lookup, IPC_EXCL and ENOENT" \
    "shmtest keyed lookup -> OK" "$out"
check_contains "the ipcs enumeration path (SHM_INFO, SHM_STAT, IPC_INFO)" \
    "shmtest shm_info+shm_stat+ipc_info -> OK" "$out"
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

# --- differential against the host kernel's real SysV shm -------------------
GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
SG=$(mktemp -d)
m12_ready=1
for p in shm_sysv shm_stat shm_exec shm_edge shm_key; do
    $GCC -static-pie -O2 -o "$SG/$p" "tests/guests/$p.c" 2>/dev/null ||
        m12_ready=0
done
if [ "$m12_ready" = 0 ]; then
    echo "  skip: guest cross-compiler unavailable"
else
    # shm_diff <desc> <prog>: emulated vs the real kernel, stdout + rc.
    shm_diff() {
        out_k=$("$QEMU" "$SG/$2" 2>/dev/null); rc_k=$?
        out_e=$(run -R "$SG" "/$2" 2>/dev/null); rc_e=$?
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

    # ...and again over the file-backed tier, which must be indistinguishable
    # from the memfd one (only the broker's backing differs).
    out_k=$("$QEMU" "$SG/shm_sysv" 2>/dev/null)
    out_e=$(CNG_SHM_FORCE_FILE=1 run -R "$SG" /shm_sysv 2>/dev/null)
    check_contains "m12 file-backed shm_sysv still matches" "$out_k" "$out_e"

    # The guest's calls really are being emulated, not passed to the host: the
    # dispatcher traces every one under CNG_DEBUG.
    n=$(CNG_DEBUG=1 run -R "$SG" /shm_sysv 2>&1 | grep -c 'sysv-shm')
    if [ "$n" -ge 8 ]; then
        pass=$((pass + 1)); printf '  ok   %s\n' "m12 the guest's shm syscalls reach the emulation ($n)"
    else
        fail=$((fail + 1)); printf '  FAIL %s\n' "m12 guest shm syscalls not emulated (traced $n)"
    fi

    # --- namespace scope ----------------------------------------------------
    # Default: one namespace per invocation, so a keyed segment does not leak
    # from one launch to the next (two containers do not share IPC).
    K=51ab0001
    run -R "$SG" /shm_key $K create first-invocation >/dev/null 2>&1
    out=$(run -R "$SG" /shm_key $K find 2>/dev/null)
    check_contains "m12 a keyed segment does not leak between invocations" \
        "found=0" "$out"

    # --shared-proc widens the namespace to the rootfs, the same way it widens
    # the guest process view.
    K=51ab0002
    run --shared-proc -R "$SG" /shm_key $K create shared-invocation >/dev/null 2>&1
    out=$(run --shared-proc -R "$SG" /shm_key $K find 2>/dev/null)
    check_contains "m12 --shared-proc shares segments between invocations" \
        "found=1 text=shared-invocation" "$out"
    run --shared-proc -R "$SG" /shm_key $K rmid >/dev/null 2>&1
fi
rm -rf "$SG"

# --- guest-shell smoke ------------------------------------------------------
# ipcs(1) is what a user reaches for; busybox's applet drives SHM_INFO/SHM_STAT
# exactly as shm_stat.c does, so this only has to show the tool runs and reports
# an empty namespace the way it would against a kernel with no segments.
M12_ALPINE="${M12_ALPINE:-/home/sol/arm64chroot/tests/.cache/rootfs/alpine}"
if [ -x "$M12_ALPINE/bin/busybox" ]; then
    SR=$(mktemp -d); cp -a "$M12_ALPINE/." "$SR"
    out=$(run -R "$SR" /bin/sh -c 'ipcs -m; echo rc=$?' 2>/dev/null)
    check_contains "m12 ipcs -m runs in a guest shell" "rc=0" "$out"
    rm -rf "$SR"
else
    echo "  skip: alpine rootfs missing (ipcs scenario)"
fi
