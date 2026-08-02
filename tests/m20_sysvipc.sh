# M22 System V semaphores and message queues (sourced by tests/run.sh).
#
# M12 gave the guest its own shared-memory namespace but left semget/semop/
# semctl/semtimedop and msgget/msgsnd/msgrcv/msgctl running natively, so on a
# desktop host the guest operated in the HOST's sem/msg namespace: it could
# attach to host semaphores, and host `ipcs -s`/`-q` listed the guest's objects.
# They were refused ENOSYS as a stop-gap; this milestone emulates them from the
# same broker daemon shm uses, which is also what makes them work at all on
# Android, where the whole SysV family is off the app seccomp allow-list.
#
# Two kinds of coverage, for two different reasons:
#   * `-t ipctest` drives the dispatcher directly, so it runs everywhere --
#     including on a host with no working SysV IPC of its own, which is exactly
#     the target platform;
#   * the guest programs run once under the emulation and once straight under
#     qemu-aarch64, where the same code reaches the host kernel's real
#     semget/semop/msgsnd. Unlike the shm differential, which leans on qemu's
#     own shmat, nothing is emulated on the reference side here: every call is
#     forwarded to the kernel, so the comparison is against the genuine article.
echo "== M22: System V semaphores and message queues =="

# --- dispatcher self-test ---------------------------------------------------
out=$(run_t 120 -t ipctest 2>&1); rc=$?
check "ipctest overall" 0 "$rc"
check_contains "semget, SETVAL/GETVAL and a multi-operation semop" \
    "ipctest semget+setval+semop -> OK" "$out"
check_contains "a vector that cannot proceed rolls back entirely" \
    "ipctest semop atomic rollback -> OK" "$out"
check_contains "GETALL/SETALL stream their vector over the connection" \
    "ipctest semctl getall+setall -> OK" "$out"
check_contains "msgctl's enumeration commands and the msginfo constants" \
    "ipctest msgctl enumeration -> OK" "$out"
check_contains "IPC_STAT/IPC_SET and the ipcs enumeration commands" \
    "ipctest semctl stat+set+enumeration -> OK" "$out"
check_contains "a blocking semop parks in the daemon and is woken by another process" \
    "ipctest blocking semop woken -> OK" "$out"
check_contains "semtimedop's deadline expires in the daemon" \
    "ipctest semtimedop timeout -> OK" "$out"
check_contains "nsops is narrowed to the width the kernel takes it at" \
    "ipctest semop nsops width -> OK" "$out"
check_contains "the semadj range, cumulative within a vector and at its ends" \
    "ipctest sem_undo range -> OK" "$out"
check_contains "SEM_UNDO is applied at death, with no exit hook to do it" \
    "ipctest sem_undo after exit val=2 -> OK" "$out"
check_contains "the semaphore error cases, in the kernel's order" \
    "ipctest sem error cases -> OK" "$out"
check_contains "keyed lookup, IPC_EXCL and the id dying with IPC_RMID" \
    "ipctest sem keyed lookup -> OK" "$out"
check_contains "the whole msgrcv selection rule (by type, at-most, FIFO)" \
    "ipctest msgsnd+msgrcv selection -> OK" "$out"
check_contains "a short buffer is E2BIG, or truncation under MSG_NOERROR" \
    "ipctest msgrcv E2BIG+MSG_NOERROR -> OK" "$out"
check_contains "a blocking msgrcv is fed by a sender in another process" \
    "ipctest blocking msgrcv woken -> OK" "$out"
check_contains "the message error cases and IPC_RMID" \
    "ipctest msg error cases+rmid -> OK" "$out"

# --- differential against the host kernel's real SysV IPC -------------------
IG=$(mktemp -d)
m22_ready=0
if ! guest_xlate_ready "SysV sem/msg differential"; then
    :
else
    m22_ready=1
    for p in sem_sysv sem_block sem_undo sem_key; do
        guest_cc "$IG/$p" "tests/guests/$p.c" || m22_ready=0
    done
    if [ "$m22_ready" = 0 ]; then
        skip "SysV sem/msg differential: the guest programs do not build here ($(head -1 "$GUEST_CC_LOG" 2>/dev/null))"
    else
        # Android drops SysV IPC from bionic and denies it to app domains, so
        # there is no kernel reference to diff against there -- `-t ipctest`
        # above is what covers the emulation on that platform.
        m22_base=$(emu_t 90 "$IG/sem_sysv" 2>/dev/null)
        case "$m22_base" in
        *done*) ;;
        *)
            m22_ready=0
            skip "SysV sem/msg differential: this host has no working SysV IPC to diff against"
            ;;
        esac
    fi
fi
if [ "$m22_ready" = 1 ]; then
    # ipc_diff <desc> <prog>: emulated vs the real kernel, stdout + rc.
    ipc_diff() {
        out_k=$(emu_t 90 "$IG/$2" 2>/dev/null); rc_k=$?
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        out_e=$(run_t 90 $GUEST_BINDS -R "$IG" "/$2" 2>/dev/null); rc_e=$?
        if [ "$out_k" = "$out_e" ] && [ "$rc_k" = "$rc_e" ]; then
            pass=$((pass + 1)); printf '  ok   %s\n' "$1"
        else
            fail=$((fail + 1)); printf '  FAIL %s\n' "$1"
            printf '    kernel: %s (rc %s)\n' "$(echo "$out_k" | tr '\n' '|')" "$rc_k"
            printf '    cng   : %s (rc %s)\n' "$(echo "$out_e" | tr '\n' '|')" "$rc_e"
        fi
    }
    ipc_diff "m22 sem_sysv matches the real kernel byte-for-byte" sem_sysv
    # The blocking half: every way a sleeping operation can end. The EINTR leg
    # is the one that cannot work by accident -- the client half runs inside the
    # SIGSYS handler, where all signals but SIGSYS are masked, so a sleeping
    # semop is never woken by the signal arriving and the pending set has to be
    # polled against the mask the frame will restore.
    ipc_diff "m22 sem_block matches it for every way a sleeper ends" sem_block
    # SEM_UNDO with no exit hook anywhere: the broker applies it from the pid's
    # incarnation, and it has to be visible immediately after the reap.
    ipc_diff "m22 sem_undo matches it, SIGKILL included" sem_undo

    # --- namespace scope (nothing to diff: the host has one namespace) -----
    # By default the namespace is per invocation, so a keyed set one launch
    # creates must be invisible to the next.
    K=51bb0001
    run_t 60 -R "$IG" /sem_key $K create 4 >/dev/null 2>&1
    out=$(run_t 60 -R "$IG" /sem_key $K find 2>/dev/null)
    check_contains "m22 a keyed set does not leak between invocations" \
        "found=0" "$out"

    # --shared-proc widens it to the rootfs, the same way it widens the process
    # view -- and then the second launch reads what the first left behind.
    K=51bb0002
    run_t 60 --shared-proc -R "$IG" /sem_key $K create 4 >/dev/null 2>&1
    out=$(run_t 60 --shared-proc -R "$IG" /sem_key $K find 2>/dev/null)
    check_contains "m22 --shared-proc shares sets and queues between invocations" \
        "found=1 val=4 msg=4" "$out"
    run_t 60 --shared-proc -R "$IG" /sem_key $K rmid >/dev/null 2>&1

    # --- and the containment that is the point of all of it ----------------
    # The guest's objects must never appear in the HOST's namespace. `ipcs` is
    # the check a user would make; where it is absent the leg sits out rather
    # than passing for the wrong reason.
    if ! have ipcs; then
        skip "m22 host-namespace check: no ipcs(1) here"
    else
        K=51bb0003
        run_t 60 -R "$IG" /sem_key $K create 4 >/dev/null 2>&1
        hostview=$(ipcs -s 2>/dev/null; ipcs -q 2>/dev/null)
        case "$hostview" in
        *51bb0003*) fail=$((fail + 1))
            echo "  FAIL m22 the guest's keyed objects reached the HOST namespace" ;;
        *) pass=$((pass + 1))
            echo "  ok   m22 the host sem/msg namespace is untouched" ;;
        esac
    fi
fi
rm -rf "$IG"

# --- guest-shell smoke ------------------------------------------------------
# `ipcs -s`/`-q` is what a user reaches for, and busybox's applet drives
# SEM_INFO/SEM_STAT and MSG_INFO/MSG_STAT exactly as the enumeration group in
# `-t ipctest` does. This only has to show the tool runs against the emulated
# namespace and reports it empty, the way it would against a kernel with none.
M22_ALPINE="${M22_ALPINE:-$CNG_ALPINE}"
if [ -n "$M22_ALPINE" ] && [ -x "$M22_ALPINE/bin/busybox" ]; then
    SR=$(mktemp -d); cp -a "$M22_ALPINE/." "$SR"
    out=$(run_t 60 -R "$SR" /bin/sh -c 'ipcs -s; ipcs -q; echo rc=$?' 2>/dev/null)
    check_contains "m22 ipcs -s and -q run in a guest shell" "rc=0" "$out"
    rm -rf "$SR"
else
    skip "m22 ipcs guest-shell scenario: no alpine rootfs"
fi
