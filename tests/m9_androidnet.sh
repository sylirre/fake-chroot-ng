# M9 Android seccomp-compat net (sourced by tests/run.sh). Validates the SIGSYS
# handler branching via synthetic contexts (real nested seccomp needs a device).
echo "== M9: Android seccomp net =="
run -t nettest >/dev/null 2>&1
check "gate-net + dispatch + passthrough branches" 0 $?
nettest_out=$(run -t nettest 2>/dev/null)
check_contains "gate-trapped reissue -> ENOSYS" "gate-net: regs0=-38" "$nettest_out"
# sigprocmask(how, &m, &m) — one variable for both masks — must not lose the
# requested set to the writability probe, which validates by zeroing.
check_contains "an aliased sigprocmask unblocks only what it named" \
    "nettest sigprocmask aliased: mask=0x800 old=0xa00 -> OK" "$nettest_out"
# ...and the argument checks the kernel makes before it changes anything. The
# call never reaches it, so a wrong sigsetsize passed silently and an out-of-
# range `how` was taken as SIG_SETMASK — replacing the mask, not adding to it.
check_contains "sigprocmask refuses a bad sigsetsize and a bad how" \
    "nettest sigprocmask args: size=-22 kept=1 how=-22 kept=1 -> OK" \
    "$nettest_out"
blocktest_out=$(run -t blocktest 2>&1); blocktest_rc=$?
check "blocklist gates reissue -> ENOSYS" 0 $blocktest_rc
# Android allows accept4 and blocks accept, and glibc and musl issue only the
# latter on AArch64: a blocked accept is made as the accept4 it is, with and
# without an address to fill, and is ENOSYS only when accept4 is blocked too.
check_contains "a blocked accept is made as accept4, which is allowed" \
    "blocktest accept(blocked, accept4 allowed)=" "$blocktest_out"
check_contains "...and the whole of it holds" \
    "both blocked=-38 accept4=" "$blocktest_out"
check_absent "...with no failing leg" "-> FAIL" "$blocktest_out"
# The uid and gid setters without -u. Android's app filter refuses all of them
# but setresuid, and each was answered ENOSYS, from a trap of that filter and
# from -R on any host; the kernel tells such a process 0 for a call that changes
# nothing, EPERM for one that would, EINVAL for an id of -1 (cred.c real_set).
case "$blocktest_out" in
*"blocktest setid: SKIP"*)
    skip "uid/gid setters answered as the kernel would: this process holds CAP_SETUID/CAP_SETGID or has ids that differ"
    ;;
*)
    check_contains "a refused uid/gid setter is answered as the kernel would" \
        "blocktest setid: refused 34/34, as measured 30/30 as the kernel answers, ids kept=1 -> OK" \
        "$blocktest_out"
    ;;
esac

# ...and in a guest, on every tier this host has, once as the host serves the
# setters and once with CNG_SETID_DENY=1, which takes them as Android does. The
# text is what a kernel prints (the x86_64 host's own, and qemu-user's
# pass-through), libc's setxid broadcast to a second thread included.
SETID_DIR=$(mktemp -d)
SETID_WANT="setuid_self=0
setgid_self=0
setuid_other=-1 errno=1
setgid_other=-1 errno=1
setuid_invalid=-1 errno=22
setgid_invalid=-1 errno=22
setreuid_keep=0
setreuid_self=0
setregid_other=-1 errno=1
setresuid_self=0
setresuid_other=-1 errno=1
setresgid_keep=0
setresgid_other=-1 errno=1
setfsuid_self=1
setfsuid_other=1
setfsgid_other=1
setgroups_none=-1 errno=1
ids_kept=1
threads_setgid=0
threads_setuid=0
done"
if guest_xlate_ready "uid/gid setters in a guest" &&
    guest_cc_report "$SETID_DIR/setid" tests/guests/setid.c -pthread; then
    for _tier in -R plain; do
        if [ "$_tier" = plain ] && [ "$CNG_SECCOMP_LIVE" != 1 ]; then
            skip "uid/gid setters in a guest, seccomp tier: the filter is inert here"
            continue
        fi
        _opt=""
        [ "$_tier" = -R ] && _opt=-R
        for _deny in 0 1; do
            _label="uid/gid setters in a guest answer as a kernel does ($_tier)"
            [ "$_deny" = 1 ] &&
                _label="uid/gid setters in a guest, refused as Android refuses them ($_tier)"
            # shellcheck disable=SC2086  # $_opt and $GUEST_BINDS are split on purpose
            _got=$(
                [ "$_deny" = 1 ] && export CNG_SETID_DENY=1
                run_t 60 $_opt $GUEST_BINDS "$SETID_DIR" /setid 2>/dev/null
            )
            case "$_got" in
            SKIP:*)
                skip "$_label: ${_got#SKIP: }"
                continue
                ;;
            esac
            if [ "$_got" = "$SETID_WANT" ]; then
                pass=$((pass + 1))
                echo "  ok   $_label"
            else
                fail=$((fail + 1))
                echo "  FAIL $_label"
                printf '%s\n' "$_got" | sed 's/^/    /' | head -24
            fi
        done
    done
    # ...and under a filter of the host's that refuses the eight as Android's
    # does, installed before chroot-ng starts (tests/guests/ambtrap.c): what
    # the startup probe has to find, rather than what the knob says.
    if guest_cc_report "$SETID_DIR/ambtrap" tests/guests/ambtrap.c; then
        for _tier in -R plain; do
            _label="uid/gid setters in a guest, under a filter that refuses them ($_tier)"
            if [ "$_tier" = plain ] && [ "$CNG_SECCOMP_LIVE" != 1 ]; then
                skip "$_label: the filter is inert here"
                continue
            fi
            _opt=""
            [ "$_tier" = -R ] && _opt=-R
            # shellcheck disable=SC2086  # $_opt and $GUEST_BINDS are split on purpose
            _got=$(emu_t 60 "$SETID_DIR/ambtrap" "$BIN" $_opt $GUEST_BINDS \
                "$SETID_DIR" /setid 2>/dev/null)
            case "$_got" in
            SKIP:*)
                skip "$_label: ${_got#SKIP: }"
                continue
                ;;
            esac
            if [ "$_got" = "$SETID_WANT" ]; then
                pass=$((pass + 1))
                echo "  ok   $_label"
            else
                fail=$((fail + 1))
                echo "  FAIL $_label"
                printf '%s\n' "$_got" | sed 's/^/    /' | head -24
            fi
        done
    fi
fi
rm -rf "$SETID_DIR"
