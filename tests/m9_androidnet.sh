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
run -t blocktest >/dev/null 2>&1
check "blocklist gates reissue -> ENOSYS" 0 $?
