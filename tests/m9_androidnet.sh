# M9 Android seccomp-compat net (sourced by tests/run.sh). Validates the SIGSYS
# handler branching via synthetic contexts (real nested seccomp needs a device).
echo "== M9: Android seccomp net =="
run -t nettest >/dev/null 2>&1
check "gate-net + dispatch + passthrough branches" 0 $?
check_contains "gate-trapped reissue -> ENOSYS" "gate-net: regs0=-38" "$(run -t nettest 2>/dev/null)"
run -t blocktest >/dev/null 2>&1
check "blocklist gates reissue -> ENOSYS" 0 $?
