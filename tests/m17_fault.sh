# M17-7 guest-pointer validation tests (sourced by tests/run.sh).
#
# The syscalls the monitor emulates rather than re-issues dereference the
# guest's pointers itself, so the kernel never validates them for us — and the
# SIGSYS handler runs with SIGSEGV masked, which makes a fault there unblockable
# and fatal. A bad pointer must therefore come back -EFAULT.
#
# `-t faulttest` drives the dispatcher directly, so it exercises the emulation
# on every host rather than only where the seccomp tier is live. It reports SKIP
# where no memfd can back the probe (the helpers then answer "accessible" and the
# old behaviour stands).
echo "== M17-7: EFAULT instead of death on a bad guest pointer =="

out=$(run_t 30 -t faulttest 2>&1)
rc=$?
case "$out" in
*"probe unavailable"*)
    skip "faulttest: no memfd here, so the pointer probe is inert"
    ;;
*)
    check "faulttest rc" 0 $rc
    check_absent "no case faulted" "FAIL" "$out"
    for _c in rt_sigaction rt_sigprocmask getcwd getresuid getresgid \
        setgroups getgroups capget shmctl sendmsg; do
        check_contains "$_c answers EFAULT" "faulttest $_c=-14 want=-14 -> OK" \
            "$out"
    done
    check_contains "valid pointers still work" \
        "faulttest valid getresuid=0" "$out"
    ;;
esac
