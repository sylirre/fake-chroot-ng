# M17-9 seccomp(2)/prctl virtualization tests (sourced by tests/run.sh).
#
# Our own confinement is visible to the guest through two prctl ops, and a guest
# filter installed over ours would govern the syscalls the SIGSYS handler
# re-issues. `-t prctltest` drives the emulation through the dispatcher (so it
# runs on every host); `-t bpftest` proves the filter traps exactly the four ops
# we own and lets the rest of prctl through untrapped, which is what keeps
# PR_SET_VMA off the handler.
echo "== M17-9: seccomp(2) and prctl =="

out=$(run_t 30 -t prctltest 2>&1)
check "prctltest rc" 0 $?
check_absent "no prctl case failed" "FAIL" "$out"
check_contains "PR_GET_SECCOMP does not report our filter" \
    "prctltest GET_SECCOMP=0" "$out"
check_contains "the host no_new_privs bit is hidden" \
    "prctltest GET_NO_NEW_PRIVS (host bit hidden)=0" "$out"
check_contains "a guest filter is refused" \
    "prctltest SET_SECCOMP refused=-13" "$out"
check_contains "seccomp(2) is ENOSYS" "prctltest seccomp(2) refused=-38" "$out"
check_contains "the guest's own no_new_privs is remembered" \
    "prctltest GET_NO_NEW_PRIVS after the guest set it=1" "$out"
check_contains "an op we do not own still reaches the kernel" \
    "prctltest SET_NAME passthrough rc=0 comm=cngprctl" "$out"
# (the filter side — which prctl ops trap at all — is asserted with the rest of
# the BPF program in m5b_monitor.sh)
