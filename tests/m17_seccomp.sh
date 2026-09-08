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
check_contains "the getter refuses a stray argument, as the setter does" \
    "prctltest GET_NO_NEW_PRIVS with a stray argument is EINVAL=-22" "$out"
check_contains "an op we do not own still reaches the kernel" \
    "prctltest SET_NAME passthrough rc=0 comm=cngprctl" "$out"
# (the filter side — which prctl ops trap at all — is asserted with the rest of
# the BPF program in m5b_monitor.sh)

# ...and the same bit asked about by more than one task. Linux keeps
# no_new_privs in task_struct: a thread setting it says nothing about its
# siblings, a task created afterwards inherits its creator's, and fork carries
# it across. One flag for the whole process instead answered 1 for every thread
# the moment any one of them set it, and gave a forked child the process's bit
# rather than the forking task's. Differential against the same program run
# straight under the kernel, where no monitor of ours is installed and the
# answers are the kernel's own.
#
# One line cannot match. spawned_by_unset asks what a thread created by a task
# WITHOUT the bit reads once a sibling has set it, and answering that means
# knowing which task created the thread — which means trapping thread creation,
# the one call this design cannot trap (a re-issued clone returns into the
# handler on the new thread's stack, with no frame to sigreturn through; see
# cng_build_seccomp_traceall). It is asserted on both sides instead, so the
# divergence is written down rather than passed over.
NPD=$(mktemp -d)
if guest_xlate_ready "per-task no_new_privs leg" &&
    guest_cc_report "$NPD/nnpthread" tests/guests/nnpthread.c -lpthread; then
    np_k=$(emu "$NPD/nnpthread" 2>/dev/null)
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    np_g=$(run_t 60 -R $GUEST_BINDS "$NPD" /nnpthread 2>/dev/null)
    np_kf=$(printf '%s\n' "$np_k" | grep -v '^spawned_by_unset=')
    np_gf=$(printf '%s\n' "$np_g" | grep -v '^spawned_by_unset=')
    if [ -z "$np_k" ]; then
        skip "per-task no_new_privs differential: the reference run produced nothing"
    elif [ "$np_kf" = "$np_gf" ]; then
        pass=$((pass + 1))
        echo "  ok   the per-task bit matches the kernel"
    else
        fail=$((fail + 1))
        echo "  FAIL the per-task bit diverges from the kernel"
        printf '    kernel: %s\n' "$(echo "$np_k" | tr '\n' '|')"
        printf '    cng   : %s\n' "$(echo "$np_g" | tr '\n' '|')"
    fi
    check_contains "a sibling setting it does not set it here" \
        "self_after_sibling_set=0" "$np_g"
    check_contains "a fork takes the forking task's bit, not the process's" \
        "forked_by_unset=0" "$np_g"
    check_contains "a thread created by a task that holds it inherits it" \
        "spawned_by_set=1" "$np_g"
    check_contains "the kernel's answer for the shape no in-process monitor sees" \
        "spawned_by_unset=0" "$np_k"
    check_contains "...where the emulation reports its floor instead" \
        "spawned_by_unset=1" "$np_g"
fi
rm -rf "$NPD"
