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
    # Two mechanisms answer the same question: process_vm_readv/writev against
    # our own pid where the kernel has them (one syscall, no descriptor), and a
    # copy through a scratch memfd where it does not (qemu-user, and an Android
    # policy that denies the pair). Whichever is live, every leg below must give
    # the same answer — so the forced-fallback run repeats the whole set.
    check_contains "the probe names the mechanism it used" "faulttest probe " \
        "$out"
    memfd_out=$(CNG_UACCESS_MEMFD=1 run_t 30 -t faulttest 2>&1)
    check "faulttest rc with the memfd fallback forced" 0 $?
    check_contains "the knob really forces the fallback" \
        "mech=memfd" "$memfd_out"
    check_absent "no case faulted on the fallback" "FAIL" "$memfd_out"
    check_absent "no case faulted" "FAIL" "$out"
    for _c in rt_sigaction rt_sigprocmask getcwd getresuid getresgid \
        setgroups getgroups capget shmctl sendmsg readlinkat "execve path" \
        "execve argv" "execve argv string"; do
        check_contains "$_c answers EFAULT" "faulttest $_c=-14 want=-14 -> OK" \
            "$out"
    done
    # readlinkat's bufsiz is the other half of that buffer being ours to write:
    # a non-positive one is EINVAL, and the answer is clamped at the int width.
    check_contains "readlinkat's bufsiz is taken as an int and clamps" \
        "faulttest readlink-bufsiz neg=-22 short=1 -> OK" "$out"
    # A sockaddr, and a whole mmsg vector of them, are read before the kernel
    # would have validated either. The errno is the host's to choose here (the
    # test fd is not a socket, so its refusal comes first) — what is asserted is
    # that the dispatcher answers rather than faulting, which the "no case
    # faulted" leg above enforces and a crash would take the whole run down.
    check_contains "a bad socket address answers rather than faults" \
        "faulttest socket-addr" "$out"
    check_contains "valid pointers still work" \
        "faulttest valid getresuid=0" "$out"
    ;;
esac
