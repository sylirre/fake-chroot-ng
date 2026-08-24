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
        setgroups getgroups capget shmctl sendmsg readlinkat "openat path" \
        "renameat path2" "execve path" "execve argv" "execve argv string"; do
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
    # A send on an emulated netlink socket is the one send that never reaches
    # the kernel: the request is parsed here and answered from the stand-in
    # pair, so nothing else was going to look at the pointer. Both spellings
    # count — sendto's buffer and sendmsg's first iovec base, which was probed
    # one level short. Before, neither was an EFAULT but a SIGSEGV inside the
    # handler, which is unblockable: the whole `-t faulttest` run died here.
    check_contains "a netlink send with a bad buffer answers EFAULT" \
        "faulttest netlink sendto=-14 sendmsg=-14 want=-14 -> OK" "$out"
    # The copy-in pair execve's second pass takes argv/envp with. A probe
    # followed by a memcpy is two acts, and a guest thread can unmap the strings
    # in the gap between them — the memcpy then faults in the handler, which is
    # what the probes exist to prevent. That race cannot be scheduled here, so
    # what is asserted is the property that holds whatever the race does: a
    # string ending inside the live page arrives (str=3), one running into the
    # hole past it is EFAULT rather than an over-read (over=-14), a cap with no
    # terminator under it is E2BIG (cap=-7), and a range half in the hole comes
    # back whole or not at all (half=-14, fits=0).
    check_contains "a guest string is measured and taken in one act" \
        "faulttest copyin: str=3 over=-14 cap=-7 half=-14 fits=0 bad=-14 -> OK" \
        "$out"
    check_contains "...on the memfd tier too" \
        "faulttest copyin: str=3 over=-14 cap=-7 half=-14 fits=0 bad=-14 -> OK" \
        "$memfd_out"
    # The two measurements ride on the same apparatus. They answer out of a
    # copy now: probing a page and then walking the guest's own bytes had the
    # same gap, and the walk is the half that faults. A string or a vector
    # ending inside the live page is measured; one running into the hole past
    # it is EFAULT rather than an over-read.
    for _o in "$out" "$memfd_out"; do
        check_contains "a guest string and vector are measured out of a copy" \
            "faulttest measure: str=3 over=-14 cap=-7 vec=1 vecover=-14 -> OK" \
            "$_o"
        # And the write direction: cng_user_writable followed by a store has
        # the identical gap, and the store cannot be taken back.
        check_contains "bytes go out to the guest in one act" \
            "faulttest copyout: fits=0 over=-14 bad=-14 -> OK" "$_o"
        # A fork brings the staging descriptor across with the address space,
        # and the file behind it: two processes writing into the same bytes of
        # one memfd read each other's back. It surfaced as a guest command
        # failing with EFAULT about one run in thirty — a shell pipeline forks
        # two children and both translate a path at once.
        check_contains "a forked child stages through a descriptor of its own" \
            "faulttest fork: parent=1 child=1 -> OK" "$_o"
    done
    check_contains "valid pointers still work" \
        "faulttest valid getresuid=0" "$out"
    ;;
esac
