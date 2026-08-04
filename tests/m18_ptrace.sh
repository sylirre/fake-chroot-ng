# M18 ptrace(2) emulation tests (sourced by tests/run.sh).
#
# Differential against the real kernel: tests/guests/pt_probe.c is built twice —
# once as the AArch64 guest, run under chroot-ng, and once for the host, run
# directly — and the two must print the same lines. What it prints is protocol
# only (stop kinds, wait statuses, event codes, exit codes), so the comparison
# holds across architectures; the host build is the oracle wherever chroot-ng
# needs an emulator, and on an AArch64 host the same binary run without
# chroot-ng is a same-architecture oracle for free.
#
# The guest has to be one whose syscalls chroot-ng actually intercepts. On a
# device that is every guest (the seccomp tier traps them); under qemu-user,
# where no filter is live, it means a static guest under -R.
echo "== M18: ptrace =="

# The single-step next-PC decoder, checked directly: it is pure logic, it runs
# on every host, and a branch it misreads is the one failure mode with no
# safety net (the breakpoint lands where the tracee never goes).
ptout=$(run_t 60 -t ptracetest 2>&1)
check "single-step decoder + the SIGSYS tier's stop path" 0 $?
check_contains "pointer-auth branches are refused, not guessed" \
    "braaz is refused, not guessed: OK" "$ptout"
# The tier that runs on a device: no guest filter is applied under qemu-user, so
# every live-guest leg below goes through the -R trampoline instead. This drives
# cng_sigsys_body directly — real fork, real registry and mailbox, synthesized
# trap — so the wrapper that only devices execute is covered here too.
check_contains "SIGSYS tier: a tracee stops cooperatively" \
    "sigsys tier: cooperative stop -> OK" "$ptout"
check_contains "SIGSYS tier: syscall-entry stop" \
    "sigsys tier: syscall-entry stop -> OK" "$ptout"
check_contains "SIGSYS tier: the tracer reads the trapped register file" \
    "sigsys tier: regs at the entry stop -> OK" "$ptout"
check_contains "SIGSYS tier: syscall-exit stop carries the result" \
    "sigsys tier: syscall-exit stop -> OK" "$ptout"
# The pointer-auth mask gdb asks for whenever AT_HWCAP says PACA, and is fatal
# about ("unable to fetch pauth registers"). Measured rather than asked for, so
# what is asserted is the shape the kernel's own answer always has.
case "$ptout" in
*"pauth mask"*) check_contains "pauth mask has the kernel's shape" \
    "pauth mask 0x" "$ptout"
    check_contains "...and is accepted" "-> OK" \
        "$(echo "$ptout" | grep 'pauth mask')" ;;
*) check_contains "no pauth here: the regset is refused as the kernel does" \
    "no pauth, refused -> OK" "$ptout" ;;
esac

# The two filters a ptrace role stacks on a task, simulated: they are only
# installed once a guest traces, and no guest filter runs under qemu-user, so
# this is the only check they get on a cross host.
out=$(run -t bpftest 2>&1)
check_contains "a tracee traps on every syscall" "traceall: read traps -> OK" "$out"
check_contains "...except rt_sigreturn" \
    "traceall: rt_sigreturn stays native -> OK" "$out"
check_contains "...and thread creation" \
    "traceall: thread clone stays native -> OK" "$out"
check_contains "a tracer traps only on wait and signal-sending" \
    "tracer: wait4 traps -> OK" "$out"
check_contains "...and nothing else" "tracer: read stays native -> OK" "$out"

PT_DIR=$(mktemp -d)
PT_GUEST="$PT_DIR/pt_guest"
PT_ORACLE="$PT_DIR/pt_oracle"

# The oracle: on a host that runs AArch64 binaries directly, the guest build
# itself (no chroot-ng in the way); otherwise a host-native build.
pt_oracle_build() {
    if [ -z "$QEMU" ]; then
        PT_ORACLE=$PT_GUEST
        return 0
    fi
    for c in ${HOSTCC:-} cc gcc clang; do
        have "$c" || continue
        # Same optimization level guest_cc uses: the breakpoint scenario pokes
        # over a function's first instruction, so both sides must have been
        # compiled the same way for the comparison to mean anything.
        "$c" -O2 -o "$PT_ORACLE" tests/guests/pt_probe.c 2>/dev/null && return 0
    done
    return 1
}

# One scenario, both ways. Extra arguments are passed to both runs, with the
# binary's own path substituted per side (the exec scenarios re-exec themselves).
pt_case() {
    _sc=$1
    _oracle_out=$(cd "$PT_DIR" && timeout 60 "./$(basename "$PT_ORACLE")" \
        "$_sc" "./$(basename "$PT_ORACLE")" 2>/dev/null)
    _guest_out=$(run_t 90 -R / "$PT_GUEST" "$_sc" "$PT_GUEST" 2>/dev/null)
    if [ "$_oracle_out" = "$_guest_out" ]; then
        pass=$((pass + 1))
        printf '  ok   ptrace %s matches the kernel\n' "$_sc"
    else
        fail=$((fail + 1))
        printf '  FAIL ptrace %s diverges from the kernel\n' "$_sc"
        printf '       kernel: %s\n' "$(echo "$_oracle_out" | tr '\n' '|')"
        printf '       guest : %s\n' "$(echo "$_guest_out" | tr '\n' '|')"
    fi
}

if [ "$CNG_SECCOMP_LIVE" != 1 ] && [ "${GUESTLD:-}" != "-static-pie" ] &&
    [ "${GUESTLD:-}" != "-static" ]; then
    skip "ptrace: the guest links dynamically and no filter is live, so the tracee's syscalls are not intercepted here"
elif ! guest_cc_report "$PT_GUEST" tests/guests/pt_probe.c; then
    :
elif ! pt_oracle_build; then
    skip "ptrace: no host compiler for the differential oracle"
else
    # The tracee side: stops, resumption, and the exit status reaching the
    # tracer.
    pt_case basic
    # Syscall-entry/exit stops for every syscall, which is what strace needs and
    # what the stacked trap-everything filter exists for.
    pt_case sysstop
    # PTRACE_GET_SYSCALL_INFO, which modern strace prefers over pairing the
    # stops itself.
    pt_case sysinfo
    # A tracer cancelling a syscall at its entry stop and substituting the
    # return value — proot's whole method.
    pt_case cancel
    # Reading and writing the tracee's memory.
    pt_case poke
    # Signal-delivery stops: suppressed, and delivered.
    pt_case signal
    pt_case deliver
    # PTRACE_O_TRACEFORK: the event stop, the new pid, the auto-attached child.
    pt_case fork
    # ptrace survives an emulated execve, with and without TRACEEXEC.
    pt_case exec
    pt_case execstart
    # The arguments a tracer reads are the guest's own: a path syscall stops
    # before chroot-ng translates it, so no host path (and no rootfs prefix)
    # reaches the trace. This is the specific way native host ptrace was wrong.
    pt_case patharg
    # PTRACE_O_TRACEEXIT: the stop before the death, and the status that is
    # about to be reported.
    pt_case exitstop
    # gdb's two mechanisms: a breakpoint poked into read-only text, and
    # single-stepping (which no hardware here can do for us).
    pt_case break
    pt_case step
    # PTRACE_ATTACH to a process that is already running, and DETACH.
    pt_case attach
    # process_vm_readv against a stopped tracee — strace's fast path, served
    # from the mailbox because the host may refuse it. The iovec counts are a
    # tracer's to choose and the emulation walks the arrays by them, so this
    # asks the kernel what each count means: import_iovec narrows nr_segs to an
    # `unsigned` before refusing it above UIO_MAXIOV, which makes 1<<60 read as
    # zero segments rather than an error. Taking that count at face value both
    # wrapped the length validation to nothing (1<<60 entries of 16 bytes is
    # exactly 2^64) and then walked the array off the end of guest memory.
    pt_case vmrw
    # Signals the emulation does not take over must still reach the kernel while
    # the task is traced. It hooks every catchable signal to route delivery
    # through the stop machinery, but SIGKILL and SIGSTOP are not among them —
    # nothing can be — and treating "traced" as "we own every signal" answered
    # rt_sigaction(SIGKILL, act) from a private mirror, reporting success where
    # the kernel says EINVAL. Query-only stays allowed on both, which is the
    # half a blanket refusal would get wrong.
    pt_case sigact
    # waitid names the states it will accept and the kernel honours each one
    # separately. The emulation gated its whole registry on WSTOPPED, so a wait
    # asking only for stops could be handed an exit, and one asking only for
    # exits — what a tracer reaping a dead tracee issues — never consulted the
    # registry at all.
    pt_case waitid

    # ...and the same, with a rootfs actually in the way: the guest binary is
    # bound in so it can be loaded, and the trace must still read the guest's
    # own string rather than the translated host path.
    mkdir -p "$PT_DIR/rootfs"
    out=$(run_t 90 -R -b "$PT_DIR:$PT_DIR" "$PT_DIR/rootfs" "$PT_GUEST" \
        patharg 2>/dev/null)
    check_contains "no host path reaches the trace under a rootfs" \
        "openat path /cng-probe-path" "$out"

    # --no-ptrace refuses instead of emulating, and says so the way the kernel
    # does when it refuses: EPERM, which every tracer reports rather than
    # misinterpreting.
    out=$(run_t 60 --no-ptrace -R / "$PT_GUEST" basic 2>&1)
    check_contains "--no-ptrace refuses the guest tracer" "bad first stop" "$out"
fi

rm -rf "$PT_DIR"
