# M8 svc-rewriting tests (sourced by tests/run.sh). Rewriting needs no kernel
# support, so it is exercised on every host — which on a cross host is also the
# only end-to-end proof of path translation with a real glibc guest, the seccomp
# tier being inert under qemu-user.
echo "== M8: svc rewriting =="

rwout=$(run -t rwtest 2>&1); rwrc=$?
check "trampoline preserves regs + correct syscall" 0 "$rwrc"
check_contains "rewrote the svc sites" "rewrote 2 site" "$rwout"
# "Preserves regs" means the whole register file, not the arguments. A syscall
# leaves everything but x0 alone — the kernel saves the integer registers into
# pt_regs and never touches the FP ones — and the C dispatcher a rewritten site
# branches into is under no such discipline. Two ways it took what it did not own,
# both measured: gcc spends d0/d1/d16 on an openat of a synthesized /proc/stat
# (`cnt v0.8b` for the CPU popcount, `fmov d1, x0` as a cheap spill slot), and the
# trampoline kept x16/x17 as scratch, on the reasoning that a veneer may — but a
# veneer stands at a *call*, and gcc -O2 does hold live values in IP0/IP1 across
# an `svc`. This line prints only when every sentinel came back.
check_contains "nothing behind a rewritten syscall is spent from the guest's own" \
    "openat=ok -> OK" "$rwout"
# The other exit: when a tracer moves pc or sp at a syscall stop there is nowhere
# to keep them but x16/x17, so that arm still spends the pair — and it has to get
# everything else right, including entering the pc it was handed.
check_contains "the exit for a tracer-moved pc enters it, with the rest restored" \
    "marker=9a9a x12=c0c -> OK" "$rwout"

# The other half of M8: which words may be rewritten at all. A scan matching a
# bare 0xD4000001 cannot tell an instruction from a data word that equals one,
# and a PF_X PT_LOAD is not a code segment — on a musl link it is the whole
# read-only image, and even -z separate-code leaves the unwind tables in it.
# Ten such data words sit in stock Alpine/Debian aarch64 rootfs images, every
# one in .gcc_except_table; the site the probe below uses is verbatim from
# Debian trixie's libstdc++. So the object's section headers say where its code
# is, and the "unmapped" leg is the control that says the word really is taken
# when nothing rules it out.
case "$rwout" in
*"rwtest codemap: unavailable"*)
    skip "code map from section headers: no memfd to build a synthetic object"
    ;;
*)
    check_contains "the code map is the section headers, contiguous ones merged" \
        "rwtest codemap: ranges=2 [1000,1180) [3000,3040) headerless=0 -> OK" \
        "$rwout"
    ;;
esac
# mapped=1: with a code map, only the instruction is taken. unmapped=2: with a
# map that covers the data too, the LSDA word is taken — the corruption this
# guards against, reproduced. filtered=1 / dataonly=0: with no headers to trust,
# the syscall-context filter keeps the site and rejects the data word.
check_contains "a data word equal to svc #0 is left alone, the real site taken" \
    "rwtest scan: mapped=1 unmapped=2 filtered=1 dataonly=0 -> OK" "$rwout"

# The lazy tier. A SIGSYS trap knows something no scan of the bytes can: the CPU
# fetched that word and executed it as `svc #0`. So the sites the AoT pass could
# not reach — a library the kernel mapped natively, a JIT's output, an object
# whose headers named no code — are patched on their first trap instead. No
# filter fires on a cross host, so the driver calls the patcher with the address
# a SIGSYS would have handed it; what that leaves untested is three lines in the
# handler, and the device covers those.
case "$rwout" in
*"rwtest lazy: no executable memory"*)
    skip "lazy svc patching: no anonymous executable memory on this host"
    ;;
*)
    check_contains "a site is patched in read-only text and runs from there" \
        "rwtest lazy: sites=2 patched=2 repeat=0 nonsvc=0 pid=ok openat=ok -> OK" \
        "$rwout"
    ;;
esac

ROOT=$(mktemp -d)
mkdir -p "$ROOT/bin" "$ROOT/etc"
printf 'GREETING-VIA-REWRITE' > "$ROOT/etc/greeting"
# shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
m8run() { run $GUEST_BINDS "$@"; }

if ! guest_xlate_ready "rewrite-translated guest legs"; then
    :
elif guest_cc_report "$ROOT/bin/readfile" tests/guests/readfile.c; then
    out=$(m8run -R "$ROOT" /bin/readfile 2>/dev/null); rc=$?
    check "rewrite-translated glibc guest exits 0" 0 $rc
    check_contains "guest openat translated into rootfs via rewrite" \
        "GREETING-VIA-REWRITE" "$out"

    # The same guest with no -R. Which answer is correct depends on the host: on a
    # real AArch64 kernel the seccomp monitor installs and translates it anyway
    # (the tier that matters on a device, and the only place it can be observed);
    # under qemu-user nothing traps, so the guest's open reaches the untranslated
    # host path and fails. Either way this is the control that proves the rewrite
    # leg above was not passing for some unrelated reason.
    if [ "$CNG_SECCOMP_LIVE" = 1 ]; then
        out=$(m8run "$ROOT" /bin/readfile 2>/dev/null); rc=$?
        check "without -R the seccomp tier translates instead" 0 $rc
        check_contains "seccomp-translated openat reached the rootfs" \
            "GREETING-VIA-REWRITE" "$out"
    else
        m8run "$ROOT" /bin/readfile >/dev/null 2>&1
        check "without -R and with the filter inert: not translated (rc 3)" 3 $?
    fi
fi

# A thread's clone is a rewritten site like any other, and it is the one site
# whose child cannot come back through the trampoline: it returns from the
# dispatcher with SP pointing at the stack the guest just allocated for it,
# where none of those frames exist. The seccomp tier never meets this, because
# the filter tests CLONE_VM/CLONE_VFORK and lets a thread run untrapped; -R
# rewrites everything it can reach, so the dispatcher took the call and stripped
# CLONE_VM — which with CLONE_THREAD is what the kernel answers EINVAL to.
# pthread_create did not work under -R at all. Differential against the same
# program run straight under the kernel, which is what "threads work" means.
if guest_xlate_ready "threads-under-rewrite leg" &&
    guest_cc_report "$ROOT/bin/threads" tests/guests/threads.c -lpthread; then
    printf 'THREADS-OK\n' > "$ROOT/etc/threads-marker"
    want=$(emu "$ROOT/bin/threads" "$ROOT/etc/threads-marker" 2>/dev/null)
    out=$(m8run -R "$ROOT" /bin/threads /etc/threads-marker 2>/dev/null); rc=$?
    check "a threaded guest runs under -R" 0 $rc
    check_contains "every thread started, opened a guest path and kept its FP" \
        "threads: started=8 reads=8 tids=8 fp=8" "$out"
    if [ -n "$want" ]; then
        check "and matches the same program under the kernel" "$want" "$out"
    else
        skip "threads kernel differential: the reference run produced nothing"
    fi
fi

# execve from a rewritten svc site must be emulated in-process (translated,
# monitor kept), not re-issued raw — raw would exec the untranslated guest path
# on the host and fail with ENOENT.
if guest_xlate_ready "execve-via-rewrite leg" &&
    guest_cc_report "$ROOT/bin/hello" tests/guests/hello.c &&
    guest_cc_report "$ROOT/bin/execer" tests/guests/execer.c; then
    out=$(m8run -R "$ROOT" /bin/execer 2>/dev/null); rc=$?
    check "execve via rewrite exits through exec'd guest" 42 $rc
    check_contains "exec'd program got its argv" "argv1=from-execer" "$out"
fi

rm -rf "$ROOT"

# ...and the same chain with BOTH programs non-PIE, which the emulation used to
# corrupt. Two ET_EXEC images share the link-time vaddr 0x400000, so the
# MAP_FIXED load of the new one lands on the .rodata/heap holding the very argv
# strings the caller passed — and those reach the new stack only after the load.
# The exec'd program still ran and still exited 42, so nothing but an argv
# assertion catches it. Built here with an explicit -static -no-pie rather than
# whatever link mode the harness picked, since the collision needs the fixed
# vaddr: on the usual static-PIE guest each image gets its own base and the bug
# is invisible.
XR=$(mktemp -d); mkdir -p "$XR/bin"
if [ -n "$GUESTCC" ] &&
    $GUESTCC -static -no-pie -O2 -o "$XR/bin/hello" tests/guests/hello.c \
        2>"$GUEST_CC_LOG" &&
    $GUESTCC -static -no-pie -O2 -o "$XR/bin/execer" tests/guests/execer.c \
        2>>"$GUEST_CC_LOG"; then
    check "exec chain: both programs are fixed-address ET_EXEC" EXEC \
        "$(elf_type "$XR/bin/execer")"
    out=$(run -R "$XR" /bin/execer 2>/dev/null); rc=$?
    check "ET_EXEC execs ET_EXEC at the same vaddr: exit code" 42 $rc
    check_contains "argv0 survives the colliding load" "argv0=/bin/hello" "$out"
    check_contains "argv1 survives the colliding load" "argv1=from-execer" "$out"
    # envp goes through the same snapshot, so guard it too — though not against
    # this bug: execer passes the environ it inherited (the environment chroot-ng
    # built from -E), which lives on the original stack and no image load
    # touches. This one is a check on the copy itself.
    out=$(run -R -E CNG_TEST=collide "$XR" /bin/execer 2>/dev/null)
    check_contains "the environment still reaches the exec'd program" \
        "CNG_TEST=collide" "$out"
else
    skip "fixed-vaddr exec-collision leg: no -static -no-pie AArch64 toolchain"
fi
rm -rf "$XR"

# A translated syscall must stay inside the stack the guest was running on.
# The dispatcher is deep — ~24 KiB for cng_dispatch's frame alone, ~66 KiB for
# a whole openat translation — which is why the SIGSYS tier switches to a
# dedicated scratch stack before entering it. The trampoline tier calls the very
# same code from an ordinary context and did not, so a guest that runs syscalls
# on a small stack (musl's 128 KiB threads, Go's ~8 KiB goroutines, any
# sigaltstack) had the monitor write off the end of it. Not a crash, either: the
# frame is bigger than a guard page, so it stepped over the guard into ordinary
# guest memory. The guest sets SP into a small region itself and counts how many
# bytes of a canary below it moved.
SSR=$(mktemp -d)
mkdir -p "$SSR/etc"
printf 'guest\n' > "$SSR/etc/hostname"
if guest_xlate_ready "small-stack syscall leg" &&
    guest_cc_report "$SSR/smallstack" tests/guests/smallstack.c; then
    for _k in 8 16 64; do
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        out=$(run_t 60 -R $GUEST_BINDS "$SSR" /smallstack $_k 2>/dev/null)
        check "a syscall on a ${_k} KiB guest stack writes nothing below it" \
            "clobbered=0" "$out"
    done
    # ...and again with no slot in the scratch table to be had: 256 live threads
    # already holding one, an mmap the host refused, or an outer dispatch on this
    # thread that is on the slot already (a nested trap, which a guest with its
    # own sigaltstack reaches from inside its own signal handler). All three used
    # to fall back to the interrupted stack, which is not a fallback but the very
    # failure the legs above measure. CNG_SCRATCH_NONE forces the case, since a
    # working host does not reach it on its own: before the fix this clobbers
    # 1970 bytes at 8 KiB, 220 at 64 KiB, and dies outright at 16.
    for _k in 8 16 64; do
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        out=$(CNG_SCRATCH_NONE=1 run_t 60 -R $GUEST_BINDS "$SSR" /smallstack $_k \
            2>/dev/null)
        check "...and still nothing with no scratch slot to be had (${_k} KiB)" \
            "clobbered=0" "$out"
    done
fi
rm -rf "$SSR"
