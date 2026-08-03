# M3 loader tests (sourced by tests/run.sh). Builds a guest with whatever AArch64
# toolchain this host has (tests/lib.sh picked it, and the link mode it proved
# works: static-PIE where possible, plain static, else dynamic on bionic) and
# runs it through `chroot-ng`. The rootfs is "/" throughout, so a dynamically
# linked guest still finds its interpreter at a real host path.
echo "== M3: ul_exec loader ($GUEST_LD_DESC guest) =="

GDIR=build/tests
mkdir -p "$GDIR"

if guest_cc_report "$GDIR/hello" tests/guests/hello.c; then
    # The link mode fixes the ELF type: -static-pie and a dynamic link give
    # ET_DYN (loaded at a base we choose), plain -static gives ET_EXEC at a fixed
    # vaddr. Both paths matter and the loader takes a different branch for each.
    case "$GUESTLD" in
    -static) m3_want=EXEC ;;
    *) m3_want=DYN ;;
    esac
    check "guest ELF type matches the link mode ($m3_want)" \
        "$m3_want" "$(elf_type "$GDIR/hello")"

    # CNG_TEST is set in BOTH environments and the guest must see the -E value:
    # the host environment is not inherited at all (M17-16 covers the scrubbing
    # itself; here it is the -E entry's trip through the stack builder).
    out=$(CNG_TEST=host run -E CNG_TEST=hello / "$GDIR/hello" AA BB 2>&1); rc=$?
    check "loader exit code propagates (42)" 42 $rc
    check_contains "guest ran (argc)" "guest: argc=3" "$out"
    check_contains "argv0 forwarded" "argv0=$GDIR/hello" "$out"
    check_contains "argv1 forwarded" "guest: argv1=AA" "$out"
    check_contains "argv2 forwarded" "guest: argv2=BB" "$out"
    check_contains "-E env forwarded, host value not" "guest: CNG_TEST=hello" "$out"
    check_contains "guest made a syscall (pid)" "guest: pid=" "$out"

    # file-backed mapping path (-F): the fallback used on Android when the
    # SELinux policy revokes anonymous executable memory. Must produce a working
    # guest. (It is the only tier available at all when execmem is denied, which
    # is why it is not gated on CNG_EXECMEM.)
    out=$(run -F / "$GDIR/hello" FB 2>&1); rc=$?
    check "file-backed (-F) exit code (42)" 42 $rc
    check_contains "file-backed guest ran" "guest: argc=2" "$out"
    check_contains "file-backed argv forwarded" "argv1=FB" "$out"
fi

# Fixed-address non-PIE guest (ET_EXEC @ 0x400000, e.g. gcc's cc1). chroot-ng is
# linked high (0x1000000000) precisely so MAP_FIXED-loading such a guest at
# 0x400000 doesn't overwrite our own monitor; verify it loads and runs (both the
# anon and file-backed paths, since the collision is in the fixed mapping).
if [ -n "$GUESTCC" ] &&
    $GUESTCC -static -no-pie -O2 -o "$GDIR/hello_exec" tests/guests/hello.c \
        2>"$GUEST_CC_LOG"; then
    check "guest is fixed-address ET_EXEC" EXEC "$(elf_type "$GDIR/hello_exec")"
    out=$(run / "$GDIR/hello_exec" NP 2>&1); rc=$?
    check "ET_EXEC@0x400000 guest exit (42) — no collision with monitor" 42 $rc
    check_contains "ET_EXEC guest ran" "guest: argc=2" "$out"
    out=$(run -F / "$GDIR/hello_exec" NPF 2>&1); rc=$?
    check "ET_EXEC@0x400000 file-backed exit (42)" 42 $rc
else
    skip "ET_EXEC leg: no -static -no-pie AArch64 toolchain"
fi

# The reserved span has to cover every byte the loader then writes into it.
# A PT_LOAD may name more file bytes than memory bytes; the kernel maps each
# segment separately so that costs it nothing, but here one reservation is sized
# from the segment list and everything is pread into it — sized from p_memsz
# alone, the file part ran off the end, into whatever the kernel had placed
# after. Answered by the loader directly (`-t elfspan` builds the object in a
# memfd), since no toolchain emits one and no rootfs need hold it.
run -t elfspan >/dev/null 2>&1
check "a PT_LOAD whose file part exceeds its memory part stays in its reserve" \
    0 $?
check_contains "...and every byte of it arrived" "rc=0 tail=1" \
    "$(run -t elfspan 2>&1)"
