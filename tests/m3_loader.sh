# M3 loader tests (sourced by tests/run.sh). Compiles a static-PIE guest with
# the cross toolchain and runs it through `chroot-ng` under qemu.
echo "== M3: ul_exec loader (static-PIE) =="

GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
GDIR=build/tests
mkdir -p "$GDIR"

if $GCC -static-pie -O2 -o "$GDIR/hello" tests/guests/hello.c 2>"$GDIR/hello.log"; then
    # Confirm it is ET_DYN (PIE) as the loader expects.
    if file "$GDIR/hello" | grep -q "pie executable"; then
        pass=$((pass + 1)); printf '  ok   guest is static-PIE (ET_DYN)\n'
    else
        fail=$((fail + 1)); printf '  FAIL guest not PIE: %s\n' "$(file "$GDIR/hello")"
    fi

    out=$(CNG_TEST=hello run / "$GDIR/hello" AA BB 2>&1); rc=$?
    check "loader exit code propagates (42)" 42 $rc
    check_contains "guest ran (argc)" "guest: argc=3" "$out"
    check_contains "argv0 forwarded" "argv0=$GDIR/hello" "$out"
    check_contains "argv1 forwarded" "guest: argv1=AA" "$out"
    check_contains "argv2 forwarded" "guest: argv2=BB" "$out"
    check_contains "env forwarded" "guest: CNG_TEST=hello" "$out"
    check_contains "guest made a syscall (pid)" "guest: pid=" "$out"
else
    fail=$((fail + 1))
    printf '  FAIL could not build static-PIE guest:\n'
    sed 's/^/    /' "$GDIR/hello.log"
fi

# file-backed mapping path (-F): the fallback used on Android when NO_NEW_PRIVS
# revokes anon executable memory. Must produce a working guest.
out=$(run -F / "$GDIR/hello" FB 2>&1); rc=$?
check "file-backed (-F) exit code (42)" 42 $rc
check_contains "file-backed guest ran" "guest: argc=2" "$out"
check_contains "file-backed argv forwarded" "argv1=FB" "$out"

# Fixed-address non-PIE guest (ET_EXEC @ 0x400000, e.g. gcc's cc1). chroot-ng is
# linked high (0x1000000000) precisely so MAP_FIXED-loading such a guest at
# 0x400000 doesn't overwrite our own monitor; verify it loads and runs (both the
# anon and file-backed paths, since the collision is in the fixed mapping).
if $GCC -static -no-pie -O2 -o "$GDIR/hello_exec" tests/guests/hello.c \
        2>"$GDIR/hello_exec.log"; then
    if file "$GDIR/hello_exec" | grep -qi 'ELF.*executable' &&
       ! file "$GDIR/hello_exec" | grep -qi 'pie'; then
        pass=$((pass + 1)); printf '  ok   guest is fixed-address ET_EXEC\n'
    else
        fail=$((fail + 1)); printf '  FAIL guest not ET_EXEC: %s\n' \
            "$(file "$GDIR/hello_exec")"
    fi
    out=$(run / "$GDIR/hello_exec" NP 2>&1); rc=$?
    check "ET_EXEC@0x400000 guest exit (42) — no collision with monitor" 42 $rc
    check_contains "ET_EXEC guest ran" "guest: argc=2" "$out"
    out=$(run -F / "$GDIR/hello_exec" NPF 2>&1); rc=$?
    check "ET_EXEC@0x400000 file-backed exit (42)" 42 $rc
else
    printf '  (skip ET_EXEC test: no -static -no-pie toolchain)\n'
fi
