# M3 loader tests (sourced by tests/run.sh). Compiles a static-PIE guest with
# the cross toolchain and runs it through `chroot-ng run` under qemu.
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

    out=$(CNG_TEST=hello run run -- "$GDIR/hello" AA BB 2>&1); rc=$?
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
