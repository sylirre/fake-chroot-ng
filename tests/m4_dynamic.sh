# M4 dynamic-loader tests (sourced by tests/run.sh). Requires an aarch64 sysroot
# for ld.so/libc; skips cleanly if absent. Uses LD_LIBRARY_PATH so ld.so finds
# libc at a real host path (M5 will instead redirect ld.so's opens into the
# guest rootfs via the SIGSYS translator).
echo "== M4: ul_exec loader (dynamic) =="

GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
GDIR=build/tests
mkdir -p "$GDIR"
SYSROOT="${CNG_SYSROOT:-/usr/aarch64-linux-gnu}"
LDSO="$SYSROOT/lib/ld-linux-aarch64.so.1"

if [ ! -e "$LDSO" ]; then
    printf '  skip dynamic tests (no aarch64 sysroot at %s)\n' "$SYSROOT"
elif ! $GCC -O2 -o "$GDIR/hello_dyn" tests/guests/hello.c 2>"$GDIR/hello_dyn.log"; then
    fail=$((fail + 1)); printf '  FAIL could not build dynamic guest\n'
    sed 's/^/    /' "$GDIR/hello_dyn.log"
else
    if file "$GDIR/hello_dyn" | grep -q "dynamically linked"; then
        pass=$((pass + 1)); printf '  ok   guest is dynamically linked\n'
    else
        fail=$((fail + 1)); printf '  FAIL guest not dynamic\n'
    fi
    out=$(CNG_TEST=dyn LD_LIBRARY_PATH="$SYSROOT/lib" \
          run run -L "$SYSROOT" -- "$GDIR/hello_dyn" XX YY 2>&1); rc=$?
    check "dynamic exit code (42)" 42 $rc
    check_contains "ld.so bootstrapped main (argc)" "guest: argc=3" "$out"
    check_contains "dynamic argv forwarded" "guest: argv1=XX" "$out"
    check_contains "dynamic env forwarded" "guest: CNG_TEST=dyn" "$out"
fi
