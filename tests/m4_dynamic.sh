# M4 dynamic-loader tests (sourced by tests/run.sh). Needs an AArch64 ELF
# interpreter on this host; skips cleanly if there is none.
#
# On an AArch64 host the interpreter is simply on the system paths, and with the
# rootfs at "/" the loader resolves it directly. On a cross host it lives under
# the toolchain sysroot instead, so chroot-ng is pointed at it with -L and ld.so
# with LD_LIBRARY_PATH (M5 is what redirects ld.so's opens into a real guest
# rootfs through the SIGSYS translator).
echo "== M4: ul_exec loader (dynamic) =="

GDIR=build/tests
mkdir -p "$GDIR"

if [ "$CNG_NATIVE" = 1 ]; then
    M4_SYSROOT=${CNG_SYSROOT-}
else
    M4_SYSROOT=${CNG_SYSROOT-/usr/aarch64-linux-gnu}
fi
M4_LDSO=
for c in "$M4_SYSROOT/lib/ld-linux-aarch64.so.1" \
    "$M4_SYSROOT/lib/ld-musl-aarch64.so.1" \
    "$M4_SYSROOT/lib64/ld-linux-aarch64.so.1" \
    "$M4_SYSROOT/system/bin/linker64"; do
    if [ -e "$c" ]; then M4_LDSO=$c; break; fi
done

if [ -z "$GUESTCC" ]; then
    skip "dynamic tests: no AArch64 guest toolchain"
elif [ -z "$M4_LDSO" ]; then
    skip "dynamic tests: no AArch64 ELF interpreter under '${M4_SYSROOT:-/}'"
elif ! $GUESTCC -O2 -o "$GDIR/hello_dyn" tests/guests/hello.c \
    2>"$GUEST_CC_LOG"; then
    fail=$((fail + 1)); printf '  FAIL could not build dynamic guest\n'
    sed 's/^/    /' "$GUEST_CC_LOG"
else
    if elf_has_interp "$GDIR/hello_dyn"; then
        pass=$((pass + 1)); printf '  ok   guest is dynamically linked\n'
    else
        fail=$((fail + 1)); printf '  FAIL guest not dynamic\n'
    fi
    # Both go in with -E: ld.so reads LD_LIBRARY_PATH from the environment on the
    # stack the loader built, and that environment is not inherited from the host
    # (M17-16) — so the host's copy of either variable would never arrive.
    if [ -n "$M4_SYSROOT" ]; then
        out=$(run -L "$M4_SYSROOT" -E CNG_TEST=dyn \
            -E LD_LIBRARY_PATH="$M4_SYSROOT/lib" \
            / "$GDIR/hello_dyn" XX YY 2>&1); rc=$?
    else
        out=$(run -E CNG_TEST=dyn / "$GDIR/hello_dyn" XX YY 2>&1); rc=$?
    fi
    check "dynamic exit code (42)" 42 $rc
    check_contains "ld.so bootstrapped main (argc)" "guest: argc=3" "$out"
    check_contains "dynamic argv forwarded" "guest: argv1=XX" "$out"
    check_contains "dynamic env forwarded" "guest: CNG_TEST=dyn" "$out"
fi
