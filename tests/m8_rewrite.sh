# M8 svc-rewriting tests (sourced by tests/run.sh). Unlike the seccomp path,
# rewriting needs no kernel support, so it is fully exercised under qemu — which
# also gives the first end-to-end proof of path translation with a real glibc
# guest.
echo "== M8: svc rewriting =="

run -t rwtest >/dev/null 2>&1
check "trampoline preserves regs + correct syscall" 0 $?
check_contains "rewrote the svc site" "rewrote 1 site" "$(run -t rwtest 2>&1)"

GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
GDIR=build/tests
mkdir -p "$GDIR"
ROOT=$(mktemp -d)
mkdir -p "$ROOT/bin" "$ROOT/etc"
printf 'GREETING-VIA-REWRITE' > "$ROOT/etc/greeting"

if $GCC -static-pie -O2 -o "$ROOT/bin/readfile" tests/guests/readfile.c \
        2>"$GDIR/readfile.log"; then
    out=$(run -R "$ROOT" /bin/readfile 2>/dev/null); rc=$?
    check "rewrite-translated glibc guest exits 0" 0 $rc
    check_contains "guest openat translated into rootfs via rewrite" \
        "GREETING-VIA-REWRITE" "$out"
    # Negative control: no -R + seccomp inert under qemu => no translation.
    run "$ROOT" /bin/readfile >/dev/null 2>&1
    check "without -R under qemu: open not translated (rc 3)" 3 $?
else
    fail=$((fail + 1)); printf '  FAIL could not build readfile guest\n'
    sed 's/^/    /' "$GDIR/readfile.log"
fi

# execve from a rewritten svc site must be emulated in-process (translated,
# monitor kept), not re-issued raw — raw would exec the untranslated guest path
# on the host and fail with ENOENT.
if $GCC -static-pie -O2 -o "$ROOT/bin/hello" tests/guests/hello.c \
        2>"$GDIR/hello.log" &&
   $GCC -static-pie -O2 -o "$ROOT/bin/execer" tests/guests/execer.c \
        2>"$GDIR/execer.log"; then
    out=$(run -R "$ROOT" /bin/execer 2>/dev/null); rc=$?
    check "execve via rewrite exits through exec'd guest" 42 $rc
    check_contains "exec'd program got its argv" "argv1=from-execer" "$out"
else
    fail=$((fail + 1)); printf '  FAIL could not build execer guests\n'
    sed 's/^/    /' "$GDIR/hello.log" "$GDIR/execer.log" 2>/dev/null
fi

rm -rf "$ROOT"
