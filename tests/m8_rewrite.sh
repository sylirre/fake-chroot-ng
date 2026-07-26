# M8 svc-rewriting tests (sourced by tests/run.sh). Rewriting needs no kernel
# support, so it is exercised on every host — which on a cross host is also the
# only end-to-end proof of path translation with a real glibc guest, the seccomp
# tier being inert under qemu-user.
echo "== M8: svc rewriting =="

run -t rwtest >/dev/null 2>&1
check "trampoline preserves regs + correct syscall" 0 $?
check_contains "rewrote the svc site" "rewrote 1 site" "$(run -t rwtest 2>&1)"

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

# execve from a rewritten svc site must be emulated in-process (translated,
# monitor kept), not re-issued raw — raw would exec the untranslated guest path
# on the host and fail with ENOENT.
if [ "$GUESTLD" = "-static" ]; then
    # With a plain -static toolchain both programs are ET_EXEC at the same fixed
    # 0x400000, and the emulated execve MAP_FIXED-maps the new image there before
    # it has copied the caller's argv strings — which are .rodata in the OLD
    # image. The exec'd program then comes up with garbage argv. That is the M3
    # fixed-vaddr collision (docs/STATUS.md), not something this leg is about, so
    # it only runs with a relocatable guest.
    skip "execve-via-rewrite leg: two ET_EXEC guests would collide at 0x400000"
elif guest_xlate_ready "execve-via-rewrite leg" &&
    guest_cc_report "$ROOT/bin/hello" tests/guests/hello.c &&
    guest_cc_report "$ROOT/bin/execer" tests/guests/execer.c; then
    out=$(m8run -R "$ROOT" /bin/execer 2>/dev/null); rc=$?
    check "execve via rewrite exits through exec'd guest" 42 $rc
    check_contains "exec'd program got its argv" "argv1=from-execer" "$out"
fi

rm -rf "$ROOT"
