# M23: mmap(PROT_EXEC) of a file the host refuses (sourced by tests/run.sh).
#
# chroot-ng's loader defeats a noexec mount by reading a guest image with pread
# and mapping it anonymously — but a dynamic guest's libraries are mapped by the
# guest's OWN ld.so, which asks for PROT_EXEC straight from the file. On a true
# MNT_NOEXEC mount the kernel refuses that and every dynamically linked guest
# dies in its interpreter. The dispatcher answers the refusal with the same
# anonymous copy the loader would have made, and rewrites the library's `svc`
# sites on the way (execmap.c) — which is also the only route by which -R ever
# reaches a library's code.
#
# No host here has a true noexec mount to offer, so the path is forced with
# CNG_MMAP_FORCE_ANON=1: take the anonymous route without asking the kernel
# first. Same testing convention as CNG_SHM_FORCE_FILE / CNG_PROCREG_NONE.
echo "== M23: mmap(PROT_EXEC) served from anonymous memory =="

# The filter half: mmap must trap for exactly this shape of request and for
# nothing else, or every anonymous allocation a guest makes pays for a handler.
out=$(run -t bpftest 2>&1)
check_contains "an executable file mapping traps" \
    "bpftest mmap exec file mapping traps: TRAP -> OK" "$out"
check_contains "...and so does the MAP_FIXED form a linker uses" \
    "bpftest mmap exec fixed file mapping traps: TRAP -> OK" "$out"
check_contains "an anonymous executable mapping runs native" \
    "bpftest mmap anonymous exec runs native: ALLOW -> OK" "$out"
check_contains "an ordinary RW allocation runs native" \
    "bpftest mmap an anonymous RW allocation runs native: ALLOW -> OK" "$out"

# What lies past the end of the file. A file mapping longer than its file
# answers a fault on any page wholly past EOF with SIGBUS, and a truncated
# object dies there; the anonymous copy pread what the file had and left the
# rest zero, so the same object ran on -- into pages of `udf #0` for code, and
# into zeroes with no word said for data. The tail is put back under the file
# now (a mapping without PROT_EXEC is one no mount refuses), and the self-test
# is a differential against the kernel's own mapping of the same file, page by
# page, from a child that touches each.
out=$(run -t execmaptest 2>&1); rc=$?
check "execmaptest exit 0" 0 $rc
check_contains "a page wholly past EOF faults as the kernel's would" \
    "execmap page2-past-eof: ours=107 kernel=107 -> OK" "$out"
check_contains "...and so does a mapping that begins past EOF" \
    "execmap whole-mapping-past-eof: ours=107 kernel=107 -> OK" "$out"
check_contains "the partial last page still reads as zeroes, as the kernel's does" \
    "execmap page1-zeroes: ours=2 kernel=2 -> OK" "$out"
check_contains "and the kernel's answer really is SIGBUS, not two mappings that both died" \
    "execmap kernel past-eof is SIGBUS: 1 -> OK" "$out"

XMR=$(mktemp -d)
mkdir -p "$XMR/bin" "$XMR/etc"
printf 'GREETING-VIA-EXECMAP' > "$XMR/etc/greeting"
cng_dyn_binds

# A DYNAMIC guest, deliberately: the harness's own link mode is static-PIE on
# most hosts, and a static guest never maps a library at all.
if [ -z "$GUESTCC" ]; then
    skip "execmap legs: no AArch64 guest toolchain"
elif ! $GUESTCC -O2 -o "$XMR/bin/readfile" tests/guests/readfile.c \
    2>"$GUEST_CC_LOG"; then
    fail=$((fail + 1)); printf '  FAIL could not build a dynamic guest\n'
    sed 's/^/    /' "$GUEST_CC_LOG"
elif ! elf_has_interp "$XMR/bin/readfile"; then
    skip "execmap legs: this toolchain links even -O2 guests statically"
else
    # shellcheck disable=SC2086  # both are deliberately split arg lists
    xmrun() { run $GUEST_DYN_L $GUEST_DYN_BINDS "$@"; }

    out=$(CNG_MMAP_FORCE_ANON=1 xmrun -R "$XMR" /bin/readfile 2>/dev/null); rc=$?
    check "a dynamic guest starts with every library mapped from a copy" 0 $rc
    # The guest's open() is libc's, in a library chroot-ng never loaded itself.
    # Reaching the rootfs means the copy carried the code AND that its svc sites
    # were rewritten — the coverage -R had no way to get before.
    check_contains "...and its libc openat is translated into the rootfs" \
        "GREETING-VIA-EXECMAP" "$out"

    # The control. Without the knob the mapping is granted by the kernel and
    # stays file-backed, so nothing rewrites libc: on a seccomp-inert host the
    # guest's open reaches the untranslated host path and fails, while on a real
    # kernel the SIGSYS tier translates it as it always did. Either way this
    # proves the leg above was not passing for some unrelated reason.
    if [ "$CNG_SECCOMP_LIVE" = 1 ]; then
        out=$(xmrun -R "$XMR" /bin/readfile 2>/dev/null); rc=$?
        check "unforced, the seccomp tier translates the same open" 0 $rc
        check_contains "seccomp-translated openat reached the rootfs" \
            "GREETING-VIA-EXECMAP" "$out"
    else
        xmrun -R "$XMR" /bin/readfile >/dev/null 2>&1
        check "unforced and with the filter inert: not translated (rc 3)" 3 $?
    fi

    # The conversion is a copy of a MAP_PRIVATE file mapping, so a second run of
    # the same guest must be indistinguishable from the first — nothing about it
    # is stateful, and a leaked trampoline pool or a half-protected page would
    # show up as a difference here.
    a=$(CNG_MMAP_FORCE_ANON=1 xmrun -R "$XMR" /bin/readfile 2>/dev/null)
    b=$(CNG_MMAP_FORCE_ANON=1 xmrun -R "$XMR" /bin/readfile 2>/dev/null)
    check "the same guest run twice answers the same" "$a" "$b"

    # The other tier: with no -R the hook is reached through the filter instead,
    # which is the arrangement a device actually runs. It needs a live filter to
    # mean anything — with none, nothing intercepts mmap (or ld.so's opens), so
    # there is no leg here to run rather than one that fails.
    if [ "$CNG_SECCOMP_LIVE" = 1 ]; then
        CNG_MMAP_FORCE_ANON=1 xmrun "$XMR" /bin/readfile >/dev/null 2>&1
        check "the copy is served on the seccomp tier, with no -R at all" 0 $?
    else
        skip "execmap without -R: nothing intercepts mmap here (filter inert)"
    fi
fi
rm -rf "$XMR"
