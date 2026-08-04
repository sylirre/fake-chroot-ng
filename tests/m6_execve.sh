# M6 execve-emulation tests (sourced by tests/run.sh). The seccomp trap of
# execve is inert under qemu, but the two halves of the emulation are covered:
# loading+stack-building is the same code M3/M4 validate, and the ucontext
# redirect that resumes into the new program is validated here.
echo "== M6: execve emulation (ucontext redirect) =="

run -t jmptest >/dev/null 2>&1
check "ucontext redirect resumes at new pc (exit 7)" 7 $?
check_contains "landed in redirected context" \
    "landed in redirected context" \
    "$(run -t jmptest 2>&1)"

# shebang script exec: #!interp [arg] -> [interp, arg, script, orig-args...]
# $GUEST_BINDS is empty for a self-contained (static) guest; where the toolchain
# only links dynamically it exposes the ELF interpreter's own directories, which
# a rootfs holding nothing but the test binary cannot otherwise provide.
ER=$(mktemp -d)
if guest_cc_report "$ER/hello" tests/guests/hello.c; then
    printf '#!/hello sheb\n' > "$ER/script"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    exectest() { run -t exectest $GUEST_BINDS -r "$ER" "$@"; }
    out=$(exectest /script AA 2>&1); rc=$?
    check "shebang exec exit 42" 42 $rc
    check_contains "shebang interp is argv0"  "argv0=/hello" "$out"
    check_contains "shebang arg passed"       "argv1=sheb"   "$out"
    check_contains "script path passed"       "argv2=/script" "$out"
    check_contains "original arg passed"      "argv3=AA"     "$out"
    out=$(exectest /hello X 2>&1)
    check_contains "plain ELF exec via emulate_execve" "argv0=/hello" "$out"
    # /proc/self/exe fixup updates to the exec'd program (needed for e.g. Go's
    # GOROOT derivation), with symlinks resolved to match the kernel.
    check_contains "exec updates /proc/self/exe target" "exe=/hello" "$out"
    ln -s /hello "$ER/go"
    out=$(exectest /go X 2>&1)
    check_contains "exec resolves symlink for /proc/self/exe" "exe=/hello" "$out"

    # apk runs package scripts as execve("/proc/self/fd/N"). That magic link
    # names an open file of *this* process: its target is a host path (or no
    # path at all — memfd/O_TMPFILE/deleted), so it must not be re-rooted into
    # the rootfs the way a guest symlink target is.
    exec 9< "$ER/script"
    out=$(exectest /proc/self/fd/9 AA 2>&1); rc=$?
    check "shebang script exec'd via /proc/self/fd" 42 $rc
    check_contains "interp gets the fd path as the script" \
        "argv2=/proc/self/fd/9" "$out"
    exec 9<&-
    exec 9< "$ER/hello"
    out=$(exectest /proc/self/fd/9 X 2>&1); rc=$?
    check "plain ELF exec'd via /proc/self/fd" 42 $rc
    check_contains "exec via fd path names the real file for /proc/self/exe" \
        "exe=/hello" "$out"
    exec 9<&-

    # execve(2) checks *execute* permission; only a reopen needs read. apk's
    # package scripts are exec'd through an fd whose inode grants exactly that,
    # so the image has to come from the fd we already hold.
    if [ "$(id -u)" -ne 0 ]; then
        cp "$ER/hello" "$ER/xonly"
        exec 9< "$ER/xonly"
        chmod 111 "$ER/xonly"
        out=$(exectest /proc/self/fd/9 X 2>&1); rc=$?
        check "exec via fd of a file the guest may not read" 42 $rc
        check_contains "loaded from the fd, not a reopen" \
            "argv0=/proc/self/fd/9" "$out"
        exec 9<&-
    fi

    # a failed exec must report why, like the kernel does: an unreadable target
    # is EACCES, not a blanket ENOENT.
    if [ "$(id -u)" -ne 0 ]; then
        cp "$ER/hello" "$ER/noperm"; chmod 000 "$ER/noperm"
        check_contains "unreadable exec target reports EACCES" \
            "emulate_execve failed x0=-13" \
            "$(exectest /noperm 2>&1)"
    fi

    # --- M17-10: shebang nesting -------------------------------------------
    # A script whose interpreter is itself a script is followed a bounded number
    # of times (BINPRM_MAX_RECURSION) and then answered ELOOP. Each level
    # prepends its own interpreter and pushes the previous one down, so the whole
    # chain shows up in the final argv — which is the only way to see that the
    # levels ran in order rather than being collapsed.
    #
    # d1 is one script level, d2 two, and so on. The depth the kernel stops at is
    # measured rather than encoded: an identical chain is built on the host and
    # the deepest one that runs is the number the guest has to match. It did not
    # — the emulation stopped one level early and refused a chain the kernel
    # executes, which no amount of reading fs/exec.c had settled.
    _d=1
    printf '#!/hello\n' >"$ER/d1"
    while [ $_d -lt 8 ]; do
        printf '#!/d%d\n' $_d >"$ER/d$((_d + 1))"
        _d=$((_d + 1))
    done
    chmod 755 "$ER"/d? 2>/dev/null || :

    NREF=$(mktemp -d)
    printf '#!/bin/sh\nexit 0\n' >"$NREF/d1"
    _d=1
    while [ $_d -lt 8 ]; do
        printf '#!%s/d%d\n' "$NREF" $_d >"$NREF/d$((_d + 1))"
        _d=$((_d + 1))
    done
    chmod 755 "$NREF"/d?
    KDEPTH=0
    _d=1
    while [ $_d -le 8 ]; do
        "$NREF/d$_d" 2>/dev/null || break
        KDEPTH=$_d
        _d=$((_d + 1))
    done
    rm -rf "$NREF"
    check_contains "the host kernel bounds #! nesting somewhere sane" "$KDEPTH" \
        "$(echo 4 5 6)"

    GDEPTH=0
    _d=1
    while [ $_d -le 8 ]; do
        exectest "/d$_d" AA >/dev/null 2>&1
        [ $? = 42 ] || break   # 42 is what the exec'd guest exits with
        GDEPTH=$_d
        _d=$((_d + 1))
    done
    check "a #! chain nests exactly as deep as the kernel allows" "$KDEPTH" \
        "$GDEPTH"
    check_contains "one level past that is ELOOP" "emulate_execve failed x0=-40" \
        "$(exectest "/d$((KDEPTH + 1))" AA 2>&1)"

    # The whole chain, in order, in the final argv: four levels is enough to
    # show the pushing-down without depending on where the limit sits.
    out=$(exectest /d4 AA 2>&1); rc=$?
    check "a four-deep shebang chain runs" 42 $rc
    check_contains "the innermost interpreter is argv0" "argv0=/hello" "$out"
    check_contains "each level pushed its script down (1)" "argv1=/d1" "$out"
    check_contains "each level pushed its script down (2)" "argv2=/d2" "$out"
    check_contains "each level pushed its script down (3)" "argv3=/d3" "$out"
    check_contains "the original script is last" "argv4=/d4" "$out"
    check_contains "the guest's own argument survives all of it" "argv5=AA" \
        "$out"

    # --- M17-10: execveat's flags word -------------------------------------
    # It was never read: a real dirfd resolved against the cwd instead, and
    # AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW did nothing at all.
    mkdir -p "$ER/sub"
    cp "$ER/hello" "$ER/sub/hello"
    out=$(exectest -D /sub hello X 2>&1); rc=$?
    check "a relative execveat resolves against its dirfd" 42 $rc
    check_contains "and runs the program there" "argv0=hello" "$out"
    # ..-climbing out of a dirfd is clamped at the guest root, not followed onto
    # the host: /sub/../../hello is /hello inside the rootfs.
    check_contains "a dirfd-relative '..' is clamped at the guest root" \
        "exe=/hello" "$(exectest -D /sub ../../hello X 2>&1)"
    out=$(exectest -e /hello X 2>&1); rc=$?
    check "AT_EMPTY_PATH executes the fd itself" 42 $rc
    # ...and /proc/self/exe names the file, not the descriptor it came through.
    # Those fds are opened O_CLOEXEC (apk's package scripts, every memfd exec),
    # so the magic link has to be read before the commit point closes them; read
    # after, it answered ENOENT and the exe link came out as "/". `go` computes
    # GOROOT from this.
    check_contains "an fd-exec still reports the file as /proc/self/exe" \
        "exectest: exe=/hello" "$out"
    check_contains "AT_SYMLINK_NOFOLLOW refuses a symlinked target" \
        "emulate_execve failed x0=-40" "$(exectest -N /go X 2>&1)"
    out=$(exectest -N /hello X 2>&1); rc=$?
    check "AT_SYMLINK_NOFOLLOW on a real file still runs it" 42 $rc
    check_contains "an undefined execveat flag is EINVAL" \
        "emulate_execve failed x0=-22" "$(exectest -B /hello 2>&1)"

    # --- M17-10: state a real execve drops with the address space ------------
    # Ours keeps the address space, so the heap and any POSIX timer outlive the
    # program that owned them — a timer would go on firing into a program that
    # never armed it. -R arms both before the emulation and reports afterwards.
    out=$(exectest -R /hello 2>&1); rc=$?
    check "exec resets the state that would have died with the image" 0 $rc
    check_contains "the heap is wound back and the timer deleted" \
        "execreset: brk_back=1 timer_created=1 timer_gone=1 -> OK" "$out"
fi
rm -rf "$ER"

# --- M17-10: a failed exec must leave the calling program running -----------
# A binary whose PT_INTERP names a file that is not there is how an exec fails
# in a partially populated rootfs — a tree without the loader its binaries were
# linked against, a musl program under glibc — and the kernel's answer is ENOENT
# to a program that is still running: it opens and validates the ELF interpreter
# before it touches the old address space.
#
# Ours mapped the program first and looked for the interpreter afterwards. An
# ET_EXEC image goes down MAP_FIXED at its link-time vaddr — which for two
# binaries out of one toolchain is the caller's own text — so the errno came back
# to a program whose code had just been replaced. Measured: rc 139 and no output
# at all, against the kernel's exec=ENOENT / alive=1 / rc 44.
#
# Both halves of the pair have to be non-PIE for anything to be overwritten, and
# whether a toolchain links that way is not something to assume: the ELF shapes
# are checked, and a toolchain that cannot produce them skips rather than passing
# vacuously. qemu-user is no oracle for this one — it emulates execve by
# re-executing itself, so a missing interpreter is its own loader's complaint and
# not the kernel's errno — hence a host-native build for the reference side.
IFD=$(mktemp -d)
IF_NOINTERP=/cng-no-such-interp.so

# The oracle: on a host that runs AArch64 directly the guest pair is its own
# reference; otherwise the same two sources built host-native and linked alike.
if_oracle_build() {
    if [ -z "$QEMU" ]; then
        IF_ORACLE=$IFD/interpfail
        IF_TARGET=$IFD/badinterp
        return 0
    fi
    for _c in ${HOSTCC:-} cc gcc clang; do
        have "$_c" || continue
        "$_c" -O2 -no-pie -o "$IFD/if_host" tests/guests/interpfail.c \
            2>/dev/null || continue
        "$_c" -O2 -no-pie "-Wl,--dynamic-linker=$IF_NOINTERP" \
            -o "$IFD/bad_host" tests/guests/hello.c 2>/dev/null || continue
        IF_ORACLE=$IFD/if_host
        IF_TARGET=$IFD/bad_host
        return 0
    done
    return 1
}
if_host_run() { if [ -n "$TIMEOUT" ]; then "$TIMEOUT" 60 "$@"; else "$@"; fi; }

if [ -z "$GUESTCC" ]; then
    skip "failed-exec survival: no AArch64 guest toolchain"
elif [ "$CNG_SECCOMP_LIVE" != 1 ] && [ "$CNG_EXECMEM" != 1 ]; then
    skip "failed-exec survival: no filter is live and -R cannot rewrite without execmem"
elif ! guest_cc "$IFD/interpfail" tests/guests/interpfail.c -static -no-pie ||
    ! guest_cc "$IFD/badinterp" tests/guests/hello.c -no-pie \
        "-Wl,--dynamic-linker=$IF_NOINTERP"; then
    skip "failed-exec survival: no non-PIE pair builds here ($(head -1 "$GUEST_CC_LOG" 2>/dev/null))"
elif [ "$(elf_type "$IFD/interpfail")" != EXEC ] ||
    [ "$(elf_type "$IFD/badinterp")" != EXEC ] ||
    ! elf_has_interp "$IFD/badinterp"; then
    skip "failed-exec survival: this toolchain links no ET_EXEC pair carrying a PT_INTERP, so nothing would be overwritten"
elif ! if_oracle_build; then
    skip "failed-exec survival: no host compiler for the differential oracle"
else
    if_out_k=$(if_host_run "$IF_ORACLE" "$IF_TARGET" 2>/dev/null); if_rc_k=$?
    if_out_g=$(run_t 90 -R "$IFD" /interpfail /badinterp 2>/dev/null); if_rc_g=$?
    if [ "$if_out_k" = "$if_out_g" ] && [ "$if_rc_k" = "$if_rc_g" ]; then
        pass=$((pass + 1))
        printf '  ok   a missing ELF interpreter is an errno and a live caller, as the kernel has it\n'
    else
        fail=$((fail + 1))
        printf '  FAIL a missing ELF interpreter does not match the kernel\n'
        printf '       kernel: %s (rc %s)\n' "$(echo "$if_out_k" | tr '\n' '|')" \
            "$if_rc_k"
        printf '       cng   : %s (rc %s)\n' "$(echo "$if_out_g" | tr '\n' '|')" \
            "$if_rc_g"
    fi

    # The other shape of the same failure: an interpreter that is there but is
    # not a loadable ELF, which fails in the header pass rather than in the
    # resolver. The errno still diverges here — the kernel distinguishes (a
    # header too short to be one is EIO, measured) where we answer ENOENT for
    # every interpreter failure — so what is asserted is the part this is about:
    # the caller is alive to be told.
    printf 'not an ELF\n' >"$IFD$IF_NOINTERP"
    chmod 755 "$IFD$IF_NOINTERP"
    check_contains "an unloadable interpreter also leaves the caller running" \
        "alive=1" "$(run_t 90 -R "$IFD" /interpfail /badinterp 2>&1)"
fi
rm -rf "$IFD"

# emulated execve must close FD_CLOEXEC fds like a real execve, or fork/exec
# launchers (git run-command, posix_spawn) block on their O_CLOEXEC notify pipe.
out=$(run -t cloexectest 2>&1); rc=$?
check "cloexectest exit 0" 0 "$rc"
check_contains "emulated execve closes FD_CLOEXEC fds" \
    "cloexec: cloexec_closed=1 plain_open=1 -> OK" "$out"
