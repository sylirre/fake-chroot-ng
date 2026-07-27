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
    # A script whose interpreter is itself a script is followed up to four
    # times, as fs/exec.c bounds it; the fifth is ELOOP. Each level prepends its
    # own interpreter and pushes the previous one down, so the whole chain shows
    # up in the final argv — which is the only way to see that the levels ran in
    # order rather than being collapsed.
    printf '#!/hello\n'  >"$ER/s4"
    printf '#!/s4\n'     >"$ER/s3"
    printf '#!/s3\n'     >"$ER/s2"
    printf '#!/s2\n'     >"$ER/s1"
    printf '#!/s1\n'     >"$ER/s0"
    out=$(exectest /s1 AA 2>&1); rc=$?
    check "a four-deep shebang chain runs" 42 $rc
    check_contains "the innermost interpreter is argv0" "argv0=/hello" "$out"
    check_contains "each level pushed its script down (1)" "argv1=/s4" "$out"
    check_contains "each level pushed its script down (2)" "argv2=/s3" "$out"
    check_contains "each level pushed its script down (3)" "argv3=/s2" "$out"
    check_contains "the original script is last" "argv4=/s1" "$out"
    check_contains "the guest's own argument survives all of it" "argv5=AA" \
        "$out"
    check_contains "a fifth level is ELOOP" "emulate_execve failed x0=-40" \
        "$(exectest /s0 AA 2>&1)"

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

# emulated execve must close FD_CLOEXEC fds like a real execve, or fork/exec
# launchers (git run-command, posix_spawn) block on their O_CLOEXEC notify pipe.
out=$(run -t cloexectest 2>&1); rc=$?
check "cloexectest exit 0" 0 "$rc"
check_contains "emulated execve closes FD_CLOEXEC fds" \
    "cloexec: cloexec_closed=1 plain_open=1 -> OK" "$out"
