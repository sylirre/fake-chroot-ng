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
GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
ER=$(mktemp -d)
if $GCC -static-pie -O2 -o "$ER/hello" tests/guests/hello.c 2>/dev/null; then
    printf '#!/hello sheb\n' > "$ER/script"
    out=$(run -t exectest -r "$ER" /script AA 2>&1); rc=$?
    check "shebang exec exit 42" 42 $rc
    check_contains "shebang interp is argv0"  "argv0=/hello" "$out"
    check_contains "shebang arg passed"       "argv1=sheb"   "$out"
    check_contains "script path passed"       "argv2=/script" "$out"
    check_contains "original arg passed"      "argv3=AA"     "$out"
    out=$(run -t exectest -r "$ER" /hello X 2>&1)
    check_contains "plain ELF exec via emulate_execve" "argv0=/hello" "$out"
    # /proc/self/exe fixup updates to the exec'd program (needed for e.g. Go's
    # GOROOT derivation), with symlinks resolved to match the kernel.
    check_contains "exec updates /proc/self/exe target" "exe=/hello" "$out"
    ln -s /hello "$ER/go"
    out=$(run -t exectest -r "$ER" /go X 2>&1)
    check_contains "exec resolves symlink for /proc/self/exe" "exe=/hello" "$out"

    # apk runs package scripts as execve("/proc/self/fd/N"). That magic link
    # names an open file of *this* process: its target is a host path (or no
    # path at all — memfd/O_TMPFILE/deleted), so it must not be re-rooted into
    # the rootfs the way a guest symlink target is.
    exec 9< "$ER/script"
    out=$(run -t exectest -r "$ER" /proc/self/fd/9 AA 2>&1); rc=$?
    check "shebang script exec'd via /proc/self/fd" 42 $rc
    check_contains "interp gets the fd path as the script" \
        "argv2=/proc/self/fd/9" "$out"
    exec 9<&-
    exec 9< "$ER/hello"
    out=$(run -t exectest -r "$ER" /proc/self/fd/9 X 2>&1); rc=$?
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
        out=$(run -t exectest -r "$ER" /proc/self/fd/9 X 2>&1); rc=$?
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
            "$(run -t exectest -r "$ER" /noperm 2>&1)"
    fi
fi
rm -rf "$ER"

# emulated execve must close FD_CLOEXEC fds like a real execve, or fork/exec
# launchers (git run-command, posix_spawn) block on their O_CLOEXEC notify pipe.
out=$(run -t cloexectest 2>&1); rc=$?
check "cloexectest exit 0" 0 "$rc"
check_contains "emulated execve closes FD_CLOEXEC fds" \
    "cloexec: cloexec_closed=1 plain_open=1 -> OK" "$out"
