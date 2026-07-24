# M6 execve-emulation tests (sourced by tests/run.sh). The seccomp trap of
# execve is inert under qemu, but the two halves of the emulation are covered:
# loading+stack-building is the same code M3/M4 validate, and the ucontext
# redirect that resumes into the new program is validated here.
echo "== M6: execve emulation (ucontext redirect) =="

run _jmptest >/dev/null 2>&1
check "ucontext redirect resumes at new pc (exit 7)" 7 $?
check_contains "landed in redirected context" \
    "landed in redirected context" \
    "$(run _jmptest 2>&1)"

# shebang script exec: #!interp [arg] -> [interp, arg, script, orig-args...]
GCC="${GUESTCC:-aarch64-linux-gnu-gcc-13}"
ER=$(mktemp -d)
if $GCC -static-pie -O2 -o "$ER/hello" tests/guests/hello.c 2>/dev/null; then
    printf '#!/hello sheb\n' > "$ER/script"
    out=$(run _exectest -r "$ER" /script AA 2>&1); rc=$?
    check "shebang exec exit 42" 42 $rc
    check_contains "shebang interp is argv0"  "argv0=/hello" "$out"
    check_contains "shebang arg passed"       "argv1=sheb"   "$out"
    check_contains "script path passed"       "argv2=/script" "$out"
    check_contains "original arg passed"      "argv3=AA"     "$out"
    out=$(run _exectest -r "$ER" /hello X 2>&1)
    check_contains "plain ELF exec via emulate_execve" "argv0=/hello" "$out"
    # /proc/self/exe fixup updates to the exec'd program (needed for e.g. Go's
    # GOROOT derivation), with symlinks resolved to match the kernel.
    check_contains "exec updates /proc/self/exe target" "exe=/hello" "$out"
    ln -s /hello "$ER/go"
    out=$(run _exectest -r "$ER" /go X 2>&1)
    check_contains "exec resolves symlink for /proc/self/exe" "exe=/hello" "$out"
fi
rm -rf "$ER"

# emulated execve must close FD_CLOEXEC fds like a real execve, or fork/exec
# launchers (git run-command, posix_spawn) block on their O_CLOEXEC notify pipe.
out=$(run _cloexectest 2>&1); rc=$?
check "cloexectest exit 0" 0 "$rc"
check_contains "emulated execve closes FD_CLOEXEC fds" \
    "cloexec: cloexec_closed=1 plain_open=1 -> OK" "$out"
