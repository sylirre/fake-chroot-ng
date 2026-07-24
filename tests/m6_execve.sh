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
