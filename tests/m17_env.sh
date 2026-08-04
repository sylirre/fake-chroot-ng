# M17-16 guest-environment tests (sourced by tests/run.sh).
#
# The guest does not inherit chroot-ng's environment: a host variable describes
# the host and not the rootfs, so only TERM/COLORTERM cross over (they describe
# the terminal both sides share) and everything else is spelled out with
# -E/--env. Every leg pins TERM, COLORTERM and a few canary host variables, so
# what the invoking terminal happens to export cannot change the entry count
# that the scrubbing assertion rests on.
echo "== M17-16: guest environment =="

GDIR=build/tests
mkdir -p "$GDIR"

# --- option parsing (no guest binary needed) --------------------------------
run -E FOO / /no-such-program >/dev/null 2>&1
check "an --env spec without '=' is refused" 2 $?
out=$(run -E FOO / /no-such-program 2>&1)
check_contains "the bad --env spec is diagnosed" \
    "chroot-ng: --env 'FOO': expected VAR=VAL" "$out"
run -E =VAL / /no-such-program >/dev/null 2>&1
check "an --env spec with an empty name is refused" 2 $?
run --env >/dev/null 2>&1
check "--env with no argument is refused" 2 $?
out=$(run --env 2>&1)
check_contains "the missing --env argument is diagnosed" \
    "option '--env' requires an argument" "$out"

# The cap: CNG_MAX_ENV entries, then a refusal rather than a silent truncation.
# In a subshell, so setting the positional parameters cannot disturb the
# harness — and cleared first, so the harness's own arguments cannot disturb
# this: `$@` here is whatever run.sh was invoked with, and appending to it
# spliced that in front of the -E list as the rootfs.
out=$(
    set --
    i=0
    while [ "$i" -lt 200 ]; do
        set -- "$@" -E "V$i=1"
        i=$((i + 1))
    done
    run "$@" / /no-such-program 2>&1
    echo "rc=$?"
)
check_contains "over the --env cap is refused" "rc=2" "$out"
check_contains "the --env cap is diagnosed" "too many --env entries" "$out"

# --- what the guest actually receives --------------------------------------
# m17_env ARGS... — envdump under a fixed host environment. The canaries are the
# variables that would do the most damage if they crossed over: HOME and
# LD_LIBRARY_PATH point at host paths a guest has its own versions of.
m17_env() {
    TERM=cng-term COLORTERM=cng-color CNG_TEST=leak HOME=/host/home \
        LD_LIBRARY_PATH=/host/lib run "$@" / "$GDIR/envdump" 2>&1
}

if guest_cc_report "$GDIR/envdump" tests/guests/envdump.c; then
    out=$(m17_env)
    check_contains "TERM is inherited from the host" "env: TERM=cng-term" "$out"
    check_contains "COLORTERM is inherited from the host" \
        "env: COLORTERM=cng-color" "$out"
    check_contains "and nothing else is: the guest environment is those two" \
        "env count=2" "$out"
    check_absent "no host variable leaks (canary)" "CNG_TEST=leak" "$out"
    check_absent "no host HOME leaks" "HOME=/host/home" "$out"
    check_absent "no host LD_LIBRARY_PATH leaks" "LD_LIBRARY_PATH" "$out"

    out=$(m17_env -E FOO=bar --env=A=B=C -E "SPACED=a b")
    check_contains "-E sets a guest variable" "env: FOO=bar" "$out"
    check_contains "--env=VAR=VAL: the name ends at the FIRST '='" \
        "env: A=B=C" "$out"
    check_contains "an -E value may contain spaces" "env: SPACED=a b" "$out"
    check_contains "-E entries plus the inherited pair, nothing more" \
        "env count=5" "$out"

    out=$(m17_env -E EMPTY=)
    check_contains "-E VAR= sets an empty value" "env: EMPTY=" "$out"
    check_contains "an empty value still counts as one entry" "env count=3" "$out"

    # -E wins over the inherited value, and replaces it rather than joining it:
    # a duplicate would leave getenv() (first match) and a shell re-exporting
    # envp (last match) disagreeing about which value won.
    out=$(m17_env -E TERM=override)
    check_contains "-E overrides an inherited TERM" "env: TERM=override" "$out"
    check_absent "the inherited TERM is gone, not shadowed" "TERM=cng-term" "$out"
    check_contains "the override did not add an entry" "env count=2" "$out"

    out=$(m17_env -E FOO=first -E FOO=second)
    check_contains "a repeated -E name keeps the last value" \
        "env: FOO=second" "$out"
    check_absent "the earlier -E value is gone, not shadowed" "FOO=first" "$out"
    check_contains "a repeated -E name is one entry" "env count=3" "$out"
else
    skip "guest-environment legs: no AArch64 guest toolchain"
fi

# --- a real rootfs: the guest's own tools agree ----------------------------
# Two views of the same environment have to match: what busybox `env` prints
# (the stack the loader built) and /proc/self/environ (the guest identity the
# registry publishes — the kernel's own copy would describe the chroot-ng
# invocation, i.e. the host environment this test says must not be visible).
M17_ALPINE="${M17_ALPINE:-$CNG_ALPINE}"

if [ -z "$M17_ALPINE" ] || [ ! -x "$M17_ALPINE/bin/busybox" ]; then
    skip "guest-environment rootfs scenarios: no alpine rootfs"
else
    m17_want="FOO=bar
TERM=cng-term
COLORTERM=cng-color"

    # m17_alpine ARGS... — a guest program under the same fixed host environment.
    m17_alpine() {
        TERM=cng-term COLORTERM=cng-color CNG_TEST=leak HOME=/host/home \
            run -R -E FOO=bar "$M17_ALPINE" "$@" 2>/dev/null
    }

    # m17_exact <desc> <got> — the environment must be m17_want and nothing else.
    m17_exact() {
        if [ "$2" = "$m17_want" ]; then
            pass=$((pass + 1)); printf '  ok   %s\n' "$1"
        else
            fail=$((fail + 1)); printf '  FAIL %s\n' "$1"
            printf '    want: %s\n' "$(echo "$m17_want" | tr '\n' ' ')"
            printf '    got:  %s\n' "$(echo "$2" | tr '\n' ' ')"
        fi
    }

    # env(1) directly, with no shell in between: a shell exports PWD and SHLVL of
    # its own, which would make this an assertion about busybox instead.
    m17_exact "the guest's own env(1) sees exactly -E plus the terminal pair" \
        "$(m17_alpine /bin/busybox env)"
    # /proc/self/environ is a snapshot of what the process started with — a
    # shell's own additions do not appear in it — so this one may use a shell.
    m17_exact "/proc/self/environ is the guest environment, not chroot-ng's" \
        "$(m17_alpine /bin/busybox sh -c 'tr "\0" "\n" < /proc/self/environ')"

    # An emulated execve carries the environment on, as a real one would: the
    # exec'd program inherits the caller's, which is the built guest environment
    # (plus whatever the intervening shell exported — hence a containment check).
    got=$(m17_alpine /bin/busybox sh -c 'exec env')
    check_contains "an exec'd program inherits the guest environment" \
        "FOO=bar" "$got"
    check_absent "and the exec derives nothing fresh from the host" \
        "CNG_TEST=leak" "$got"

    # No PATH is set, and nothing needs one: a shell supplies its own default,
    # which is why chroot-ng synthesizes nothing here.
    got=$(run -R "$M17_ALPINE" /bin/busybox sh -c 'head -1 /etc/os-release' \
        2>/dev/null)
    check_contains "a guest shell still works with no PATH in its environment" \
        "Alpine Linux" "$got"
fi
