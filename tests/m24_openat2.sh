# M24: openat2(2)'s open_how.resolve (sourced by tests/run.sh).
#
# openat2 was translated like openat and re-issued with the guest's own
# open_how — which carries `resolve`, a description of the resolution WE are the
# one performing. Every bit of it was then judged against the wrong namespace:
# RESOLVE_BENEATH saw the absolute host path translation had just produced and
# answered EXDEV for every relative name a guest could pass; RESOLVE_IN_ROOT
# re-rooted that host path at the dirfd and named a file nobody asked for; and
# RESOLVE_NO_SYMLINKS was simply violated, since the resolver had already
# followed the links the guest asked it not to.
#
# Two layers. The self-test drives the parts decided before the re-issue, so it
# runs on every host — which matters, because no qemu-user build implements
# openat2 and a cross host cannot reach the syscall at all. The differential
# runs the same guest program twice, once with no emulation, and demands the
# kernel's own answers byte for byte; it skips where openat2 is unavailable.
echo "== M24: openat2 resolve semantics =="

O2R=$(mktemp -d)
mkdir -p "$O2R/w" "$O2R/b"
out=$(run -t o2test "$O2R" 2>&1); rc=$?
check "o2test overall" 0 "$rc"
check_contains "RESOLVE_NO_SYMLINKS refuses a link, and only a link" \
    "o2test nosym link=-40 plain=0 unconstrained=0 -> OK" "$out"
check_contains "a magic link is a link: NO_MAGICLINKS, and NO_SYMLINKS implies it" \
    "o2test nomagic magic=-40 via-nosym=-40 ordinary=0 unconstrained=0 -> OK" \
    "$out"
# A bind is the only mount crossing a guest can see — it is what the guest's own
# /proc/self/mounts shows it — so it is what NO_XDEV has to be judged against,
# rather than the host's real mount list, where the rootfs prefix is a crossing
# the guest never asked about.
check_contains "RESOLVE_NO_XDEV is judged against the guest's mount table" \
    "o2test noxdev into-bind=-18 same-mount=0 out-of-bind=-18 unconstrained=0 -> OK" \
    "$out"
check_contains "the open_how size rules are the kernel's (EINVAL/E2BIG/EFAULT)" \
    "o2test abi small=-22 tail=-7 null=-14 over=-7" "$out"
rm -rf "$O2R"

# --- differential: the same program, once with no emulation at all -----------
O2D=$(mktemp -d)
mkdir -p "$O2D/d"
O2N=$(mktemp -d)
if ! guest_xlate_ready "openat2 differential"; then
    :
elif ! guest_cc_report "$O2D/openat2" tests/guests/openat2.c; then
    :
else
    want=$(emu "$O2D/openat2" "$O2N" 2>/dev/null)
    case "$want" in
    *openat2=unsupported*)
        skip "openat2 differential: no openat2 here (pre-5.6 kernel, or qemu-user)"
        ;;
    "")
        skip "openat2 differential: the reference run produced nothing"
        ;;
    *)
        # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split list
        got=$(run -R $GUEST_BINDS "$O2D" /openat2 /d 2>/dev/null)
        check "every openat2 resolve case matches the host kernel" "$want" "$got"
        # Named individually as well, so a failure says which rule broke rather
        # than printing two blocks of text.
        for _c in nosym_link nosym_plain nosym_magic nomagic_magic \
            nomagic_link beneath_abs beneath_dotdot beneath_abslink \
            beneath_ok inroot_abs inroot_abslink inroot_dotdot badbit \
            size_small size_big_tail; do
            _w=$(printf '%s\n' "$want" | grep "^$_c=")
            check_contains "$_c" "$_w" "$got"
        done
        ;;
    esac
fi
rm -rf "$O2D" "$O2N"
