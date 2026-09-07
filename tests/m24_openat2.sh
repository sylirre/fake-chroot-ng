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
mkdir -p "$O2R/w/sub" "$O2R/b"
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
# RESOLVE_BENEATH / RESOLVE_IN_ROOT. The kernel applies these exactly, so the
# call goes over untranslated wherever the guest's namespace has nothing to add
# under the dirfd — and where it does, the kernel would resolve in the HOST's
# view of that subtree, which is a different tree: a bind is not there, and
# neither are the /proc and /dev zones. Those are walked here instead, with the
# scope applied by the walk and then stripped from the re-issue, exactly as the
# other resolve bits already are. The differential below covers the pass-through
# route (its dirfd has no overlay under it); this covers the walked one.
check_contains "a scoped lookup crosses a bind, which the kernel's own cannot see" \
    "o2test scope bind in-root=1 beneath=1 unscoped=1 -> OK" "$out"
check_contains "BENEATH refuses what leaves the scope, IN_ROOT re-roots and clamps it" \
    "o2test scope escape beneath-abs=-18 beneath-dotdot=-18 beneath-inside=1 in-root-abs=1 in-root-dotdot=1 -> OK" \
    "$out"
check_contains "an absolute symlink target is judged the same way" \
    "o2test scope abslink beneath=-18 in-root=1 unscoped=1 -> OK" "$out"
# nd_jump_link(): "Not currently safe for scoped-lookups" — every magic link is
# EXDEV under either scope, where the NO_*LINKS bits give ELOOP. The directory
# the fd links live in is not one of them and opens normally (both measured).
check_contains "a magic link is EXDEV under a scope, and the fd directory is not one" \
    "o2test scope magic beneath=-18 in-root=-18 fd-dir=0 unscoped=0 -> OK" "$out"
# ...and the route itself: walked only where the guest's namespace has something
# to add under the dirfd. A dirfd on the bind's own mount point already is the
# bind, so it is handed to the kernel like any other unremarkable directory.
check_contains "the walk is taken for a scope with an overlay under it, and only then" \
    "o2test scope route root=1 plain=1 at-bind=1 -> OK" "$out"
# ...and the whole of it through the dispatcher: a scoped name that lands on a
# file chroot-ng synthesizes. No kernel can answer that — passed through, the
# guest would have got the HOST's /proc/mounts — so the guest's own mount table
# coming back is the walked route's answer and nothing else's. Where the number
# cannot be issued at all the walk never runs and ENOSYS is the whole answer:
# a pre-5.6 kernel and qemu-user have no openat2, and Android's ambient filter
# refuses the one its kernel has, which dispatch emulates the same way.
case "$out" in
*"o2test scope synth enosys"*)
    skip "scoped openat2 end to end: openat2 cannot be issued here (pre-5.6 kernel, qemu-user, or refused by the ambient filter)"
    ;;
*)
    check_contains "a scoped openat2 reaches the synthesized /proc" \
        "o2test scope synth table -> OK" "$out"
    ;;
esac
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
