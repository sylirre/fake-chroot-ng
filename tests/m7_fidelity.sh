# M7 fidelity tests (sourced by tests/run.sh). Drives the dispatcher directly so
# the fixups are exercised under qemu (no seccomp needed).
echo "== M7: fidelity (uid/gid faking, /proc, link2symlink) =="

ROOT=$(mktemp -d)
printf hi > "$ROOT/f"
printf x > "$ROOT/suid"; chmod 6755 "$ROOT/suid"   # setuid+setgid executable
out=$(run -t faketest -r "$ROOT" /f 2>&1)

check_contains "getuid faked to 0"          "getuid=0"            "$out"
check_contains "geteuid faked to 0"         "geteuid=0"           "$out"
check_contains "stat ownership remapped to 0" "st_uid=0 st_gid=0" "$out"
check_contains "/proc/self/exe fixup"       "exe=/bin/sh"         "$out"
check_contains "fchown faked to success"    "fchown=0"            "$out"
check_contains "fchmod on a descriptor faked to success" "fchmod=0" "$out"
check_contains "stat and fstat agree about ownership under --fake-id" \
    "stat_vs_fstat stat=0:0 fstat=0:0 -> OK" "$out"
check_contains "fake-root reopens a file it may execute but not read" \
    "fakeroot_reopen: opened=1 mode_kept=1 -> OK" "$out"
check_contains "a refused reopen is served from the fd we hold, rewound" \
    "fd_reopen: dup=1 content=1 -> OK" "$out"
check_contains "supplementary groups empty" "ngroups=0"           "$out"
check_contains "capget reports full set under fake-root" "cap_eff=ffffffff" "$out"
# The header version is negotiated. An unknown one gets the kernel's own written
# back and fails — except for the data-less probe that IS the negotiation — and
# a v1 header buys one data block, never the two a v2/v3 caller sized for.
check_contains "capget negotiates the capability header version" \
    "cap_ver probe=0 got=20080522 bad=-22 v1=0 v1_spill=0" "$out"
check_contains "privilege drop is real and irreversible" \
    "setuid_drop rc=0 uid=1000 regain=-1" "$out"
check_contains "setuid-root shows setuid exec as root:root" \
    "suid_stat st_uid=0 st_gid=0" "$out"
check_contains "setuid-on-exec elevates euid/egid to 0 (ruid kept)" \
    "suid_exec ruid=1000 euid=0 egid=0" "$out"
check_contains "su can then become root" "su_to_root rc=0 uid=0" "$out"
check_contains "implied identity defaults to real invoking id (not root)" \
    "implied_id uid=4321 gid=8765" "$out"
check_contains "explicit -u overrides the implied default" \
    "explicit_id uid=1000 gid=1000" "$out"

rm -rf "$ROOT"

# link2symlink backing-file scheme (present emulated hardlinks as regular files
# with a shared inode + st_nlink) + fchdir cwd tracking. Force the l2s fallback
# via the block-list (tmpfs allows hardlinks); the test toggles the opt-in flag
# (-l/--link2symlink) itself, checking the off state first.
L2=$(mktemp -d); mkdir -p "$L2/w"
out=$(run -t l2stest "$L2" 2>&1); rc=$?
check "l2stest overall (l2s + fchdir)" 0 "$rc"
check_contains "l2s is off by default (link refusal passes through)" \
    "l2s-off: rc=-38 created=0 -> OK" "$out"
check_contains "l2s presents the group as regular files (nlink, inode, content)" \
    "l2s: rc=0 eexist=1 reg=1 nlink2=1 sameino=1 noleak=1 content=1 -> OK" "$out"
check_contains "l2s preserves mtime through the backing file" \
    "l2s-mtime: set=0 mtime=287454020 -> OK" "$out"
check_contains "l2s handles dirfd-relative links (apk's pattern)" \
    "l2s-dirfd: rc=0 reg2=1 -> OK" "$out"
check_contains "l2s decref reclaims the backing on last unlink" \
    "l2s-decref: nlink_after1=1 gone=1 -> OK" "$out"
check_contains "l2s backing pair lives in the central store, names stay clean" \
    "l2s-store: store=1 user_clean=1 -> OK" "$out"
check_contains "l2s fstat/AT_EMPTY_PATH/statx-mask report emulated nlink" \
    "l2s-fstat: fd=1 empty=1 emptyx=1 mask=1 -> OK" "$out"
check_contains "l2s readlink via dirfd refuses with EINVAL" \
    "l2s-dirfd-readlink: einval=1 -> OK" "$out"
check_contains "l2s cross-directory link shares inode/count via the store" \
    "l2s-xdir: rc=0 ino=1 nlink3=1 abs=1 rel=1 -> OK" "$out"
check_contains "l2s store dir hidden from root listing" \
    "l2s-hide: root_clean=1 have_w=1 -> OK" "$out"
check_contains "l2s fully-filtered getdents batch re-reads (no fake EOF)" \
    "l2s-hide-batch: clean=1 eof=1 -> OK" "$out"
check_contains "l2s machinery is unreachable by name (ENOENT)" \
    "l2s-deny: create=1 data=1 store=1 chdir=1 -> OK" "$out"
check_contains "l2s NOFOLLOW chown lands on the backing file" \
    "l2s-chown: suid_cleared=1 -> OK" "$out"
check_contains "l2s RENAME_NOREPLACE refuses without decref" \
    "l2s-noreplace: eexist=1 nlink=1 -> OK" "$out"
check_contains "l2s RENAME_EXCHANGE keeps both names and the count" \
    "l2s-exchange: rc=0 swapped=1 nlink3=1 -> OK" "$out"
check_contains "l2s legacy link mv'ed cross-dir is repointed" \
    "l2s-mvfix: reg=1 nlink2=1 content=1 -> OK" "$out"
check_contains "l2s O_TMPFILE publish via AT_EMPTY_PATH linkat" \
    "l2s-tmpfile: rc=0 reg=1 content=1 mode=1 -> OK" "$out"
check_contains "l2s linkat-by-fd bumps the group" \
    "l2s-fdlink: rc=0 nlink4=1 -> OK" "$out"
check_contains "l2s O_NOFOLLOW opens the link, still ELOOPs real symlinks" \
    "l2s-nofollow: open=1 content=1 sym_eloop=1 -> OK" "$out"
check_contains "l2s legacy per-dir format fully interoperates" \
    "l2s-old: reg=1 same=1 bump3=1 xdir4=1 back2=1 einval=1 -> OK" "$out"
check_contains "l2s unusable store falls back to the per-dir scheme" \
    "l2s-storefail: rc=0 reg=1 sameino=1 beside=1 -> OK" "$out"
check_contains "dirfd args tolerate dirty upper halves (glibc w-registers)" \
    "l2s-dirtyfd: rc=0 nlink2=1 -> OK" "$out"
check_contains "fchdir updates virtual cwd" "fchdir: cwd=/w -> OK" "$out"
check_contains "chdir through a symlink records the directory it landed in" \
    "chdir-symlink: rc=0 cwd=/w -> OK" "$out"
rm -rf "$L2"

# --- auxv fidelity ---------------------------------------------------------
# AT_UID/AT_EUID must agree with the credential syscalls (they used to carry
# chroot-ng's own host ids under --fake-id, so getauxval contradicted getuid);
# AT_SECURE must be computed from a real set-id transition rather than hardcoded
# 0, since it is what makes glibc/musl sanitize LD_PRELOAD; and AT_RANDOM must be
# fresh per exec, since the stack canary comes from it and a copy of our own gave
# every program in an exec chain the same one.
#
# The identity leg compares auxv against getuid()/geteuid() as the guest sees
# them, so it needs a tier that intercepts the guest's own credential syscalls —
# otherwise auxv reports the fake id and getuid the real one, and the leg fails
# for want of translation rather than because auxv is wrong.
AXD=$(mktemp -d)
if ! guest_xlate_ready "auxv fidelity legs"; then
    :
elif guest_cc_report "$AXD/auxprobe" tests/guests/auxprobe.c; then
    mkdir -p "$AXD/rootfs/bin"; cp "$AXD/auxprobe" "$AXD/rootfs/bin/"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    auxrun() { run -R $GUEST_BINDS "$@"; }
    out=$(auxrun -u 0:0 "$AXD/rootfs" /bin/auxprobe 2>/dev/null)
    check_contains "auxv identity agrees with the fake id" \
        "AT_UID=0 AT_EUID=0 getuid=0 geteuid=0" "$out"
    check_contains "AT_SECURE is 0 with no set-id transition" "AT_SECURE=0" "$out"
    r1=$(auxrun "$AXD/rootfs" /bin/auxprobe 2>/dev/null | grep AT_RANDOM)
    r2=$(auxrun "$AXD/rootfs" /bin/auxprobe 2>/dev/null | grep AT_RANDOM)
    if [ -n "$r1" ] && [ "$r1" != "$r2" ]; then
        pass=$((pass + 1)); echo "  ok   AT_RANDOM is fresh per exec"
    else
        fail=$((fail + 1)); echo "  FAIL AT_RANDOM is fresh per exec ($r1 vs $r2)"
    fi
fi
rm -rf "$AXD"

# --- the initial program's own /proc/self/exe ------------------------------
# Every program after the first gets its exe link from the emulated execve; the
# first one is the one nothing republishes, and it used to report <program>
# verbatim. Two things follow from that, and both are asserted here because the
# oracle answers the same in all four combinations (absolute/relative x
# file/symlink): the link must be absolute — glibc does not merely tolerate that
# but *asserts* the leading '/' inside _dl_get_origin, so a relative <program>
# aborted the guest before main, making the first leg an acceptance check rather
# than a string comparison — and it must name the file that was loaded rather than
# the symlink that named it, which is what comm is derived from as well.
EXG=build/tests
EXD=$(mktemp -d)
mkdir -p "$EXG"
if ! guest_xlate_ready "initial-program exe legs"; then
    :
elif guest_cc_report "$EXG/exeprobe" tests/guests/exeprobe.c; then
    mkdir -p "$EXD/rootfs/bin"
    cp "$EXG/exeprobe" "$EXD/rootfs/bin/"
    ln -s exeprobe "$EXD/rootfs/bin/exelink"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    exerun() { run -R $GUEST_BINDS "$@"; }

    out=$(exerun "$EXD/rootfs" /bin/exeprobe 2>/dev/null); rc=$?
    check "the initial program reports its own exe link" 0 $rc
    check_contains "an absolute <program> names itself" "exe=/bin/exeprobe" "$out"

    out=$(exerun "$EXD/rootfs" bin/exeprobe 2>/dev/null); rc=$?
    check "a relative <program> starts at all" 0 $rc
    check_contains "a relative <program> still reports an absolute exe" \
        "exe=/bin/exeprobe" "$out"

    out=$(exerun "$EXD/rootfs" /bin/exelink 2>/dev/null)
    check_contains "a symlinked <program> reports the file, not the link" \
        "exe=/bin/exeprobe" "$out"
    check_contains "comm follows the file the program resolved to" \
        "comm=exeprobe" "$out"

    # The identity rootfs takes its cwd from the host, so a relative <program>
    # there resolves against the launch directory rather than the guest root.
    out=$(run -R / "$EXG/exeprobe" 2>/dev/null)
    check_contains "identity rootfs: a relative <program> reports its host path" \
        "exe=$(pwd -P)/$EXG/exeprobe" "$out"
fi
rm -rf "$EXD"
