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
# The set has to hold a realistic list. initgroups(3) against a directory
# service hands over more than a handful, and a ceiling it trips is an EINVAL
# that takes `su` and `login` with it; 64 was low enough to be reachable.
check_contains "a 200-group list round-trips through the credential set" \
    "groups set=0 got=200 same=1 over=-22" "$out"
check_contains "capget reports full set under fake-root" "cap_eff=ffffffff" "$out"
# The header version is negotiated. An unknown one gets the kernel's own written
# back and fails — except for the data-less probe that IS the negotiation — and
# a v1 header buys one data block, never the two a v2/v3 caller sized for.
check_contains "capget negotiates the capability header version" \
    "cap_ver probe=0 got=20080522 bad=-22 v1=0 v1_spill=0" "$out"
# (uid_t)-1 is INVALID_UID to setuid/setgid, refused with EINVAL before any
# privilege question, and a setgroups list carrying it is EINVAL with the set
# untouched. The "leave unchanged" -1 belongs to setre*id/setres*id and to
# setfsuid, which must still take it. The blind install left 4294967295 as
# every id of the process.
check_contains "setuid/setgid/setgroups refuse the invalid id, the keep forms take it" \
    "invalid_id setuid=-22 setgid=-22 setgroups=-22 ngroups=0 keep=0/0/0 uid=0 gid=0 -> OK" \
    "$out"
check_contains "privilege drop is real and irreversible" \
    "setuid_drop rc=0 uid=1000 regain=-1" "$out"
check_contains "setuid-root shows setuid exec as root:root" \
    "suid_stat st_uid=0 st_gid=0" "$out"
check_contains "setuid-on-exec elevates euid/egid to 0 (ruid kept)" \
    "suid_exec ruid=1000 euid=0 egid=0" "$out"
check_contains "su can then become root" "su_to_root rc=0 uid=0" "$out"
# ...and an exec resets the saved set-user-ID to the effective one, which is
# what makes a privilege drop permanent. An elevated program that drops only its
# EFFECTIVE id keeps suid at 0 and can come back (the "before" half asserts the
# setup is real); once it execs anything, set-id bit or not, the kernel clears
# that and the regain must fail. It did not, so a dropped root survived every
# exec in the chain and any later program could take it back.
check_contains "exec clears the saved set-user-ID, so a drop is final" \
    "exec_clears_saved before=0 after=-1 -> OK" "$out"
check_contains "implied identity defaults to real invoking id (not root)" \
    "implied_id uid=4321 gid=8765" "$out"
check_contains "explicit -u overrides the implied default" \
    "explicit_id uid=1000 gid=1000" "$out"

rm -rf "$ROOT"

# An id spec out of range must be refused, not wrapped. Accumulated into an
# `unsigned`, "4294967296" is 0 — and 0 is root, so a spec that should have been
# an error instead selected the fake identity with the most authority there is
# and turned on every DAC check the emulation fakes for root. All three spellings
# reach the same parser, and two of them ignored its verdict entirely.
for _spec in "-u 4294967296" "-u4294967296" "--fake-id=4294967296" \
    "-u 1000:99999999999"; do
    # shellcheck disable=SC2086  # _spec is a deliberately split arg list
    out=$(run $_spec / /bin/true 2>&1)
    check_contains "an out-of-range id spec ($_spec) is refused" \
        "expected UID or UID:GID" "$out"
done
# ...and the largest one that does fit still works.
out=$(run -t faketest -u 4294967295 2>&1 || true)
check_absent "a uid at the top of the range is not refused" \
    "expected UID or UID:GID" "$out"

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
# The records the kernel writes for the links are the symlinks' own — DT_LNK,
# the link's inode — where stat() of the same name answers the backing file's.
# Busybox stats every entry, so M10's shell differential never saw it; GNU ls
# -F / find -type f / ls -i read the record and did.
check_contains "l2s links list as the regular file stat() reports" \
    "l2s-dirent: rc=0 dl1_reg_ino=1 dl2_reg_ino=1 sym_lnk=1 -> OK" "$out"
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
# ...and every other call that declines to follow the final component lands on
# the backing file too: O_PATH|O_NOFOLLOW (an fd whose fstat is the regular
# file), name_to_handle_at (the group's handle, not the link's), the l-xattr
# calls (set through one name, read through another), an IN_DONT_FOLLOW watch
# (fires for a change through another name), fchmodat2(AT_SYMLINK_NOFOLLOW),
# and openat2's O_NOFOLLOW and RESOLVE_NO_SYMLINKS. Each used to operate on the
# emulation's own symlink. Fields the host cannot issue (openat2 under qemu-user,
# fchmodat2 on a kernel before 6.6) read -1 and are not failures; the rest must be 1.
check_contains "l2s no-follow calls all land on the backing file" \
    "l2s-nofollow-rest: opath_reg=1 handle=1 xattr=1 watch=1" "$out"
check_absent "...and none of them failed" "-> FAIL (-1 = not issuable here)" "$out"
check_contains "l2s legacy per-dir format fully interoperates" \
    "l2s-old: reg=1 same=1 bump3=1 xdir4=1 back2=1 einval=1 -> OK" "$out"
check_contains "l2s unusable store falls back to the per-dir scheme" \
    "l2s-storefail: rc=0 reg=1 sameino=1 beside=1 -> OK" "$out"
check_contains "dirfd args tolerate dirty upper halves (glibc w-registers)" \
    "l2s-dirtyfd: rc=0 nlink2=1 -> OK" "$out"
# A link is the emulation's by its target, and the target is text: one naming
# a data-shaped file outside the view is an ordinary symlink (it used to steer
# lstat, utimensat, an O_NOFOLLOW open and unlink onto that host file), the
# guest may not write such a target at all, and a descriptor on a file outside
# the view is linked by copying through it, never by moving the file.
check_contains "l2s link targets outside the view are not the emulation's" \
    "l2s-spoof: lnk=1 follow=1 kept=1 guard=1 fdcopy=1 -> OK" "$out"
check_contains "l2s links of a copied rootfs heal onto the copy's own store" \
    "l2s-copied: own=1 reclaimed=1 orig_kept=1 -> OK" "$out"
check_contains "l2s groups linked before a narrowing chroot stay recognized" \
    "l2s-home: reg=1 decref=1 -> OK" "$out"
# Where the host permits hardlinks, a link of the emulation's own file used to
# be the host's: of the symlink by name (a name the count never had, whose
# group's last counted unlink deleted the data under it), of the backing file
# followed or by descriptor. It joins the group now.
check_contains "l2s links of the emulation's own file join the group" \
    "l2s-hostlink: joined=1 kept=1 -> OK" "$out"
# A group's count is its one marker as the emulation spells it. Stray names of
# the same grammar — the inode plus 2^64, which the parse wrapped back onto the
# inode, an unpadded count, a leading-zero inode — were taken for it whenever
# listed first, and were all there was once the real marker was gone.
check_contains "l2s reads a group's count from its own marker only" \
    "l2s-marker: two=1 lost=1 three=1 gone=1 strays=1 -> OK" "$out"
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

# --- SO_PEERCRED under the fake identity --------------------------------------
# The kernel names the peer by the real invoking ids; the emulation remaps the
# pair to the fake identity so a daemon comparing them with its own getuid()
# finds them equal. The answer is delivered out of a buffer of the monitor's —
# it used to be corrected in the guest's own buffer a syscall after the kernel
# filled it, which left the real uid readable there for the interval and took
# whatever a racing thread had put there as the thing to remap — with
# sock_getsockopt's own length rules applied to it: cut to the struct and
# reported cut, that many bytes for a short one, nothing for zero, EINVAL for
# a negative.
PCD=$(mktemp -d)
if ! guest_xlate_ready "SO_PEERCRED legs"; then
    :
elif guest_cc_report "$PCD/peercred" tests/guests/peercred.c; then
    mkdir -p "$PCD/rootfs/bin"; cp "$PCD/peercred" "$PCD/rootfs/bin/"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run_t 60 -R $GUEST_BINDS -u 0:0 "$PCD/rootfs" /bin/peercred 2>/dev/null)
    check_contains "a peer's ids are remapped to the fake identity" \
        "len=12 -> got=12 pid_ok=1 uid=0 gid=0 self=0:0" "$out"
    check_contains "...a long length is cut to the struct and reported cut" \
        "len=64 -> got=12 pid_ok=1 uid=0 gid=0 self=0:0" "$out"
    check_contains "...a short one gets that many bytes" \
        "len=8 -> got=8 pid_ok=1 uid=0 self=0:0" "$out"
    check_contains "...zero gets nothing" "len=0 -> got=0 pid_ok=-1 self=0:0" "$out"
    check_contains "...and a negative one is the kernel's EINVAL" \
        "len=-1 -> errno=22" "$out"
    # Without a fake identity nothing is trapped and the real ids come back.
    out=$(run_t 60 -R $GUEST_BINDS "$PCD/rootfs" /bin/peercred 2>/dev/null)
    check_contains "without a fake identity the real pair is reported" \
        "len=12 -> got=12 pid_ok=1 uid=$(id -u) gid=$(id -g) self=$(id -u):$(id -g)" \
        "$out"
fi
rm -rf "$PCD"

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

    # The same links named against an open /proc/self fd, which is how GNU
    # coreutils resolves every entry of `ls -l /proc/self/`. The magic-link
    # fixups were reached only for an absolute name or AT_FDCWD, so this
    # spelling went to the kernel: "exe" came back as the monitor's own binary
    # and "cwd" as the rootfs's location on the device.
    check_contains "a dirfd-relative /proc/self/exe reads as the guest path" \
        "at_exe=/bin/exeprobe" "$out"
    check_contains "...and cwd likewise, leaking no host path" "at_cwd=/" "$out"
    check_absent "no rootfs host path reaches the guest through readlinkat" \
        "$EXD" "$out"

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

# --- process-wide emulated state read while another thread changes it -------
# The kernel replaces a task's cwd, root and credentials as one object, so a
# concurrent reader sees the old or the new. The emulation kept each as a struct
# edited in place: a getcwd racing a chdir copied out half of one directory name
# and half of another (measured: "/b" for a cwd that was "/a" or "/bbb...b"),
# and a getgroups racing a setgroups read the new count with the old list. Each
# is now published whole (path.c, cred.c), and the guest counts every answer
# that was neither the old state nor the new: 15-25 torn cwds and ~3200 torn
# group lists per run before, none after.
VRD=$(mktemp -d)
if ! guest_xlate_ready "view-race legs"; then
    :
elif guest_cc "$VRD/viewrace" tests/guests/viewrace.c -pthread; then
    mkdir -p "$VRD/root/bin"; cp "$VRD/viewrace" "$VRD/root/bin/viewrace"
    out=$(run_t 120 -R "$VRD/root" /bin/viewrace cwd 2>/dev/null)
    check_contains "a getcwd racing a chdir sees one directory or the other" \
        "viewrace cwd: writer=ok torn=0" "$out"
    # Every setter is a glibc setxid broadcast, a signal to the sibling and a
    # handshake with it: a minute on an emulated AArch64 machine.
    out=$(run_t 300 -R -u "$VRD/root" /bin/viewrace groups 2>/dev/null)
    check_contains "a getgroups racing a setgroups sees one list or the other" \
        "viewrace groups: writer=ok torn=0" "$out"
else
    skip "view-race legs: could not build tests/guests/viewrace.c with -pthread"
fi
rm -rf "$VRD"

# --- host data passing through a guest buffer ---------------------------------
# Three answers the monitor rewrites after the kernel has produced them: an fd
# link's target (a host path), a /proc listing (the host's pids) and a peer's
# credentials (the real uid). Each used to be produced by the kernel straight
# into the guest's buffer and corrected there a syscall later, so for that
# interval the host's answer sat in the guest's memory — readable by any other
# thread of it, and rewritable into what the correction then worked from. Each
# is produced into a buffer of the monitor's now and the guest's is written
# once, with the guest's answer. The guest runs the call on one thread and
# scans the buffer on another for what must never be there; before, it found
# it hundreds of thousands of times a run.
LKD=$(mktemp -d)
if ! guest_xlate_ready "buffer-leak legs"; then
    :
elif guest_cc "$LKD/leakrace" tests/guests/leakrace.c -pthread; then
    mkdir -p "$LKD/root/bin" "$LKD/root/d"; cp "$LKD/leakrace" "$LKD/root/bin/"
    echo hi > "$LKD/root/d/f"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    lkrun() { run_t 120 -R $GUEST_BINDS "$@"; }
    # The needle is the temp directory's own name: part of every host path
    # under the rootfs, and no guest path.
    out=$(lkrun "$LKD/root" /bin/leakrace readlink /d/f "$(basename "$LKD")" \
        2>/dev/null)
    check_contains "an fd link's host target never enters the guest's buffer" \
        "leakrace readlink: iters=" "$out"
    check_contains "...not once" " leaks=0" "$out"
    out=$(lkrun "$LKD/root" /bin/leakrace dents 2>/dev/null)
    check_contains "a hidden pid never enters the guest's listing buffer" \
        "leakrace dents: iters=" "$out"
    check_contains "...not once" " leaks=0" "$out"
    out=$(lkrun -u 0:0 "$LKD/root" /bin/leakrace peercred "$(id -u)" 2>/dev/null)
    check_contains "a peer's real uid never enters the guest's ucred" \
        "leakrace peercred: iters=" "$out"
    check_contains "...not once" " leaks=0" "$out"
else
    skip "buffer-leak legs: could not build tests/guests/leakrace.c with -pthread"
fi
rm -rf "$LKD"
