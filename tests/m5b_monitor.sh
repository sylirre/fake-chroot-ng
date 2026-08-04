# M5b monitor tests (sourced by tests/run.sh). Exercises the dispatcher and the
# signal round-trip directly; the seccomp trap itself is inert under qemu-user
# and must be confirmed on a real AArch64 kernel.
echo "== M5b: syscall monitor (dispatch + signal) =="

ROOT=$(mktemp -d)
mkdir -p "$ROOT/etc"
printf 'HELLO-FROM-ROOTFS' > "$ROOT/etc/greeting"

check_contains "dispatch openat translated into rootfs" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /etc/greeting 2>&1)"

# --- the rootfs argument itself ---------------------------------------------
# It is a prefix, and every guest path is joined to it, so the two ways of
# getting one that is not what the user typed both end somewhere they did not
# ask for. An empty one is the identity — `chroot-ng "$ROOTFS" rm -rf /` with the
# variable unset ran against the host root, silently. And one that did not fit
# the 512-byte field was truncated, which lands mid-component: the guest was
# rooted at a shorter path, or at one that is not a directory at all. (The
# truncation also read one byte past the buffer while trimming trailing slashes,
# since cng_strlcpy reports the length of the source.)
run "" /bin/true >/dev/null 2>&1
check "an empty rootfs argument is refused" 2 $?
check_contains "the empty rootfs is diagnosed, with the deliberate spelling" \
    "chroot-ng: <rootfs> is empty (use '/' for the host root)" \
    "$(run "" /bin/true 2>&1)"
M5B_DEEP="$ROOT"
while [ ${#M5B_DEEP} -lt 512 ]; do M5B_DEEP="$M5B_DEEP/dddddddddddddddddddd"; done
mkdir -p "$M5B_DEEP"
run "$M5B_DEEP" /bin/true >/dev/null 2>&1
check "a rootfs path too long to hold is refused, not truncated" 2 $?
check_contains "the over-long rootfs is diagnosed with the limit" \
    "path too long (max 511)" "$(run "$M5B_DEEP" /bin/true 2>&1)"
check_contains "a bind destination too long to hold is refused too" \
    "--bind '$ROOT:/$(printf 'b%.0s' $(seq 1 300))': path too long" \
    "$(run -b "$ROOT:/$(printf 'b%.0s' $(seq 1 300))" "$ROOT" /bin/true 2>&1)"

# The runtime's own formatter, which everything here reports through and the
# SIGSYS handler runs with every signal but SIGSYS masked — so an out-of-bounds
# read in it is an unblockable kill, not a wrong string. A format ending in a
# bare '%' had one: stepping past the '%' is unconditional and the flag, width
# and length scans all stop at the terminator, so the conversion dispatch landed
# on '\0', emitted it, and let the loop walk off the end of the literal and keep
# formatting the bytes after it — consuming a va_arg for every '%' it found.
# Latent (every format in the tree is a literal, none ending in '%'), so the
# probe builds its formats at runtime and puts known bytes past the terminator:
# the walk shows as a reported length of 9 rather than 2.
check_contains "a format ending in a bare % stops at the terminator" \
    "fmt: bare=1,2 wide=1,2 normal=1,6 [x007%y]" \
    "$(run -t dtest fmt / 2>&1)"

run -t dtest -r "$ROOT" access /etc/greeting >/dev/null 2>&1
check "dispatch faccessat: present file" 0 $?
run -t dtest -r "$ROOT" access /etc/nope >/dev/null 2>&1
check "dispatch faccessat: missing file" 1 $?

# faccessat2's AT_SYMLINK_NOFOLLOW asks about the link itself, so a dangling one
# exists while following it does not. Resolving the final component during
# translation answered for the target and lost the distinction.
ln -s /nowhere "$ROOT/dangling"
# chroot(2) is privileged. Ungated, an unprivileged guest could move its own
# root where a real kernel refuses -- a check the guest's own code may rely on
# (a daemon that drops privileges and expects chroot to fail afterwards).
mkdir -p "$ROOT/sub"
check_contains "chroot needs CAP_SYS_CHROOT (fake-root), else EPERM" \
    "chroot: unpriv=-1 root=0 cwd=/" \
    "$(run -t dtest -r "$ROOT" chroot /sub 2>&1)"

check_contains "faccessat2 AT_SYMLINK_NOFOLLOW answers for the link itself" \
    "accessnf: nofollow=0 follow=-2" \
    "$(run -t dtest -r "$ROOT" accessnf /dangling 2>&1)"
check_contains "...and for an ordinary file both forms agree" \
    "accessnf: nofollow=0 follow=0" \
    "$(run -t dtest -r "$ROOT" accessnf /etc/greeting 2>&1)"

# faccessat(2) is a three-argument syscall -- dirfd, path, mode -- and has no
# flags word; only faccessat2 has one. Read as flags, a stray AT_SYMLINK_NOFOLLOW
# in the caller's x3 made fake-root's X_OK recovery stat the /proc fd link
# (mode 0700: executable whatever it points at) instead of the file behind it,
# so a non-executable file answered "yes" depending on register leftovers.
printf x > "$ROOT/etc/noexec"
chmod 0644 "$ROOT/etc/noexec"
exec 7< "$ROOT/etc/noexec"
check_contains "faccessat has no flags word, so x3 cannot change its answer" \
    "accessgb: clean=-13 dirty=-13" \
    "$(run -t dtest -r "$ROOT" accessgb /proc/self/fd/7 2>&1)"
exec 7<&-

# Root's DAC bypass covers a *permission* denial and nothing else. It used to
# fire on any negative answer at all and recover it from a stat, so two refusals
# the kernel gives root as readily as anyone else came back as "granted":
# EINVAL, for a mode word carrying bits outside R_OK|W_OK|X_OK, and EROFS, which
# sb_permission() raises for MAY_WRITE on a read-only superblock before it ever
# reaches the DAC check ("Nobody gets write access to a read-only fs" — no
# capability escape, so real root sees it too).
#
# The EROFS half is the failure ro_denied() exists to prevent, reached by a
# route it cannot see: it knows our own :ro binds, not a rootfs that is
# genuinely mounted read-only — on Android /system, /vendor and /apex all are.
# `test -w` answered yes and the write that followed got EROFS.
ARW=$(mktemp -d)
: >"$ARW/f"
chmod 0444 "$ARW/f"
a_out=$(run -t dtest -r "$ARW" accessfr /f 2>&1)
check_contains "fake-root still grants a write the file's own mode denies" \
    "w=0" "$a_out"
check_contains "...but an invalid access mode stays EINVAL" "badmode=-22" \
    "$a_out"
check_contains "...and a missing file stays ENOENT" "missing=-2" "$a_out"
rm -rf "$ARW"

# ...and the same question asked of a filesystem that really is mounted
# read-only. Field 4 of /proc/mounts is the option list; `test -w` on the result
# is the host kernel confirming the premise, since inode_permission() runs
# sb_permission() before the DAC check and so answers EROFS whatever the mode.
M5RO=$(awk '$4 ~ /(^|,)ro(,|$)/ { print $2; exit }' /proc/mounts 2>/dev/null)
if [ -z "$M5RO" ] || [ ! -r "$M5RO" ] || [ -w "$M5RO" ]; then
    skip "read-only-mount leg: no read-only mount on this host to check against"
else
    ro_out=$(run -t dtest -r "$M5RO" accessfr / 2>&1)
    check_contains "a genuinely read-only mount is EROFS to fake-root too" \
        "w=-30" "$ro_out"
    check_contains "...while a read of the same name still succeeds" "r=0" \
        "$ro_out"
fi

# Plant a file OUTSIDE the rootfs; guest /../ must not reach it.
printf SECRET > "$ROOT/../esc_$$"
check_contains "dispatch blocks .. escape" \
    "open: errno 2" \
    "$(run -t dtest -r "$ROOT" open "/../esc_$$" 2>&1)"
rm -f "$ROOT/../esc_$$"

# /proc magic links live in the host namespace: an fd link names this process's
# own open file whatever the rootfs is, and /proc/self/cwd is the *guest* cwd,
# not the host one. Re-rooting either readlink target lands on nothing.
exec 7< "$ROOT/etc/greeting"
check_contains "dispatch openat through /proc/self/fd" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /proc/self/fd/7 2>&1)"
exec 7<&-
check_contains "dispatch openat through /proc/self/cwd" \
    "read: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" open /proc/self/cwd/etc/greeting 2>&1)"

# CNG_DEBUG error logging must not read a scalar syscall arg as a path pointer:
# truncate's length is large enough to look like one, and dereferencing it is a
# wild read inside the handler (SIGSEGV masked there => the guest is killed).
out=$(run -t dtest -r "$ROOT" dbgpath /etc 2>&1); rc=$?
check "debug logging survives a scalar syscall arg" 0 "$rc"

check_contains "debug logging still reports the real error" \
    "dbgpath: survived rc=-21 -> OK" "$out"

# ...and an EMPTY CNG_DEBUG is off, as it is for every other CNG_* switch (the
# two beside it in the same loop, and cng_broker_env, all require a non-empty
# value). `CNG_DEBUG= chroot-ng ...` is how a shell clears a variable for one
# command; it used to turn verbose logging on instead, onto the guest's own
# stderr -- a stream package managers capture.
# The knob is read by cng_run, so a real (here: failing) guest launch is what
# drives it; the banner it stamps is the cheapest thing to look for.
check_contains "CNG_DEBUG=1 does log" "[cng] chroot-ng" \
    "$(CNG_DEBUG=1 run "$ROOT" /nosuchprogram 2>&1)"
check_absent "an empty CNG_DEBUG does not" "[cng] chroot-ng" \
    "$(CNG_DEBUG= run "$ROOT" /nosuchprogram 2>&1)"
check_absent "and CNG_DEBUG=0 does not" "[cng] chroot-ng" \
    "$(CNG_DEBUG=0 run "$ROOT" /nosuchprogram 2>&1)"

# A name resolved relative to a real dirfd must be contained exactly like an
# absolute one. It used to be passed to the kernel untouched, and the kernel has
# no rootfs: a ".." run climbed out (find/rm -rf/tar -C all issue these) and an
# absolute symlink target was taken from the host root.
mkdir -p "$ROOT/sub"
printf SECRET > "$ROOT/../atesc_$$"
check_contains "dirfd-relative .. cannot escape the rootfs" \
    "atrel: errno 2" \
    "$(run -t dtest -r "$ROOT" atrel /sub "../../atesc_$$" 2>&1)"
rm -f "$ROOT/../atesc_$$"
# ..-clamped, the same walk still reaches the real file inside the rootfs.
check_contains "dirfd-relative .. still resolves inside the rootfs" \
    "atrel: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" atrel /sub "../etc/greeting" 2>&1)"
# An absolute symlink target is a guest path, so it re-roots rather than
# reaching the host file of the same name.
ln -sf /etc/greeting "$ROOT/sub/lnk"
check_contains "dirfd-relative absolute symlink re-roots into the rootfs" \
    "atrel: HELLO-FROM-ROOTFS" \
    "$(run -t dtest -r "$ROOT" atrel /sub lnk 2>&1)"

# AT_EMPTY_PATH names the descriptor, not a name to resolve. The empty name was
# walked like any other relative one -- the probe deciding that ends in a
# readlinkat, which for an empty name reports on the dirfd, so a symlink fd said
# "this is a link, walk it" -- and the walk then resolved the fd's own guest path
# dereferencing its final component. fstatat described the TARGET where the
# kernel describes the link, and a dangling link answered ENOENT where the kernel
# answers fine. That is the race-free lstat-by-fd idiom systemd and util-linux
# use everywhere. Byte-for-byte against the host build, which is the kernel.
EPD=$(mktemp -d)
printf hi > "$EPD/f"; ln -s f "$EPD/l"; ln -s nowhere "$EPD/dang"
if ! guest_xlate_ready "AT_EMPTY_PATH legs"; then
    :
elif guest_cc_report "$EPD/emptypath" tests/guests/emptypath.c; then
    ep_k=""
    if have cc && cc -O1 -o "$EPD/ep_host" tests/guests/emptypath.c 2>/dev/null; then
        ep_k=$("$EPD/ep_host" "$EPD" 2>/dev/null)
    fi
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    ep_g=$(run_t 60 -R $GUEST_BINDS "$EPD" /emptypath 2>/dev/null)
    if [ -z "$ep_k" ]; then
        skip "AT_EMPTY_PATH differential: no host compiler for the oracle"
    elif [ "$ep_k" = "$ep_g" ]; then
        pass=$((pass + 1))
        echo "  ok   AT_EMPTY_PATH matches the kernel byte-for-byte"
    else
        fail=$((fail + 1))
        echo "  FAIL AT_EMPTY_PATH diverges from the kernel"
        printf '    kernel: %s\n' "$(echo "$ep_k" | tr '\n' '|')"
        printf '    cng   : %s\n' "$(echo "$ep_g" | tr '\n' '|')"
    fi
fi
rm -rf "$EPD"

# name_to_handle_at's flag runs the other way from every other *at() call: it
# does NOT follow a final symlink unless AT_SYMLINK_FOLLOW is given. Translation
# treated it as a follower, so it encoded the target instead of the link, and a
# dangling link — which the kernel encodes happily, never looking at the target —
# came back ENOENT. Byte-for-byte against the host build.
NHD=$(mktemp -d)
printf hi > "$NHD/f"; ln -s f "$NHD/l"; ln -s nowhere "$NHD/dang"
if ! guest_xlate_ready "name_to_handle_at legs"; then
    :
elif guest_cc_report "$NHD/handleat" tests/guests/handleat.c; then
    nh_k=""
    if have cc && cc -O1 -o "$NHD/nh_host" tests/guests/handleat.c 2>/dev/null; then
        nh_k=$("$NHD/nh_host" "$NHD" 2>/dev/null)
    fi
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    nh_g=$(run_t 60 -R $GUEST_BINDS "$NHD" /handleat 2>/dev/null)
    if [ -z "$nh_k" ]; then
        skip "name_to_handle_at differential: no host compiler for the oracle"
    elif [ "$nh_k" = "$nh_g" ]; then
        pass=$((pass + 1))
        echo "  ok   name_to_handle_at matches the kernel byte-for-byte"
    else
        fail=$((fail + 1))
        echo "  FAIL name_to_handle_at diverges from the kernel"
        printf '    kernel: %s\n' "$(echo "$nh_k" | tr '\n' '|')"
        printf '    cng   : %s\n' "$(echo "$nh_g" | tr '\n' '|')"
    fi
fi
rm -rf "$NHD"

# The xattr family was never trapped, so a guest's absolute path reached the HOST
# filesystem: getxattr answered existence questions about it and setxattr wrote
# it. Translation shows up in the errno: a name that resolves inside the rootfs
# reaches a real file and answers "no such attribute", while an untranslated path
# lands on a host name that is not there -> ENOENT (2).
#
# Which errno "reached a real file" is depends on the filesystem holding it --
# ENODATA (61) where user.* xattrs are supported, EOPNOTSUPP (95) where they are
# not (tmpfs before 6.6), or an SELinux refusal on a device -- so take it from an
# identity-rootfs control run over the very same file instead of pinning a
# number. All that matters is that it is distinguishable from ENOENT.
xa_ctl=$(run -t dtest -r / getxa "$ROOT/etc/greeting" 2>&1)
xa_real=$(printf '%s\n' "$xa_ctl" |
    sed -n 's/.*getxa: errno \([0-9]*\).*/\1/p' | head -1)
# The host-only path is one we create outside the rootfs: absolute, present on
# the host, and absent from the rootfs, which is the shape of the pre-fix escape.
XAH=$(mktemp); printf x >"$XAH"
if [ -z "$xa_real" ] || [ "$xa_real" = 2 ]; then
    skip "xattr legs: no errno on this filesystem distinguishes reached from contained"
else
    check_contains "xattr on a host-only path is contained" \
        "getxa: errno 2" \
        "$(run -t dtest -r "$ROOT" getxa "$XAH" 2>&1)"
    check_contains "xattr reaches the rootfs file, so it is translated not blocked" \
        "getxa: errno $xa_real" \
        "$(run -t dtest -r "$ROOT" getxa /etc/greeting 2>&1)"
fi
rm -f "$XAH"

# inotify_add_watch is the last path-bearing syscall with no dirfd form, and the
# only one whose a0 is not one — which is how it was missed. Untranslated it was
# the containment exactly inverted: a watch on a name present only on the HOST
# armed, while the rootfs's own file answered ENOENT. Both directions are
# asserted, so a blanket refusal cannot pass either.
INOH=$(mktemp); printf x >"$INOH"
check_contains "inotify on a host-only path is contained" \
    "inotify: errno 2" \
    "$(run -t dtest -r "$ROOT" inotify "$INOH" 2>&1)"
check_contains "inotify reaches the rootfs file, so it is translated not blocked" \
    "inotify: errno 0" \
    "$(run -t dtest -r "$ROOT" inotify /etc/greeting 2>&1)"
rm -f "$INOH"

# A ":ro" bind must answer EROFS for every mutating path syscall while still
# serving reads. The rw run is the negative control: the same calls must NOT
# report EROFS there, so a blanket refusal cannot pass both legs.
RB=$(mktemp -d); printf 'RO-DATA' > "$RB/f"
out=$(run -t dtest -r "$ROOT" -b "$RB":/ro:ro robind /ro/f 2>&1); rc=$?
check ":ro bind refuses every mutating syscall" 0 "$rc"
check_contains ":ro bind still serves reads" "robind ro read: rc=" "$out"
check_contains ":ro bind refuses a write open" \
    "robind ro open-w: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses unlinkat" \
    "robind ro unlinkat: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses rename" \
    "robind ro renameat: rc=-30 -> OK" "$out"
# access(W_OK) reports a read-only filesystem — SuS requires it and the kernel
# does it — so `test -w` inside a :ro bind agrees with what the write would do
# rather than with the host file's own mode. R_OK on the same name still passes.
check_contains ":ro bind reports itself to access(W_OK)" \
    "robind ro access-w: rc=-30 -> OK" "$out"
check_contains ":ro bind still answers access(R_OK)" \
    "robind ro access-r: rc=0 -> OK" "$out"
# The refusal keys on the resolved HOST path, and a plain name against a
# directory fd inside the bind never used to acquire one — so it went straight
# to the kernel and the mount was read-only only to whoever spelled the name out
# in full. rm -rf, find -delete, tar and git all work through a dirfd.
check_contains ":ro bind refuses a write open through a dirfd" \
    "robind ro at-open-w: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses a create through a dirfd" \
    "robind ro at-creat: rc=-30 -> OK" "$out"
check_contains ":ro bind refuses an unlink through a dirfd" \
    "robind ro at-unlink: rc=-30 -> OK" "$out"
check_contains ":ro bind still reads through a dirfd" \
    "robind ro at-read: rc=" "$out"
# A read-only mount refuses where the kernel reaches it, and for the calls that
# must operate on an existing name that is *after* the path has resolved -- so a
# name that is not there is ENOENT, the same answer a writable mount gives. The
# refusal used to be returned before the syscall was issued and so did not
# depend on the file existing, which told `[ -e f ] || : >f` that an absent file
# was present and sent it down the wrong branch. Measured on a squashfs mount:
# open(missing, O_WRONLY), O_TRUNC, truncate, chmod, chown and utimensat all
# answer ENOENT there, and EROFS only on a name that is there.
for _leg in open-w open-trunc truncate chmod chown utimensat; do
    check_contains ":ro bind answers ENOENT for a $_leg on a name that is not there" \
        "robind ro miss-$_leg: rc=-2 -> OK" "$out"
done
# ...and the other half, which the kernel orders the other way round: the
# create-and-remove family takes write access on the parent before it looks at
# the final component, so those are EROFS even for a name that is not there.
for _leg in open-creat mkdir unlink; do
    check_contains ":ro bind answers EROFS for a $_leg on a name that is not there" \
        "robind ro miss-$_leg: rc=-30 -> OK" "$out"
done
out=$(run -t dtest -r "$ROOT" -b "$RB":/rw robind /rw/f 2>&1); rc=$?
check "a plain (rw) bind reports no EROFS" 0 "$rc"
rm -rf "$RB"

run -t sigtest >/dev/null 2>&1
check "signal round-trip + ucontext readable" 0 $?
check_contains "sigtest handler ran" "handler ran" "$(run -t sigtest 2>&1)"

rm -rf "$ROOT"

# symlink resolution: absolute guest-target symlinks re-rooted (Alpine busybox
# style), relative symlinks, and no escape via a symlink target.
SR=$(mktemp -d)
mkdir -p "$SR/bin"
printf REAL-BB > "$SR/bin/busybox"
ln -s /bin/busybox "$SR/bin/ls"
ln -s busybox "$SR/bin/cat"
ln -s /../../../etc/passwd "$SR/bin/esc"
check_contains "abs symlink re-rooted into rootfs" "read: REAL-BB" \
    "$(run -t dtest -r "$SR" open /bin/ls 2>&1)"
check_contains "relative symlink resolved" "read: REAL-BB" \
    "$(run -t dtest -r "$SR" open /bin/cat 2>&1)"
check_contains "symlink target cannot escape rootfs" "open: errno 2" \
    "$(run -t dtest -r "$SR" open /bin/esc 2>&1)"
rm -rf "$SR"

# The SIGSYS handler runs the (stack-hungry) dispatcher on a large per-thread
# scratch stack so it never smashes a small guest stack (e.g. Go's ~8 KiB
# goroutine stacks). Validate the stack-switch trampoline itself.
out=$(run -t stackswtest 2>&1); rc=$?
check "stackswtest exit 0" 0 "$rc"
check_contains "handler stack switch runs on scratch and preserves caller" \
    "stacksw: ran_on_scratch=1 ret=0xc0de caller_ok=1 -> OK" "$out"
# ...and there has to be a stack to switch to. The table those come from is keyed
# by TID and had no way to give a slot back: nothing hooks thread exit, so a
# runtime that gets through hundreds of short-lived threads (Go, a JVM's GC
# workers) filled it, and from then on the dispatcher ran on the guest's own
# stack — where its frame is bigger than a guard page, so it steps over the guard
# into guest memory instead of faulting. A slot whose thread has exited is now
# taken over, stack and all; a live thread's is never touched.
check_contains "a full scratch table recovers the slots of threads that exited" \
    "stacksw reclaim: filled=300/300 then=" "$out"
check_contains "...with a stack, and never at the expense of a live thread" \
    "mapped=1 mine_kept=1 -> OK" "$out"

# And a SIGSYS that arrives while the handler is already on that scratch stack
# must not land on the frame of the one that put it there. The kernel picks a
# frame's address with sigsp(): SA_ONSTACK plus an SP that is not on the
# alt-stack means the alt-stack TOP — which the handler satisfies a second time
# once it has switched stacks, so the nested frame was written at exactly the
# outer frame's address (measured with a plain C repro, natively and under qemu:
# delta 0). The alt-stack is now disarmed for the duration; rt_sigreturn puts the
# guest's back from the frame. A real nested SIGSYS needs an ambient filter to
# block a syscall we re-issue, so the handler raises one itself on request.
out=$(run -t nesttest 2>&1); rc=$?
check "nesttest exit 0" 0 "$rc"
check_contains "a nested SIGSYS frame does not land on the outer one" \
    "nested=elsewhere same=0 -> OK" "$out"
check_contains "...and the outer handler still returns through its own frame" \
    "nest: child status 0 -> OK" "$out"

# ...and what runs there must not itself scale with the guest's argv. The
# emulated execve accepts a quarter of RLIMIT_STACK of arguments (megabytes),
# and the guest-stack builder used to collect one address per entry in a VLA of
# the caller's stack -- so an exec the kernel takes happily, `rm *` in a
# directory of fifty thousand files, overflowed the 256 KiB scratch stack. With
# every signal but SIGSYS masked there, that kills the guest outright: before
# the fix this leg does not fail, it segfaults.
out=$(run -t argvtest 2>&1); rc=$?
check "argvtest exit 0" 0 "$rc"
check_contains "a 50k-entry argv builds on a handler-sized stack" \
    "argv: n=50000 shape=1 strings=1 env=1 caller_ok=1 -> OK" "$out"

# A vfork-style clone (CLONE_VFORK|CLONE_VM, as Go's os/exec and posix_spawn use)
# must be converted to a real COW fork, or the in-process emulated execve would
# load the new program over the shared parent's memory.
out=$(run -t clonetest 2>&1); rc=$?
check "clonetest exit 0" 0 "$rc"
check_contains "vfork clone converted to private-VM fork" \
    "clone: pid>0=1 child_exit7=1 private_vm=1 -> OK" "$out"

# A vfork-style clone carrying a caller-provided child stack (musl __clone /
# posix_spawn, as gcc uses to launch cc1) must resume the converted child on
# that stack — driven through the real SIGSYS body, which fixes uc->sp.
out=$(run -t clonestktest 2>&1); rc=$?
check "clonestktest exit 0" 0 "$rc"
check_contains "converted clone resumes child on its own stack" \
    "clonestk: pid>0=1 child_sp=childstk=1 parent_sp=orig=1 -> OK" "$out"

# The BPF filter itself: qemu-user does not honor a guest's seccomp filter, so
# its logic is verified by building it and running it through an interpreter —
# the only pre-device check available for it.
out=$(run -t bpftest 2>&1); rc=$?
check "bpftest exit 0" 0 "$rc"
check_contains "filter is structurally valid (jumps in range, ends in RET)" \
    "jumps_in_range=1 -> OK" "$out"
check_contains "path syscalls trap, others run native" \
    "bpftest openat traps: TRAP -> OK" "$out"
check_contains "in-gate reissue is allowed (no re-trap)" \
    "bpftest in-gate reissue allowed: ALLOW -> OK" "$out"
check_contains "fork traps (registry publish), threads do not" \
    "bpftest thread runs native: ALLOW -> OK" "$out"
check_contains "reads trap only for the reserved synthesized fd range" \
    "bpftest read of a synth fd traps: TRAP -> OK" "$out"
check_contains "an fd arg with a dirty upper half is judged on its low word" \
    "bpftest read with a dirty upper half is judged on the low word: ALLOW -> OK" \
    "$out"
check_contains "a foreign architecture is killed" \
    "bpftest foreign arch killed -> OK" "$out"
check_contains "the System V shm syscalls trap (M12 emulation)" \
    "bpftest shmat traps: TRAP -> OK" "$out"
# io_uring submits path operations through a ring, never an svc, so a created
# ring reaches the host filesystem with no trap and no translation. The filter
# must refuse it outright -- including from inside the gate, which exempts our
# own re-issues but must not become a hole for a call we never make.
check_contains "io_uring is refused ENOSYS by the filter" \
    "bpftest io_uring_setup is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "io_uring is refused even from inside the gate" \
    "bpftest in-gate io_uring is refused too: ERRNO -> OK" "$out"
# clone3's flags sit behind a pointer, so BPF cannot tell a thread from a vfork.
# Refusing it puts glibc's posix_spawn/pthread_create back on __NR_clone, where
# the CLONE_VFORK->fork conversion lives; otherwise a shared-VM child would
# reach the emulated execve and load the new program over its parent.
check_contains "clone3 is refused so spawns use the converted clone path" \
    "bpftest clone3 is refused ENOSYS: ERRNO -> OK" "$out"
# acct(2) names a file, and was the last path-bearing syscall in the table that
# was neither trapped nor refused: unprivileged it is EPERM, but chroot-ng run
# as root would have pointed the machine's process accounting at whatever the
# guest named. It cannot be translated either -- there is one such file per
# machine, so re-rooting the name only files the host's records in the guest.
check_contains "acct is refused ENOSYS by the filter" \
    "bpftest acct is refused ENOSYS: ERRNO -> OK" "$out"
# A guest-installed filter also governs the syscalls the SIGSYS handler
# re-issues through the gate, which that filter knows nothing about -- so
# seccomp(2) is refused outright. prctl carries the same capability under an op
# number it shares with process state we must not slow down (bionic's allocator
# calls PR_SET_VMA on every mapping), so the filter tests the op itself.
check_contains "seccomp(2) is refused ENOSYS by the filter" \
    "bpftest seccomp(2) is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "the prctl ops that describe our confinement trap" \
    "bpftest prctl PR_SET_SECCOMP traps: TRAP -> OK" "$out"
check_contains "PR_GET_SECCOMP traps, so it cannot report our mode 2" \
    "bpftest prctl PR_GET_SECCOMP traps: TRAP -> OK" "$out"
check_contains "the rest of prctl stays untrapped" \
    "bpftest prctl PR_SET_VMA runs native: ALLOW -> OK" "$out"
# fstat/fchmod are trapped only where they have something to do: under a fake
# identity, where fstat must remap ownership the way stat does and fchmod needs
# the same fail-soft. Off, an ordinary fstat must not pay for a trap.
check_contains "the fake-id set adds fstat and fchmod, and only then" \
    "bpftest fake-id: fstat_off=1 fstat_on=1 fchmod_on=1 -> OK" "$out"
# SysV sem/msg are emulated from the same broker as shm, so they trap rather
# than being refused -- and they trap unconditionally, so the guest gets its own
# namespace whatever the host's own IPC would have allowed.
check_contains "SysV semaphores trap for emulation" \
    "bpftest semget traps: TRAP -> OK" "$out"
check_contains "...including the blocking operation" \
    "bpftest semtimedop traps: TRAP -> OK" "$out"
check_contains "SysV message queues trap for emulation" \
    "bpftest msgget traps: TRAP -> OK" "$out"
check_contains "...including both ends of the queue" \
    "bpftest msgrcv traps: TRAP -> OK" "$out"
# POSIX mqueue: the same leak one namespace over. An mq name is not a filesystem
# path -- it names an entry in the per-IPC-namespace mqueue mount -- so no path
# trap can translate it and the rootfs prefix cannot scope it. Left native, a
# guest mq_open() created its queue in the HOST's namespace.
check_contains "POSIX message queues no longer reach the host namespace" \
    "bpftest mq_open is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "and the descriptor-taking mqueue calls are refused with them" \
    "bpftest mq_timedsend is refused ENOSYS: ERRNO -> OK" "$out"
check_contains "shm is still emulated rather than refused" \
    "bpftest shmget still traps for emulation: TRAP -> OK" "$out"
check_contains "fchmodat2 is translated, not refused" \
    "bpftest fchmodat2 traps for translation: TRAP -> OK" "$out"
check_contains "plain clone still traps for the vfork conversion" \
    "bpftest plain clone still traps for the conversion: TRAP -> OK" "$out"

# The -R trampoline tier runs with no filter, so the designed-ENOSYS refusals
# cannot come from the kernel there -- the dispatcher must answer them itself.
# bpftest covers the filter; this covers the other tier, and is the only one of
# the two that qemu-user can actually run.
DR=$(mktemp -d)
out=$(run -t dtest -r "$DR" denied /x 2>&1); rc=$?
check "the trampoline tier refuses the designed-ENOSYS set itself" 0 "$rc"
check_contains "io_uring is refused on the -R tier" \
    "denied io_uring_setup: rc=-38 -> OK" "$out"
check_contains "clone3 is refused on the -R tier" \
    "denied clone3: rc=-38 -> OK" "$out"
check_contains "an ordinary syscall still runs on the -R tier" \
    "denied control getpid: rc=" "$out"
check_contains "POSIX message queues are refused on the -R tier" \
    "denied mq_open: rc=-38 -> OK" "$out"
# The mount family took paths and was neither trapped nor refused, so the
# guest's own untranslated spelling went to the host kernel to be judged. A
# mount cannot be carried out here in any case — the path layer would not know
# about it and the synthesized /proc/self/mounts is built from the rootfs and
# its binds — so ENOSYS is the honest answer, where EPERM implied it might have
# worked with privilege.
check_contains "mount is refused rather than judged by the host" \
    "denied mount: rc=-38 -> OK" "$out"
check_contains "umount2 likewise" "denied umount2: rc=-38 -> OK" "$out"
check_contains "pivot_root likewise" "denied pivot_root: rc=-38 -> OK" "$out"
check_contains "quotactl likewise" "denied quotactl: rc=-38 -> OK" "$out"
check_contains "swapon likewise" "denied swapon: rc=-38 -> OK" "$out"
check_contains "acct likewise" "denied acct: rc=-38 -> OK" "$out"
rm -rf "$DR"
