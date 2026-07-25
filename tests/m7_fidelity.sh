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
check_contains "fake-root reopens a file it may execute but not read" \
    "fakeroot_reopen: opened=1 mode_kept=1 -> OK" "$out"
check_contains "a refused reopen is served from the fd we hold, rewound" \
    "fd_reopen: dup=1 content=1 -> OK" "$out"
check_contains "supplementary groups empty" "ngroups=0"           "$out"
check_contains "capget reports full set under fake-root" "cap_eff=ffffffff" "$out"
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
rm -rf "$L2"
