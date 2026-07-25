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
# via the block-list (tmpfs allows hardlinks).
L2=$(mktemp -d); mkdir -p "$L2/w"
out=$(run -t l2stest "$L2" 2>&1); rc=$?
check "l2stest overall (l2s + fchdir)" 0 "$rc"
check_contains "l2s presents the group as regular files (nlink, inode, content)" \
    "l2s: rc=0 eexist=1 reg=1 nlink2=1 sameino=1 noleak=1 content=1 -> OK" "$out"
check_contains "l2s preserves mtime through the backing file" \
    "l2s-mtime: set=0 mtime=287454020 -> OK" "$out"
check_contains "l2s handles dirfd-relative links (apk's pattern)" \
    "l2s-dirfd: rc=0 reg2=1 -> OK" "$out"
check_contains "l2s decref reclaims the backing on last unlink" \
    "l2s-decref: nlink_after1=1 gone=1 -> OK" "$out"
check_contains "fchdir updates virtual cwd" "fchdir: cwd=/w -> OK" "$out"
rm -rf "$L2"
