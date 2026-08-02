# M5a path-translation tests (sourced by tests/run.sh). Pure logic; fully
# exercised under qemu via the _xlate debug command.
echo "== M5a: path translation =="

check_contains "rootfs prefix" \
    "/etc/passwd -> /root/etc/passwd" \
    "$(run -t xlate -r /root /etc/passwd)"

check_contains ".. cannot escape rootfs" \
    "/a/b/../../../etc -> /root/etc" \
    "$(run -t xlate -r /root /a/b/../../../etc)"

check_contains "dot and double-slash collapse" \
    "/a/./b//c -> /root/a/b/c" \
    "$(run -t xlate -r /root /a/./b//c)"

check_contains "bind subpath" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /hostdev:/dev /dev/null)"

check_contains "bind exact match" \
    "/dev -> /hostdev" \
    "$(run -t xlate -r /root -b /hostdev:/dev /dev)"

check_contains "longest bind wins" \
    "/dev/pts/3 -> /PTS/3" \
    "$(run -t xlate -r /root -b /HD:/dev -b /PTS:/dev/pts /dev/pts/3)"

check_contains "relative path uses cwd" \
    "foo/bar -> /root/home/u/foo/bar" \
    "$(run -t xlate -r /root -C /home/u foo/bar)"

check_contains "no-chroot rootfs / is identity" \
    "/etc -> /etc" \
    "$(run -t xlate -r / /etc)"

check_contains "bind prefix is component-aware (no /devextra match)" \
    "/devextra/x -> /root/devextra/x" \
    "$(run -t xlate -r /root -b /hostdev:/dev /devextra/x)"

# chroot(2) moves the root; it unmounts nothing. Binds under the new root are
# rebased onto it (apk runs every package script under chroot(".")).
check_contains "chroot to / keeps the binds" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /hostdev:/dev -c / /dev/null)"

check_contains "chroot moves the rootfs" \
    "/etc -> /root/a/etc" \
    "$(run -t xlate -r /root -c /a /etc)"

check_contains "chroot rebases a bind under the new root" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /hostdev:/a/dev -c /a /dev/null)"

# Uses /etc, not /dev: after a chroot the rebased view spells the guest's own
# /dev as "/dev" again, so the device zone below picks it up and the bind-drop
# would not be what the result showed.
check_contains "chroot drops a bind outside the new root" \
    "/etc/hosts -> /root/a/etc/hosts" \
    "$(run -t xlate -r /root -b /hostetc:/etc -c /a /etc/hosts)"

# The /dev zone: a whitelist of harmless host devices passes through, everything
# else under /dev comes from the rootfs, and the fd aliases are the /proc magic
# links (which reach pipes and memfds no re-rooted name could describe).
check_contains "/dev whitelist passes through to the host node" \
    "/dev/null -> /dev/null" "$(run -t xlate -r /root /dev/null)"
check_contains "/dev/console maps to the host tty" \
    "/dev/console -> /dev/tty" "$(run -t xlate -r /root /dev/console)"
check_contains "/dev/pts subpaths pass through" \
    "/dev/pts/3 -> /dev/pts/3" "$(run -t xlate -r /root /dev/pts/3)"
check_contains "/dev/fd is the /proc fd link" \
    "/dev/fd/7 -> /proc/self/fd/7" "$(run -t xlate -r /root /dev/fd/7)"
check_contains "/dev/stdin is fd 0" \
    "/dev/stdin -> /proc/self/fd/0" "$(run -t xlate -r /root /dev/stdin)"
# The containment half: a device NOT on the whitelist must not be reachable.
check_contains "a non-whitelisted device resolves into the rootfs" \
    "/dev/sda1 -> /root/dev/sda1" "$(run -t xlate -r /root /dev/sda1)"
check_contains "/dev itself is the rootfs directory (so it can be listed)" \
    "/dev -> /root/dev" "$(run -t xlate -r /root /dev)"
# A bind still outranks the zone: cng_fs_translate matches binds first.
check_contains "a -b bind outranks the /dev zone" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /hostdev:/dev /dev/null)"

check_contains "chroot rebases the cwd" \
    "x -> /root/a/b/x" \
    "$(run -t xlate -r /root -C /a/b -c /a x)"

# :ro binds. The -t xlate harness resolves paths only, so the flag is asserted
# through the mount table in m11 and through a real write in m5b; here we only
# pin that ":ro" is stripped from the destination rather than becoming part of
# the guest prefix (the pre-0.1.0 parse folded it into the host path).
check_contains "a :ro suffix is not part of the guest mount point" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /hostdev:/dev:ro /dev/null)"

# --- M17-11: physical resolution ------------------------------------------
# Resolution is the kernel's, not the shell's: ".." backs out of where a symlink
# actually led, so it has to be applied while walking, not collapsed lexically
# up front. `-t xlate -R` runs the real resolver (it readlinks each component,
# so these need a tree on disk); `-n` leaves the final component's own symlink
# alone, which is what O_NOFOLLOW and AT_SYMLINK_NOFOLLOW need.
XR=$(mktemp -d)
mkdir -p "$XR/usr/bin" "$XR/usr/lib" "$XR/lib" "$XR/etc"
ln -s /usr/bin "$XR/bin"        # absolute target, re-rooted into the rootfs
ln -s usr/lib "$XR/l"           # relative target
: >"$XR/etc/f"
ln -s /etc/f "$XR/link"
xres() { run -t xlate -R -r "$XR" "$@"; }
check_contains "'..' backs out of where the symlink led, not out of its name" \
    "/bin/../lib -> $XR/usr/lib" "$(xres /bin/../lib)"
check_contains "a symlinked directory resolves to its target" \
    "/bin -> $XR/usr/bin" "$(xres /bin)"
check_contains "'..' on a symlinked directory lands in the target's parent" \
    "/bin/.. -> $XR/usr" "$(xres /bin/..)"
check_contains "a relative symlink target resolves against its own directory" \
    "/l/target -> $XR/usr/lib/target" "$(xres /l/target)"
check_contains "a final symlink is followed by default" \
    "/link -> $XR/etc/f" "$(xres /link)"
check_contains "'..' cannot climb out of the guest root" \
    "/../../etc -> $XR/etc" "$(xres /../../etc)"
check_contains "the final component's symlink is kept under -n" \
    "/link -> $XR/link" "$(run -t xlate -n -r "$XR" /link)"
check_contains "...while the components before it still resolve under -n" \
    "/bin/../lib -> $XR/usr/lib" "$(run -t xlate -n -r "$XR" /bin/../lib)"
rm -rf "$XR"

# A formatted line longer than cng_dprintf's 1024-byte window. Two failures
# have lived here: PUT evaluated its argument only when there was room to store
# it, so `while (*s) PUT(*s++)` stopped advancing once the buffer filled and
# spun forever; and cutting the line at the window's width took its trailing
# newline with it, running two rows of a synthesized /proc file together. The
# window is now refilled instead, so the line comes out whole however long it
# is — 600 bytes of path against a rootfs prefix clears 1024 twice over.
_lp=/
_i=0
while [ $_i -lt 12 ]; do
    _lp="${_lp}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    _i=$((_i + 1))
done
_out=$(run_t 20 -t xlate -r /root "$_lp" 2>&1)
check "an over-long line does not spin" 0 $?
# "<601> -> /root<601>" = 601 + 4 + 5 + 601; the trailing newline is stripped
# by the command substitution, and its presence is what a cut line would lose.
check "...and is emitted whole, newline included" 1211 \
    "$(printf %s "$_out" | wc -c | tr -d ' ')"
check "...as a single line" 1 "$(printf '%s\n' "$_out" | wc -l | tr -d ' ')"

# A guest path that fits, whose translated host path does not. cng_fs_translate
# used to cut it and report success, so the syscall ran against a DIFFERENT,
# shorter name — an unlink deleting the wrong entry, an O_CREAT making the wrong
# file. It must refuse instead, and the dispatcher must answer ENAMETOOLONG
# rather than hand the kernel the guest's own untranslated spelling.
_c=cccccccccc
_c="$_c$_c$_c$_c$_c"   # 50
_c="$_c$_c$_c$_c"      # 200
XL=$(mktemp -d)/"$_c"  # a rootfs prefix long enough to matter
mkdir -p "$XL"
_g=""
_i=0
while [ $_i -lt 20 ]; do   # 20 * 201 = 4020 bytes: fits alone, not once prefixed
    _g="$_g/$_c"
    _i=$((_i + 1))
done
check_contains "a path the rootfs prefix pushes past PATH_MAX is refused" \
    "<overflow>" "$(run_t 20 -t xlate -r "$XL" "$_g" 2>&1)"
run_t 20 -t dtest -r "$XL" open "$_g" >"$CNG_TMP/toolong.out" 2>&1
check_contains "...and the syscall answers ENAMETOOLONG, not the wrong file" \
    "open: errno 36" "$(cat "$CNG_TMP/toolong.out")"
rm -rf "$(dirname "$XL")"
