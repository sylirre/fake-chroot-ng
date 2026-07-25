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
    "$(run -t xlate -r /root -b /dev:/hostdev /dev/null)"

check_contains "bind exact match" \
    "/dev -> /hostdev" \
    "$(run -t xlate -r /root -b /dev:/hostdev /dev)"

check_contains "longest bind wins" \
    "/dev/pts/3 -> /PTS/3" \
    "$(run -t xlate -r /root -b /dev:/HD -b /dev/pts:/PTS /dev/pts/3)"

check_contains "relative path uses cwd" \
    "foo/bar -> /root/home/u/foo/bar" \
    "$(run -t xlate -r /root -C /home/u foo/bar)"

check_contains "no-chroot rootfs / is identity" \
    "/etc -> /etc" \
    "$(run -t xlate -r / /etc)"

check_contains "bind prefix is component-aware (no /devextra match)" \
    "/devextra/x -> /root/devextra/x" \
    "$(run -t xlate -r /root -b /dev:/hostdev /devextra/x)"

# chroot(2) moves the root; it unmounts nothing. Binds under the new root are
# rebased onto it (apk runs every package script under chroot(".")).
check_contains "chroot to / keeps the binds" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /dev:/hostdev -c / /dev/null)"

check_contains "chroot moves the rootfs" \
    "/etc -> /root/a/etc" \
    "$(run -t xlate -r /root -c /a /etc)"

check_contains "chroot rebases a bind under the new root" \
    "/dev/null -> /hostdev/null" \
    "$(run -t xlate -r /root -b /a/dev:/hostdev -c /a /dev/null)"

check_contains "chroot drops a bind outside the new root" \
    "/dev/null -> /root/a/dev/null" \
    "$(run -t xlate -r /root -b /dev:/hostdev -c /a /dev/null)"

check_contains "chroot rebases the cwd" \
    "x -> /root/a/b/x" \
    "$(run -t xlate -r /root -C /a/b -c /a x)"
