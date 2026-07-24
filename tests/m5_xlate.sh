# M5a path-translation tests (sourced by tests/run.sh). Pure logic; fully
# exercised under qemu via the _xlate debug command.
echo "== M5a: path translation =="

check_contains "rootfs prefix" \
    "/etc/passwd -> /root/etc/passwd" \
    "$(run _xlate -r /root /etc/passwd)"

check_contains ".. cannot escape rootfs" \
    "/a/b/../../../etc -> /root/etc" \
    "$(run _xlate -r /root /a/b/../../../etc)"

check_contains "dot and double-slash collapse" \
    "/a/./b//c -> /root/a/b/c" \
    "$(run _xlate -r /root /a/./b//c)"

check_contains "bind subpath" \
    "/dev/null -> /hostdev/null" \
    "$(run _xlate -r /root -b /dev:/hostdev /dev/null)"

check_contains "bind exact match" \
    "/dev -> /hostdev" \
    "$(run _xlate -r /root -b /dev:/hostdev /dev)"

check_contains "longest bind wins" \
    "/dev/pts/3 -> /PTS/3" \
    "$(run _xlate -r /root -b /dev:/HD -b /dev/pts:/PTS /dev/pts/3)"

check_contains "relative path uses cwd" \
    "foo/bar -> /root/home/u/foo/bar" \
    "$(run _xlate -r /root -C /home/u foo/bar)"

check_contains "no-chroot rootfs / is identity" \
    "/etc -> /etc" \
    "$(run _xlate -r / /etc)"

check_contains "bind prefix is component-aware (no /devextra match)" \
    "/devextra/x -> /root/devextra/x" \
    "$(run _xlate -r /root -b /dev:/hostdev /devextra/x)"
