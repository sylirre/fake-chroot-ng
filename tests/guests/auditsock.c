/* The audit interface (M16c).
 *
 * libaudit's audit_open() is a bare socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT),
 * and shadow-utils wraps it in audit_help_open(), which survives exactly three
 * errnos — EINVAL, EPROTONOSUPPORT, EAFNOSUPPORT, every one of them a way of
 * saying "this kernel was built without audit" — and exits on anything else:
 *
 *     useradd: Cannot open audit interface - aborting.
 *
 * Android's SELinux policy refuses the app domain a netlink_audit_socket with
 * EACCES, which is not one of the three, and that is what stops `useradd`,
 * `usermod`, `passwd`, `chage`, `groupadd` and shadow's `su` inside a rootfs on
 * a device. So this guest prints that decision rule, not just the errno: the
 * `survives` field is audit_help_open()'s branch, and a run can be judged the
 * way the tools themselves judge it.
 *
 * The second line pins the narrowness of the answer — a NETLINK_ROUTE socket and
 * an ordinary AF_INET one must be untouched by it. It is kept separate because
 * the first line is compared against an unemulated run and the rtnetlink one
 * legitimately differs there (that is M16's whole subject).
 */
#include <errno.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    errno = 0;
    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    int e = (fd < 0) ? errno : 0;
    /* audit_help_open(), verbatim. */
    int survives = (fd >= 0) || e == EINVAL || e == EPROTONOSUPPORT ||
                   e == EAFNOSUPPORT;
    printf("audit: open=%d errno=%d survives=%d\n", fd >= 0, e, survives);
    if (fd >= 0)
        close(fd);

    int nr = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int in = socket(AF_INET, SOCK_DGRAM, 0);
    printf("other: route=%d inet=%d\n", nr >= 0, in >= 0);
    if (nr >= 0)
        close(nr);
    if (in >= 0)
        close(in);
    return 0;
}
