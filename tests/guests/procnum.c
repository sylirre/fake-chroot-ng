/* /proc names spelled with a leading zero (M69).
 *
 * procfs looks its numbered entries up with name_to_int(), which refuses a
 * leading zero: "/proc/self/fd/05" and "/proc/0<pid>/status" do not exist,
 * whatever descriptor 5 and process <pid> are. The monitor read the digits
 * itself wherever it answers for such a name — an exec through an fd link, a
 * readlink of exe, a synthesized status — and took "05" for 5.
 *
 * Prints one line per name: what the call answered, as an errno or "ok". The
 * output is byte-comparable against a run with no chroot-ng in the way. An
 * exec that works re-enters this program with "child" and says so instead.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void say(const char *what, long r) {
    if (r < 0)
        printf("%s: errno=%d\n", what, errno);
    else
        printf("%s: ok\n", what);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) {
        printf("exec %s: ran\n", argc > 2 ? argv[2] : "?");
        return 0;
    }
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("open exe: errno=%d\n", errno);
        return 1;
    }
    /* The descriptor is kept off 0..9 so a one-digit spelling cannot be it. */
    int hi = fcntl(fd, F_DUPFD_CLOEXEC, 20);
    close(fd);
    fd = hi;
    int pid = getpid();
    char p[128], buf[256];
    struct stat st;

    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    say("fd plain open", open(p, O_RDONLY | O_CLOEXEC));
    snprintf(p, sizeof p, "/proc/self/fd/0%d", fd);
    say("fd zero open", open(p, O_RDONLY | O_CLOEXEC));
    say("fd zero stat", stat(p, &st));
    snprintf(p, sizeof p, "/dev/fd/00%d", fd);
    say("devfd zero stat", stat(p, &st));
    say("fd 0 stat", stat("/proc/self/fd/0", &st));
    say("fd 00 stat", stat("/proc/self/fd/00", &st));

    snprintf(p, sizeof p, "/proc/%d/status", pid);
    say("pid plain status", open(p, O_RDONLY | O_CLOEXEC));
    snprintf(p, sizeof p, "/proc/0%d/status", pid);
    say("pid zero status", open(p, O_RDONLY | O_CLOEXEC));
    /* cmdline is one the monitor always serves itself (procfs.c). */
    snprintf(p, sizeof p, "/proc/%d/cmdline", pid);
    say("pid plain cmdline", open(p, O_RDONLY | O_CLOEXEC));
    snprintf(p, sizeof p, "/proc/0%d/cmdline", pid);
    say("pid zero cmdline", open(p, O_RDONLY | O_CLOEXEC));
    snprintf(p, sizeof p, "/proc/0%d/exe", pid);
    say("pid zero exe readlink", readlink(p, buf, sizeof buf));
    say("pid zero exe open", open(p, O_RDONLY | O_CLOEXEC));
    snprintf(p, sizeof p, "/proc/0%d/cwd", pid);
    say("pid zero cwd stat", stat(p, &st));

    char *ev[] = {0};
    snprintf(p, sizeof p, "/proc/self/fd/0%d", fd);
    char *av[] = {p, "child", "fd-zero", 0};
    execve(p, av, ev);
    say("exec fd-zero", -1);
    snprintf(p, sizeof p, "/proc/0%d/exe", pid);
    char *av2[] = {p, "child", "pid-zero-exe", 0};
    execve(p, av2, ev);
    say("exec pid-zero-exe", -1);
    return 0;
}
