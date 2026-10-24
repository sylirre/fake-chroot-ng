/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Terminal ioctls that Android's SELinux policy refuses an app, served from
 * the ones it allows (src/monitor/tty.c).
 *
 * The policy whitelists, per object class, the ioctls an app domain may issue,
 * and the list is short for a pty: TCGETS, TCSETS*, TIOCGWINSZ and a few more
 * are on it (Android 8's has no TCSETSF yet), the rest answer EACCES -- on a
 * terminal and on a pipe alike. A
 * guest runs its ioctls natively, so it met the refusal itself. The requests
 * below are the ones a libc turns into a verdict about the terminal, and the
 * filter traps exactly these (seccomp.c) so that the dispatcher can answer
 * them when the host will not.
 */
#ifndef CNG_TTY_H
#define CNG_TTY_H

/* The requests the filter traps, always: not only with a :ro bind in the view,
 * as the mount writers are. The dispatcher's list is this one. */
extern const unsigned cng_ioctl_tty[];
extern const int cng_ioctl_tty_n;

/* Is `req` one of them? */
int cng_tty_request(unsigned req);

/* Answer one of them on host descriptor `fd` with the guest argument `argp`:
 * 0 or the result the host gave, or -errno. */
long cng_tty_ioctl(long fd, unsigned req, long argp);

/* CNG_TERMIOS2_DENY=1: refuse the termios2 ioctls (TCGETS2, TCSETS2, ...) with
 * EACCES before the host is asked, as Android's policy does, so they are
 * served from TCGETS/TCSETS. Settled before the first guest instruction,
 * read-only after. */
extern int cng_g_termios2_deny;

/* CNG_TIOCGSID_DENY=1: the same for TIOCGSID (tcgetsid), which the policy
 * refuses on a pty slave and on a pipe; it is then served from TCGETS,
 * TIOCGPGRP and getsid. */
extern int cng_g_tiocgsid_deny;

/* CNG_TCSETSF_DENY=1: the same for TCSETSF (tcsetattr(TCSAFLUSH)), which
 * Android 8's policy refuses on a pty; it is then served from TCFLSH and
 * TCSETSW, and so is the TCSETSF2 that falls back to it. */
extern int cng_g_tcsetsf_deny;

#endif /* CNG_TTY_H */
