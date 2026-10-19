# M10: link2symlink guest-shell fidelity (sourced by tests/run.sh).
#
# Differential against arm64chroot running REAL hardlinks: the oracle binary
# has l2s compiled out and this host's filesystem allows link(2), so the same
# shell script runs once with genuine hardlinks (oracle) and once with the
# emulation forced on (CNG_L2S_FORCE routes every linkat through l2s). Stdout
# and exit status must match byte-for-byte — any visible difference means the
# emulation is distinguishable from real hardlinks in a guest shell.
#
# Rules: scenarios are self-contained; raw inode numbers are never printed
# (compare with `[ a = b ] && echo same-ino`); busybox `find` has no
# -samefile (GNU-only — exercised in the Debian leg).
#
# The oracle is a host-native program, not an AArch64 one, so this whole
# milestone only runs where a matching build of it exists (tests/lib.sh checks
# its machine against the host's and drops it otherwise). Locations come from
# tests/lib.sh; M10_ORACLE/M10_ALPINE/M10_DEBIAN still override per-milestone.
echo "== M10: l2s shell (differential vs arm64chroot real hardlinks) =="

M10_ORACLE="${M10_ORACLE:-$CNG_ORACLE}"
M10_ALPINE="${M10_ALPINE:-$CNG_ALPINE}"
M10_DEBIAN="${M10_DEBIAN:-$CNG_DEBIAN}"

CNG_L2S_FORCE=1
export CNG_L2S_FORCE   # chroot-ng only; the oracle ignores it

m10_ready=0
if [ -n "$M10_ORACLE" ] && [ -x "$M10_ORACLE" ] &&
    [ -n "$M10_ALPINE" ] && [ -x "$M10_ALPINE/bin/busybox" ]; then
    # Sanity: the oracle must produce real hardlinks (l2s compiled out).
    SAN=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$SAN"
    san=$("$M10_ORACLE" "$SAN" /bin/sh -c \
        'cd /tmp; echo x>a; ln a b; stat -c %h a' 2>/dev/null)
    rm -rf "$SAN"
    if [ "$san" = "2" ]; then
        m10_ready=1
    else
        skip "oracle does not produce real hardlinks (got '$san')"
    fi
else
    skip "differential l2s legs: no host-native oracle or no alpine rootfs"
fi

# l2s_diff <desc> <script>: run <script> under both, compare stdout + rc.
l2s_diff() {
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    out_o=$("$M10_ORACLE" "$RO" /bin/sh -c "$2" 2>/dev/null); rc_o=$?
    out_e=$(run -R -l "$REM" /bin/sh -c "$2" 2>/dev/null); rc_e=$?
    if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
        pass=$((pass + 1)); echo "  ok   m10 $1"
    else
        fail=$((fail + 1)); echo "  FAIL m10 $1"
        echo "    oracle rc=$rc_o: $(printf %s "$out_o" | head -c 300)"
        echo "    chroot rc=$rc_e: $(printf %s "$out_e" | head -c 300)"
    fi
    rm -rf "$RO" "$REM"
}

if [ "$m10_ready" -eq 1 ]; then
    l2s_diff "ln basics: nlink, shared inode, content" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; stat -c %h a b;
         [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino; cat b'

    l2s_diff "cross-directory ln" \
        'cd /tmp; mkdir -p d/s; cd d; echo hi>a; ln a s/c; stat -c %h a s/c;
         [ "$(stat -c %i a)" = "$(stat -c %i s/c)" ] && echo same-ino; cat s/c'

    l2s_diff "hiding: ls -a in link dir and at /" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; ls -a; ls -a /'

    l2s_diff "readlink on a hardlink fails" \
        'cd /tmp; echo hi>a; ln a b; readlink b; echo rc=$?'

    l2s_diff "write-through: append via one name, read via other" \
        'cd /tmp; echo hi>a; ln a b; echo more >> a; cat b; stat -c %h b'

    l2s_diff "mv a link cross-directory" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; mv b /tmp/b2;
         cat /tmp/b2; stat -c %h /tmp/b2;
         [ "$(stat -c %i a)" = "$(stat -c %i /tmp/b2)" ] && echo same-ino'

    l2s_diff "rm one name drops nlink" \
        'cd /tmp; echo hi>a; ln a b; rm b; stat -c %h a; ls'

    l2s_diff "rm all names, rmdir succeeds" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; rm a b; cd ..;
         rmdir d; echo rc=$?; ls'

    l2s_diff "rm -rf a tree holding link groups" \
        'cd /tmp; mkdir -p t/x t/y; echo hi>t/x/a; ln t/x/a t/x/b;
         ln t/x/a t/y/c; rm -rf t; echo rc=$?; ls -a'

    # link(2) of a symlink links the symlink: a second name with the same
    # text and times, followed by neither (the count is the one divergence,
    # so it is not printed). The fallback opened the source and drew ELOOP.
    l2s_diff "ln of a symlink links the symlink" \
        'cd /tmp; echo hi>a; ln -s a sl; touch -h -d "2020-01-02 03:04:05" sl;
         ln sl sl2; echo rc=$?; stat -c "%F %Y" sl sl2; readlink sl2; cat sl2;
         mkdir d; ln sl d/sl3; readlink d/sl3; cat d/sl3; echo rc=$?'

    # rename(2) of a name onto another name of the same file does nothing:
    # both names stay and the count is unchanged. The host saw two symlinks
    # and moved one over the other.
    l2s_diff "mv between two names of one file does nothing" \
        'cd /tmp; echo x>m; ln m n; mv m n; echo mv=$?; ls m n; stat -c %h m n;
         mkdir d; ln n d/o; mv d/o m; echo mv=$?; ls m n d; stat -c %h m n d/o;
         echo y>p; mv p n; echo mv=$?; stat -c %h m n d/o; cat n d/o'

    # A FIFO's names are one pipe: what is written to one is read from the
    # other. The fallback opened the FIFO to copy it and hung.
    l2s_diff "ln of a FIFO: both names are one pipe" \
        'cd /tmp; mkfifo f; ln f g; echo rc=$?; stat -c "%h %F" f g;
         [ "$(stat -c %i f)" = "$(stat -c %i g)" ] && echo same-ino;
         (echo hi > f &); cat g; mkdir d; ln g d/h; stat -c %h f;
         rm f; stat -c "%h %F" g d/h; rm g d/h; ls -a'

    l2s_diff "double ln refuses with EEXIST" \
        'cd /tmp; echo hi>a; ln a b; ln a b 2>&1; echo rc=$?'

    l2s_diff "tar round-trip restores the hardlink" \
        'cd /tmp; mkdir d; echo hi>d/a; ln d/a d/b; tar cf t.tar d;
         rm -rf d; tar xf t.tar; stat -c %h d/a d/b;
         [ "$(stat -c %i d/a)" = "$(stat -c %i d/b)" ] && echo same-ino;
         cat d/b'

    l2s_diff "binary content through a link (cmp)" \
        'cd /tmp; cp /bin/busybox f1; ln f1 f2; cmp f1 f2 && echo cmp-ok;
         stat -c %h f2'

    # A group whose data file cannot be opened. The marker update used to be
    # serialized by an flock on the data file itself, opened for reading, so a
    # mode 0000 or 0200 file — which packages do ship — ran the update
    # unlocked, and two links or unlinks of the group at once could leave
    # st_nlink wrong or a backing file behind. The lock is a file of our own
    # in the store now; the group's own modes are irrelevant to it.
    l2s_diff "ln and rm of an unreadable and a write-only file" \
        'cd /tmp; echo hi>a; chmod 000 a; ln a b; ln b c; stat -c "%h %a" a b c;
         rm b; stat -c %h a c; echo w>w; chmod 200 w; ln w w2; rm w;
         stat -c "%h %a" w2; chmod 644 w2; cat w2'
    # ...and the emulator says so itself: an update it had to run unlocked is
    # logged, and there must be none.
    REM=$(mktemp -d); cp -a "$M10_ALPINE/." "$REM"
    err=$(CNG_DEBUG=1 run -R -l "$REM" /bin/sh -c \
        'cd /tmp; echo hi>a; chmod 000 a; ln a b; ln b c; rm b; rm c' 2>&1 >/dev/null)
    check_absent "m10 the marker update of an unreadable group was locked" \
        "unlocked update" "$err"
    rm -rf "$REM"

    # Persistence: links made in one session must look identical in the
    # next (fresh process, same rootfs) — the on-disk store alone carries
    # the state.
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    s1='cd /tmp; echo hi>a; ln a b; stat -c %h a'
    s2='cd /tmp; stat -c %h a b;
        [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino; cat b;
        readlink b; echo rc=$?; ls -a'
    o1=$("$M10_ORACLE" "$RO" /bin/sh -c "$s1" 2>/dev/null)
    o2=$("$M10_ORACLE" "$RO" /bin/sh -c "$s2" 2>/dev/null); rc_o=$?
    e1=$(run -R -l "$REM" /bin/sh -c "$s1" 2>/dev/null)
    e2=$(run -R -l "$REM" /bin/sh -c "$s2" 2>/dev/null); rc_e=$?
    if [ "$o1" = "$e1" ] && [ "$o2" = "$e2" ] && [ "$rc_o" = "$rc_e" ]; then
        pass=$((pass + 1)); echo "  ok   m10 persistence across sessions"
    else
        fail=$((fail + 1)); echo "  FAIL m10 persistence across sessions"
        echo "    oracle: [$o1|$o2] rc=$rc_o"
        echo "    chroot: [$e1|$e2] rc=$rc_e"
    fi
    rm -rf "$RO" "$REM"

    # A rootfs copied with `cp -a` is a tree of its own: real hardlinks come
    # out of the copy as groups of the copy's. The emulated ones keep their
    # text, which names the ORIGINAL's store, and a link was taken for what
    # its text named — so the copy's `rm` of both names deleted the
    # original's data, and the original's names were left dangling. A tree
    # of busybox and its loader is enough, and saves copying the whole image
    # four times.
    RO=$(mktemp -d); REM=$(mktemp -d)
    for _r in "$RO/r" "$REM/r"; do
        mkdir -p "$_r/bin" "$_r/lib" "$_r/tmp"
        cp "$M10_ALPINE/bin/busybox" "$_r/bin/busybox"
        ln -s busybox "$_r/bin/sh"
        cp "$M10_ALPINE/lib/ld-musl-aarch64.so.1" "$_r/lib/"
    done
    s1='cd /tmp; echo orig > a; busybox ln a b; busybox stat -c %h a'
    s2='cd /tmp; echo copy >> a; busybox cat b; busybox stat -c %h a b;
        busybox rm a b; busybox ls -a'
    s3='cd /tmp; busybox cat a; busybox stat -c %h a b'
    o1=$("$M10_ORACLE" "$RO/r" /bin/sh -c "$s1" 2>/dev/null)
    e1=$(run -R -l "$REM/r" /bin/sh -c "$s1" 2>/dev/null)
    cp -a "$RO/r" "$RO/c"; cp -a "$REM/r" "$REM/c"
    o2=$("$M10_ORACLE" "$RO/c" /bin/sh -c "$s2" 2>/dev/null)
    e2=$(run -R -l "$REM/c" /bin/sh -c "$s2" 2>/dev/null)
    o3=$("$M10_ORACLE" "$RO/r" /bin/sh -c "$s3" 2>/dev/null); rc_o=$?
    e3=$(run -R -l "$REM/r" /bin/sh -c "$s3" 2>/dev/null); rc_e=$?
    if [ "$o1|$o2|$o3" = "$e1|$e2|$e3" ] && [ "$rc_o" = "$rc_e" ] &&
        [ -n "$o3" ]; then
        pass=$((pass + 1)); echo "  ok   m10 a copied rootfs leaves the original's groups alone"
    else
        fail=$((fail + 1)); echo "  FAIL m10 a copied rootfs leaves the original's groups alone"
        echo "    oracle: [$o1|$o2|$o3] rc=$rc_o"
        echo "    chroot: [$e1|$e2|$e3] rc=$rc_e"
    fi
    rm -rf "$RO" "$REM"
fi

# proot-distro's groups. A rootfs installed through proot-distro holds the
# hardlinks proot made: every name a symlink holding the HOST path of an
# indirection symlink in "<rootfs>/.l2s", which names the data file beside it,
# "<indirection>.<CCCC>", CCCC the live count. They are laid down here by hand
# as proot writes them, and for the oracle as the real hardlinks they stand
# for; the same script must print the same bytes. A third group's texts name
# an old rootfs path (a moved tree), a fourth is proot's layout without
# PROOT_L2S_DIR (the chain beside the first name). Then the tree must be what
# proot itself would leave, so it goes on working under proot: the counts in
# the names, the indirections naming the data, the moved group's texts
# repointed, the groups whose last name went gone. Before, every name was a
# symlink dangling into "<rootfs><rootfs>/.l2s".
if [ "$m10_ready" -eq 1 ]; then
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    P=$(cd "$REM" && pwd -P)
    mkdir -p "$RO/g/s" "$RO/h" "$REM/g/s" "$REM/h" "$REM/.l2s"
    printf 'hello\n' > "$RO/g/a"; ln "$RO/g/a" "$RO/g/b"; ln "$RO/g/a" "$RO/g/s/c"
    printf 'hello\n' > "$REM/.l2s/.l2s.a0001.0003"
    ln -s "$P/.l2s/.l2s.a0001.0003" "$REM/.l2s/.l2s.a0001"
    for _n in a b s/c; do ln -s "$P/.l2s/.l2s.a0001" "$REM/g/$_n"; done
    cp "$M10_ALPINE/bin/busybox" "$RO/g/echo"; ln "$RO/g/echo" "$RO/g/true"
    cp "$M10_ALPINE/bin/busybox" "$REM/.l2s/.l2s.echo0001.0002"
    ln -s "$P/.l2s/.l2s.echo0001.0002" "$REM/.l2s/.l2s.echo0001"
    for _n in echo true; do ln -s "$P/.l2s/.l2s.echo0001" "$REM/g/$_n"; done
    _old=/nonexistent/old-rootfs/.l2s
    printf 'moved\n' > "$RO/g/m1"; ln "$RO/g/m1" "$RO/g/m2"
    printf 'moved\n' > "$REM/.l2s/.l2s.m10001.0002"
    ln -s "$_old/.l2s.m10001.0002" "$REM/.l2s/.l2s.m10001"
    for _n in m1 m2; do ln -s "$_old/.l2s.m10001" "$REM/g/$_n"; done
    printf 'beside\n' > "$RO/h/p"; ln "$RO/h/p" "$RO/g/q"
    printf 'beside\n' > "$REM/h/.l2s.p0001.0002"
    ln -s "$P/h/.l2s.p0001.0002" "$REM/h/.l2s.p0001"
    ln -s "$P/h/.l2s.p0001" "$REM/h/p"; ln -s "$P/h/.l2s.p0001" "$REM/g/q"
    s='cd /g; stat -c "%h %F %s" a b s/c;
       [ "$(stat -c %i a)" = "$(stat -c %i s/c)" ] && echo same-ino;
       cat s/c; readlink b; echo rl=$?; ls -a . s; find . -type f | sort;
       ln b d; stat -c %h a d; rm a; stat -c %h b d s/c; mv b s/c; echo mv=$?;
       stat -c %h b s/c d; echo new > n; mv n d; stat -c %h b s/c d; cat d b;
       ./echo via-member; stat -c %h echo true;
       stat -c %h m1 m2; cat m2; ln m1 m3; rm m1; stat -c %h m2 m3;
       stat -c %h q /h/p; cat q; rm /h/p q; ls -a /h; rm b s/c; ls -a . s'
    out_o=$("$M10_ORACLE" "$RO" /bin/sh -c "$s" 2>/dev/null); rc_o=$?
    out_e=$(run -R -l "$REM" /bin/sh -c "$s" 2>/dev/null); rc_e=$?
    if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
        pass=$((pass + 1)); echo "  ok   m10 proot-distro's groups read as hardlinks"
    else
        fail=$((fail + 1)); echo "  FAIL m10 proot-distro's groups read as hardlinks"
        echo "    oracle rc=$rc_o: $(printf %s "$out_o" | head -c 600)"
        echo "    chroot rc=$rc_e: $(printf %s "$out_e" | head -c 600)"
    fi
    left=$(cd "$REM" && ls -A .l2s | grep -v '^\.lock$' | tr '\n' ' ';
        readlink .l2s/.l2s.echo0001 .l2s/.l2s.m10001 g/echo g/m2 g/m3 |
            sed "s|^$P|P|" | tr '\n' ' '; ls -A h | tr '\n' ' ')
    check "m10 ...and proot's bookkeeping is what proot would leave" \
        ".l2s.echo0001 .l2s.echo0001.0002 .l2s.m10001 .l2s.m10001.0002 P/.l2s/.l2s.echo0001.0002 P/.l2s/.l2s.m10001.0002 P/.l2s/.l2s.echo0001 P/.l2s/.l2s.m10001 P/.l2s/.l2s.m10001 " \
        "$left"
    rm -rf "$RO" "$REM"
fi

# The dirents themselves. Every leg above goes through busybox, which stats
# each entry it lists, so a record that lies about a link — the kernel's is the
# symlink's own: DT_LNK, the link's inode — never showed. GNU ls -F, find
# -type f and ls -i read the record instead. A compiled guest reads the
# directory raw and prints each entry's d_type and whether d_ino is what stat()
# and lstat() of the same name answer; with real hardlinks a link is "REG
# same same", and the emulation has to print the same line. The links are
# made in three shapes: beside the file, cross-directory (the group joined
# through the store), and after the tree is moved, which leaves the links'
# absolute targets stale until the first stat heals them — a listing must
# say what that stat will.
if [ "$m10_ready" -eq 1 ] && guest_xlate_ready "l2s raw-dirent leg" &&
    guest_cc_report "$CNG_TMP/dents" tests/guests/dents.c; then
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    cp "$CNG_TMP/dents" "$RO/bin/dents"; cp "$CNG_TMP/dents" "$REM/bin/dents"
    s1='cd /tmp; mkdir d d/sub; cd d; echo hi>a; ln a b; ln -s a s; ln a sub/c;
        /bin/dents . | sort; /bin/dents sub | sort'
    s2='cd /tmp/d; /bin/dents . | sort; /bin/dents sub | sort; stat -c %h a b sub/c'
    o1=$("$M10_ORACLE" "$RO" /bin/sh -c "$s1" 2>/dev/null)
    e1=$(run -R -l "$REM" /bin/sh -c "$s1" 2>/dev/null)
    mv "$RO" "$RO.moved"; mv "$REM" "$REM.moved"
    RO="$RO.moved"; REM="$REM.moved"
    o2=$("$M10_ORACLE" "$RO" /bin/sh -c "$s2" 2>/dev/null); rc_o=$?
    e2=$(run -R -l "$REM" /bin/sh -c "$s2" 2>/dev/null); rc_e=$?
    if [ "$o1" = "$e1" ] && [ "$o2" = "$e2" ] && [ "$rc_o" = "$rc_e" ] &&
        [ -n "$o1" ]; then
        pass=$((pass + 1)); echo "  ok   m10 raw dirents: d_type/d_ino of the links"
    else
        fail=$((fail + 1)); echo "  FAIL m10 raw dirents: d_type/d_ino of the links"
        echo "    oracle rc=$rc_o: $(printf %s "$o1|$o2" | head -c 600)"
        echo "    chroot rc=$rc_e: $(printf %s "$e1|$e2" | head -c 600)"
    fi
    rm -rf "$RO" "$REM"
fi

# First links of one file, made at once. A first link moves the file into the
# store and leaves a symlink in its name. Made unlocked, two at once lost the
# file (the later moved the earlier's symlink over the data), a linker that
# found the symlink, or no name at all between the rename and the symlink,
# failed, and a reader saw the name missing or drew ELOOP on it. Eight linkers
# and a reader per round: with real hardlinks every count is 0, so the kernel's
# answer is known and no oracle is needed.
if guest_xlate_ready "l2s first-link race leg" &&
    guest_cc_report "$CNG_TMP/l2srace" tests/guests/l2srace.c; then
    R=$(mktemp -d)
    mkdir -p "$R/bin" "$R/w"
    cp "$CNG_TMP/l2srace" "$R/bin/l2srace"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run_t 300 $GUEST_BINDS -R -l "$R" /bin/l2srace /w 30 2>/dev/null)
    check_contains "m10 first links at once: none fails or loses the file, no reader sees it go" \
        "linkfail=0 miss=0 lost=0 nlinkbad=0 inobad=0" "$out"
    rm -rf "$R"
fi

# A link and an unlink from a signal handler that interrupted another. Every
# count change holds the store lock (an flock) across several syscalls, and on
# the -R tier the dispatcher runs on the guest's own signal mask: a handler
# delivered inside one that linked or unlinked a name itself waited for the
# lock its own thread held, forever. The timer's delay is swept across the time
# one link+unlink takes; with real hardlinks every call succeeds and the group
# ends with its two names, so no oracle is needed. A hang is the bug.
if guest_xlate_ready "l2s link from a signal handler leg" &&
    guest_cc_report "$CNG_TMP/l2ssig" tests/guests/l2ssig.c; then
    R=$(mktemp -d)
    mkdir -p "$R/bin" "$R/w"
    cp "$CNG_TMP/l2ssig" "$R/bin/l2ssig"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run_t 120 $GUEST_BINDS -R -l "$R" /bin/l2ssig /w 2>/dev/null)
    check_contains "m10 a link from a handler that interrupted another" \
        "l2ssig: handled>0=1 bad=0 nlink=2" "$out"
    rm -rf "$R"
fi

# A fork by another thread while one links. The lock is an flock, which belongs
# to the open file: a child forked while it was held kept a duplicate of that
# file, and the close that gave the lock back left it held until the child
# exec'd or exited, so the next change of any group waited out the child.
# Children that wait without exec'ing are forked under a loop of links; with
# real hardlinks no pair is held up.
if guest_xlate_ready "l2s link beside a fork leg" &&
    guest_cc_report "$CNG_TMP/l2sfork" tests/guests/l2sfork.c -pthread; then
    R=$(mktemp -d)
    mkdir -p "$R/bin" "$R/w"
    cp "$CNG_TMP/l2sfork" "$R/bin/l2sfork"
    # shellcheck disable=SC2086  # $GUEST_BINDS is a deliberately split arg list
    out=$(run_t 120 $GUEST_BINDS -R -l "$R" /bin/l2sfork /w 2>/dev/null)
    check_contains "m10 a fork while the lock is held does not keep it" \
        "l2sfork: stalled=0 bad=0" "$out"
    rm -rf "$R"
fi

# Debian leg: glibc + GNU coreutils/findutils (`find -samefile`, GNU stat).
# Gated on a smoke test proving translation is live — a dynamic-glibc guest
# under -R + qemu can silently run untranslated (ld.so-loaded libc.so has no
# rewritten svc sites), which would read the HOST's /etc, not the guest's.
if [ "$m10_ready" -eq 1 ] && [ -n "$M10_DEBIAN" ] && [ -x "$M10_DEBIAN/bin/ls" ]; then
    RD=$(mktemp -d)
    cp -a "$M10_DEBIAN/." "$RD"
    smoke=$(run -R -l "$RD" /bin/sh -c 'head -1 /etc/os-release' 2>/dev/null)
    case "$smoke" in
    *[Dd]ebian*)
        RDO=$(mktemp -d)
        cp -a "$M10_DEBIAN/." "$RDO"
        ds='cd /tmp; mkdir d; cd d; echo hi>a; ln a b; stat -c %h a b;
            [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino;
            find . -samefile a | sort; cat b'
        out_o=$("$M10_ORACLE" "$RDO" /bin/sh -c "$ds" 2>/dev/null); rc_o=$?
        out_e=$(run -R -l "$RD" /bin/sh -c "$ds" 2>/dev/null); rc_e=$?
        if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
            pass=$((pass + 1)); echo "  ok   m10 debian: GNU stat + find -samefile"
        else
            fail=$((fail + 1)); echo "  FAIL m10 debian: GNU stat + find -samefile"
            echo "    oracle rc=$rc_o: $(printf %s "$out_o" | head -c 300)"
            echo "    chroot rc=$rc_e: $(printf %s "$out_e" | head -c 300)"
        fi
        rm -rf "$RDO"
        ;;
    *)
        skip "debian glibc guest not translating under -R (got '$smoke')"
        ;;
    esac
    rm -rf "$RD"
elif [ "$m10_ready" -eq 1 ]; then
    skip "debian leg: no debian rootfs"
fi

unset CNG_L2S_FORCE
