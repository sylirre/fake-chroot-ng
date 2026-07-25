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
echo "== M10: l2s shell (differential vs arm64chroot real hardlinks) =="

M10_ORACLE="${M10_ORACLE:-/home/sol/arm64chroot/arm64chroot}"
M10_ALPINE="${M10_ALPINE:-/home/sol/arm64chroot/tests/.cache/rootfs/alpine}"
M10_DEBIAN="${M10_DEBIAN:-/home/sol/arm64-rootfs/debian-fresh}"

CNG_L2S_FORCE=1
export CNG_L2S_FORCE   # chroot-ng only; the oracle ignores it

m10_ready=0
if [ -x "$M10_ORACLE" ] && [ -x "$M10_ALPINE/bin/busybox" ]; then
    # Sanity: the oracle must produce real hardlinks (l2s compiled out).
    SAN=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$SAN"
    san=$("$M10_ORACLE" "$SAN" /bin/sh -c \
        'cd /tmp; echo x>a; ln a b; stat -c %h a' 2>/dev/null)
    rm -rf "$SAN"
    if [ "$san" = "2" ]; then
        m10_ready=1
    else
        echo "  skip: oracle does not produce real hardlinks (got '$san')"
    fi
else
    echo "  skip: oracle or alpine rootfs missing"
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
fi

# Debian leg: glibc + GNU coreutils/findutils (`find -samefile`, GNU stat).
# Gated on a smoke test proving translation is live — a dynamic-glibc guest
# under -R + qemu can silently run untranslated (ld.so-loaded libc.so has no
# rewritten svc sites), which would read the HOST's /etc, not the guest's.
if [ "$m10_ready" -eq 1 ] && [ -x "$M10_DEBIAN/bin/ls" ]; then
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
        echo "  skip: debian glibc guest not translating under -R (got '$smoke')"
        ;;
    esac
    rm -rf "$RD"
elif [ "$m10_ready" -eq 1 ]; then
    echo "  skip: debian rootfs missing"
fi

unset CNG_L2S_FORCE
