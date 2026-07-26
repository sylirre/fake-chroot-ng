# chroot-ng test harness — platform layer (sourced first by tests/run.sh).
#
# The suite has to run on three hosts, and every difference between them is
# resolved here rather than inside the milestone scripts:
#
#   Linux x86_64      cross-built binary; chroot-ng and every AArch64 guest run
#                     under qemu-aarch64.  qemu-user does not apply a guest's
#                     seccomp filter, so the SIGSYS tier is INERT there and the
#                     -R (svc-rewriting) tier is what carries translation.
#   Linux aarch64     native: no emulator, and the seccomp/SIGSYS tier is LIVE.
#   Termux (Android)  native as well, but the guest toolchain is bionic clang:
#                     -static-pie may not link, so compiled guests can be
#                     dynamic and then need the platform linker's directories
#                     bound into a synthetic rootfs.
#
# What the milestone scripts get from here:
#
#   run / run_t          run $BIN (chroot-ng), optionally under a timeout
#   emu / emu_t          run any other AArch64 program the same way
#   guest_cc OUT SRC     build a tests/guests/*.c program; rc 2 = no toolchain
#   GUEST_BINDS          -b args a dynamic guest needs inside a fresh rootfs
#   GUEST_LD_DESC        human name of the link mode in use
#   CNG_SECCOMP_LIVE     1 when the in-process monitor really traps syscalls
#   CNG_EXECMEM          1 when anon RW->RX memory is permitted
#   CNG_GUEST_XLATE      1 when a compiled guest's own path syscalls get
#                        translated here (see guest_xlate_ready)
#   CNG_ALPINE/_DEBIAN/_ORACLE  rootfs + differential-oracle locations
#   skip MSG             uniform, counted "  skip <msg>" reporting
#   elf_type / elf_machine / elf_has_interp   ELF facts without file(1)
#
# Overridable from the environment: BIN, QEMU (set empty to force direct
# execution), GUESTCC, GUESTLD, GUEST_BINDS, CNG_ROOTFS_DIR, CNG_ALPINE,
# CNG_DEBIAN, CNG_ORACLE, CNG_SYSROOT. See tests/README.md.

pass=${pass:-0}
fail=${fail:-0}
skipped=${skipped:-0}

BIN="${BIN:-build/chroot-ng}"

have() { command -v "$1" >/dev/null 2>&1; }

# skip DESC — a leg that cannot be exercised on this host. Counted so the
# summary never reads like full coverage when half the suite sat out.
skip() {
    skipped=$((skipped + 1))
    printf '  skip %s\n' "$1"
}

# ---- running AArch64 programs ---------------------------------------------
# On an AArch64 host $QEMU is empty and everything runs directly; elsewhere the
# emulator prefixes the command line. Kept as functions rather than a variable
# so an empty $QEMU never becomes an empty argv[0].

emu() {
    if [ -n "$QEMU" ]; then "$QEMU" "$@"; else "$@"; fi
}

# emu_t SECS CMD... — as emu, but bounded: a test that blocks (a netlink dump
# that never terminates, a socket that never accepts) should fail one check
# rather than wedge the suite.
emu_t() {
    _t=$1
    shift
    if [ -z "$TIMEOUT" ]; then emu "$@"
    elif [ -n "$QEMU" ]; then "$TIMEOUT" "$_t" "$QEMU" "$@"
    else "$TIMEOUT" "$_t" "$@"
    fi
}

run() { emu "$BIN" "$@"; }
run_t() {
    _t=$1
    shift
    emu_t "$_t" "$BIN" "$@"
}

# ---- ELF facts, without file(1) (absent on a bare Termux) ------------------
# e_type at offset 16, e_machine at 18, both 2-byte little-endian; od's native
# byte order matches on every host we target (x86_64 / AArch64 LE).

elf_u16() { od -An -tu2 -j"$2" -N2 "$1" 2>/dev/null | tr -d ' \n'; }

# elf_type FILE -> EXEC | DYN | other-numeric | empty
elf_type() {
    case "$(elf_u16 "$1" 16)" in
    2) echo EXEC ;;
    3) echo DYN ;;
    "") echo "" ;;
    *) elf_u16 "$1" 16 ;;
    esac
}

# elf_machine FILE -> e_machine (183 == EM_AARCH64)
elf_machine() { elf_u16 "$1" 18; }

elf_is_aarch64() { [ "$(elf_machine "$1")" = 183 ]; }

# elf_has_interp FILE — true for a dynamically linked executable. readelf when
# there is one; otherwise the .interp section name, which only appears in the
# section-header string table of an object that has the segment.
elf_has_interp() {
    for _re in readelf llvm-readelf aarch64-linux-gnu-readelf; do
        if have "$_re"; then
            "$_re" -l "$1" 2>/dev/null | grep -q INTERP
            return $?
        fi
    done
    LC_ALL=C grep -aq '\.interp' "$1"
}

# ---- platform detection ----------------------------------------------------

cng_detect_host() {
    HOST_ARCH=$(uname -m 2>/dev/null || echo unknown)
    case "$HOST_ARCH" in
    aarch64 | arm64) CNG_NATIVE=1 ;;
    *) CNG_NATIVE=0 ;;
    esac

    CNG_TERMUX=0
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux/files/usr ]; then
        CNG_TERMUX=1
    fi
    case "${PREFIX:-}" in
    */com.termux/*) CNG_TERMUX=1 ;;
    esac

    # QEMU: an explicit setting always wins, INCLUDING an empty one — that is how
    # to force direct execution on a cross host that runs AArch64 binaries some
    # other way (a binfmt_misc handler), or to override the auto-picked build.
    CNG_EMU_MISSING=0
    if [ "${QEMU+x}" != x ]; then
        QEMU=
        if [ "$CNG_NATIVE" = 0 ]; then
            for _q in qemu-aarch64-static qemu-aarch64; do
                if have "$_q"; then
                    QEMU=$_q
                    break
                fi
            done
            [ -n "$QEMU" ] || CNG_EMU_MISSING=1
        fi
    fi

    TIMEOUT=
    have timeout && TIMEOUT=timeout
}

# ---- guest toolchain ------------------------------------------------------
# The milestone scripts build small AArch64 programs (tests/guests/*.c) to drive
# chroot-ng as a real guest would. Which compiler that is, and whether it can
# link statically, is entirely host-dependent — so probe rather than assume, and
# prove the result by running it.

cng_detect_guestcc() {
    # Every one of these has to be defined before the first early return: the
    # milestone scripts run under `set -u` and read them whether or not a
    # toolchain turned up. Note the explicitness of GUESTLD is captured before it
    # is defaulted, since "set to empty" means "dynamic, no fallback".
    if [ "${GUESTLD+x}" = x ]; then _ld_explicit=1; else _ld_explicit=0; fi
    GUESTLD=${GUESTLD-}
    GUEST_STATIC=0
    GUEST_BINDS=${GUEST_BINDS:-}
    GUEST_LD_DESC=none
    GUEST_CC_LOG=$CNG_TMP/guest_cc.log

    if [ -n "${GUESTCC:-}" ]; then
        have "$GUESTCC" || {
            GUESTCC=
            return 1
        }
    else
        # A native compiler is only a candidate on an AArch64 host; on x86_64 an
        # unprefixed gcc would happily build an x86 binary and every guest test
        # would then fail for the wrong reason.
        if [ "$CNG_NATIVE" = 1 ]; then
            set -- aarch64-linux-gnu-gcc-13 aarch64-linux-gnu-gcc cc gcc clang
        else
            set -- aarch64-linux-gnu-gcc-13 aarch64-linux-gnu-gcc-12 \
                aarch64-linux-gnu-gcc aarch64-linux-musl-gcc
        fi
        GUESTCC=
        for _c in "$@"; do
            if have "$_c"; then
                GUESTCC=$_c
                break
            fi
        done
        [ -n "$GUESTCC" ] || return 1
    fi

    printf 'int main(void){return 7;}\n' >"$CNG_TMP/ldprobe.c"
    # Most of the suite needs a self-contained guest it can drop into a synthetic
    # rootfs, so prefer static-PIE, then plain static, and only fall back to
    # dynamic (Termux/bionic, where there is no libc.a to link against). An
    # explicit GUESTLD is honoured exactly, with no fallback.
    if [ "$_ld_explicit" = 1 ]; then
        cng_try_guest_ld "$GUESTLD" && return 0
        GUESTCC=
        GUESTLD=
        return 1
    fi
    for _m in -static-pie -static ""; do
        cng_try_guest_ld "$_m" && return 0
    done
    GUESTCC=
    GUESTLD=
    return 1
}

# cng_try_guest_ld MODE — can $GUESTCC build an AArch64 binary this way, and does
# the result actually run here? Sets GUESTLD/GUEST_STATIC/GUEST_LD_DESC on yes.
cng_try_guest_ld() {
    rm -f "$CNG_TMP/ldprobe"
    # shellcheck disable=SC2086  # $1 is a single flag or deliberately empty
    $GUESTCC $1 -O0 -o "$CNG_TMP/ldprobe" "$CNG_TMP/ldprobe.c" \
        2>"$GUEST_CC_LOG" || return 1
    elf_is_aarch64 "$CNG_TMP/ldprobe" || return 1
    emu_t 30 "$CNG_TMP/ldprobe" >/dev/null 2>&1
    [ $? = 7 ] || return 1
    GUESTLD=$1
    case "$1" in
    "")
        GUEST_STATIC=0
        GUEST_LD_DESC=dynamic
        ;;
    -static-pie)
        GUEST_STATIC=1
        GUEST_LD_DESC=static-pie
        ;;
    *)
        GUEST_STATIC=1
        GUEST_LD_DESC=$1
        ;;
    esac
    [ "$GUEST_STATIC" = 1 ] || cng_guest_binds
    return 0
}

# A dynamically linked guest resolves its ELF interpreter and libraries through
# the guest view, so a synthetic rootfs holding nothing but the binary cannot
# start it — chroot-ng reports "cannot load interpreter <rootfs>/lib/ld-...".
# Expose the host directories the loader needs at the same guest paths. (Only for
# rootfs the suite builds itself — never for a real Alpine/Debian tree, which
# ships its own.) Preset GUEST_BINDS in the environment for an unusual layout.
cng_guest_binds() {
    [ -z "${GUEST_BINDS:-}" ] || return 0
    GUEST_BINDS=
    for _d in /system /apex /linkerconfig /vendor /lib /lib64 /usr/lib \
        /usr/lib64 ${PREFIX:+"$PREFIX"}; do
        [ -d "$_d" ] || continue
        GUEST_BINDS="$GUEST_BINDS -b $_d:$_d"
    done
}

# guest_cc OUT SRC [flags...] — build an AArch64 guest program.
#   rc 0   built
#   rc 1   build failed (diagnostics in $GUEST_CC_LOG) — a real failure
#   rc 2   no usable guest toolchain on this host — the caller should skip
guest_cc() {
    [ -n "$GUESTCC" ] || return 2
    _out=$1
    _src=$2
    shift 2
    # shellcheck disable=SC2086  # $GUESTLD is a flag or deliberately empty
    $GUESTCC $GUESTLD -O2 -o "$_out" "$_src" "$@" 2>"$GUEST_CC_LOG"
}

# guest_xlate_ready WHAT — can this host observe a compiled guest's OWN path
# syscalls being translated at all? Emits the reason and returns 1 if not, so a
# milestone that depends on it says which of the two prerequisites is missing.
guest_xlate_ready() {
    if [ -z "$GUESTCC" ]; then
        skip "$1: no AArch64 guest toolchain"
        return 1
    fi
    if [ "$CNG_GUEST_XLATE" = 0 ]; then
        skip "$1: seccomp inert here and the guest links dynamically, so neither tier reaches libc's svc sites"
        return 1
    fi
    return 0
}

# guest_cc_report OUT SRC — build, and on failure emit the right diagnosis:
# "skip" where no toolchain exists, a counted FAIL where one does and broke.
guest_cc_report() {
    guest_cc "$@"
    _rc=$?
    case $_rc in
    0) return 0 ;;
    2) skip "no AArch64 guest toolchain: cannot build $2" ;;
    *)
        fail=$((fail + 1))
        printf '  FAIL could not build %s\n' "$2"
        sed 's/^/    /' "$GUEST_CC_LOG" 2>/dev/null | head -8
        ;;
    esac
    return 1
}

# ---- chroot-ng capabilities on THIS host ----------------------------------
# Which tier is live changes what the suite may assert: with the filter inert
# (qemu-user) an untranslated run is the expected outcome, and on a real AArch64
# kernel the very same run must come back translated. Ask the binary rather than
# inferring it from uname.

cng_probe_caps() {
    CNG_SECCOMP_LIVE=0
    CNG_EXECMEM=0
    CNG_PROBE_OUT=$(run --probe / 2>&1)
    case "$CNG_PROBE_OUT" in
    *"filter RET_ERRNO    WORKS"*) CNG_SECCOMP_LIVE=1 ;;
    esac
    case "$CNG_PROBE_OUT" in
    *"RESULT    OK"*) CNG_EXECMEM=1 ;;
    esac
}

# ---- guest rootfs images + the differential oracle ------------------------
# Several milestones need a real AArch64 userland (Alpine busybox, Debian glibc)
# and M10 needs the arm64chroot oracle. None of that can be assumed present, so
# search a few locations and let the milestone skip cleanly.

# cng_find_rootfs NAME MARKER — first candidate dir containing MARKER, or empty.
cng_find_rootfs() {
    for _c in ${CNG_ROOTFS_DIR:+"$CNG_ROOTFS_DIR/$1"} \
        "tests/.cache/rootfs/$1" \
        ${HOME:+"$HOME/arm64chroot/tests/.cache/rootfs/$1"} \
        ${HOME:+"$HOME/arm64-rootfs/$1"}; do
        if [ -x "$_c/$2" ]; then
            echo "$_c"
            return 0
        fi
    done
    echo ""
}

cng_detect_images() {
    CNG_ALPINE="${CNG_ALPINE:-$(cng_find_rootfs alpine bin/busybox)}"
    CNG_DEBIAN="${CNG_DEBIAN:-$(cng_find_rootfs debian-fresh bin/ls)}"
    [ -n "$CNG_DEBIAN" ] || CNG_DEBIAN="$(cng_find_rootfs debian bin/ls)"

    # The oracle is a host-native emulator, not an AArch64 program: usable only
    # where its own machine matches this host.
    CNG_ORACLE="${CNG_ORACLE:-}"
    if [ -z "$CNG_ORACLE" ]; then
        for _o in ${HOME:+"$HOME/arm64chroot/arm64chroot"}; do
            [ -x "$_o" ] || continue
            CNG_ORACLE=$_o
            break
        done
    fi
    if [ -n "$CNG_ORACLE" ]; then
        _m=$(elf_machine "$CNG_ORACLE")
        case "$HOST_ARCH:$_m" in
        x86_64:62 | aarch64:183 | arm64:183) : ;;
        *) CNG_ORACLE= ;;
        esac
    fi
}

# ---- init ------------------------------------------------------------------

cng_platform_init() {
    CNG_TMP=$(mktemp -d)
    cng_detect_host
    cng_detect_guestcc || :
    cng_probe_caps
    cng_detect_images

    # Will a compiled guest's OWN path syscalls really be translated? The seccomp
    # tier catches every guest; where it is inert (qemu-user) only -R rewriting is
    # left, and that reaches the svc sites in the objects the loader maps — not
    # the libc.so a dynamic guest's ld.so maps afterwards. So the legs that assert
    # translation from inside a compiled guest need one of the two.
    CNG_GUEST_XLATE=0
    if [ "$CNG_SECCOMP_LIVE" = 1 ] || [ "$GUEST_STATIC" = 1 ]; then
        CNG_GUEST_XLATE=1
    fi
}

cng_platform_banner() {
    printf '== platform ==\n'
    printf '  host          %s%s\n' "$HOST_ARCH" \
        "$([ "$CNG_TERMUX" = 1 ] && echo ' (Termux/Android)')"
    printf '  exec          %s\n' \
        "$([ -n "$QEMU" ] && echo "$QEMU" || echo 'native (no emulator)')"
    printf '  seccomp tier  %s\n' \
        "$([ "$CNG_SECCOMP_LIVE" = 1 ] && echo 'live' ||
            echo 'inert (-R rewriting carries translation)')"
    printf '  execmem       %s\n' \
        "$([ "$CNG_EXECMEM" = 1 ] && echo 'permitted' || echo 'DENIED')"
    printf '  guest cc      %s\n' \
        "$([ -n "$GUESTCC" ] && echo "$GUESTCC ($GUEST_LD_DESC)" ||
            echo 'none — guest-binary legs will skip')"
    printf '  alpine rootfs %s\n' "${CNG_ALPINE:-none}"
    printf '  debian rootfs %s\n' "${CNG_DEBIAN:-none}"
    printf '  l2s oracle    %s\n' "${CNG_ORACLE:-none}"
}
