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
#   cng_rootfs NAME fetch  provision a pinned rootfs image on demand
#   skip MSG             uniform, counted "  skip <msg>" reporting
#   elf_type / elf_machine / elf_has_interp   ELF facts without file(1)
#
# Overridable from the environment: BIN, QEMU (set empty to force direct
# execution), GUESTCC, GUESTLD, GUEST_BINDS, CNG_ROOTFS_DIR, CNG_ROOTFS_FETCH,
# CNG_ALPINE, CNG_DEBIAN, CNG_ORACLE, CNG_SYSROOT. See tests/README.md.

pass=${pass:-0}
fail=${fail:-0}
skipped=${skipped:-0}

BIN="${BIN:-build/chroot-ng}"

have() { command -v "$1" >/dev/null 2>&1; }

# The host's sh by a name the host kernel can follow from a #! line. Not
# /bin/sh: Android had no /bin before 10, and termux-exec's rewrite of the name
# reaches only the first level of a script whose interpreter is a script.
HOST_SH=$(command -v sh)

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

# kref CMD... — run a host-built reference, the stand-in for "what the kernel
# answers" in a differential. Termux preloads libtermux-exec into every process,
# and it wraps execve: the exec probes of a reference run answered EACCES for a
# path the kernel calls ENOTDIR or ENOENT, which is the shim's verdict and not
# the kernel's. A guest under chroot-ng never carries the preload (its
# environment is the one it was given), so the reference is run without it.
kref() { env -u LD_PRELOAD "$@"; }

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
#
# Bionic's linker reads nothing under /lib, and binding it anyway is not
# harmless: an Android ramdisk may carry a /lib of its own (/lib/modules on
# Android 8), and the bind then hides the test rootfs's /lib — M19's
# lib/apk/exec among it. So an Android host binds Android's directories only.
cng_guest_binds() {
    [ -z "${GUEST_BINDS:-}" ] || return 0
    GUEST_BINDS=
    if [ -e /system/bin/linker64 ]; then
        set -- /system /apex /linkerconfig /vendor
    else
        set -- /lib /lib64 /usr/lib /usr/lib64
    fi
    for _d in "$@" ${PREFIX:+"$PREFIX"}; do
        [ -d "$_d" ] || continue
        GUEST_BINDS="$GUEST_BINDS -b $_d:$_d"
    done
}

# cng_outside_binds DIR — where a scratch tree may be put in front of the
# arm64chroot oracle. The oracle spells a guest path with the longest HOST prefix
# it finds, and a rootfs that sits inside a directory $GUEST_BINDS exposes is then
# spelled as the bind: Termux's $TMPDIR is inside $PREFIX, which is bound for the
# linker, so the oracle's getcwd answered "/data/data/.../tmp.X/a/b" for a guest
# whose cwd is /a/b — chroot-ng answers /a/b there, as the kernel's chroot would,
# so the reference is the one at fault. Prints DIR itself when no bind contains it;
# otherwise DIR is moved under $HOME, where none does, and the new name is
# printed. Callers re-point their variable and clean up as before.
cng_outside_binds() {
    _real=$(cd "$1" 2>/dev/null && pwd -P) || {
        printf '%s\n' "$1"
        return 0
    }
    _in=0
    for _w in $GUEST_BINDS; do
        [ "$_w" = -b ] && continue
        case "$_real/" in "${_w#*:}"/*) _in=1 ;; esac
    done
    if [ "$_in" = 1 ] && _to=$(mktemp -d "${HOME:-/}/cng-unbound.XXXXXX" 2>/dev/null) &&
        rmdir "$_to" && mv "$1" "$_to"; then
        printf '%s\n' "$_to"
        return 0
    fi
    printf '%s\n' "$1"
}

# cng_dyn_binds — the same directories, for a guest that is dynamic even though
# this host's probed link mode is static (M23 builds one deliberately, since the
# noexec .so path only exists for a guest whose OWN ld.so maps libraries). On a
# cross host the AArch64 interpreter and libc are under the toolchain sysroot
# rather than at the host's own /lib, so they are exposed at the guest paths the
# binary names instead of at their host ones. Sets GUEST_DYN_BINDS, and beside
# it GUEST_DYN_L — the `-L` that names the same sysroot to the loader, which is
# empty on a native host and must be, or the interpreter the binary asks for is
# looked up under a prefix that is not there.
cng_dyn_binds() {
    GUEST_DYN_BINDS=
    GUEST_DYN_L=
    if [ "$CNG_NATIVE" = 1 ]; then _sr=${CNG_SYSROOT-}; else
        _sr=${CNG_SYSROOT-/usr/aarch64-linux-gnu}
    fi
    if [ -n "$_sr" ]; then
        GUEST_DYN_L="-L $_sr"
        for _d in lib lib64 usr/lib usr/lib64; do
            [ -d "$_sr/$_d" ] || continue
            GUEST_DYN_BINDS="$GUEST_DYN_BINDS -b $_sr/$_d:/$_d"
        done
    else
        for _d in /system /apex /linkerconfig /vendor /lib /lib64 /usr/lib \
            /usr/lib64 ${PREFIX:+"$PREFIX"}; do
            [ -d "$_d" ] || continue
            GUEST_DYN_BINDS="$GUEST_DYN_BINDS -b $_d:$_d"
        done
    fi
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
# and M10 needs the arm64chroot oracle. The userlands are pinned images the
# suite provisions itself under $CNG_ROOTFS_DIR (default tests/.cache/rootfs):
# Alpine at startup, since seven milestones use it, and Debian only when M10
# reaches its one leg, which needs the oracle as well. The oracle is another
# project and cannot be fetched, so it is searched for. A milestone left
# without an image or the oracle skips cleanly.

# cng_rootfs_pin NAME — the image NAME is provisioned from: _rf_file (the
# tarball's name under downloads/), _rf_url, _rf_sha (its sha256) and
# _rf_marker (the program that makes a tree usable). Bumping an image is an
# edit here and nothing else: a provisioned tree is stamped with the hash it
# came from, and one stamped with another is replaced on the next run.
cng_rootfs_pin() {
    case "$1" in
    alpine)
        # The stock minirootfs: the suite only ever calls bin/busybox in it.
        _rf_file=alpine-minirootfs-3.20.3-aarch64.tar.gz
        _rf_url=https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/$_rf_file
        _rf_sha=041fa34a81788242df9e78fa69b97ab45b8ec47ddbf88864755610414a7bf3de
        _rf_marker=bin/busybox
        ;;
    debian)
        # Debian publishes no minirootfs. The official debian:trixie-20261020-slim
        # image is a single layer per platform, and Docker Hub serves a layer by
        # its own sha256: the linux/arm64/v8 one's digest is pin and checksum.
        _rf_file=debian-trixie-20261020-slim-arm64.tar.gz
        _rf_sha=ddc0c1e36a6793411b6c8d48e1ddad2987405d377da92bcf532ed3181c2e4d62
        _rf_url=https://registry-1.docker.io/v2/library/debian/blobs/sha256:$_rf_sha
        _rf_marker=bin/ls
        ;;
    *) return 1 ;;
    esac
}

# cng_get URL OUT [HEADER] — download URL to OUT ("-" is stdout).
cng_get() {
    if have curl; then
        curl -fsSL --retry 3 --connect-timeout 30 ${3:+-H "$3"} -o "$2" "$1"
    elif have wget; then
        wget -q -T 30 ${3:+--header="$3"} -O "$2" "$1"
    else
        return 127
    fi
}

# cng_rootfs_fetch NAME OUT — download NAME's pinned tarball to OUT.
cng_rootfs_fetch() {
    case "$1" in
    debian)
        # Even an anonymous pull from Docker Hub needs a bearer token.
        _tok=$(cng_get "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull" - |
            sed -n 's/.*"token" *: *"\([^"]*\)".*/\1/p')
        [ -n "$_tok" ] && cng_get "$_rf_url" "$2" "Authorization: Bearer $_tok"
        ;;
    *) cng_get "$_rf_url" "$2" ;;
    esac
}

cng_sha256() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# cng_rootfs_lock NAME — runs sharing $CNG_ROOTFS_DIR take turns provisioning.
# mkdir is the one atomic test-and-set every host has; a lock whose owner has
# died is taken over. Released by removing the directory.
cng_rootfs_lock() {
    _lk=$CNG_ROOTFS_DIR/.$1.lock
    _n=0
    until mkdir "$_lk" 2>/dev/null; do
        _p=$(cat "$_lk/pid" 2>/dev/null)
        if [ -n "$_p" ] && ! kill -0 "$_p" 2>/dev/null; then
            rm -rf "$_lk"
            continue
        fi
        [ "$_n" = 0 ] && echo "  waiting for another run to provision $1" >&2
        _n=$((_n + 1))
        [ "$_n" -le 900 ] || return 1
        sleep 1
    done
    echo $$ >"$_lk/pid"
}

# cng_rootfs NAME [fetch] — CNG_ROOTFS is set to $CNG_ROOTFS_DIR/NAME when that
# tree is usable, otherwise emptied with the reason in CNG_ROOTFS_WHY. A tree is
# usable once it has its marker and is stamped with the pinned hash, or carries
# no stamp at all: one staged by hand is used as it is and never touched. With
# "fetch", a missing or stale tree is provisioned.
cng_rootfs() {
    CNG_ROOTFS=
    CNG_ROOTFS_WHY=
    cng_rootfs_pin "$1" || return 1
    _rf_dir=$CNG_ROOTFS_DIR/$1
    _rf_stamp=$CNG_ROOTFS_DIR/.$1.sha256
    cng_rootfs_usable && return 0
    if [ "${2:-}" != fetch ]; then
        CNG_ROOTFS_WHY="not provisioned yet"
        return 1
    fi
    if ! mkdir -p "$CNG_ROOTFS_DIR/downloads" || ! cng_rootfs_lock "$1"; then
        CNG_ROOTFS_WHY="cannot lock $CNG_ROOTFS_DIR for provisioning"
        return 1
    fi
    cng_rootfs_provision "$1"
    _rc=$?
    rm -rf "$CNG_ROOTFS_DIR/.$1.lock"
    return $_rc
}

cng_rootfs_usable() {
    [ -x "$_rf_dir/$_rf_marker" ] || return 1
    [ ! -e "$_rf_stamp" ] || [ "$(cat "$_rf_stamp")" = "$_rf_sha" ] || return 1
    CNG_ROOTFS=$_rf_dir
}

# cng_rootfs_provision NAME — under the lock. The tarball in downloads/ is
# downloaded first when absent (never with CNG_ROOTFS_FETCH=0) and checked
# against the pin either way. It is unpacked beside the tree and renamed into
# place, so a run that dies midway leaves nothing half-written under the name.
cng_rootfs_provision() {
    cng_rootfs_usable && return 0 # another run got there first
    if [ -e "$_rf_dir" ] && [ ! -e "$_rf_stamp" ]; then
        CNG_ROOTFS_WHY="$_rf_dir has no $_rf_marker and was not provisioned here"
        return 1
    fi
    if ! have sha256sum; then
        CNG_ROOTFS_WHY="no sha256sum to check $_rf_file with"
        return 1
    fi
    _tb=$CNG_ROOTFS_DIR/downloads/$_rf_file
    if [ "$(cng_sha256 "$_tb")" != "$_rf_sha" ]; then
        if [ "${CNG_ROOTFS_FETCH:-1}" = 0 ]; then
            CNG_ROOTFS_WHY="no $_rf_file matching its pin in downloads/, and CNG_ROOTFS_FETCH=0"
            return 1
        fi
        echo "  fetching $_rf_file" >&2
        if ! cng_rootfs_fetch "$1" "$_tb.part"; then
            rm -f "$_tb.part"
            CNG_ROOTFS_WHY="cannot download $_rf_url"
            return 1
        fi
        if [ "$(cng_sha256 "$_tb.part")" != "$_rf_sha" ]; then
            rm -f "$_tb.part"
            CNG_ROOTFS_WHY="$_rf_file does not match its pinned sha256"
            return 1
        fi
        if ! mv -f "$_tb.part" "$_tb"; then
            CNG_ROOTFS_WHY="cannot store $_tb"
            return 1
        fi
    fi
    _new=$CNG_ROOTFS_DIR/.$1.new
    rm -rf "$_new"
    if ! mkdir "$_new" || ! (cd "$_new" && gzip -dc "$_tb" | tar -xof -) ||
        [ ! -x "$_new/$_rf_marker" ]; then
        rm -rf "$_new"
        CNG_ROOTFS_WHY="cannot unpack $_rf_file"
        return 1
    fi
    # Only a tree stamped as provisioned here gets this far to be replaced.
    rm -rf "$_rf_dir"
    if [ -e "$_rf_dir" ]; then
        rm -rf "$_new"
        CNG_ROOTFS_WHY="cannot remove the stale $_rf_dir"
        return 1
    fi
    if ! echo "$_rf_sha" >"$_rf_stamp" || ! mv "$_new" "$_rf_dir"; then
        rm -rf "$_new"
        CNG_ROOTFS_WHY="cannot move the unpacked tree to $_rf_dir"
        return 1
    fi
    CNG_ROOTFS=$_rf_dir
}

cng_detect_images() {
    # Absolute, since the provisioning and the milestones change directory.
    CNG_ROOTFS_DIR="${CNG_ROOTFS_DIR:-tests/.cache/rootfs}"
    case "$CNG_ROOTFS_DIR" in
    /*) : ;;
    *) CNG_ROOTFS_DIR=$PWD/$CNG_ROOTFS_DIR ;;
    esac
    CNG_ALPINE="${CNG_ALPINE:-}"
    CNG_ALPINE_WHY=
    if [ -z "$CNG_ALPINE" ]; then
        cng_rootfs alpine fetch
        CNG_ALPINE=$CNG_ROOTFS
        CNG_ALPINE_WHY=$CNG_ROOTFS_WHY
    fi
    # Only looked for here: M10 provisions it when it reaches the Debian leg.
    CNG_DEBIAN="${CNG_DEBIAN:-}"
    CNG_DEBIAN_WHY=
    if [ -z "$CNG_DEBIAN" ]; then
        cng_rootfs debian
        CNG_DEBIAN=$CNG_ROOTFS
        CNG_DEBIAN_WHY=$CNG_ROOTFS_WHY
    fi

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
    printf '  alpine rootfs %s\n' "${CNG_ALPINE:-none ($CNG_ALPINE_WHY)}"
    printf '  debian rootfs %s\n' "${CNG_DEBIAN:-none ($CNG_DEBIAN_WHY)}"
    printf '  l2s oracle    %s\n' "${CNG_ORACLE:-none}"
}
