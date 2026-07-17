#!/usr/bin/env bash
# build-sq.sh - reproducible build of the PQC-capable Sequoia sq binary.
#
# Provenance: capauth/docs/PQC_ROOT_MIGRATION.md section 3.
# Pinned target:
#   sq            1.4.0-pqc.1   (sequoia-openpgp 2.2.0-pqc.1, crates.io, --locked)
#   Rust          rustc >= 1.79 required; reference builds:
#                 .158 rustup rustc 1.96.0; .41 rustup nightly 1.98.0 (2026-06-27)
#   Crypto        OpenSSL >= 3.5 (native ML-KEM / ML-DSA / SLH-DSA)
#                 (.158: linuxbrew openssl@3 3.6.2; .41: system OpenSSL 3.6.3)
#
# Build deps (Debian/Ubuntu): pkg-config capnproto clang libsqlite3-dev patchelf
# Build deps (Arch/Manjaro):  pkgconf capnproto clang sqlite
#
# Env overrides:
#   OSSL               OpenSSL prefix to build against (default: autodetect)
#   SQ_VERSION         crate version (default 1.4.0-pqc.1)
#   CARGO_BUILD_JOBS   parallel codegen jobs (default: nproc, capped at 8)
#   CARGO_TARGET_DIR   persistent target dir (default ~/pqc-build/target)
#   CARGO_INSTALL_ROOT install prefix; binary lands in $CARGO_INSTALL_ROOT/bin
#                      (default: cargo's own, normally ~/.cargo)
#   LIBCLANG_PATH      libclang dir for bindgen (autodetected, see below)
set -uo pipefail

SQ_VERSION="${SQ_VERSION:-1.4.0-pqc.1}"

# Prefer rustup toolchain when present, else distro rustc.
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

# --- OpenSSL selection -------------------------------------------------
# A usable prefix must ship headers, not just runtime libs. If the
# linuxbrew openssl@3 keg is complete, pin to it (the .158 reference
# build); otherwise fall back to the system OpenSSL, which must be >= 3.5
# for the PQ primitives.
BREW_OSSL=/home/linuxbrew/.linuxbrew/opt/openssl@3
if [ -z "${OSSL:-}" ]; then
    if [ -f "$BREW_OSSL/include/openssl/ssl.h" ]; then
        OSSL="$BREW_OSSL"
    else
        OSSL=""   # system OpenSSL via pkg-config
    fi
fi

if [ -n "$OSSL" ]; then
    export OPENSSL_DIR="$OSSL"
    export OPENSSL_LIB_DIR="$OSSL/lib"
    export OPENSSL_INCLUDE_DIR="$OSSL/include"
    export PKG_CONFIG_PATH="$OSSL/lib/pkgconfig"
    # THE fix: bindgen/clang must see the OpenSSL headers
    export BINDGEN_EXTRA_CLANG_ARGS="-I$OSSL/include"
    export C_INCLUDE_PATH="$OSSL/include"
    export CPATH="$OSSL/include"
    export LD_LIBRARY_PATH="$OSSL/lib:${LD_LIBRARY_PATH:-}"
    echo "=== OpenSSL: pinned prefix $OSSL ==="
else
    sysver="$(openssl version 2>/dev/null | awk '{print $2}')"
    case "$sysver" in
        3.[5-9].*|3.[1-9][0-9]*|[4-9].*) ;;
        *) echo "FATAL: system OpenSSL '$sysver' < 3.5 lacks PQ primitives; set OSSL=<prefix>" >&2
           exit 1 ;;
    esac
    echo "=== OpenSSL: system ($sysver) ==="
fi

# --- bindgen / libclang ------------------------------------------------
# GOTCHA (hit on .41, 2026-07-17): the locked bindgen 0.71.1 emits OPAQUE
# structs against libclang >= 22 (every OpenSSL struct becomes `_address`
# only, then `ossl` fails with E0080 layout under-/overflow errors). Pin
# bindgen to an older libclang when the system one is too new.
if [ -z "${LIBCLANG_PATH:-}" ]; then
    for d in /usr/lib/llvm18/lib /usr/lib/llvm20/lib /usr/lib/llvm21/lib; do
        [ -e "$d/libclang.so" ] && export LIBCLANG_PATH="$d" && break
    done
fi
[ -n "${LIBCLANG_PATH:-}" ] && echo "=== LIBCLANG_PATH=$LIBCLANG_PATH ==="

# --- Cargo knobs -------------------------------------------------------
jobs_default="$(nproc 2>/dev/null || echo 2)"
[ "$jobs_default" -gt 8 ] && jobs_default=8
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$jobs_default}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/pqc-build/target}"   # persistent, reuse across retries
mkdir -p "$CARGO_TARGET_DIR"

echo "=== rustc $(rustc --version) | jobs $CARGO_BUILD_JOBS | target $CARGO_TARGET_DIR ==="
echo "=== START $(date) ==="
cargo install sequoia-sq --version "$SQ_VERSION" --locked \
    --no-default-features --features crypto-openssl \
    ${CARGO_INSTALL_ROOT:+--root "$CARGO_INSTALL_ROOT"}
rc=$?
echo "=== DONE $(date) exit=$rc ==="

BIN="${CARGO_INSTALL_ROOT:-$HOME/.cargo}/bin/sq"
if [ -x "$BIN" ]; then
    # Runtime durability: when built against a non-system prefix, pin the
    # rpath so sq runs without LD_LIBRARY_PATH (see migration doc sec. 3).
    if [ -n "$OSSL" ] && command -v patchelf >/dev/null; then
        patchelf --set-rpath "$OSSL/lib" "$BIN" && echo "rpath pinned to $OSSL/lib"
    fi
    echo "sq INSTALLED: $("$BIN" version 2>&1 | head -2 | tr '\n' ' ')"
fi
exit $rc
