#!/usr/bin/env bash
# CapAuth identity-state restore - the confirm-gated inverse of capauth-backup.sh.
#
# Consumes one timestamped artifact dir produced by scripts/capauth-backup.sh and
# restores the identity STATE it holds, in place, onto the live paths:
#   1. The verification-service keystore (SQLite `keys.db`) - enrolled consumer
#      public keys / fingerprints.
#   2. The bunker pairing session store (`bunker_sessions.json`) - approved
#      phone<->desktop pairings (session id + opaque join token; NO key material).
#   3. The Authentik Postgres DB - ONLY when --include-pg is passed AND the target
#      is configured. This REPLACES objects in the target DB, so it is off by
#      default and separately gated.
#
# This is a DESTRUCTIVE, gated operation: it overwrites live identity state. It
# will NOT proceed without an explicit confirmation:
#   - interactive: you must type RESTORE at the prompt, or
#   - non-interactive: pass --yes (for tested/automated round-trips).
#
# What it deliberately does NOT touch (see docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md):
#   - The ROOT PRIVATE KEY and operator/agent private profiles. Those are never in
#     a capauth-backup.sh artifact (offline custody / sovereign backup only), so
#     this tool has nothing to restore there and cannot fork an identity.
#
# Safety:
#   - Verifies every artifact against the backup MANIFEST.txt sha256 BEFORE writing
#     anything. A checksum mismatch aborts the whole restore (fail-closed).
#   - Each live target it overwrites is first copied aside to <target>.pre-restore-<ts>.
#   - NEVER echoes secrets. Postgres password comes from PGPASSWORD / ~/.pgpass only.
#   - --dry-run verifies + prints the plan and touches nothing.
#
# Usage:
#   scripts/capauth-restore.sh <backup-dir>            # restore that artifact (prompts)
#   scripts/capauth-restore.sh --latest                # restore newest under BACKUP_DIR
#   scripts/capauth-restore.sh <backup-dir> --yes      # non-interactive (round-trips/tests)
#   scripts/capauth-restore.sh <backup-dir> --dry-run  # verify + plan only, touch nothing
#   scripts/capauth-restore.sh <backup-dir> --include-pg --yes   # also restore Authentik PG
#
# Configuration (mirrors capauth-backup.sh; all via env):
#   CAPAUTH_DB_PATH            keystore SQLite target  (default ~/.capauth/service/keys.db)
#   CAPAUTH_BUNKER_STORE       bunker store target     (default ~/.capauth/service/bunker_sessions.json; "" disables)
#   CAPAUTH_BACKUP_DIR         where --latest looks     (default ~/.capauth/backups)
#   Authentik Postgres (only used with --include-pg; all must be set):
#   CAPAUTH_AUTHENTIK_PG_HOST, CAPAUTH_AUTHENTIK_PG_PORT (default 5432),
#   CAPAUTH_AUTHENTIK_PG_DB, CAPAUTH_AUTHENTIK_PG_USER
#   Password: export PGPASSWORD or use ~/.pgpass (never passed on the CLI).

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
CAPAUTH_HOME_DIR="${CAPAUTH_HOME:-$HOME/.capauth}"
DB_PATH="${CAPAUTH_DB_PATH:-$CAPAUTH_HOME_DIR/service/keys.db}"
if [[ -n "${CAPAUTH_BUNKER_STORE+x}" ]]; then
    BUNKER_STORE="$CAPAUTH_BUNKER_STORE"
else
    BUNKER_STORE="$CAPAUTH_HOME_DIR/service/bunker_sessions.json"
fi
BACKUP_ROOT="${CAPAUTH_BACKUP_DIR:-$CAPAUTH_HOME_DIR/backups}"

PG_HOST="${CAPAUTH_AUTHENTIK_PG_HOST:-}"
PG_PORT="${CAPAUTH_AUTHENTIK_PG_PORT:-5432}"
PG_DB="${CAPAUTH_AUTHENTIK_PG_DB:-}"
PG_USER="${CAPAUTH_AUTHENTIK_PG_USER:-}"

DRY_RUN=0
ASSUME_YES=0
INCLUDE_PG=0
USE_LATEST=0
SRC=""

TS="$(date -u +%Y%m%dT%H%M%SZ)"

# ── Output helpers (status only, never secrets) ───────────────────────────────
log()  { echo "[capauth-restore] $*"; }
warn() { echo "[capauth-restore] WARN: $*" >&2; }
die()  { echo "[capauth-restore] ERROR: $*" >&2; exit 1; }

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
    else echo "(sha256 unavailable)"; fi
}

usage() {
    sed -n '30,39p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-2}"
}

# ── Arg parse ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=1 ;;
        --yes|-y)     ASSUME_YES=1 ;;
        --include-pg) INCLUDE_PG=1 ;;
        --latest)     USE_LATEST=1 ;;
        -h|--help)    usage 0 ;;
        -*)           die "unknown option: $1 (see --help)" ;;
        *)            [[ -n "$SRC" ]] && die "unexpected extra argument: $1"; SRC="$1" ;;
    esac
    shift
done

# ── Resolve the source artifact dir ───────────────────────────────────────────
if [[ "$USE_LATEST" -eq 1 ]]; then
    [[ -n "$SRC" ]] && die "pass either <backup-dir> or --latest, not both"
    [[ -d "$BACKUP_ROOT" ]] || die "backup root not found: $BACKUP_ROOT"
    SRC="$(find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'capauth-backup-*' 2>/dev/null | sort | tail -n1)"
    [[ -n "$SRC" ]] || die "no capauth-backup-* dir under $BACKUP_ROOT"
    log "latest artifact: $SRC"
fi

[[ -n "$SRC" ]] || { warn "no backup dir given"; usage 2; }
[[ -d "$SRC" ]] || die "not a directory: $SRC"
MANIFEST="$SRC/MANIFEST.txt"
[[ -f "$MANIFEST" ]] || die "no MANIFEST.txt in $SRC (not a capauth backup artifact?)"

log "source: $SRC   (dry-run=$DRY_RUN, include-pg=$INCLUDE_PG)"

# ── Integrity verify (fail-closed) BEFORE touching anything ───────────────────
# Manifest lines look like:  <filename>: ... sha256=<hex>
manifest_sha() {
    # Echo the recorded sha256 for a given artifact basename, or empty if absent.
    grep -E "^$1: " "$MANIFEST" 2>/dev/null | sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p' | head -n1
}

verify_one() {
    local name="$1" f="$SRC/$1" want got
    [[ -f "$f" ]] || return 1        # not present in this artifact
    want="$(manifest_sha "$name")"
    if [[ -z "$want" ]]; then
        warn "$name present but has no sha256 in MANIFEST; refusing to trust it"
        return 2
    fi
    got="$(sha "$f")"
    if [[ "$got" != "$want" ]]; then
        die "checksum MISMATCH for $name (manifest=$want actual=$got); aborting, nothing restored"
    fi
    log "verified $name (sha256 ok)"
    return 0
}

HAVE_KEYSTORE=0; HAVE_BUNKER=0; HAVE_PG=0; PG_FILE=""
verify_one "keys.db"              && HAVE_KEYSTORE=1 || true
verify_one "bunker_sessions.json" && HAVE_BUNKER=1   || true
# Authentik dump filename is authentik-<db>.sql.gz - discover it.
PG_FILE="$(find "$SRC" -maxdepth 1 -type f -name 'authentik-*.sql.gz' 2>/dev/null | head -n1)"
if [[ -n "$PG_FILE" ]]; then
    verify_one "$(basename "$PG_FILE")" && HAVE_PG=1 || true
fi

if [[ "$HAVE_KEYSTORE" -eq 0 && "$HAVE_BUNKER" -eq 0 && "$HAVE_PG" -eq 0 ]]; then
    die "artifact has no restorable identity state (no keys.db / bunker_sessions.json / authentik dump)"
fi

# ── Plan ──────────────────────────────────────────────────────────────────────
log "restore plan:"
[[ "$HAVE_KEYSTORE" -eq 1 ]] && log "  keys.db              -> $DB_PATH"
[[ "$HAVE_BUNKER"   -eq 1 && -n "$BUNKER_STORE" ]] && log "  bunker_sessions.json -> $BUNKER_STORE"
[[ "$HAVE_BUNKER"   -eq 1 && -z "$BUNKER_STORE" ]] && log "  bunker_sessions.json -> (skipped: CAPAUTH_BUNKER_STORE=\"\")"
if [[ "$HAVE_PG" -eq 1 ]]; then
    if [[ "$INCLUDE_PG" -eq 1 ]]; then
        log "  $(basename "$PG_FILE") -> pg://$PG_USER@$PG_HOST:$PG_PORT/$PG_DB (REPLACES objects)"
    else
        log "  $(basename "$PG_FILE") -> (skipped: pass --include-pg to restore the Authentik DB)"
    fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY RUN - verification passed, nothing was written."
    exit 0
fi

# ── Confirm gate ──────────────────────────────────────────────────────────────
if [[ "$ASSUME_YES" -ne 1 ]]; then
    if [[ ! -t 0 ]]; then
        die "refusing to overwrite live identity state without confirmation; pass --yes for non-interactive restore"
    fi
    echo "This OVERWRITES live capauth identity state at the paths above." >&2
    printf 'Type RESTORE to proceed: ' >&2
    read -r reply
    [[ "$reply" == "RESTORE" ]] || die "confirmation not given (got '${reply}'); aborting"
fi

# ── Apply ─────────────────────────────────────────────────────────────────────
# Copy a live target aside before overwriting it (best-effort undo).
preserve() {
    local target="$1"
    if [[ -f "$target" ]]; then
        local aside="${target}.pre-restore-${TS}"
        cp -p "$target" "$aside"
        chmod 600 "$aside" 2>/dev/null || true
        log "preserved existing $(basename "$target") -> $(basename "$aside")"
    fi
}

restore_keystore() {
    [[ "$HAVE_KEYSTORE" -eq 1 ]] || return 0
    local src="$SRC/keys.db"
    mkdir -p "$(dirname "$DB_PATH")"
    preserve "$DB_PATH"
    if command -v sqlite3 >/dev/null 2>&1; then
        # Restore via online .restore so the target is a consistent copy.
        rm -f "$DB_PATH"
        sqlite3 "$DB_PATH" ".restore '$src'"
    else
        warn "sqlite3 not found; falling back to cp"
        cp -p "$src" "$DB_PATH"
    fi
    chmod 600 "$DB_PATH"
    if command -v sqlite3 >/dev/null 2>&1; then
        local ok; ok="$(sqlite3 "$DB_PATH" 'PRAGMA integrity_check;' 2>/dev/null || echo 'FAILED')"
        [[ "$ok" == "ok" ]] || die "restored keys.db failed integrity_check ($ok)"
    fi
    log "restored keys.db -> $DB_PATH (integrity ok)"
}

restore_bunker() {
    [[ "$HAVE_BUNKER" -eq 1 ]] || return 0
    if [[ -z "$BUNKER_STORE" ]]; then
        log "bunker: skipped (CAPAUTH_BUNKER_STORE=\"\")"
        return 0
    fi
    local src="$SRC/bunker_sessions.json"
    mkdir -p "$(dirname "$BUNKER_STORE")"
    preserve "$BUNKER_STORE"
    cp -p "$src" "$BUNKER_STORE"
    chmod 600 "$BUNKER_STORE"
    log "restored bunker_sessions.json -> $BUNKER_STORE"
}

restore_authentik_pg() {
    [[ "$HAVE_PG" -eq 1 ]] || return 0
    if [[ "$INCLUDE_PG" -ne 1 ]]; then
        log "authentik pg: present in artifact but not restored (no --include-pg)"
        return 0
    fi
    [[ -n "$PG_HOST" && -n "$PG_DB" && -n "$PG_USER" ]] \
        || die "--include-pg set but CAPAUTH_AUTHENTIK_PG_HOST/DB/USER not configured"
    command -v psql   >/dev/null 2>&1 || die "psql not found; cannot restore Authentik DB"
    command -v gunzip >/dev/null 2>&1 || die "gunzip not found; cannot decompress Authentik dump"
    log "authentik pg: restoring $(basename "$PG_FILE") into $PG_USER@$PG_HOST:$PG_PORT/$PG_DB"
    # Password from PGPASSWORD/~/.pgpass only, never on the CLI, never logged.
    if gunzip -c "$PG_FILE" | psql --host="$PG_HOST" --port="$PG_PORT" \
            --username="$PG_USER" --dbname="$PG_DB" --no-password \
            --set ON_ERROR_STOP=on >/dev/null 2>"$SRC/.pg_restore.err"; then
        rm -f "$SRC/.pg_restore.err"
        log "restored Authentik DB (psql applied dump)"
    else
        die "Authentik DB restore failed (see stderr capture); target may be partially modified"
    fi
}

restore_keystore
restore_bunker
restore_authentik_pg

log "done. Verify: capauth profile verify / service status per docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md"
