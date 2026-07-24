#!/usr/bin/env bash
# CapAuth identity-state backup - scheduled, retained, off-box optional.
#
# Backs up the recoverable identity STATE that has no other automated backup:
#   1. The verification-service keystore (SQLite `keys.db`) - the enrolled
#      consumer public keys / fingerprints (PII-minimal, no private key material).
#   2. The Authentik Postgres DB (flows, stages, OAuth providers) - ONLY when a
#      target is configured. This holds the .13 edge SSO wiring for forgejo/sksso.
#
# What it deliberately does NOT touch (see docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md):
#   - The ROOT PRIVATE KEY. Per the DR runbook Step 1, the root key lives in
#     Chef's OFFLINE custody (two independent copies, ROOT_ROTATION_CEREMONY.md
#     Phase 0). It is never written to an automated cron backup. This script will
#     refuse to copy `private.asc` / `.gnupg` private material.
#   - Operator identity.json and per-agent capauth profiles - already covered by
#     the sovereign backup / Syncthing (DR runbook Step 5).
#
# Safety:
#   - Read-only against the live DB (uses sqlite3 online `.backup`; never writes
#     the source). Idempotent: each run creates its own timestamped dir.
#   - NEVER echoes or persists secrets. Postgres password is read from the
#     environment / ~/.pgpass only and is never printed.
#   - Backup dir is created 0700; dumps are 0600.
#
# Restore procedure: docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md (Step 6 keystore,
# Step 9 the .13 Authentik edge). This script only PRODUCES the artifacts that
# runbook restores; it does not restore.
#
# Usage:
#   scripts/capauth-backup.sh            # run a backup now
#   scripts/capauth-backup.sh --dry-run  # show what would happen, touch nothing
#
# Configuration (all via env, sane defaults):
#   CAPAUTH_DB_PATH            keystore SQLite path (default ~/.capauth/service/keys.db)
#   CAPAUTH_DATA_VOLUME        docker volume holding /data/keys.db when the host
#                              path is absent (default: capauth_data)
#   CAPAUTH_BACKUP_DIR         where backups are written (default ~/.capauth/backups)
#   CAPAUTH_BACKUP_RETAIN_DAYS prune backups older than N days (default 14)
#   CAPAUTH_BACKUP_REMOTE      optional rsync target for off-box copy
#                              (e.g. user@host:/srv/capauth-backups). Unset = local only.
#   Authentik Postgres (all must be set to enable the pg_dump leg):
#   CAPAUTH_AUTHENTIK_PG_HOST, CAPAUTH_AUTHENTIK_PG_PORT (default 5432),
#   CAPAUTH_AUTHENTIK_PG_DB, CAPAUTH_AUTHENTIK_PG_USER
#   Password: export PGPASSWORD or use ~/.pgpass (never passed on the CLI).

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
CAPAUTH_HOME_DIR="${CAPAUTH_HOME:-$HOME/.capauth}"
DB_PATH="${CAPAUTH_DB_PATH:-$CAPAUTH_HOME_DIR/service/keys.db}"
DATA_VOLUME="${CAPAUTH_DATA_VOLUME:-capauth_data}"
BACKUP_ROOT="${CAPAUTH_BACKUP_DIR:-$CAPAUTH_HOME_DIR/backups}"
RETAIN_DAYS="${CAPAUTH_BACKUP_RETAIN_DAYS:-14}"
REMOTE="${CAPAUTH_BACKUP_REMOTE:-}"

PG_HOST="${CAPAUTH_AUTHENTIK_PG_HOST:-}"
PG_PORT="${CAPAUTH_AUTHENTIK_PG_PORT:-5432}"
PG_DB="${CAPAUTH_AUTHENTIK_PG_DB:-}"
PG_USER="${CAPAUTH_AUTHENTIK_PG_USER:-}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

TS="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/capauth-backup-$TS"

# ── Output helpers (status only, never secrets) ───────────────────────────────
log()  { echo "[capauth-backup] $*"; }
warn() { echo "[capauth-backup] WARN: $*" >&2; }
die()  { echo "[capauth-backup] ERROR: $*" >&2; exit 1; }

run() {
    # Echo the action; execute unless --dry-run.
    log "$*"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    "$@"
}

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
    else echo "(sha256 unavailable)"; fi
}

# ── Preflight ─────────────────────────────────────────────────────────────────
log "run $TS  (dry-run=$DRY_RUN)"
log "destination: $DEST"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY RUN - no files will be created, no commands with side effects run."
fi

run mkdir -p "$DEST"
[[ "$DRY_RUN" -eq 0 ]] && chmod 700 "$BACKUP_ROOT" "$DEST"

MANIFEST="$DEST/MANIFEST.txt"
manifest() { [[ "$DRY_RUN" -eq 1 ]] && return 0; echo "$*" >> "$MANIFEST"; }

manifest "CapAuth identity-state backup"
manifest "timestamp_utc: $TS"
manifest "host: $(hostname)"
manifest "note: root private key is NOT included (offline custody only)"
manifest "restore: docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md"
manifest ""

BACKED_UP_ANY=0

# ── 1. Keystore (SQLite keys.db) ──────────────────────────────────────────────
backup_keystore() {
    local dst="$DEST/keys.db"

    if [[ -f "$DB_PATH" ]]; then
        # Guard: never let this be a private-key file by mistake.
        case "$(basename "$DB_PATH")" in
            private.asc|*.gpg|*.key) die "refusing to back up private key material: $DB_PATH" ;;
        esac
        log "keystore: host path $DB_PATH -> keys.db (online .backup)"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            if command -v sqlite3 >/dev/null 2>&1; then
                # Online backup: consistent snapshot of a live DB, source untouched.
                sqlite3 "$DB_PATH" ".backup '$dst'"
            else
                warn "sqlite3 not found; falling back to cp (best-effort consistency)"
                cp -p "$DB_PATH" "$dst"
            fi
            chmod 600 "$dst"
            manifest "keys.db: source=$DB_PATH bytes=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst") sha256=$(sha "$dst")"
        fi
        BACKED_UP_ANY=1
        return 0
    fi

    # Host path absent - try the docker volume (container may own /data).
    if command -v docker >/dev/null 2>&1 && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
        log "keystore: host path absent; pulling keys.db from docker volume $DATA_VOLUME"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            # Copy out via a throwaway read-only mount. cp of a live sqlite is
            # best-effort; for a running service prefer a maintenance window.
            docker run --rm -v "$DATA_VOLUME":/data:ro -v "$DEST":/backup \
                busybox sh -c 'test -f /data/keys.db && cp /data/keys.db /backup/keys.db' \
                || { warn "keys.db not present in volume $DATA_VOLUME"; return 0; }
            chmod 600 "$dst" 2>/dev/null || true
            manifest "keys.db: source=docker-volume:$DATA_VOLUME bytes=$(stat -c%s "$dst" 2>/dev/null || echo '?') sha256=$(sha "$dst")"
        fi
        BACKED_UP_ANY=1
        return 0
    fi

    warn "no keystore found at $DB_PATH and no docker volume $DATA_VOLUME; skipping keystore leg"
}

# ── 2. Authentik Postgres (optional) ──────────────────────────────────────────
backup_authentik_pg() {
    if [[ -z "$PG_HOST" || -z "$PG_DB" || -z "$PG_USER" ]]; then
        log "authentik pg: not configured (CAPAUTH_AUTHENTIK_PG_HOST/DB/USER unset); skipping"
        return 0
    fi
    if ! command -v pg_dump >/dev/null 2>&1; then
        warn "authentik pg configured but pg_dump not found; skipping"
        return 0
    fi

    local dst="$DEST/authentik-${PG_DB}.sql.gz"
    # Password comes from PGPASSWORD/~/.pgpass - never placed on the CLI, never logged.
    log "authentik pg: pg_dump $PG_USER@$PG_HOST:$PG_PORT/$PG_DB -> $(basename "$dst")"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if pg_dump --host="$PG_HOST" --port="$PG_PORT" --username="$PG_USER" \
                   --dbname="$PG_DB" --no-password --format=plain 2>"$DEST/.pg_dump.err" \
                   | gzip -9 > "$dst"; then
            chmod 600 "$dst"
            rm -f "$DEST/.pg_dump.err"
            manifest "authentik-${PG_DB}.sql.gz: source=pg://$PG_USER@$PG_HOST:$PG_PORT/$PG_DB bytes=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst") sha256=$(sha "$dst")"
            BACKED_UP_ANY=1
        else
            warn "pg_dump failed (see stderr capture); check credentials in ~/.pgpass. Not aborting other legs."
            # Preserve error but ensure no partial dump masquerades as good.
            rm -f "$dst"
        fi
    else
        BACKED_UP_ANY=1
    fi
}

# ── 3. Off-box copy (optional) ────────────────────────────────────────────────
copy_offbox() {
    [[ -z "$REMOTE" ]] && { log "off-box: CAPAUTH_BACKUP_REMOTE unset; local retention only"; return 0; }
    if ! command -v rsync >/dev/null 2>&1; then
        warn "off-box target set but rsync not found; skipping off-box copy"
        return 0
    fi
    log "off-box: rsync $DEST/ -> $REMOTE/"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        rsync -a --chmod=D700,F600 "$DEST" "$REMOTE/" \
            || warn "off-box rsync failed; local backup retained"
    fi
}

# ── 4. Rotation ───────────────────────────────────────────────────────────────
rotate() {
    log "rotation: pruning backups older than $RETAIN_DAYS days under $BACKUP_ROOT"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    # Only prune our own timestamped dirs; never anything else.
    find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'capauth-backup-*' \
        -mtime +"$RETAIN_DAYS" -print -exec rm -rf {} + 2>/dev/null || true
}

# ── Main ──────────────────────────────────────────────────────────────────────
backup_keystore
backup_authentik_pg

if [[ "$BACKED_UP_ANY" -eq 0 ]]; then
    warn "nothing was backed up - no keystore and no Authentik pg configured"
    # Remove the manifest-only dir so rotation math stays clean.
    [[ "$DRY_RUN" -eq 0 ]] && rm -rf "$DEST" 2>/dev/null || true
    exit 3
fi

copy_offbox
rotate

log "done: $DEST"
[[ "$DRY_RUN" -eq 0 ]] && log "manifest: $MANIFEST"
