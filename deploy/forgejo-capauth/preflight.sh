#!/usr/bin/env bash
# Preflight secret guard for the CapAuth + Forgejo compose stack.
#
# Refuses to start (exit non-zero) when a required secret is unset, empty, or
# still the committed placeholder default. This forces the operator to set a
# real, unique secret before `docker compose up` ever runs, closing the
# default-secret security hole.
#
# Usage:
#   ./preflight.sh            # checks secrets, exits 0 if all good
#   ./preflight.sh && docker compose up -d
#
# Secrets are read from the environment, or from ./.env if present (the same
# file compose loads), so this check sees exactly what the stack would run with.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env the same way docker compose does, without leaking it into callers.
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
    set +a
fi

# Minimum acceptable secret length (chars). Real secrets should be >= 32.
MIN_LEN=16

fail=0
err() { echo "PREFLIGHT ERROR: $*" >&2; fail=1; }

check_secret() {
    local name="$1"
    local value="${!name:-}"

    if [[ -z "$value" ]]; then
        err "$name is unset or empty. Set a strong unique value in $SCRIPT_DIR/.env (see .env.example)."
        return
    fi

    # Reject the committed placeholder defaults (any change-me / changeme form).
    case "$value" in
        change-me* | changeme* | CHANGE-ME* | CHANGEME* | change_me* | CHANGE_ME*)
            err "$name is still the insecure placeholder default. Set a strong unique value in $SCRIPT_DIR/.env."
            return
            ;;
    esac

    if (( ${#value} < MIN_LEN )); then
        err "$name is too short (< ${MIN_LEN} chars). Use at least 32 random chars, e.g. python3 -c 'import secrets; print(secrets.token_hex(32))'."
        return
    fi
}

check_secret CAPAUTH_ADMIN_TOKEN
check_secret CAPAUTH_JWT_SECRET

if (( fail )); then
    {
        echo ""
        echo "Refusing to start: fix the secret(s) above, then re-run ./preflight.sh."
        echo "Generate a strong value with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
    } >&2
    exit 1
fi

echo "Preflight secret check passed: CAPAUTH_ADMIN_TOKEN and CAPAUTH_JWT_SECRET are set and non-default."
