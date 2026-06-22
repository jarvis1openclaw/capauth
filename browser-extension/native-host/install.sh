#!/usr/bin/env bash
#
# Register the CapAuth native-messaging signer host for Chrome/Chromium on Linux.
#
# Usage:
#   ./install.sh <EXTENSION_ID> [--browser chrome|chromium|brave|edge|all]
#
# <EXTENSION_ID> is the 32-char ID shown on chrome://extensions for the loaded
# CapAuth extension (toggle Developer mode to see it).
#
# What it does:
#   1. Copies the host manifest, substituting the absolute path to
#      capauth_signer.py and your extension ID into allowed_origins.
#   2. Writes it to the per-user Native Messaging hosts dir for each browser.
#   3. Makes capauth_signer.py executable.
#
# ---------------------------------------------------------------------------
# Per-OS Native Messaging host manifest locations (for reference / porting):
#
#   Linux (per-user):
#     Chrome    ~/.config/google-chrome/NativeMessagingHosts/com.capauth.signer.json
#     Chromium  ~/.config/chromium/NativeMessagingHosts/com.capauth.signer.json
#     Brave     ~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/...
#     Edge      ~/.config/microsoft-edge/NativeMessagingHosts/...
#
#   macOS (per-user):
#     Chrome    ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.capauth.signer.json
#     Chromium  ~/Library/Application Support/Chromium/NativeMessagingHosts/...
#     Brave     ~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/...
#     Edge      ~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/...
#     (host "path" must be absolute; same JSON format.)
#
#   Windows:
#     Register a registry key pointing at the manifest, e.g.:
#       HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.capauth.signer
#       (Default) = C:\path\to\com.capauth.signer.json
#     and the manifest "path" must point at a launcher (e.g. capauth_signer.bat
#     that runs `python capauth_signer.py`). See Chrome docs: Native messaging.
# ---------------------------------------------------------------------------

set -euo pipefail

HOST_NAME="com.capauth.signer"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_SCRIPT="${SCRIPT_DIR}/capauth_signer.py"
TEMPLATE="${SCRIPT_DIR}/${HOST_NAME}.json"

EXTENSION_ID="${1:-}"
BROWSER="all"

# crude flag parse for --browser
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --browser) BROWSER="${2:-all}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${EXTENSION_ID}" ]]; then
  echo "usage: $0 <EXTENSION_ID> [--browser chrome|chromium|brave|edge|all]" >&2
  exit 2
fi
if [[ ! "${EXTENSION_ID}" =~ ^[a-p]{32}$ ]]; then
  echo "warning: '${EXTENSION_ID}' doesn't look like a 32-char extension ID — continuing anyway." >&2
fi
if [[ ! -f "${HOST_SCRIPT}" ]]; then
  echo "error: host script not found: ${HOST_SCRIPT}" >&2
  exit 1
fi

chmod +x "${HOST_SCRIPT}"

# Build the populated manifest in a temp file.
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT
sed \
  -e "s|__HOST_PATH__|${HOST_SCRIPT}|g" \
  -e "s|__EXTENSION_ID__|${EXTENSION_ID}|g" \
  "${TEMPLATE}" > "${TMP_MANIFEST}"

declare -A DIRS=(
  [chrome]="${HOME}/.config/google-chrome/NativeMessagingHosts"
  [chromium]="${HOME}/.config/chromium/NativeMessagingHosts"
  [brave]="${HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  [edge]="${HOME}/.config/microsoft-edge/NativeMessagingHosts"
)

install_to() {
  local dir="$1"
  mkdir -p "${dir}"
  cp "${TMP_MANIFEST}" "${dir}/${HOST_NAME}.json"
  echo "installed: ${dir}/${HOST_NAME}.json"
}

if [[ "${BROWSER}" == "all" ]]; then
  for b in chrome chromium brave edge; do
    # Only install where the browser's config root already exists.
    if [[ -d "$(dirname "${DIRS[$b]}")" ]]; then
      install_to "${DIRS[$b]}"
    fi
  done
else
  if [[ -z "${DIRS[$BROWSER]:-}" ]]; then
    echo "error: unknown browser '${BROWSER}'" >&2
    exit 2
  fi
  install_to "${DIRS[$BROWSER]}"
fi

echo
echo "Done. Requirements:"
echo "  * 'gpg' on PATH with your secret key imported (gpg --list-secret-keys)."
echo "  * gpg-agent running (smartcard/YubiKey supported)."
echo "  * The extension's manifest must include the \"nativeMessaging\" permission."
echo
echo "Test the host manually:"
echo "  printf '\\x12\\x00\\x00\\x00{\"op\":\"get_fingerprint\"}' | python3 \"${HOST_SCRIPT}\""
