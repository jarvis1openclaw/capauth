#!/usr/bin/env bash
#
# build-release.sh — build (and optionally sign) a Nextcloud App Store release
# tarball for the CapAuth app, WITHOUT krankerl. Pure tar + openssl.
#
# The App Store requires the archive to contain a single top-level folder whose
# name equals the app id ("capauth/") with appinfo/info.xml inside it. GitHub's
# auto-generated source tarballs do NOT match this layout, so we build our own.
#
# Usage:
#   ./build-release.sh                      # build tarball only
#   ./build-release.sh --sign               # build + emit base64 signature
#   APP_KEY=/path/to/capauth.key ./build-release.sh --sign
#
# Output:
#   build/artifacts/capauth.tar.gz          # the release archive
#   build/artifacts/capauth.tar.gz.sig.b64  # base64 signature (with --sign)
#
set -euo pipefail

APP_ID="capauth"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${HERE}/build/artifacts"
STAGE="${BUILD_DIR}/${APP_ID}"
TARBALL="${BUILD_DIR}/${APP_ID}.tar.gz"
# Default signing key location follows the Nextcloud convention.
APP_KEY="${APP_KEY:-${HOME}/.nextcloud/certificates/${APP_ID}.key}"

DO_SIGN=0
[[ "${1:-}" == "--sign" ]] && DO_SIGN=1

echo ">> Cleaning ${BUILD_DIR}"
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE}"

# Copy the app into the staging folder, honouring .nextcloudignore.
# We use rsync with an exclude file derived from .nextcloudignore.
echo ">> Staging app -> ${STAGE}"
EXCLUDES=()
if [[ -f "${HERE}/.nextcloudignore" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line//[[:space:]]/}"
        [[ -n "${line}" ]] && EXCLUDES+=( "--exclude=${line}" )
    done < "${HERE}/.nextcloudignore"
fi
rsync -a "${EXCLUDES[@]}" \
    --exclude='build' --exclude='.git' \
    "${HERE}/" "${STAGE}/"

# Sanity: the manifest must be present.
test -f "${STAGE}/appinfo/info.xml" || { echo "!! appinfo/info.xml missing in stage"; exit 1; }

# Validate against the live App Store schema if xmllint + network are available.
if command -v xmllint >/dev/null 2>&1; then
    if curl -fsS https://apps.nextcloud.com/schema/apps/info.xsd -o "${BUILD_DIR}/info.xsd" 2>/dev/null; then
        echo ">> Validating info.xml against App Store XSD"
        xmllint --noout --schema "${BUILD_DIR}/info.xsd" "${STAGE}/appinfo/info.xml"
        rm -f "${BUILD_DIR}/info.xsd"
    fi
fi

echo ">> Creating ${TARBALL}"
# Deterministic-ish tar: sorted, owned by root, no extended attrs.
tar --create --gzip \
    --owner=0 --group=0 \
    --sort=name \
    --file="${TARBALL}" \
    --directory="${BUILD_DIR}" \
    "${APP_ID}"

echo ">> Built: ${TARBALL}"
ls -l "${TARBALL}"

if [[ "${DO_SIGN}" == "1" ]]; then
    test -f "${APP_KEY}" || { echo "!! signing key not found at ${APP_KEY} (set APP_KEY=...)"; exit 1; }
    echo ">> Signing tarball with ${APP_KEY}"
    SIG="$(openssl dgst -sha512 -sign "${APP_KEY}" "${TARBALL}" | openssl base64 -A)"
    echo -n "${SIG}" > "${TARBALL}.sig.b64"
    echo ">> Signature (base64) written to ${TARBALL}.sig.b64"
    echo "${SIG}"
fi

echo ">> Done."
