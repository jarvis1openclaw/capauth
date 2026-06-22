/**
 * Canonical CAPAUTH_NONCE payload builder (phone-signer copy).
 *
 * Byte-identical to:
 *   - browser-extension/lib/openpgp.js  buildCanonicalNoncePayload()
 *   - src/capauth/authentik/verifier.py canonical_nonce_payload()
 *   - the shared cross-impl fixture tests/fixtures/canonical_nonce_v2_vector.json
 *
 * IMPORTANT (security): the phone does NOT trust the canonical bytes sent by the
 * desktop blindly. It REBUILDS the canonical V2 string from the structured
 * fields the desktop must also send, and signs the rebuilt bytes only if they
 * match what was relayed. For the spike the phone signs the relayed payload
 * verbatim (it IS the canonical bytes) AND displays origin/fingerprint for the
 * human to approve — re-derivation cross-check is a documented hardening step.
 *
 * @module canonical
 */

/**
 * Parse a CAPAUTH_NONCE_V2 canonical payload into its fields (for display +
 * the optional re-derivation cross-check).
 *
 * @param {string} payload
 * @returns {{version:string, fields:Object}}
 */
export function parseCanonical(payload) {
  const lines = String(payload).split("\n");
  const version = lines[0] || "";
  const fields = {};
  for (let i = 1; i < lines.length; i++) {
    const eq = lines[i].indexOf("=");
    if (eq > 0) fields[lines[i].slice(0, eq)] = lines[i].slice(eq + 1);
  }
  return { version, fields };
}

/**
 * Rebuild the canonical V2 bytes from fields (cross-check helper).
 * @param {Object} f - fields object from parseCanonical().fields
 * @returns {string}
 */
export function rebuildCanonicalV2(f) {
  return [
    "CAPAUTH_NONCE_V2",
    `nonce=${f.nonce}`,
    `client_nonce=${f.client_nonce}`,
    `origin=${f.origin}`,
    `timestamp=${f.timestamp}`,
    `service=${f.service}`,
    `expires=${f.expires}`,
  ].join("\n");
}
