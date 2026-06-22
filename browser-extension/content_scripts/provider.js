/**
 * CapAuth `window.capauth` provider — NIP-07-style key-signing API for web pages.
 *
 * This script runs in the **page's MAIN world** (same JS context as the site)
 * so it can attach `window.capauth`. It exposes a tiny, deliberately minimal
 * API mirroring Nostr's NIP-07 `window.nostr`:
 *
 *   await window.capauth.getFingerprint()
 *       → resolves to the user's 40-char PGP fingerprint (or null if locked /
 *         not configured). No private-key material is ever returned.
 *
 *   await window.capauth.signChallenge(challenge)
 *       → resolves to an ASCII-armored PGP detached signature over the
 *         CAPAUTH_NONCE_V2 canonical payload. The page passes the server's
 *         challenge fields; the PROVIDER itself injects
 *         `origin = window.location.origin` (Tier B origin-binding — the page
 *         CANNOT override it). The private key never enters page scope: signing
 *         happens in the extension's isolated world / service worker.
 *
 *   window.capauth.isCapAuth === true   (feature-detection flag)
 *   window.capauth.version
 *
 * ─────────────────────────────────────────────────────────────────────────
 * SECURITY MODEL — why the key stays out of page scope
 * ─────────────────────────────────────────────────────────────────────────
 * The MAIN-world provider holds NO secrets. It is a thin RPC stub that
 * forwards requests to the ISOLATED-world bridge (`provider_bridge.js`) via
 * `window.postMessage`, which in turn talks to the background service worker
 * (the only place the unlocked PGP key lives). The bridge re-derives
 * `window.location.origin` itself before signing, so even a compromised page
 * provider cannot lie about the origin.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * TIER B ORIGIN-BINDING (the real anti-phishing fix)
 * ─────────────────────────────────────────────────────────────────────────
 * A transparent phishing proxy at evil.example relays the real server's
 * challenge to the victim. With the paste/CLI flow the user signs the
 * server-asserted `origin=realserver` and the proxy replays it — phishing
 * succeeds. With `window.capauth`, the SIGNER sets `origin` from the page it
 * is ACTUALLY on (evil.example). The real server then verifies
 * `signed.origin == its own RP origin` and rejects `invalid_origin`. The
 * signature is bound to where the browser really is — WebAuthn-equivalent.
 *
 * @module content_scripts/provider
 */

(function () {
  "use strict";

  if (window.capauth) return; // already injected (e.g. double-run guard)

  const PROVIDER_VERSION = "0.2.0";

  // requestId -> { resolve, reject, timer }
  const pending = new Map();

  function newRequestId() {
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    return "req-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  /**
   * Send an RPC to the isolated-world bridge and await its reply.
   *
   * @param {string} method - "getFingerprint" | "signChallenge".
   * @param {Object} params - Method params (challenge fields, etc.).
   * @returns {Promise<any>} Resolves with the bridge's result.
   */
  function call(method, params) {
    return new Promise((resolve, reject) => {
      const requestId = newRequestId();

      const timer = setTimeout(() => {
        if (pending.has(requestId)) {
          pending.delete(requestId);
          reject(new Error("CapAuth request timed out (no extension response)."));
        }
      }, 120_000); // generous — covers the user consent + passphrase unlock

      pending.set(requestId, { resolve, reject, timer });

      window.postMessage(
        {
          __capauth: true,
          direction: "page->ext",
          requestId,
          method,
          params: params || {},
        },
        window.location.origin // target our own origin; bridge filters on this
      );
    });
  }

  // Receive replies from the isolated-world bridge.
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__capauth !== true || data.direction !== "ext->page") return;

    const entry = pending.get(data.requestId);
    if (!entry) return;
    clearTimeout(entry.timer);
    pending.delete(data.requestId);

    if (data.ok) {
      entry.resolve(data.result);
    } else {
      entry.reject(new Error(data.error || "CapAuth signing failed."));
    }
  });

  /**
   * The public `window.capauth` API surface.
   *
   * Frozen so a page cannot monkey-patch methods after injection.
   */
  const capauth = Object.freeze({
    isCapAuth: true,
    version: PROVIDER_VERSION,

    /**
     * Return the user's PGP fingerprint, or null if not configured / locked.
     * Never exposes any private-key material.
     *
     * @returns {Promise<string|null>}
     */
    async getFingerprint() {
      const res = await call("getFingerprint", {});
      return res && res.fingerprint ? res.fingerprint : null;
    },

    /**
     * Sign a CapAuth challenge, returning an armored detached PGP signature.
     *
     * TIER B: the page provides only the server's challenge fields. The
     * PROVIDER/bridge injects `origin = window.location.origin`; any `origin`
     * supplied by the caller is IGNORED. This is what binds the signature to
     * the real page origin and defeats relay/proxy phishing.
     *
     * @param {Object} challenge - Server challenge.
     * @param {string} challenge.nonce - Server nonce UUID.
     * @param {string} challenge.client_nonce_echo - Echoed client nonce.
     * @param {string} challenge.timestamp - ISO 8601 issued-at.
     * @param {string} challenge.service - Service identifier (hostname).
     * @param {string} challenge.expires - ISO 8601 expiry.
     * @returns {Promise<{signature:string, fingerprint:string, origin:string,
     *   canonical:string}>}
     */
    async signChallenge(challenge) {
      if (!challenge || typeof challenge !== "object") {
        throw new Error("signChallenge requires a challenge object.");
      }
      if (!challenge.nonce) {
        throw new Error("Challenge is missing required field: nonce.");
      }
      // Pass ONLY the server fields. Crucially we do NOT forward any
      // caller-supplied `origin` — the bridge sets it from the live page.
      const res = await call("signChallenge", {
        nonce: challenge.nonce,
        client_nonce_echo: challenge.client_nonce_echo,
        timestamp: challenge.timestamp,
        service: challenge.service,
        expires: challenge.expires,
      });
      return res;
    },
  });

  Object.defineProperty(window, "capauth", {
    value: capauth,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  // Announce availability (mirrors NIP-07 ecosystems' readiness signal).
  window.dispatchEvent(
    new CustomEvent("capauth:ready", {
      detail: { version: PROVIDER_VERSION, isCapAuth: true },
    })
  );
})();
