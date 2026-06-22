/**
 * CapAuth auto-fill — detects a CapAuth login page and fills the signature
 * automatically using `window.capauth` (Tier B origin-bound signing).
 *
 * Runs in the page's MAIN world (it must call `window.capauth`, which lives in
 * page scope). It handles BOTH first-party CapAuth surfaces:
 *
 *   1. Nextcloud native plugin  — /apps/capauth/login
 *        fingerprint input  #capauth-fingerprint-input
 *        signature textarea #capauth-sig-input
 *        Native login.js also listens for the `capauth:signed` event; we both
 *        fill the field AND dispatch `capauth:signed` so either path completes.
 *
 *   2. CapAuth OIDC IdP login    — /oidc/authorize
 *        fingerprint input  #fp
 *        nonce display      #nonce
 *        signature textarea #sig
 *        Submit handled by the page's own submitSig().
 *
 * Detection is route-based (path match) plus a DOM-shape fallback, so it works
 * even before page meta tags exist.
 *
 * Flow once a page is recognised AND `window.capauth` is available:
 *   a. Get the fingerprint from the extension (window.capauth.getFingerprint).
 *   b. Fill the fingerprint field and trigger the page's challenge load.
 *   c. Read the loaded challenge, call window.capauth.signChallenge(challenge)
 *      — the extension injects origin = window.location.origin (Tier B) and
 *      signs in-extension; the page never sees the key.
 *   d. Fill the signature textarea + dispatch capauth:signed for native login.js.
 *
 * @module content_scripts/autofill
 */

(function () {
  "use strict";

  function hasProvider() {
    return !!(window.capauth && window.capauth.isCapAuth);
  }

  // --- surface detection -----------------------------------------------------

  function detectSurface() {
    const path = window.location.pathname;

    // Nextcloud native plugin
    if (
      /\/apps\/capauth\/login/.test(path) ||
      document.getElementById("capauth-fingerprint-input")
    ) {
      return {
        kind: "nextcloud",
        fpInput: document.getElementById("capauth-fingerprint-input"),
        fpBtn: document.getElementById("capauth-fingerprint-btn"),
        nonceDisplay: document.getElementById("capauth-nonce-display"),
        sigInput: document.getElementById("capauth-sig-input"),
      };
    }

    // CapAuth OIDC IdP login page
    if (
      /\/oidc\/authorize/.test(path) ||
      (document.getElementById("fp") && document.getElementById("sig") && document.getElementById("nonce"))
    ) {
      return {
        kind: "oidc",
        fpInput: document.getElementById("fp"),
        nonceDisplay: document.getElementById("nonce"),
        sigInput: document.getElementById("sig"),
      };
    }

    return null;
  }

  // --- challenge extraction --------------------------------------------------
  //
  // Both pages render the challenge after a fingerprint is entered. The native
  // Nextcloud page renders the FULL canonical payload string in
  // #capauth-nonce-display; the OIDC page renders just the nonce UUID in #nonce.
  // We capture the challenge object via the `capauth:challenge` event that
  // login.js dispatches; for the OIDC page (no event) we re-fetch the challenge
  // ourselves through the same /capauth/v1/challenge endpoint.

  let capturedChallenge = null;
  window.addEventListener("capauth:challenge", (e) => {
    capturedChallenge = e.detail || null;
  });

  function genClientNonce() {
    const b = crypto.getRandomValues(new Uint8Array(16));
    return btoa(String.fromCharCode.apply(null, b));
  }

  async function fetchChallengeFor(fingerprint, base) {
    const url = base.replace(/\/$/, "") + "/capauth/v1/challenge";
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        capauth_version: "1.0",
        fingerprint,
        client_nonce: genClientNonce(),
      }),
    });
    if (!r.ok) throw new Error("challenge fetch failed: " + r.status);
    return r.json();
  }

  function setNativeValue(el, value) {
    // React-safe value setter, then fire input/change.
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // --- main flow -------------------------------------------------------------

  async function run(surface) {
    if (!hasProvider()) return; // user has the page but not the extension/key

    let fingerprint;
    try {
      fingerprint = await window.capauth.getFingerprint();
    } catch {
      return; // locked / not configured — leave the manual paste flow intact
    }
    if (!fingerprint) return;

    // 1. Fill the fingerprint and trigger the page's challenge load.
    if (surface.fpInput) {
      setNativeValue(surface.fpInput, fingerprint);
      // Nextcloud loads challenge on button click; OIDC on blur.
      if (surface.kind === "nextcloud" && surface.fpBtn) {
        surface.fpBtn.click();
      } else if (surface.kind === "oidc") {
        surface.fpInput.dispatchEvent(new Event("blur", { bubbles: true }));
      }
    }

    // 2. Wait for the challenge to be available.
    const challenge = await waitForChallenge(surface, fingerprint);
    if (!challenge) return;

    // 3. Sign via the extension (origin injected by the extension — Tier B).
    let result;
    try {
      result = await window.capauth.signChallenge(challenge);
    } catch (err) {
      // Denied / locked — surface nothing; the manual flow remains usable.
      console.warn("[capauth] auto-sign skipped:", err.message);
      return;
    }

    // 4. Fill the signature + notify native login.js.
    if (surface.sigInput) {
      setNativeValue(surface.sigInput, result.signature);
    }
    window.dispatchEvent(
      new CustomEvent("capauth:signed", {
        detail: {
          nonce_signature: result.signature,
          fingerprint: result.fingerprint,
          public_key: "",
          claims: {},
          claims_signature: "",
        },
      })
    );
  }

  async function waitForChallenge(surface, fingerprint) {
    // Prefer the event-captured challenge object (Nextcloud).
    for (let i = 0; i < 40; i++) {
      if (capturedChallenge && capturedChallenge.nonce) return capturedChallenge;

      // OIDC page: nonce UUID rendered in #nonce — fetch the full challenge.
      if (surface.kind === "oidc" && surface.nonceDisplay) {
        const txt = (surface.nonceDisplay.textContent || "").trim();
        if (/^[0-9a-f-]{36}$/i.test(txt)) {
          try {
            return await fetchChallengeFor(fingerprint, window.location.origin);
          } catch {
            return null;
          }
        }
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    return null;
  }

  // --- init ------------------------------------------------------------------

  function init() {
    const surface = detectSurface();
    if (surface) run(surface);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
