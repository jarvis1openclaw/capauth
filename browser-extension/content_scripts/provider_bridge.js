/**
 * CapAuth provider bridge — ISOLATED-world half of `window.capauth`.
 *
 * Runs in the extension's isolated content-script world (has access to
 * `chrome.runtime`, the page does not). It is the trust boundary between the
 * untrusted page (`provider.js`, MAIN world) and the background service worker
 * (holds the unlocked PGP key).
 *
 * Responsibilities:
 *   1. Receive RPC requests posted by the page provider.
 *   2. **Re-derive `origin = window.location.origin` here** (Tier B). The page
 *      cannot influence this value — it is read from the browser, in a world
 *      the page cannot reach. This is the load-bearing line for origin-binding.
 *   3. Forward `getFingerprint` / `signChallenge` to the background, which
 *      performs the actual PGP signing and the user consent prompt.
 *   4. Post the result back to the page provider.
 *
 * Because this is a content script, `window.location.origin` is the REAL
 * origin of the top frame / this frame's document — exactly what we want to
 * bind into the signature.
 *
 * @module content_scripts/provider_bridge
 */

(function () {
  "use strict";

  /**
   * The authoritative origin to bind. Read from the browser, NOT the page.
   * For a phishing proxy at evil.example this is "https://evil.example".
   */
  function trustedOrigin() {
    // window.location.origin in a content script reflects the document's true
    // origin. Even if the page lies in its postMessage payload, we ignore it.
    return window.location.origin;
  }

  function reply(requestId, ok, payload) {
    window.postMessage(
      {
        __capauth: true,
        direction: "ext->page",
        requestId,
        ok,
        ...(ok ? { result: payload } : { error: payload }),
      },
      window.location.origin
    );
  }

  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__capauth !== true || data.direction !== "page->ext") return;
    if (!data.requestId || !data.method) return;

    const origin = trustedOrigin();

    try {
      if (data.method === "getFingerprint") {
        const res = await chrome.runtime.sendMessage({
          action: "PROVIDER_GET_FINGERPRINT",
          payload: { origin },
        });
        if (res && res.success) {
          reply(data.requestId, true, { fingerprint: res.fingerprint || null });
        } else {
          reply(data.requestId, false, (res && res.error) || "No fingerprint available.");
        }
        return;
      }

      if (data.method === "signChallenge") {
        const p = data.params || {};
        // Build the challenge the background will sign. The origin is OURS,
        // not the page's — Tier B enforcement happens right here.
        const challenge = {
          nonce: p.nonce,
          client_nonce_echo: p.client_nonce_echo,
          timestamp: p.timestamp,
          service: p.service,
          expires: p.expires,
          // Authoritative, browser-attested origin:
          origin,
        };

        const res = await chrome.runtime.sendMessage({
          action: "PROVIDER_SIGN_CHALLENGE",
          payload: { challenge, origin },
        });

        if (res && res.success) {
          reply(data.requestId, true, {
            signature: res.signature,
            fingerprint: res.fingerprint,
            origin: res.origin, // echoed so the page/login.js can display it
            canonical: res.canonical, // optional: exact bytes signed (debug/verify)
          });
        } else {
          reply(data.requestId, false, (res && res.error) || "Signing failed.");
        }
        return;
      }

      reply(data.requestId, false, `Unknown method: ${data.method}`);
    } catch (err) {
      reply(data.requestId, false, `Extension error: ${err.message}`);
    }
  });
})();
