# CapAuth Browser Extension

One-click passwordless **PGP login** for sovereign services — plus a
NIP-07-style **`window.capauth`** key-signing API and **Tier B origin-binding**
(client-attested origin, the real anti-phishing fix).

The private key lives **only inside the extension**. Web pages can ask the
extension to *sign* a challenge, but they never see the key — exactly like a
WebAuthn authenticator or Nostr's `window.nostr`.

---

## What this delivers

1. **`window.capauth` provider** (NIP-07 analog) — pages call
   `window.capauth.getFingerprint()` and `window.capauth.signChallenge(challenge)`.
2. **Tier B origin-binding** — the signer injects `origin = window.location.origin`
   *itself*. A phishing proxy at `evil.example` ends up signing
   `origin=https://evil.example`, which the real server rejects.
3. **In-browser PGP signing** via OpenPGP.js — the key is imported once and
   unlocked with a passphrase; signing happens in the service worker.
4. **Auto-fill** of the CapAuth login forms (Nextcloud plugin `/apps/capauth/login`
   and the CapAuth OIDC IdP `/oidc/authorize`).
5. **Phishing-resistant consent** — before signing, the popup shows the **real**
   requesting origin and asks allow/deny.

---

## Install (Chrome / Chromium / Edge / Brave — load-unpacked)

```bash
cd browser-extension
npm install          # openpgp + esbuild + (dev) vitest/happy-dom
npm run build        # bundles OpenPGP.js -> lib/openpgp-bundle.js (required)
```

Then:

1. Open `chrome://extensions`.
2. Toggle **Developer mode** (top-right).
3. Click **Load unpacked** and select this `browser-extension/` directory.
4. Pin the CapAuth icon to the toolbar.

> The `npm run build` step is **required once** — `background.js` imports the
> bundled `lib/openpgp-bundle.js` (the bundle is git-ignored). Re-run after
> changing `lib/openpgp.js`.

---

## Import your PGP key

1. Click the CapAuth toolbar icon → **gear / Settings** (opens the options page).
2. Paste your **fingerprint** (40 hex chars), your **service URL**, your
   **armored private key** (`-----BEGIN PGP PRIVATE KEY BLOCK-----`), and
   optionally your **public key** (for first-login enrollment).
3. **Save Settings.**
4. If your key has a passphrase, open the popup and **Unlock** it. The
   passphrase is held **in memory only** for ~15 minutes (never written to
   storage) so `window.capauth` can sign without re-prompting every time.

---

## How Tier B origin-binding works (the anti-phishing fix)

CapAuth challenges are signed over the canonical **`CAPAUTH_NONCE_V2`** payload:

```
CAPAUTH_NONCE_V2
nonce=<uuid>
client_nonce=<b64>
origin=<scheme://host[:port]>     # the binding
timestamp=<iso8601>
service=<host>
expires=<iso8601>
```

- **Tier A (already shipped, server-side):** the server puts its own origin in
  `origin=` and verifies it on return. Defense-in-depth, but a transparent
  proxy still shows the user the *real* server's origin, so it does **not** stop
  phishing on its own.
- **Tier B (this extension, the real fix):** the **signer** sets `origin` from
  the page it is *actually* on. The flow:

  1. The page calls `window.capauth.signChallenge(challenge)` with only the
     server's fields. **It cannot supply `origin`** — the provider strips it.
  2. The **isolated-world bridge** reads `window.location.origin` (the browser's
     truth, in a world the page cannot reach) and attaches it.
  3. The **service worker** builds the exact `CAPAUTH_NONCE_V2` bytes with that
     origin and signs them with your unlocked key.
  4. The real server rebuilds the canonical payload with **its own** RP origin
     and verifies. If you were on `evil.example`, the signed `origin` is
     `https://evil.example` ≠ the server's origin → **`invalid_origin`,
     rejected**. The signature also covers `origin`, so it can't be edited in
     transit.

This is the WebAuthn-equivalent property: the signature is bound to where the
browser really is, and neither the server nor a relay can forge it.

### Trust boundary (where the key lives)

```
  page (MAIN world)            isolated world             service worker
  provider.js                  provider_bridge.js         background.js
  window.capauth   ──postMessage──►  attaches REAL  ──runtime──►  OpenPGP.js
  (no secrets)        (server fields)  window.location.origin       signs with
                                       + user consent               unlocked key
```

The private key and passphrase never cross into page scope.

---

## `window.capauth` API (for site authors)

```js
if (window.capauth?.isCapAuth) {
  const fp = await window.capauth.getFingerprint();        // 40-char fp or null
  const { signature, fingerprint, origin } =
    await window.capauth.signChallenge(serverChallenge);   // armored PGP sig
  // POST { fingerprint, nonce, nonce_signature: signature } to your verify endpoint.
  // NOTE: you do NOT pass origin — the extension owns it (Tier B).
}
```

Both first-party CapAuth login pages already use this automatically:
- Nextcloud plugin `login.js` (`/apps/capauth/login`)
- CapAuth OIDC IdP login page (`/oidc/authorize`)

When the extension is absent, those pages fall back to the manual paste flow.

---

## Tests

```bash
npm install        # includes vitest + happy-dom (devDeps)
npx vitest run
```

Covers (among others):
- `CAPAUTH_NONCE_V2` bytes match the **shared cross-impl fixture**
  (`tests/fixtures/canonical_nonce_v2_vector.json`) byte-for-byte — the same
  contract the Python and PHP impls assert against.
- The signed `origin` is `window.location.origin`, **not** any page-supplied
  value (Tier B).
- `signChallenge` produces a signature that **verifies** against the test
  public key over the exact canonical bytes.
- A **phishing origin** (`evil.example`) yields different signed bytes than the
  legit origin, and the relayed signature **fails** verification against the
  real server's bytes — proving relay-replay is defeated.

---

## What is stubbed / out of scope (follow-ups)

- **At-rest key encryption.** The armored private key is currently stored in
  `chrome.storage.local` (see `options.js`). The unlock plumbing
  (`UNLOCK_KEY` / in-memory passphrase session in `background.js`) is built for
  a passphrase-derived WebCrypto (PBKDF2 + AES-GCM) encryption-at-rest layer,
  but the encryption step itself is **not yet implemented**. Until then, treat
  the stored key as protected only by its own PGP passphrase + the browser
  profile's protections.
- **Multi-key management.** One identity at a time. Key selection / multiple
  fingerprints is not implemented.
- **NIP-46 QR remote / cross-device signer.** No remote-signer (phone-as-signer)
  flow — explicitly out of scope for this pass.
- **Firefox port.** `manifest.firefox.json` exists, but the `window.capauth`
  provider relies on MV3 content-script `"world": "MAIN"`, which Firefox handles
  differently (use `wrappedJSObject` / `exportFunction` page injection). The
  Firefox build needs a separate injection shim.
- **Store publishing.** Chrome Web Store / AMO submission packaging
  (`scripts/build.js` only bundles OpenPGP.js today; it does not assemble a
  `dist/` tree — load-unpacked is the supported path for now).
- **`require_origin_binding` enforcement** is a server-side config flag (Tier A
  work); this extension always emits V2 with a client-attested origin.
