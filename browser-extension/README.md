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

## Key custody — choose a signer backend

CapAuth's signer is pluggable: the background worker asks a **signer backend**
to sign the canonical challenge bytes. The backend that holds (or doesn't hold)
your key is selected in **Settings → Key Custody**. All three sign the **exact
same `CAPAUTH_NONCE_V2` bytes** — switching custody never changes what is signed.

The interface every backend implements:

```js
interface SignerBackend {
  async sign(canonicalPayloadString) -> armoredDetachedSignature
  async getFingerprint()             -> "<40-hex fp>" | ""
}
```

### Security tradeoffs (DECISIONS §6 — worst → best custody)

| # | Backend | Where the key lives | At-rest protection | Hardware token | Use when |
|---|---------|---------------------|--------------------|----------------|----------|
| 1 | **`local-plaintext`** — *Paste key (plaintext — testing)* | `chrome.storage.local`, **unencrypted** | none (only the browser profile + the key's own PGP passphrase) | no | Quick demos / dev only. Zero-dependency fallback. |
| 2 | **`local-encrypted`** — *Encrypted key in browser (passphrase)* | `chrome.storage.local` as **ciphertext only** | **PBKDF2-SHA256 ≥210k iters → AES-GCM**; decrypted into memory on unlock (~15 min) | no | The minimum bar for real use without extra tooling. |
| 3 | **`native-gpg`** — *Local gpg-agent (native host)* | **never enters the browser** — lives in OS gpg-agent | n/a (gpg-agent owns custody) | **yes** (YubiKey / smartcard via gpg-agent) | Best local custody. Requires installing the native host. |

> **NIP-46 remote signer (phone-as-bunker)** is the next step beyond all three
> and is **out of scope here** — see *Follow-ups*.

### 1 & 2 — import your PGP key (local backends)

1. Click the CapAuth toolbar icon → **gear / Settings** (opens the options page).
2. Pick a **Key Custody** option, fill the fields it reveals:
   - **Paste key (plaintext):** fingerprint + armored private key.
   - **Encrypted key:** fingerprint + armored private key + an **encryption
     passphrase** (typed twice). On **Save**, the key is encrypted with a
     passphrase-derived AES-GCM key; only the ciphertext is stored — the
     plaintext is never written. (Migration: if a legacy plaintext key exists,
     a **"Encrypt existing key"** button appears to convert it and delete the
     plaintext copy.)
3. Add your **service URL** and optionally your **public key** (enrollment).
4. **Save Settings.**
5. For both local backends: open the popup and **Unlock** with your passphrase.
   - plaintext → the PGP key passphrase;
   - encrypted → the encryption passphrase (which decrypts the envelope into
     memory; the same passphrase also unlocks the inner PGP key if protected).

   The passphrase / decrypted key is held **in memory only** for ~15 minutes
   (never written to storage) so `window.capauth` can sign without re-prompting.

### 3 — native gpg-agent host (key never enters the browser)

```bash
cd browser-extension/native-host
./install.sh <EXTENSION_ID>     # <EXTENSION_ID> from chrome://extensions
```

This installs the per-user Native Messaging manifest pointing at
`capauth_signer.py`, restricted to your extension via `allowed_origins`. Then in
**Settings → Key Custody** choose **Local gpg-agent**, click **Check for native
host** (it should show *detected* + your gpg fingerprint), and **Save**.

Requirements: `gpg` on PATH with your secret key imported, gpg-agent running
(smartcard/YubiKey supported). See `native-host/` for the protocol and the
manifest install locations for **Chrome / Chromium / Brave / Edge** and notes
for **macOS / Windows**.

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

## Native messaging host (native-gpg backend)

`native-host/capauth_signer.py` is a tiny stdio Native Messaging host. Protocol
(little-endian uint32 length prefix + UTF-8 JSON body):

```
-> { "op": "get_fingerprint" }                          <- { "fingerprint": "<40hex>" }
-> { "op": "sign", "payload": "<canonical bytes>",      <- { "signature": "<armored>" }
     "fingerprint"?: "<40hex>" }
(any error)                                             <- { "error": "<message>" }
```

The host signs with `gpg --armor --detach-sign --pinentry-mode loopback
--local-user <fp>` and writes the canonical payload to gpg's stdin **verbatim**
(no added newline), so the detached signature verifies against the exact same
`CAPAUTH_NONCE_V2` bytes the server rebuilds. The key never leaves gpg-agent; the
host only shuttles bytes and never reads/logs/echoes key material. Inputs are
length-capped and fingerprint-validated.

Manifest install locations (per-user) — see `native-host/install.sh`:

| OS | Chrome | Chromium |
|----|--------|----------|
| Linux | `~/.config/google-chrome/NativeMessagingHosts/` | `~/.config/chromium/NativeMessagingHosts/` |
| macOS | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Windows | registry key `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.capauth.signer` → manifest path; `"path"` points at a `.bat` launcher running `python capauth_signer.py` | analogous |

(Brave/Edge use their own config roots; `install.sh` handles them on Linux.)

The `manifest.json` declares the `"nativeMessaging"` permission and
`background.js` dispatches via `chrome.runtime.connectNative("com.capauth.signer")`
when the backend is `native-gpg`.

---

## Follow-ups / out of scope

- **NIP-46 remote signer (phone-as-bunker).** The phone holds the key and signs
  login requests from any device; key never touches the desktop. Transport =
  local network or **Tailscale Funnel** when remote (DECISIONS §6 step c). This
  is the **next** custody step after native-gpg — explicitly out of scope here.
- **macOS / Windows native-host packaging.** `install.sh` registers the Linux
  per-user manifest for Chrome/Chromium/Brave/Edge; macOS paths and the Windows
  registry + `.bat` launcher are **documented** (above + in `install.sh`) but
  not auto-installed. A signed installer / launcher is a follow-up.
- **Hardware-token testing.** `native-gpg` supports YubiKey/smartcard *through*
  gpg-agent (the host issues a normal `gpg --detach-sign`, gpg-agent handles
  the touch/PIN). End-to-end testing against real hardware tokens is pending.
- **Multi-key management.** One identity at a time; key selection / multiple
  fingerprints is not implemented.
- **Firefox port.** `manifest.firefox.json` exists (now incl. `nativeMessaging`),
  but the `window.capauth` provider relies on MV3 `"world": "MAIN"`, which Firefox
  handles differently. The native-messaging host manifest format also differs on
  Firefox. Needs a separate injection shim + Firefox host manifest.
- **Store publishing.** `scripts/build.js` only bundles OpenPGP.js today;
  load-unpacked is the supported path for now.
- **`require_origin_binding` enforcement** is a server-side config flag (Tier A);
  this extension always emits V2 with a client-attested origin.
