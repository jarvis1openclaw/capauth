# CapAuth Bunker — NIP-46-style Remote Signer (SPIKE)

> Status: **SPIKE** — working, demonstrable first pass with tests. Security
> hardening is deferred (see the "Hardening follow-ups" section). This is item
> #4 of the signer-custody roadmap in
> `runbooks/capauth-research/DECISIONS_2026-06-22.md` §6.

The **CapAuth Bunker** lets a **phone hold the PGP private key** and sign
login requests relayed from any device. The key **never touches the desktop /
browser**. It is the CapAuth/OpenPGP adaptation of Nostr's NIP-46 "bunker"
(`nostrconnect://`) pattern — but using our **OpenPGP + `CAPAUTH_NONCE_V2`**
canonical payload instead of Nostr/secp256k1, and preserving the Tier-B
origin-binding phishing fix.

---

## Components built

| Component | Path | Role |
|-----------|------|------|
| **Broker** | `src/capauth/service/bunker.py` | In-memory WebSocket relay: pairs `client`↔`signer` by session id, relays opaque messages. Never sees the key. |
| **Broker wiring** | `src/capauth/service/app.py` | `POST /bunker/session`, `WS /bunker/ws`, serves the phone PWA under `/bunker/`. |
| **Phone signer PWA** | `phone-signer/` | Mobile page: import+encrypt key (keyvault), pair (scan/paste URI), approval UI (origin + fingerprint + bytes), sign with OpenPGP.js. Installable PWA. |
| **Client `remote` backend** | `browser-extension/lib/signer-backends.js` | `RemoteBunkerBackend` — relays the canonical payload to the paired phone, awaits the signature. Plugs into the existing factory (`signerBackend: "remote"`). |
| **Extension pairing UI** | `browser-extension/options/*` | "Remote signer — your phone" radio + "Create pairing QR" + broker URL. |
| **Tests** | `tests/test_bunker.py`, `browser-extension/tests/unit/remote_bunker.test.js` | Broker unit + WS integration (Python); full E2E protocol round-trip with real OpenPGP verify (JS). |

---

## Protocol

### Roles
- **client** — desktop browser / extension. Builds the exact `CAPAUTH_NONCE_V2`
  canonical bytes and asks the phone to sign them.
- **signer ("bunker")** — the phone PWA holding the key. Shows an approval prompt
  and signs.
- **broker** — the relay (this service). Dumb pass-through; never sees the key.

### Pairing URI (analog of `nostrconnect://`)
```
capauth-bunker://<broker-host>/<session-id>?key=<pairing-secret>&relay=<wss-url>
```
- `broker-host` — e.g. `capauth-skstack41.skworld.io`, or a **Tailscale Funnel**
  host when remote.
- `relay` — explicit `wss://<host>/bunker/ws` the phone connects to.

`POST /bunker/session` returns `{session_id, pairing_secret, broker_host,
relay_ws_url, pairing_uri, qr_data_url}` and the desktop renders the QR.

### Message types (JSON over the WS)

Control (broker ↔ peer):
```
broker -> peer:  {"type":"paired",    "role":"client"|"signer"}
broker -> peer:  {"type":"peer_left", "role":"..."}
broker -> peer:  {"type":"error",     "code":"...", "message":"..."}
```

Relayed (client ↔ signer; broker forwards verbatim):
```
client -> signer: {"type":"sign_request", "id":"<req-id>",
                   "payload":"<CAPAUTH_NONCE_V2 canonical bytes>",
                   "origin":"<rp origin>", "fingerprint":"<expected fp>",
                   "version":"CAPAUTH_NONCE_V2"}

signer -> client: {"type":"approve",  "id":"<req-id>"}                (optional UX ping)
signer -> client: {"type":"reject",   "id":"<req-id>", "reason":"..."}
signer -> client: {"type":"sign_response", "id":"<req-id>",
                   "signature":"<armored detached sig>", "fingerprint":"<fp>"}
```

The phone signs the **exact relayed canonical bytes verbatim** — the
load-bearing cross-impl contract holds across the relay. The desktop verifies
the returned signature over those exact bytes; the phone displays + signs the
`origin`, preserving Tier-B origin binding.

---

## Transport

- **On-LAN / cluster:** the broker runs inside the deployed CapAuth service at
  `capauth-skstack41.skworld.io` →
  `POST https://capauth-skstack41.skworld.io/bunker/session` and
  `wss://capauth-skstack41.skworld.io/bunker/ws`.
- **Remote (off-LAN):** expose the same service over **Tailscale Funnel**; the
  Funnel hostname becomes the broker host (set `CAPAUTH_BUNKER_HOST` to it, or
  it derives from `CAPAUTH_BASE_URL`). No local listener required — this is the
  key advantage over the native-messaging (gpg-agent) backend.

Env knobs (service):
- `CAPAUTH_BUNKER_HOST` — explicit broker host for the pairing URI (Funnel host).
- `CAPAUTH_BASE_URL` — fallback host source.

---

## Demo runbook (pair phone ↔ desktop, do a remote-signed login)

Prereqs: the CapAuth service running (locally: `capauth-service`, or the
deployed `capauth-skstack41.skworld.io`).

1. **Serve the PWA** — it's served by the service at `/bunker/`
   (e.g. `https://capauth-skstack41.skworld.io/bunker/`). For OpenPGP.js the
   spike loads it from a CDN (vendor it locally for production — see hardening).

2. **Phone — load the key:** open `/bunker/` on the phone, paste your armored
   PGP private key, set a *vault passphrase* (encrypts the key at rest on the
   phone via PBKDF2→AES-GCM), tap **Encrypt & store**, then **Unlock**.

3. **Desktop — create the pairing:** in the extension Options → Key Custody,
   pick **"Remote signer — your phone (CapAuth Bunker)"**, set the **CapAuth
   service base URL**, click **Create pairing QR**. (Or `curl -XPOST
   $BASE/bunker/session` and render `pairing_uri` yourself.)

4. **Phone — scan/paste** the `capauth-bunker://…` URI into the PWA and tap
   **Connect**. Both sides show **paired**.

5. **Sign in:** trigger a CapAuth login on the desktop. The `remote` backend
   builds the `CAPAUTH_NONCE_V2` payload and relays a `sign_request`. The phone
   pops the **approval modal** (website origin + fingerprint + exact bytes).
   Tap **Approve & sign** → the phone signs and returns the armored signature →
   the desktop submits it to `/capauth/v1/verify` and you're logged in. The
   **key never left the phone.**

### Headless protocol demo (no browser)
The WS round-trip is exercised end-to-end by:
```
python -m pytest tests/test_bunker.py::test_ws_endpoint_pairs_and_relays_end_to_end -v
```
and the full crypto round-trip (phone signs, desktop OpenPGP-verifies the exact
`CAPAUTH_NONCE_V2` bytes) by:
```
cd browser-extension && npx vitest run tests/unit/remote_bunker.test.js
```

---

## Test results (this spike)

- **Python** `tests/test_bunker.py`: **18 passed** — pairing/secret checks,
  paired-event fan-out, relay round-trips both directions, "broker never sees the
  key", unrelayable-type rejection, leave/expiry, pairing-URI build/parse, and a
  full FastAPI `TestClient` WS integration (pair + relay `sign_request`/
  `sign_response`, asserting the canonical bytes survive byte-for-byte).
- **JS** `browser-extension/tests/unit/remote_bunker.test.js`: **7 passed** —
  end-to-end round-trip where the desktop `RemoteBunkerBackend` relays canonical
  bytes to a real `startSigner()` phone loop, the phone signs with the test PGP
  key, and the returned signature **verifies via OpenPGP over the exact shared
  fixture bytes** (`canonical_nonce_v2_vector.json`); plus broker-sees-no-key,
  Tier-B origin pass-through, reject path, swapped-fingerprint rejection, and
  factory wiring.
- **Regression:** full JS suite **77 passed** (other backends unchanged). The
  pre-existing full-Python-suite failures (`test_qr_login` order-dependence,
  `test_register_cli` help) exist **without** this change and are unrelated.

---

## Hardening follow-ups (NOT done in this spike)

1. **E2E-encrypt the relay channel.** Today the relay forwards plaintext
   app-layer JSON (TLS terminates at the funnel/ingress, so the *broker process*
   can read the canonical payload + signature). Harden by deriving an X25519
   shared secret from the pairing secret and encrypting the relayed
   `payload`/`signature` so the broker only ever sees ciphertext. (The signature
   is over public data, but the payload + origin leak metadata.)
2. **Replay / nonce protection on the bunker protocol.** Bind each
   `sign_request` to a broker-issued challenge + monotonic counter; reject
   duplicate `id`s. Today only the CapAuth nonce TTL guards replay.
3. **Broker auth + rate-limit.** Add per-IP/session rate limiting and optional
   bearer auth on `/bunker/session`; cap concurrent sessions; shorten TTL.
4. **Phone re-derivation cross-check.** Have the phone *rebuild* the
   `CAPAUTH_NONCE_V2` from structured fields and refuse to sign if the rebuilt
   bytes differ from the relayed `payload` (defends against a malicious desktop
   smuggling non-canonical bytes). Helper already present in
   `phone-signer/lib/canonical.js` (`rebuildCanonicalV2`).
5. **Push notifications.** Web Push so the phone surfaces an approval prompt when
   the PWA is backgrounded (today it must be open + connected).
6. **Funnel deployment.** Wire `tailscale funnel` on the service host, set
   `CAPAUTH_BUNKER_HOST` to the Funnel hostname, document the systemd unit.
7. **Vendor OpenPGP.js** into `phone-signer/` (sovereignty — no CDN dependency)
   and add it to the service-worker precache.
8. **Pairing-secret hygiene.** One-time-use pairing secrets; rotate on each
   `paired`; bind the secret to a single signer socket.
