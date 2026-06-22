/**
 * CapAuth signer-backend abstraction.
 *
 * Private-key custody is configurable. The background service worker no longer
 * cares HOW a payload gets signed — it asks a backend:
 *
 *   interface SignerBackend {
 *     async sign(canonicalPayloadString) -> armoredDetachedSignature
 *     async getFingerprint()             -> fp (40-char hex) | ""
 *   }
 *
 * The canonical bytes passed to `sign()` are ALWAYS the exact CAPAUTH_NONCE_V2
 * (or V1 legacy / CLAIMS) string built by the caller — the backend signs them
 * verbatim and never rebuilds them. This guarantees the signed bytes are
 * identical across all three backends (the load-bearing cross-impl contract).
 *
 * Three backends (worst → best custody), selected via
 * `capauth_settings.signerBackend`:
 *
 *   1. "local-plaintext"  — armored key in chrome.storage.local, UNENCRYPTED.
 *                           Demo-grade fallback. (current behaviour)
 *   2. "local-encrypted"  — armored key encrypted at rest (PBKDF2 → AES-GCM);
 *                           decrypted into the in-memory unlock session.
 *   3. "native-gpg"       — key NEVER enters the browser; a Native Messaging
 *                           host signs via OS gpg/gpg-agent (YubiKey/smartcard).
 *   4. "remote"           — key NEVER touches this device; a PAIRED PHONE
 *                           ("CapAuth Bunker", NIP-46-style) signs over a relay.
 *
 * @module signer-backends
 */

import { signMessage, extractFingerprint } from "./openpgp-bundle.js";
import { decryptPrivateKey, isEncryptedEnvelope } from "./keyvault.js";

export const SIGNER_BACKENDS = Object.freeze({
  LOCAL_PLAINTEXT: "local-plaintext",
  LOCAL_ENCRYPTED: "local-encrypted",
  NATIVE_GPG: "native-gpg",
  REMOTE: "remote",
});

export const DEFAULT_BACKEND = SIGNER_BACKENDS.LOCAL_PLAINTEXT;

export const NATIVE_HOST_NAME = "com.capauth.signer";

// ---------------------------------------------------------------------------
// Backend #1 — local-plaintext (current behaviour, demo-grade fallback)
// ---------------------------------------------------------------------------

/**
 * Signs with an UNENCRYPTED armored key from chrome.storage.local.
 *
 * The key's own PGP passphrase (if any) is supplied via the unlock session.
 * This is the zero-dependency fallback; it does NOT provide encryption-at-rest.
 */
export class LocalPlaintextBackend {
  /**
   * @param {Object} opts
   * @param {string} opts.privateKeyArmored - The stored armored private key.
   * @param {string} opts.fingerprint - The configured fingerprint.
   * @param {function(): string} [opts.resolvePassphrase] - Returns the PGP key
   *   passphrase (from the in-memory unlock session). Optional for keys with no
   *   passphrase.
   */
  constructor({ privateKeyArmored, fingerprint, resolvePassphrase } = {}) {
    this.privateKeyArmored = privateKeyArmored || "";
    this.fingerprint = (fingerprint || "").toUpperCase();
    this.resolvePassphrase = resolvePassphrase || (() => "");
  }

  async getFingerprint() {
    if (this.fingerprint) return this.fingerprint;
    if (this.privateKeyArmored) {
      try {
        return await extractFingerprint(this.privateKeyArmored);
      } catch {
        return "";
      }
    }
    return "";
  }

  /**
   * @param {string} canonicalPayload - Exact canonical string to sign.
   * @returns {Promise<string>} ASCII-armored detached signature.
   */
  async sign(canonicalPayload) {
    if (!this.privateKeyArmored) {
      throw new Error("No private key configured (local-plaintext backend).");
    }
    const passphrase = this.resolvePassphrase() || "";
    return signMessage(canonicalPayload, this.privateKeyArmored, passphrase);
  }
}

// ---------------------------------------------------------------------------
// Backend #2 — local-encrypted (encrypt-at-rest)
// ---------------------------------------------------------------------------

/**
 * Signs with an armored key that is stored ENCRYPTED at rest (PBKDF2 → AES-GCM).
 *
 * The armored key is held in plaintext only transiently, in the in-memory
 * unlock session, after a correct passphrase decrypts the envelope. The
 * envelope (and only the envelope) lives in chrome.storage.local.
 *
 * Unlock flow (background.js UNLOCK_KEY):
 *   passphrase -> decryptPrivateKey(envelope, passphrase) -> armored key in
 *   the unlock session. This backend reads that decrypted key for signing.
 */
export class LocalEncryptedBackend {
  /**
   * @param {Object} opts
   * @param {Object} opts.envelope - The stored encrypted-key envelope.
   * @param {string} opts.fingerprint - The configured fingerprint.
   * @param {function(): (string|null)} [opts.getDecryptedKey] - Returns the
   *   armored key from the in-memory unlock session, or null if locked.
   * @param {function(): string} [opts.getPgpPassphrase] - Returns the PGP
   *   passphrase to apply to the decrypted armored key (when the inner key is
   *   itself passphrase-protected). Defaults to "" (key carries no inner
   *   passphrase — the AES-GCM layer is the only protection).
   */
  constructor({ envelope, fingerprint, getDecryptedKey, getPgpPassphrase } = {}) {
    this.envelope = envelope || null;
    this.fingerprint = (fingerprint || "").toUpperCase();
    this.getDecryptedKey = getDecryptedKey || (() => null);
    this.getPgpPassphrase = getPgpPassphrase || (() => "");
  }

  async getFingerprint() {
    return this.fingerprint;
  }

  /**
   * @param {string} canonicalPayload - Exact canonical string to sign.
   * @returns {Promise<string>} ASCII-armored detached signature.
   */
  async sign(canonicalPayload) {
    if (!isEncryptedEnvelope(this.envelope)) {
      throw new Error("No encrypted key configured (local-encrypted backend).");
    }
    const armored = this.getDecryptedKey();
    if (!armored) {
      throw new Error("Key is locked. Unlock it with your passphrase first.");
    }
    // The recovered armored key may itself be PGP-passphrase-protected. The
    // unlock passphrase that decrypted the AES-GCM envelope is reused as the PGP
    // passphrase (common case: one passphrase). For a key exported WITHOUT an
    // inner passphrase this is "" and signMessage skips decryptKey.
    return signMessage(canonicalPayload, armored, this.getPgpPassphrase() || "");
  }

  /**
   * Decrypt the envelope (used by the UNLOCK plumbing). Static so the unlock
   * handler can decrypt without a fully-constructed signer.
   *
   * @param {Object} envelope
   * @param {string} passphrase
   * @returns {Promise<string>} The recovered armored private key.
   */
  static async unlock(envelope, passphrase) {
    return decryptPrivateKey(envelope, passphrase);
  }
}

// ---------------------------------------------------------------------------
// Backend #3 — native-gpg (Native Messaging → gpg-agent)
// ---------------------------------------------------------------------------

/**
 * Signs via a Chrome Native Messaging host that talks to the OS gpg/gpg-agent.
 *
 * The private key NEVER enters the browser. background.js connects to the host
 * (`chrome.runtime.connectNative(NATIVE_HOST_NAME)`), sends the canonical bytes,
 * and the host returns the armored detached signature. Supports smartcard /
 * YubiKey because gpg-agent does the signing.
 *
 * Host protocol (length-prefixed JSON; see native-host/capauth_signer.py):
 *   -> { op: "get_fingerprint" }              <- { fingerprint }
 *   -> { op: "sign", payload, fingerprint? }  <- { signature }
 *   (errors:                                   <- { error })
 */
export class NativeGpgBackend {
  /**
   * @param {Object} opts
   * @param {string} opts.fingerprint - The configured fingerprint (selects the
   *   signing key; passed to the host as `--local-user`).
   * @param {function(Object): Promise<Object>} [opts.sendNativeMessage] - Sends
   *   one request to the host and resolves its response. Defaults to a
   *   connectNative-based transport. Injectable for tests.
   */
  constructor({ fingerprint, sendNativeMessage } = {}) {
    this.fingerprint = (fingerprint || "").toUpperCase();
    this.sendNativeMessage = sendNativeMessage || defaultNativeTransport;
  }

  async getFingerprint() {
    // Prefer the host's own answer (it owns the key); fall back to configured.
    try {
      const res = await this.sendNativeMessage({ op: "get_fingerprint" });
      if (res && res.fingerprint) return String(res.fingerprint).toUpperCase();
      if (res && res.error) throw new Error(res.error);
    } catch (err) {
      if (this.fingerprint) return this.fingerprint;
      throw err;
    }
    return this.fingerprint;
  }

  /**
   * @param {string} canonicalPayload - Exact canonical string to sign.
   * @returns {Promise<string>} ASCII-armored detached signature.
   */
  async sign(canonicalPayload) {
    if (typeof canonicalPayload !== "string" || !canonicalPayload) {
      throw new Error("Nothing to sign (native-gpg backend).");
    }
    const msg = { op: "sign", payload: canonicalPayload };
    if (this.fingerprint) msg.fingerprint = this.fingerprint;

    const res = await this.sendNativeMessage(msg);
    if (!res) throw new Error("Native signer returned no response.");
    if (res.error) throw new Error(`Native signer error: ${res.error}`);
    if (!res.signature) throw new Error("Native signer returned no signature.");
    return res.signature;
  }
}

/**
 * Default Native Messaging transport: open a one-shot connectNative port, send
 * one request, resolve the first reply (or reject on disconnect/timeout).
 *
 * @param {Object} request
 * @returns {Promise<Object>}
 */
function defaultNativeTransport(request) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let port;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        port && port.disconnect && port.disconnect();
      } catch {
        /* ignore */
      }
      fn(arg);
    };
    const timer = setTimeout(
      () => finish(reject, new Error("Native host timed out.")),
      15_000
    );
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    } catch (err) {
      return finish(reject, new Error(`Cannot connect to native host: ${err.message}`));
    }
    port.onMessage.addListener((response) => finish(resolve, response));
    port.onDisconnect.addListener(() => {
      const le = chrome.runtime.lastError;
      finish(
        reject,
        new Error(
          le && le.message
            ? `Native host disconnected: ${le.message}`
            : "Native host not detected. Install the CapAuth signer host."
        )
      );
    });
    port.postMessage(request);
  });
}

// ---------------------------------------------------------------------------
// Backend #4 — remote ("CapAuth Bunker", NIP-46-style phone signer)
// ---------------------------------------------------------------------------

/**
 * Signs by relaying the canonical payload to a PAIRED PHONE over the CapAuth
 * Bunker broker. The private key NEVER enters the browser — it lives only on
 * the phone. This backend posts a `sign_request` over the broker WebSocket and
 * awaits the phone-produced armored detached signature.
 *
 * Custody: BEST for cross-device. Key stays on the phone (encrypted at rest via
 * keyvault); the desktop only ever sees ciphertext-of-payload-in, signature-out.
 *
 * Pairing is performed out of band (the popup/options renders a QR encoding the
 * `capauth-bunker://` URI from POST /bunker/session; the phone scans it). Once
 * paired, this backend connects as `role=client` and relays.
 *
 * Bunker message protocol (see src/capauth/service/bunker.py):
 *   client -> signer: {type:"sign_request", id, payload, origin, fingerprint,
 *                      version:"CAPAUTH_NONCE_V2"}
 *   signer -> client: {type:"sign_response", id, signature, fingerprint}
 *                     {type:"reject", id, reason}
 *
 * The canonical bytes are signed VERBATIM by the phone — the load-bearing
 * cross-impl contract holds across the relay (the desktop builds the bytes and
 * the phone signs exactly those bytes; the phone re-derives nothing).
 */
export class RemoteBunkerBackend {
  /**
   * @param {Object} opts
   * @param {string} opts.fingerprint - Expected signer fingerprint (display +
   *   post-verify check). The phone returns the fp it actually signed with.
   * @param {string} [opts.relayWsUrl] - The wss:// /bunker/ws URL (the desktop
   *   connects as role=client to this). Set during pairing.
   * @param {string} [opts.sessionId] - Paired session id.
   * @param {string} [opts.pairingSecret] - Pairing secret (key query param).
   * @param {string} [opts.origin] - RP origin to bind + display on the phone.
   * @param {function(Object): Promise<Object>} [opts.relayRoundTrip] - Sends one
   *   sign_request and resolves the sign_response. Injectable for tests;
   *   defaults to a one-shot WebSocket transport.
   * @param {number} [opts.timeoutMs] - Approval timeout (default 120s).
   */
  constructor({
    fingerprint,
    relayWsUrl,
    sessionId,
    pairingSecret,
    origin,
    relayRoundTrip,
    timeoutMs,
  } = {}) {
    this.fingerprint = (fingerprint || "").toUpperCase();
    this.relayWsUrl = relayWsUrl || "";
    this.sessionId = sessionId || "";
    this.pairingSecret = pairingSecret || "";
    this.origin = origin || "";
    this.timeoutMs = timeoutMs || 120_000;
    this.relayRoundTrip = relayRoundTrip || ((req) => this._defaultRelay(req));
  }

  async getFingerprint() {
    return this.fingerprint;
  }

  /**
   * @param {string} canonicalPayload - Exact CAPAUTH_NONCE_V2 string to sign.
   * @returns {Promise<string>} ASCII-armored detached signature from the phone.
   */
  async sign(canonicalPayload) {
    if (typeof canonicalPayload !== "string" || !canonicalPayload) {
      throw new Error("Nothing to sign (remote backend).");
    }
    if (!this.sessionId || !this.relayWsUrl) {
      throw new Error("No paired phone. Pair a CapAuth Bunker first.");
    }
    const reqId =
      (globalThis.crypto && globalThis.crypto.randomUUID && globalThis.crypto.randomUUID()) ||
      String(Date.now()) + Math.random().toString(16).slice(2);

    const request = {
      type: "sign_request",
      id: reqId,
      payload: canonicalPayload,
      origin: this.origin,
      fingerprint: this.fingerprint,
      version: "CAPAUTH_NONCE_V2",
    };

    const res = await this.relayRoundTrip(request);
    if (!res) throw new Error("Phone returned no response.");
    if (res.type === "reject") {
      throw new Error(`Phone rejected the signature${res.reason ? ": " + res.reason : "."}`);
    }
    if (res.type === "error") {
      throw new Error(`Bunker error: ${res.code || "unknown"}`);
    }
    if (!res.signature) throw new Error("Phone returned no signature.");
    // Origin-binding integrity: if the phone reports the fp it signed with and
    // we have an expected fp, they must match (the phone displayed + signed the
    // origin we sent; this guards against a swapped key).
    if (this.fingerprint && res.fingerprint) {
      if (String(res.fingerprint).toUpperCase() !== this.fingerprint) {
        throw new Error("Phone signed with an unexpected fingerprint.");
      }
    }
    return res.signature;
  }

  /**
   * Default WebSocket relay: connect as role=client, await `paired`, send the
   * sign_request, resolve the matching sign_response (or reject/timeout).
   *
   * @param {Object} request - the sign_request envelope.
   * @returns {Promise<Object>} the response envelope.
   */
  _defaultRelay(request) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const url =
        `${this.relayWsUrl}?session=${encodeURIComponent(this.sessionId)}` +
        `&role=client&key=${encodeURIComponent(this.pairingSecret)}`;
      let ws;
      const finish = (fn, arg) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          ws && ws.close && ws.close();
        } catch {
          /* ignore */
        }
        fn(arg);
      };
      const timer = setTimeout(
        () => finish(reject, new Error("Timed out waiting for phone approval.")),
        this.timeoutMs
      );
      try {
        ws = new WebSocket(url);
      } catch (err) {
        return finish(reject, new Error(`Cannot connect to bunker relay: ${err.message}`));
      }
      let sent = false;
      ws.onmessage = (evt) => {
        let msg;
        try {
          msg = JSON.parse(evt.data);
        } catch {
          return;
        }
        if (msg.type === "paired" && !sent) {
          sent = true;
          ws.send(JSON.stringify(request));
          return;
        }
        if (
          (msg.type === "sign_response" || msg.type === "reject") &&
          msg.id === request.id
        ) {
          finish(resolve, msg);
        } else if (msg.type === "error") {
          finish(resolve, msg);
        }
      };
      ws.onerror = () => finish(reject, new Error("Bunker relay socket error."));
      ws.onclose = () => {
        if (!settled) finish(reject, new Error("Bunker relay closed before signing."));
      };
    });
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build the configured signer backend from settings + runtime hooks.
 *
 * @param {Object} settings - The loaded `capauth_settings`.
 * @param {Object} [hooks]
 * @param {function(): string} [hooks.resolvePassphrase] - PGP key passphrase
 *   (plaintext backend) from the unlock session.
 * @param {function(): (string|null)} [hooks.getDecryptedKey] - Decrypted armored
 *   key (encrypted backend) from the unlock session.
 * @param {function(Object): Promise<Object>} [hooks.sendNativeMessage] - Native
 *   transport override (mainly tests).
 * @returns {SignerBackend}
 */
export function createSignerBackend(settings = {}, hooks = {}) {
  const backend = settings.signerBackend || DEFAULT_BACKEND;
  const fingerprint = settings.fingerprint || "";

  switch (backend) {
    case SIGNER_BACKENDS.LOCAL_ENCRYPTED:
      return new LocalEncryptedBackend({
        envelope: settings.encryptedKey || null,
        fingerprint,
        getDecryptedKey: hooks.getDecryptedKey,
        getPgpPassphrase: hooks.getPgpPassphrase,
      });

    case SIGNER_BACKENDS.NATIVE_GPG:
      return new NativeGpgBackend({
        fingerprint,
        sendNativeMessage: hooks.sendNativeMessage,
      });

    case SIGNER_BACKENDS.REMOTE: {
      const pairing = settings.bunkerPairing || {};
      return new RemoteBunkerBackend({
        fingerprint,
        relayWsUrl: pairing.relayWsUrl || settings.bunkerRelayWsUrl || "",
        sessionId: pairing.sessionId || "",
        pairingSecret: pairing.pairingSecret || "",
        origin: hooks.origin || settings.origin || "",
        relayRoundTrip: hooks.relayRoundTrip,
      });
    }

    case SIGNER_BACKENDS.LOCAL_PLAINTEXT:
    default:
      return new LocalPlaintextBackend({
        privateKeyArmored: settings.privateKeyArmored || "",
        fingerprint,
        resolvePassphrase: hooks.resolvePassphrase,
      });
  }
}
