/**
 * End-to-end protocol round-trip for the CapAuth Bunker remote signer.
 *
 * Proves the full chain WITHOUT a network: the desktop `RemoteBunkerBackend`
 * builds the EXACT CAPAUTH_NONCE_V2 canonical bytes (shared fixture) and emits a
 * `sign_request`; a simulated broker relays it to a simulated PHONE; the phone
 * runs the real phone-signer loop (startSigner), shows approval, signs the
 * relayed bytes with the test PGP key via OpenPGP.js, returns `sign_response`;
 * the broker relays it back; the desktop receives the armored signature and it
 * VERIFIES against the exact canonical bytes.
 *
 * Guarantees:
 *   - signed bytes are byte-identical to the shared cross-impl fixture
 *   - the broker (relay) only ever forwards the canonical payload + signature,
 *     never the private key
 *   - origin-binding (Tier B) survives: the desktop sets origin, the phone is
 *     handed + displays + signs it
 *   - reject path returns an error, not a signature
 */

import { describe, it, expect, vi } from "vitest";
import { webcrypto } from "crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
if (!globalThis.atob) globalThis.atob = (b) => Buffer.from(b, "base64").toString("binary");

import {
  createSignerBackend,
  SIGNER_BACKENDS,
  RemoteBunkerBackend,
} from "../../lib/signer-backends.js";
import { buildCanonicalNoncePayload, verifySignature, signMessage } from "../../lib/openpgp.js";
import { startSigner } from "../../../phone-signer/lib/bunker-signer.js";

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const here = dirname(fileURLToPath(import.meta.url));
function loadFixture(name) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    try {
      return JSON.parse(readFileSync(join(dir, "tests", "fixtures", name), "utf-8"));
    } catch {
      dir = dirname(dir);
    }
  }
  throw new Error(`fixture not found: ${name}`);
}

const vector = loadFixture("canonical_nonce_v2_vector.json");
const testKey = loadFixture("test_key.json");
const FP = testKey.fingerprint;

/**
 * An in-memory broker that wires a desktop relayRoundTrip() to a phone
 * startSigner() loop over a pair of fake WebSockets, mirroring bunker.py.
 *
 * Returns { clientRelay, brokerSaw } where clientRelay(req) -> Promise<resp>
 * is what the RemoteBunkerBackend uses, and brokerSaw records every relayed
 * envelope so the test can assert no key material crosses the relay.
 */
function makeInMemoryBunker({ approve = true, getDecryptedKey, fingerprint }) {
  const brokerSaw = [];
  // Phone side: a fake socket the startSigner loop reads/writes.
  let phoneOnMessage = null;
  let resolveClient = null;
  const phoneSocket = {
    send: (data) => {
      // signer -> client (relayed back through the broker)
      const msg = JSON.parse(data);
      brokerSaw.push({ from: "signer", msg });
      if (resolveClient) resolveClient(msg);
    },
    close: () => {},
    set onmessage(fn) {
      phoneOnMessage = fn;
    },
    get onmessage() {
      return phoneOnMessage;
    },
    set onopen(fn) {
      if (fn) fn();
    },
    set onclose(_fn) {},
    set onerror(_fn) {},
  };

  // Start the REAL phone signer loop against the fake socket.
  startSigner({
    relayWsUrl: "wss://broker.test/bunker/ws",
    sessionId: "sess",
    pairingSecret: "secret",
    makeSocket: () => phoneSocket,
    getFingerprint: () => fingerprint,
    requestApproval: async (req) => {
      // The phone is handed origin + fingerprint + payload (phishing-resistant).
      phoneSocket._lastApproval = req;
      return approve;
    },
    sign: async (canonicalPayload) => {
      const armored = getDecryptedKey();
      return signMessage(canonicalPayload, armored, testKey.passphrase);
    },
    onStatus: () => {},
  });

  // Broker: deliver the "paired" event to the phone loop, then relay.
  phoneOnMessage({ data: JSON.stringify({ type: "paired" }) });

  // Desktop side: relayRoundTrip(req) -> forward to phone, await its response.
  const clientRelay = (req) =>
    new Promise((resolve) => {
      resolveClient = resolve;
      brokerSaw.push({ from: "client", msg: req });
      // broker forwards client -> signer
      phoneOnMessage({ data: JSON.stringify(req) });
    });

  return { clientRelay, brokerSaw, phoneSocket };
}

describe("CapAuth Bunker — end-to-end remote-sign round-trip", () => {
  const f = vector.fields;
  const canonical = buildCanonicalNoncePayload({
    nonce: f.nonce,
    clientNonce: f.client_nonce,
    origin: f.origin,
    timestamp: f.timestamp,
    service: f.service,
    expires: f.expires,
  });

  it("canonical input equals the shared fixture byte-for-byte", () => {
    expect(canonical).toBe(vector.expected_v2);
  });

  it("desktop relays canonical bytes; phone signs; signature verifies over EXACT bytes", async () => {
    const { clientRelay, brokerSaw } = makeInMemoryBunker({
      approve: true,
      getDecryptedKey: () => testKey.privateKeyArmored,
      fingerprint: FP,
    });

    const backend = new RemoteBunkerBackend({
      fingerprint: FP,
      relayWsUrl: "wss://broker.test/bunker/ws",
      sessionId: "sess",
      pairingSecret: "secret",
      origin: f.origin,
      relayRoundTrip: clientRelay,
    });

    const sig = await backend.sign(canonical);

    // The phone-produced signature verifies against the EXACT canonical bytes.
    expect(await verifySignature(canonical, sig, testKey.publicKeyArmored)).toBe(true);
    expect(await verifySignature(vector.expected_v2, sig, testKey.publicKeyArmored)).toBe(true);

    // The broker only relayed sign_request (payload) + sign_response (signature)
    // — NO private-key material ever crossed the relay.
    const blob = JSON.stringify(brokerSaw);
    expect(blob).not.toContain("PRIVATE KEY");
    const req = brokerSaw.find((e) => e.from === "client").msg;
    expect(req.type).toBe("sign_request");
    expect(req.payload).toBe(vector.expected_v2); // byte-identical across relay
    expect(req.origin).toBe(f.origin); // Tier-B origin binding preserved
    const resp = brokerSaw.find((e) => e.from === "signer").msg;
    expect(resp.type).toBe("sign_response");
    expect(resp.signature).toBe(sig);
  });

  it("phone is handed the origin + fingerprint to display (Tier B)", async () => {
    const { clientRelay, phoneSocket } = makeInMemoryBunker({
      approve: true,
      getDecryptedKey: () => testKey.privateKeyArmored,
      fingerprint: FP,
    });
    const backend = new RemoteBunkerBackend({
      fingerprint: FP,
      relayWsUrl: "wss://broker.test/bunker/ws",
      sessionId: "sess",
      pairingSecret: "secret",
      origin: f.origin,
      relayRoundTrip: clientRelay,
    });
    await backend.sign(canonical);
    expect(phoneSocket._lastApproval.origin).toBe(f.origin);
    expect(phoneSocket._lastApproval.version).toBe("CAPAUTH_NONCE_V2");
    expect(phoneSocket._lastApproval.fingerprint).toBe(FP);
  });

  it("rejection on the phone surfaces as an error, not a signature", async () => {
    const { clientRelay } = makeInMemoryBunker({
      approve: false,
      getDecryptedKey: () => testKey.privateKeyArmored,
      fingerprint: FP,
    });
    const backend = new RemoteBunkerBackend({
      fingerprint: FP,
      relayWsUrl: "wss://broker.test/bunker/ws",
      sessionId: "sess",
      pairingSecret: "secret",
      origin: f.origin,
      relayRoundTrip: clientRelay,
    });
    await expect(backend.sign(canonical)).rejects.toThrow(/rejected/i);
  });

  it("a swapped signing fingerprint is rejected by the desktop", async () => {
    const { clientRelay } = makeInMemoryBunker({
      approve: true,
      getDecryptedKey: () => testKey.privateKeyArmored,
      fingerprint: "0000000000000000000000000000000000000000", // phone reports wrong fp
    });
    const backend = new RemoteBunkerBackend({
      fingerprint: FP,
      relayWsUrl: "wss://broker.test/bunker/ws",
      sessionId: "sess",
      pairingSecret: "secret",
      origin: f.origin,
      relayRoundTrip: clientRelay,
    });
    await expect(backend.sign(canonical)).rejects.toThrow(/unexpected fingerprint/i);
  });
});

describe("factory wires the remote backend", () => {
  it("selects RemoteBunkerBackend from settings.signerBackend='remote'", () => {
    const b = createSignerBackend(
      {
        signerBackend: SIGNER_BACKENDS.REMOTE,
        fingerprint: FP,
        bunkerPairing: {
          relayWsUrl: "wss://broker.test/bunker/ws",
          sessionId: "sess",
          pairingSecret: "secret",
        },
      },
      { origin: "https://cloud.example.org" }
    );
    expect(b).toBeInstanceOf(RemoteBunkerBackend);
    expect(b.sessionId).toBe("sess");
    expect(b.origin).toBe("https://cloud.example.org");
  });

  it("refuses to sign with no paired phone", async () => {
    const b = createSignerBackend({ signerBackend: SIGNER_BACKENDS.REMOTE, fingerprint: FP });
    await expect(b.sign("X")).rejects.toThrow(/no paired phone/i);
  });
});
