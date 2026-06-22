/**
 * Tests for the signer-backend abstraction (lib/signer-backends.js).
 *
 * Proves:
 *   - the factory selects the right backend from settings.signerBackend
 *   - each backend exposes the interface: sign() + getFingerprint()
 *   - the canonical CAPAUTH_NONCE_V2 bytes are IDENTICAL regardless of backend
 *     (the bytes are built by the caller and signed verbatim) — shared fixture
 *   - native-gpg dispatch builds the correct host message (mock connectNative)
 *   - native-gpg returns the host's armored signature; surfaces host errors
 *   - local-encrypted signs only the DECRYPTED key from the unlock session
 *     (locked → refuses), and the encrypted backend's unlock round-trips
 */

import { describe, it, expect, vi } from "vitest";
import { webcrypto } from "crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
if (!globalThis.atob) globalThis.atob = (b) => Buffer.from(b, "base64").toString("binary");

import {
  createSignerBackend,
  SIGNER_BACKENDS,
  DEFAULT_BACKEND,
  NATIVE_HOST_NAME,
  LocalPlaintextBackend,
  LocalEncryptedBackend,
  NativeGpgBackend,
} from "../../lib/signer-backends.js";

import { buildCanonicalNoncePayload, verifySignature } from "../../lib/openpgp.js";
import { encryptPrivateKey } from "../../lib/keyvault.js";

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// --- fixtures ---------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Factory selection
// ---------------------------------------------------------------------------

describe("createSignerBackend — selection", () => {
  it("defaults to local-plaintext when unset", () => {
    const b = createSignerBackend({ privateKeyArmored: "x", fingerprint: FP });
    expect(b).toBeInstanceOf(LocalPlaintextBackend);
    expect(DEFAULT_BACKEND).toBe(SIGNER_BACKENDS.LOCAL_PLAINTEXT);
  });

  it("selects local-encrypted", () => {
    const b = createSignerBackend({
      signerBackend: SIGNER_BACKENDS.LOCAL_ENCRYPTED,
      encryptedKey: { cipher: "AES-GCM", ciphertext: "x", salt: "y", iv: "z" },
      fingerprint: FP,
    });
    expect(b).toBeInstanceOf(LocalEncryptedBackend);
  });

  it("selects native-gpg", () => {
    const b = createSignerBackend({ signerBackend: SIGNER_BACKENDS.NATIVE_GPG, fingerprint: FP });
    expect(b).toBeInstanceOf(NativeGpgBackend);
  });

  it("every backend implements sign() + getFingerprint()", () => {
    for (const name of Object.values(SIGNER_BACKENDS)) {
      const b = createSignerBackend({ signerBackend: name, fingerprint: FP, privateKeyArmored: "x" });
      expect(typeof b.sign).toBe("function");
      expect(typeof b.getFingerprint).toBe("function");
    }
  });
});

// ---------------------------------------------------------------------------
// Canonical bytes are identical across backends
// ---------------------------------------------------------------------------

describe("canonical V2 bytes unchanged across backends", () => {
  // Build the exact bytes once from the shared cross-impl fixture.
  const f = vector.fields;
  const canonical = buildCanonicalNoncePayload({
    nonce: f.nonce,
    clientNonce: f.client_nonce,
    origin: f.origin,
    timestamp: f.timestamp,
    service: f.service,
    expires: f.expires,
  });

  it("the canonical input matches the shared fixture byte-for-byte", () => {
    expect(canonical).toBe(vector.expected_v2);
  });

  it("plaintext + encrypted + native backends all sign the SAME bytes", async () => {
    const signed = [];

    // plaintext
    const plain = new LocalPlaintextBackend({
      privateKeyArmored: testKey.privateKeyArmored,
      fingerprint: FP,
      resolvePassphrase: () => testKey.passphrase,
    });
    const plainSig = await plain.sign(canonical);
    signed.push(canonical); // record the exact bytes handed to sign()
    // The signature verifies against the EXACT canonical bytes.
    expect(await verifySignature(canonical, plainSig, testKey.publicKeyArmored)).toBe(true);

    // encrypted (unlock by decrypting an envelope → decrypted key in session)
    const envelope = await encryptPrivateKey(testKey.privateKeyArmored, "vault-pass");
    const decrypted = await LocalEncryptedBackend.unlock(envelope, "vault-pass");
    const enc = new LocalEncryptedBackend({
      envelope,
      fingerprint: FP,
      getDecryptedKey: () => decrypted,
      // The fixture's inner PGP key is itself passphrase-protected.
      getPgpPassphrase: () => testKey.passphrase,
    });
    const encSig = await enc.sign(canonical);
    signed.push(canonical);
    expect(await verifySignature(canonical, encSig, testKey.publicKeyArmored)).toBe(true);

    // native (capture the bytes sent to the host)
    let nativeBytes = null;
    const native = new NativeGpgBackend({
      fingerprint: FP,
      sendNativeMessage: async (msg) => {
        if (msg.op === "sign") nativeBytes = msg.payload;
        return { signature: "-----BEGIN PGP SIGNATURE-----\nmock\n-----END PGP SIGNATURE-----" };
      },
    });
    await native.sign(canonical);
    signed.push(nativeBytes);

    // All three backends were handed identical canonical bytes.
    expect(signed[0]).toBe(signed[1]);
    expect(signed[1]).toBe(signed[2]);
    expect(signed[2]).toBe(vector.expected_v2);
  });
});

// ---------------------------------------------------------------------------
// native-gpg dispatch (mock connectNative)
// ---------------------------------------------------------------------------

describe("native-gpg — host message dispatch", () => {
  it("sign builds {op:'sign', payload, fingerprint} and returns the host signature", async () => {
    const sent = [];
    const native = new NativeGpgBackend({
      fingerprint: FP,
      sendNativeMessage: async (msg) => {
        sent.push(msg);
        return { signature: "ARMORED_SIG" };
      },
    });

    const sig = await native.sign("CANONICAL_PAYLOAD");
    expect(sig).toBe("ARMORED_SIG");
    expect(sent).toHaveLength(1);
    expect(sent[0]).toEqual({ op: "sign", payload: "CANONICAL_PAYLOAD", fingerprint: FP });
  });

  it("get_fingerprint asks the host and returns its fingerprint", async () => {
    const sent = [];
    const native = new NativeGpgBackend({
      fingerprint: "",
      sendNativeMessage: async (msg) => {
        sent.push(msg);
        return { fingerprint: FP.toLowerCase() };
      },
    });
    const fp = await native.getFingerprint();
    expect(sent[0]).toEqual({ op: "get_fingerprint" });
    expect(fp).toBe(FP.toUpperCase());
  });

  it("surfaces a host error from sign()", async () => {
    const native = new NativeGpgBackend({
      fingerprint: FP,
      sendNativeMessage: async () => ({ error: "no secret key available in gpg" }),
    });
    await expect(native.sign("X")).rejects.toThrow(/native signer error.*no secret key/i);
  });

  it("rejects an empty payload before contacting the host", async () => {
    const send = vi.fn();
    const native = new NativeGpgBackend({ fingerprint: FP, sendNativeMessage: send });
    await expect(native.sign("")).rejects.toThrow(/nothing to sign/i);
    expect(send).not.toHaveBeenCalled();
  });

  it("default transport uses chrome.runtime.connectNative with the host name", async () => {
    const postMessage = vi.fn();
    let onMessageCb;
    const fakePort = {
      onMessage: { addListener: (cb) => (onMessageCb = cb) },
      onDisconnect: { addListener: vi.fn() },
      postMessage,
      disconnect: vi.fn(),
    };
    const connectNative = vi.fn(() => fakePort);
    globalThis.chrome = { runtime: { connectNative, lastError: null } };

    // No injected transport → exercises defaultNativeTransport.
    const native = new NativeGpgBackend({ fingerprint: FP });
    const p = native.sign("CANON");
    // Simulate the host replying.
    onMessageCb({ signature: "SIG" });
    await expect(p).resolves.toBe("SIG");

    expect(connectNative).toHaveBeenCalledWith(NATIVE_HOST_NAME);
    expect(postMessage).toHaveBeenCalledWith({ op: "sign", payload: "CANON", fingerprint: FP });

    delete globalThis.chrome;
  });
});

// ---------------------------------------------------------------------------
// local-encrypted — locked vs unlocked
// ---------------------------------------------------------------------------

describe("local-encrypted — requires an unlocked (decrypted) key", () => {
  it("refuses to sign while locked", async () => {
    const envelope = await encryptPrivateKey(testKey.privateKeyArmored, "vault-pass");
    const enc = new LocalEncryptedBackend({
      envelope,
      fingerprint: FP,
      getDecryptedKey: () => null, // locked
    });
    await expect(enc.sign("X")).rejects.toThrow(/locked/i);
  });

  it("unlock() decrypts the envelope; wrong passphrase fails", async () => {
    const envelope = await encryptPrivateKey(testKey.privateKeyArmored, "vault-pass");
    const recovered = await LocalEncryptedBackend.unlock(envelope, "vault-pass");
    expect(recovered).toBe(testKey.privateKeyArmored);
    await expect(LocalEncryptedBackend.unlock(envelope, "nope")).rejects.toThrow();
  });

  it("refuses to sign when no envelope is configured", async () => {
    const enc = new LocalEncryptedBackend({ envelope: null, fingerprint: FP });
    await expect(enc.sign("X")).rejects.toThrow(/no encrypted key/i);
  });
});

// ---------------------------------------------------------------------------
// local-plaintext
// ---------------------------------------------------------------------------

describe("local-plaintext — signs with the stored armored key", () => {
  it("produces a signature that verifies", async () => {
    const b = new LocalPlaintextBackend({
      privateKeyArmored: testKey.privateKeyArmored,
      fingerprint: FP,
      resolvePassphrase: () => testKey.passphrase,
    });
    const canonical = vector.expected_v2;
    const sig = await b.sign(canonical);
    expect(await verifySignature(canonical, sig, testKey.publicKeyArmored)).toBe(true);
    expect(await b.getFingerprint()).toBe(FP.toUpperCase());
  });

  it("refuses to sign with no key", async () => {
    const b = new LocalPlaintextBackend({ privateKeyArmored: "", fingerprint: FP });
    await expect(b.sign("X")).rejects.toThrow(/no private key/i);
  });
});
