/**
 * Tests for the Bunker relay E2E-encryption (capauth-bunker-e2e-v1).
 *
 * Asserts the SAME cross-impl vector as tests/test_bunker_e2e.py so the
 * broker-blind channel never drifts between JS (WebCrypto) and Python
 * (cryptography). Plus the X25519 round-trip, the E2ESession handshake, and
 * tamper detection.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  generateKexKeyPair,
  deriveKeyFromShared,
  deriveSharedKey,
  sealMessage,
  openMessage,
  E2ESession,
} from "../../lib/bunker-e2e.js";

const VECTOR = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../tests/fixtures/bunker_e2e_v1_vector.json"
    ),
    "utf-8"
  )
);

const hex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (u) =>
  [...new Uint8Array(u)].map((x) => x.toString(16).padStart(2, "0")).join("");
function b64ToHex(b64) {
  const bin = atob(b64);
  let h = "";
  for (let i = 0; i < bin.length; i++) h += bin.charCodeAt(i).toString(16).padStart(2, "0");
  return h;
}

describe("bunker-e2e cross-impl vector", () => {
  it("produces the exact wire ciphertext from the shared secret (pins KDF+AEAD)", async () => {
    const shared = hex(VECTOR.inputs.shared_secret_hex);
    const key = await deriveKeyFromShared(shared, VECTOR.inputs.pairing_secret);
    const nonce = hex(VECTOR.inputs.nonce_hex);
    const obj = JSON.parse(VECTOR.inputs.plaintext_utf8);
    const wire = await sealMessage(key, obj, nonce);
    expect(b64ToHex(wire)).toBe(VECTOR.expected.ciphertext_wire_hex);
  });

  it("mixes the QR frag into the key (active-MITM hardening) — matches vector", async () => {
    const shared = hex(VECTOR.inputs.shared_secret_hex);
    const key = await deriveKeyFromShared(
      shared,
      VECTOR.inputs.pairing_secret,
      VECTOR.inputs.qr_fragment
    );
    const nonce = hex(VECTOR.inputs.nonce_hex);
    const obj = JSON.parse(VECTOR.inputs.plaintext_utf8);
    const wire = await sealMessage(key, obj, nonce);
    expect(b64ToHex(wire)).toBe(VECTOR.expected.ciphertext_wire_with_frag_hex);
  });

  it("a key derived WITHOUT the frag cannot open one sealed WITH it", async () => {
    const shared = hex(VECTOR.inputs.shared_secret_hex);
    const withFrag = await deriveKeyFromShared(
      shared,
      VECTOR.inputs.pairing_secret,
      VECTOR.inputs.qr_fragment
    );
    const noFrag = await deriveKeyFromShared(shared, VECTOR.inputs.pairing_secret, "");
    const wire = await sealMessage(withFrag, { id: "1" });
    await expect(openMessage(noFrag, wire)).rejects.toBeTruthy();
  });

  it("opens the vector ciphertext back to the original object", async () => {
    const shared = hex(VECTOR.inputs.shared_secret_hex);
    const key = await deriveKeyFromShared(shared, VECTOR.inputs.pairing_secret);
    // base64 of the wire bytes
    const bytes = hex(VECTOR.expected.ciphertext_wire_hex);
    let bin = "";
    bytes.forEach((b) => (bin += String.fromCharCode(b)));
    const wireB64 = btoa(bin);
    expect(await openMessage(key, wireB64)).toEqual(JSON.parse(VECTOR.inputs.plaintext_utf8));
  });
});

describe("bunker-e2e X25519 ECDH", () => {
  it("both sides derive a working key from each other's pubkey", async () => {
    const a = await generateKexKeyPair();
    const b = await generateKexKeyPair();
    const ka = await deriveSharedKey(a.privateKey, b.publicKeyB64, "secret123");
    const kb = await deriveSharedKey(b.privateKey, a.publicKeyB64, "secret123");
    // keys are non-extractable; prove equality by cross sealing/opening
    const wire = await sealMessage(ka, { id: "1", v: "hello" });
    expect(await openMessage(kb, wire)).toEqual({ id: "1", v: "hello" });
  });

  it("a different pairing secret yields an incompatible key", async () => {
    const a = await generateKexKeyPair();
    const b = await generateKexKeyPair();
    const ka = await deriveSharedKey(a.privateKey, b.publicKeyB64, "right");
    const kb = await deriveSharedKey(b.privateKey, a.publicKeyB64, "wrong");
    const wire = await sealMessage(ka, { id: "1" });
    await expect(openMessage(kb, wire)).rejects.toBeTruthy();
  });
});

describe("bunker-e2e E2ESession handshake", () => {
  it("completes a kex and seals/opens both directions", async () => {
    const client = new E2ESession("pair-xyz");
    const signer = new E2ESession("pair-xyz");
    const cKex = await client.start();
    const sKex = await signer.start();
    expect(cKex.type).toBe("kex");
    await client.onKex(sKex.pub);
    await signer.onKex(cKex.pub);
    expect(client.isSecure && signer.isSecure).toBe(true);

    const req = { type: "sign_request", id: "r1", payload: "CAPAUTH_NONCE_V2\n..." };
    const env = await client.seal(req);
    expect(env.type).toBe("enc");
    expect(env.id).toBe("r1");
    expect(env.payload).toBeUndefined();
    expect(await signer.open(env)).toEqual(req);

    const resp = { type: "sign_response", id: "r1", signature: "-----BEGIN..." };
    expect(await client.open(await signer.seal(resp))).toEqual(resp);
  });

  it("refuses to seal before the peer kex arrives", async () => {
    const s = new E2ESession("p");
    await s.start();
    await expect(s.seal({ id: "x" })).rejects.toThrow(/not secured/);
  });

  it("detects a tampered ciphertext", async () => {
    const a = new E2ESession("p");
    const b = new E2ESession("p");
    const aKex = await a.start();
    const bKex = await b.start();
    await a.onKex(bKex.pub);
    await b.onKex(aKex.pub);
    const env = await a.seal({ id: "1", secret: "hi" });
    // flip the last char of the base64 ciphertext
    const bad = env.ct.slice(0, -2) + (env.ct.slice(-2) === "AA" ? "AB" : "AA");
    await expect(b.open({ ct: bad })).rejects.toBeTruthy();
  });
});
