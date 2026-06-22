/**
 * Tests for the encrypt-at-rest key vault (lib/keyvault.js).
 *
 * Proves the `local-encrypted` backend's core guarantees:
 *   - encrypt → decrypt round-trips with the correct passphrase
 *   - a WRONG passphrase fails to decrypt (AES-GCM auth-tag rejection)
 *   - the stored envelope NEVER contains the plaintext key
 *   - PBKDF2 params meet the ≥210k-iteration / SHA-256 floor
 */

import { describe, it, expect, beforeAll } from "vitest";
import { webcrypto } from "crypto";

// Web Crypto + btoa/atob shims for the Node test environment.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
if (!globalThis.atob) globalThis.atob = (b) => Buffer.from(b, "base64").toString("binary");

import {
  encryptPrivateKey,
  decryptPrivateKey,
  isEncryptedEnvelope,
  KEYVAULT_PARAMS,
} from "../../lib/keyvault.js";

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

const testKey = loadFixture("test_key.json");
const ARMORED = testKey.privateKeyArmored;
const PASS = "correct horse battery staple";

describe("keyvault — encrypt/decrypt round-trip", () => {
  it("the right passphrase decrypts back to the exact armored key", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    const recovered = await decryptPrivateKey(envelope, PASS);
    expect(recovered).toBe(ARMORED);
  });

  it("a wrong passphrase fails to decrypt", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    await expect(decryptPrivateKey(envelope, "wrong-passphrase")).rejects.toThrow(
      /incorrect passphrase|corrupted/i
    );
  });

  it("two encryptions of the same key use different salt + iv (and differ)", async () => {
    const a = await encryptPrivateKey(ARMORED, PASS);
    const b = await encryptPrivateKey(ARMORED, PASS);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    // ...but both still decrypt to the same plaintext.
    expect(await decryptPrivateKey(a, PASS)).toBe(ARMORED);
    expect(await decryptPrivateKey(b, PASS)).toBe(ARMORED);
  });
});

describe("keyvault — the envelope never leaks the plaintext key", () => {
  it("serialized envelope contains no PGP key markers or armored body", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain("BEGIN PGP PRIVATE KEY BLOCK");
    expect(serialized).not.toContain("END PGP PRIVATE KEY BLOCK");
    // No substantial slice of the armored body should appear in the envelope.
    const bodyChunk = ARMORED.replace(/\s+/g, "").slice(40, 120);
    expect(serialized.includes(bodyChunk)).toBe(false);
  });

  it("envelope only carries ciphertext + kdf params, never plaintext", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    expect(envelope).not.toHaveProperty("privateKeyArmored");
    expect(envelope).not.toHaveProperty("plaintext");
    expect(envelope.cipher).toBe("AES-GCM");
    expect(typeof envelope.ciphertext).toBe("string");
    expect(typeof envelope.salt).toBe("string");
    expect(typeof envelope.iv).toBe("string");
  });
});

describe("keyvault — KDF hardening floor", () => {
  it("uses PBKDF2-SHA256 with ≥210k iterations", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    expect(envelope.kdf).toBe("PBKDF2");
    expect(envelope.hash).toBe("SHA-256");
    expect(envelope.iterations).toBeGreaterThanOrEqual(210_000);
    expect(KEYVAULT_PARAMS.PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(210_000);
  });
});

describe("keyvault — input guards", () => {
  it("rejects encryption with an empty passphrase", async () => {
    await expect(encryptPrivateKey(ARMORED, "")).rejects.toThrow(/passphrase/i);
  });

  it("rejects encryption with no key", async () => {
    await expect(encryptPrivateKey("", PASS)).rejects.toThrow(/no armored/i);
  });

  it("isEncryptedEnvelope recognizes valid + rejects bogus shapes", async () => {
    const envelope = await encryptPrivateKey(ARMORED, PASS);
    expect(isEncryptedEnvelope(envelope)).toBe(true);
    expect(isEncryptedEnvelope(null)).toBe(false);
    expect(isEncryptedEnvelope({})).toBe(false);
    expect(isEncryptedEnvelope({ cipher: "AES-GCM" })).toBe(false);
    expect(isEncryptedEnvelope("a plaintext string")).toBe(false);
  });
});
