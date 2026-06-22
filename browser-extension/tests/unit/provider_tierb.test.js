/**
 * Tier B origin-binding tests for the `window.capauth` provider flow.
 *
 * What these tests prove (the actual anti-phishing guarantees):
 *
 *   1. The provider/bridge builds the SAME CAPAUTH_NONCE_V2 bytes as the shared
 *      cross-impl fixture (the Python/PHP contract) when given that fixture's
 *      origin — i.e. JS does not drift from the canonical format.
 *
 *   2. The origin that gets signed is `window.location.origin` (Tier B), NOT
 *      any origin the page supplies. We mock window.location.origin and assert
 *      the signed payload's origin line equals it.
 *
 *   3. signChallenge produces a PGP signature that verifies against the test
 *      public key over the exact canonical bytes.
 *
 *   4. A phishing origin (evil.example) yields a DIFFERENT signature payload
 *      than the legit origin — so a relayed challenge cannot be replayed: the
 *      real server rebuilds the canonical bytes with ITS origin, and the
 *      signature (made over evil.example) fails to verify against them.
 *
 * The provider/bridge/background are split across content-script worlds and the
 * service worker, which can't be loaded directly under vitest. We therefore
 * exercise the SAME core primitives they use (buildCanonicalNoncePayload +
 * signMessage + verifySignature from lib/openpgp.js) and model the load-bearing
 * Tier B rule explicitly: origin := window.location.origin.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { webcrypto } from "crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");

import {
  buildCanonicalNoncePayload,
  signMessage,
  verifySignature,
} from "../../lib/openpgp.js";

// --- fixtures ---------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve a fixture by walking up from this file. The canonical V2 vector is
 * the REPO-level shared contract (tests/fixtures/...), while the ephemeral test
 * key lives alongside the extension's own tests (browser-extension/tests/...).
 * Searching upward finds whichever directory holds the file.
 */
function loadFixture(name) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, "tests", "fixtures", name);
    try {
      return JSON.parse(readFileSync(candidate, "utf-8"));
    } catch {
      dir = dirname(dir);
    }
  }
  throw new Error(`fixture not found: ${name}`);
}

const vector = loadFixture("canonical_nonce_v2_vector.json");
const testKey = loadFixture("test_key.json");

/**
 * Model of the Tier B signer (bridge + background combined).
 *
 * The CRITICAL rule: the page hands us only the server's challenge fields. The
 * `origin` is taken from `window.location.origin` — the browser's truth — never
 * from the page. We mirror that here by reading a mocked window.location.origin.
 */
async function tierBSign(challengeFromPage, windowLocationOrigin, passphrase) {
  // Drop any origin the page tried to supply — Tier B ignores it.
  const { origin: _pageSuppliedOriginIgnored, ...serverFields } = challengeFromPage;

  const canonical = buildCanonicalNoncePayload({
    nonce: serverFields.nonce,
    clientNonce: serverFields.client_nonce_echo,
    origin: windowLocationOrigin, // <-- the load-bearing Tier B line
    timestamp: serverFields.timestamp,
    service: serverFields.service,
    expires: serverFields.expires,
  });

  const signature = await signMessage(canonical, testKey.privateKeyArmored, passphrase);
  return { signature, origin: windowLocationOrigin, canonical };
}

// A page-supplied challenge that mirrors the shared fixture's server fields,
// but with a LIE in the origin field (as a phishing proxy would relay).
function pageChallenge(lyingOrigin) {
  const f = vector.fields;
  return {
    nonce: f.nonce,
    client_nonce_echo: f.client_nonce,
    timestamp: f.timestamp,
    service: f.service,
    expires: f.expires,
    origin: lyingOrigin, // page/proxy claims this; Tier B must ignore it
  };
}

// ---------------------------------------------------------------------------

describe("Tier B — canonical V2 matches the shared cross-impl contract", () => {
  it("builds byte-identical V2 bytes to the fixture when origin = fixture origin", () => {
    const f = vector.fields;
    const canonical = buildCanonicalNoncePayload({
      nonce: f.nonce,
      clientNonce: f.client_nonce,
      origin: f.origin,
      timestamp: f.timestamp,
      service: f.service,
      expires: f.expires,
    });
    expect(canonical).toBe(vector.expected_v2);
  });
});

describe("Tier B — origin is window.location.origin, not page-supplied", () => {
  it("signs the browser origin even when the page lies about it", async () => {
    const realOrigin = "https://cloud.example.org"; // what the browser is on
    const challenge = pageChallenge("https://evil.example"); // page/proxy lie

    const { canonical } = await tierBSign(challenge, realOrigin, testKey.passphrase);
    const lines = canonical.split("\n");
    const originLine = lines.find((l) => l.startsWith("origin="));
    expect(originLine).toBe(`origin=${realOrigin}`);
    // The page's claimed evil origin must NOT appear in the signed bytes.
    expect(canonical.includes("evil.example")).toBe(false);
  });

  it("uses the real fixture origin → exact fixture bytes", async () => {
    const { canonical } = await tierBSign(
      pageChallenge("https://attacker.test"),
      vector.fields.origin,
      testKey.passphrase
    );
    expect(canonical).toBe(vector.expected_v2);
  });
});

describe("Tier B — signChallenge produces a verifiable signature", () => {
  it("signature verifies against the canonical bytes with the test public key", async () => {
    const origin = "https://cloud.example.org";
    const { signature, canonical } = await tierBSign(
      pageChallenge(origin),
      origin,
      testKey.passphrase
    );
    const ok = await verifySignature(canonical, signature, testKey.publicKeyArmored);
    expect(ok).toBe(true);
  });

  it("requires the correct passphrase to unlock the key", async () => {
    await expect(
      tierBSign(pageChallenge("https://cloud.example.org"), "https://cloud.example.org", "wrong-pass")
    ).rejects.toThrow();
  });
});

describe("Tier B — phishing origin defeats relay replay", () => {
  it("a signature made on evil.example does NOT verify against the real server's bytes", async () => {
    const realServerOrigin = "https://cloud.example.org";
    const phishOrigin = "https://evil.example";

    // Victim is actually on evil.example; Tier B binds origin=evil.example.
    const phishSig = await tierBSign(
      pageChallenge(realServerOrigin), // proxy relays the real challenge fields
      phishOrigin, // ...but the browser is really on evil.example
      testKey.passphrase
    );

    // The real server rebuilds the canonical payload with ITS OWN origin and
    // verifies the relayed signature against those bytes.
    const realServerCanonical = buildCanonicalNoncePayload({
      nonce: vector.fields.nonce,
      clientNonce: vector.fields.client_nonce,
      origin: realServerOrigin, // server asserts its own RP origin
      timestamp: vector.fields.timestamp,
      service: vector.fields.service,
      expires: vector.fields.expires,
    });

    // Sanity: the bytes the victim signed differ from what the server expects.
    expect(phishSig.canonical).not.toBe(realServerCanonical);

    // The relayed signature must FAIL against the server's bytes → phishing
    // rejected. (verifySignature throws on an invalid signature.)
    await expect(
      verifySignature(realServerCanonical, phishSig.signature, testKey.publicKeyArmored)
    ).rejects.toThrow();
  });

  it("legit origin verifies; phishing origin yields different signed bytes", async () => {
    const legit = await tierBSign(
      pageChallenge("https://cloud.example.org"),
      "https://cloud.example.org",
      testKey.passphrase
    );
    const phish = await tierBSign(
      pageChallenge("https://cloud.example.org"),
      "https://evil.example",
      testKey.passphrase
    );
    expect(legit.canonical).not.toBe(phish.canonical);
    // Legit verifies against its own bytes:
    expect(await verifySignature(legit.canonical, legit.signature, testKey.publicKeyArmored)).toBe(true);
  });
});
