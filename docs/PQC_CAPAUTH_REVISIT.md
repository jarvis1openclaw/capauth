# PQC CapAuth Revisit — Identity/Crypto Layer Audit

**Scope:** a code-level audit of capauth's identity/crypto layer for the PQC root
migration (#3). This is the line-by-line *"what reads, signs, stores, or parses
the root key, and what breaks when a PQC (ML-DSA-87 + Ed448) root armor reaches
it"* companion to the two planning docs:

- `docs/PQC_ROOT_MIGRATION.md` — sequencing + backend decision + build provenance.
- `docs/ROOT_ROTATION_CEREMONY.md` — the gated ceremony with Chef's real key.

This doc does **not** restate those; it pins the findings to specific
`file:line` sites in the current tree and enumerates concrete required changes.

> **Standards honesty (mandatory).** The live root identity (fingerprint
> `02BC0EB3CAD31DB691A753C70C5629AB893F9746`) is **still classical** (Ed25519 /
> RSA-4096, Shor-breakable; RFC 8032 / RFC 9580). No rotation ceremony has run.
> The PQC backend is **additive + reversible**. Targets cite FIPS 203 (ML-KEM),
> FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), RFC 8032/9580, and the **pre-RFC**
> `draft-ietf-openpgp-pqc-17` (Standards Track, RFC Editor queue — **not yet an
> RFC**; code points can still change). Posture is described **per surface**.
> Already shipped, separate from the root: hybrid per-message + DID/challenge
> signatures (ML-DSA-65 + Ed25519 composite via `skcomms.pqsig` / `pqc_identity`).

---

## 1. Every site that generates / stores / signs-with / parses the root key

The audit groups the root-key touchpoints by operation. **Fingerprint width** is
a cross-cutting issue: a v6 / RFC 9580 PQC key has a **64-hex** fingerprint, but
the entire codebase assumes the classical **40-hex** width.

### 1.1 Key generation

| Site | What it does | PQC impact |
|------|--------------|-----------|
| `profile.py:94-95` (`init_profile`) | `backend = get_backend(backend_type)` then `backend.generate_keypair(name, email, passphrase, algorithm)` | Default args are `algorithm=Algorithm.RSA4096`, `backend_type=CryptoBackendType.PGPY` (`profile.py:57-58`). To generate a PQC root, the caller MUST pass `backend_type=SEQUOIA` + `algorithm=HYBRID_ED448_MLDSA87`. **Nothing in `init_profile` itself blocks this**, but everything downstream (signing, fingerprint persistence) assumes classical — see below. |
| `crypto/__init__.py:29-41` (`get_backend`) | Returns `SequoiaBackend()` for `SEQUOIA`, else PGPy/GnuPG | Wiring is present and correct. `SequoiaBackend.available()` (`sequoia_backend.py:82-90`) gates on a runnable `sq`; raises `BackendError` otherwise. |
| `crypto/sequoia_backend.py:117-168` (`generate_keypair`) | Shells `sq key generate --cipher-suite mldsa87-ed448 --profile rfc9580 …`, returns `KeyBundle` | This is the only path that can mint a PQC signing root. **Caveat:** if `passphrase` is non-empty it writes `--new-password-file` (line 149-152), producing a **protected** key — which then **cannot be signed with** (see §1.3). |
| `crypto/pgpy_backend.py:66-71` (`generate_keypair`) | Raises `NotImplementedError` for any `algorithm.is_post_quantum` | Correct guard — PGPy can never mint PQC. No change needed; this is the intended dead-end. |

### 1.2 Key storage / persistence

| Site | What it stores | PQC impact |
|------|----------------|-----------|
| `profile.py:101-107` | Writes `public.asc` / `private.asc` (priv `chmod 0o600`) from `bundle.{public,private}_armor` | Armor is opaque text — **v6/PQC armor stores fine**. No change. |
| `profile.py:111-116` (`KeyInfo`) | Persists `bundle.fingerprint` into `profile.json` | The fingerprint is whatever the backend returned. `SequoiaBackend._fingerprint_of_file` (`sequoia_backend.py:230-235`) returns the real **64-hex** v6 fp. This 64-hex value flows into `profile.json` and every consumer of `profile.key_info.fingerprint`. |
| `models.py:99` (`KeyInfo.fingerprint`) | `Field(description="Full 40-character PGP fingerprint")` — **no length validator** | Pydantic does not enforce 40, so a 64-hex value is accepted, **but the description and downstream assumptions are wrong**. **Change:** update the description; audit every `len(fingerprint)`/40-assuming consumer. |
| `crypto/base.py:21,27` (`KeyBundle.fingerprint`) | docstring "Full 40-char hex PGP fingerprint" | Cosmetic but misleading; **change** to "40 (v4) or 64 (v6) hex". |
| `service/keystore.py:27` | `fingerprint: str` "40-char uppercase PGP fingerprint"; `service/keystore.py:62` SQLite `fingerprint TEXT PRIMARY KEY` | `TEXT` column holds 64 fine; `.upper()` normalization (`keystore.py:83,115`) is width-agnostic. **No schema change required**, only doc/string corrections. Note enrolled *clients* are independent of the root — this table matters for the bunker/web login surface, not the root itself. |

### 1.3 Signing with the key

| Site | What it does | PQC impact |
|------|--------------|-----------|
| `profile.py:140-161` (`_sign_profile`) | Self-signs `profile.json` via `backend.sign(profile_bytes, private_armor, passphrase)` | If the root is a Sequoia PQC key generated **with** a passphrase, this call hits `SequoiaBackend.sign`'s `NotImplementedError` (`sequoia_backend.py:186-191`). **This is the single biggest functional gap for a PQC root** — see §3. |
| `crypto/sequoia_backend.py:170-193` (`sign`) | `sq sign --signer-file … --signature-file …`; **raises `NotImplementedError` if `passphrase` is set** | `sq sign` has no `--password` flag in this build; a protected signer needs the `sq` keystore. **Required change:** implement passphrase signing (sq keystore import, or an alternate unlock path), OR mandate an unprotected on-disk key + OS-level protection. Until then a PQC root must be **passphrase-less** to be usable by capauth's profile/challenge paths. |
| `identity.py:69-81` (`respond_to_challenge`) | `backend.sign(data, private_key_armor, passphrase)` then `backend.fingerprint_from_armor(...)` | Backend-agnostic via `backend_type` param, **but the param defaults to `CryptoBackendType.PGPY` (`identity.py:49`)**. A PQC root cannot sign through the PGPy default — the caller MUST pass `SEQUOIA`. Same passphrase caveat applies. |
| `pqc_identity.py:122-141` (`respond_to_challenge_hybrid`) | Calls classical `respond_to_challenge` for the PGP leg + adds an `skcomms.pqsig` hybrid leg | The classical PGP leg here is the **root** signature. With a PQC root + PGPy default, this leg fails to sign. Note the hybrid leg's key is a **separate per-agent ML-DSA-65 key, never the root** (`pqc_identity.py:15-18`) — so this file is *orthogonal* to the root migration, but it still calls the root-signing path. |
| `service/app.py:240-244` | `backend = get_backend(); backend.fingerprint_from_armor(SERVER_KEY_ARMOR)` | Server identity (the service's own key), default backend. If the **service key** is ever migrated to PQC, this default-PGPy call breaks fingerprint extraction (PGPy can't parse v6). |

### 1.4 Armor parsing / fingerprint extraction / verification

| Site | What it parses | PQC impact |
|------|----------------|-----------|
| `crypto/sequoia_backend.py:219-235` (`fingerprint_from_armor` / `_fingerprint_of_file`) | `sq inspect` → regex `Fingerprint:\s*([0-9A-Fa-f]{40,64})` | Already accepts **40 or 64** hex (`_FPR_RE`, `sequoia_backend.py:54`). Correct. This is the only backend that can parse PQC armor. |
| `crypto/pgpy_backend.py:184-200` (`fingerprint_from_armor`) | `pgpy.PGPKey.from_blob(armor)` | **PGPy cannot parse a v6/PQC key** — `from_blob` raises, wrapped as `BackendError`. Any PQC armor reaching this returns an error. |
| `crypto/pgpy_backend.py:146-182` (`verify`) | `pgpy.PGPKey.from_blob(public_key_armor)` + signed-message verify | Same — PQC public armor → `from_blob` raises → caught by the bare `except Exception: return False` (line 181). **Silent verification failure** (returns `False`, not an error). |
| `authentik/verifier.py:241-267` (`verify_nonce_signature`) | Routes detach-sigs to `_verify_with_gnupg`, else PGPy `backend.verify` | **The login verification path. Breaks two ways for PQC:** (a) PGPy branch can't parse v6 armor; (b) the GnuPG branch (`verifier.py:205-238`) uses `gnupg`/`gpg2`, which **cannot verify an ML-DSA signature** (GnuPG PQC is encryption-only). See §2.1 / §3. |
| `authentik/verifier.py:270-295` (`verify_claims_signature`) | Same routing | Same break. |
| `authentik/verifier.py:298-315` (`fingerprint_from_armor`) | Default PGPy backend | Can't extract a v6 fp; returns `None` → enrollment/derived-fp checks in `service/app.py:285-308,1159-1182` fail closed. |
| `did.py:106-143` (`_pgp_armor_to_rsa_numbers`) | `pgpy.PGPKey.from_blob(armor)` then RSA `n,e` extraction | **PGPy can't parse v6; and even if it could, ML-DSA-87+Ed448 has no RSA `n,e`.** Raises `ValueError`. See §2.2. |
| `did.py:251-272` (`from_profile`) | Wraps the above in try/except → on failure builds a **fingerprint-based placeholder** `did:key` + a JWK with `note: "JWK extraction failed"` | A PQC root **degrades to a placeholder DID** with no usable public key — silently. The DID layer does **not** support a PQC key cleanly today. See §2.2. |
| `profile.py:227-252` (`verify_profile_signature`) | `backend = get_backend(profile.crypto_backend)` then `backend.verify(...)` | This one reads the backend **from the profile** (`crypto_backend` field), so a profile that stores `crypto_backend: sequoia` verifies via Sequoia. **This is the correct pattern** — see §4 recommendation to make other call sites do the same. |

---

## 2. How `SequoiaBackend` reconciles with the three integration surfaces

### 2.1 Bunker remote-signer (phone holds key + signs logins)

**Mechanism (`service/bunker.py`, `docs/CAPAUTH_BUNKER_REMOTE_SIGNER.md`):** the
broker is a *dumb relay* — it pairs `client`↔`signer` by session id and forwards
opaque (E2E-encrypted) messages; it **never sees the key or the signature
meaning** (`bunker.py:1-18,229-256`). So the broker is **algorithm-agnostic** —
a PQC signature relays through it byte-for-byte with **zero changes**. Good.

**Where it actually breaks is NOT the relay — it's the two endpoints:**

1. **The phone signer signs with OpenPGP.js** (`docs/CAPAUTH_BUNKER_REMOTE_SIGNER.md:23,
   phone-signer/ + `bunker.py:13`). OpenPGP.js has **no ML-DSA/ML-KEM signing**
   today. A PQC *root* held on the phone cannot be loaded or used by the current
   phone PWA. This is the **WebCrypto/JS PQC gap** (`CRYPTO_SPEC.md:492-498`)
   reappearing on the signer side. **Required:** the phone signer would need a
   PQC-capable signing path (FFI/WASM liboqs, or a native signer app) before a
   PQC root can be held on-phone.
2. **The server verifies the returned detach-sig via GnuPG** (`verifier.py:261-262`
   → `_verify_with_gnupg`, `verifier.py:205-238`). GnuPG **cannot verify ML-DSA**
   (encryption-only PQC). So even if the phone produced a PQC detach-sig, the
   server would reject it. **Required:** add a Sequoia verification branch (route
   `sq verify` for v6/PQC armor) — see §4.

**Net:** the bunker *protocol* is PQC-ready; the **phone signer and the server
verify path are not**. Until both gain PQC, bunker logins stay classical — which
is consistent with the additive posture (classical and PQC coexist per surface).

### 2.2 DID layer (`did.py` reads `public_key_armor`)

ML-DSA-87 + Ed448 armor does **not** flow cleanly through `did.py` today:

- `did.py` is **RSA-only** at the JWK/`did:key` level: `_pgp_armor_to_rsa_numbers`
  (`did.py:92-143`) extracts RSA `n,e`; `_build_jwk` (`did.py:186-202`) emits
  `{"kty":"RSA", …}`; the multicodec prefix is hardcoded RSA (`did.py:31-32,169-183`).
  There is **no code path** for an EdDSA, ML-DSA, or composite key — even the
  *classical* Ed25519 root would already fall to the placeholder branch.
- For a PQC root, `from_blob` raises (PGPy can't parse v6) → caught at
  `did.py:256-272` → emits a **placeholder** `did:key` from the raw fingerprint
  bytes + a JWK stub with `note: "JWK extraction failed"`. The published DID then
  carries **no verifiable public key**.
- There is **no registered multicodec** for ML-DSA-87+Ed448 composite keys, and
  **no JWK `kty`** for ML-DSA in any finalized spec (PQC COSE/JOSE are themselves
  drafts). So even a correct implementation can only emit a draft-tier
  representation.

**Required changes (DID):** add a non-RSA key path (read the primary algo via
`SequoiaBackend._primary_algo` (`sequoia_backend.py:237-246`)); for PQC, either
(a) embed the raw OpenPGP public key as the verification material (e.g. a
`publicKeyMultibase` of the cert, not a JWK), or (b) publish a draft PQC JWK and
label it pre-standard. **Until then, the DID for a PQC root is a placeholder and
must not be presented as a verifiable PQC DID.**

### 2.3 Q7 hybrid challenge path (`pqc_identity.py`)

This path is **already PQC-bearing and is independent of the root** — the hybrid
leg uses a **separate per-agent ML-DSA-65 + Ed25519 key via `skcomms.pqsig`**,
never the PGP root (`pqc_identity.py:15-18,74-81`). Two interaction points with
the root migration:

1. `respond_to_challenge_hybrid` calls the **classical** `respond_to_challenge`
   for the PGP leg (`pqc_identity.py:122-125`), which signs with the **root**.
   With a PQC root, that leg needs `backend_type=SEQUOIA` (the default is PGPy,
   `pqc_identity.py:91`) and a passphrase-less key (§1.3).
2. `verify_challenge_hybrid` (`pqc_identity.py:196-210`) delegates the PGP-leg
   verification to `identity.verify_challenge` → `get_backend(PGPY).verify`. With
   a PQC root public key, the PGPy verify returns `False` (can't parse v6), so the
   `classical_ok and hybrid_ok` AND-gate (`pqc_identity.py:210`) fails even when
   the hybrid leg is valid. **Required:** make the PGP-leg backend match the root.

**Naming note:** `pqc_identity.py` is the **ML-DSA-65 + Ed25519** (L3, alg 30)
per-message/challenge surface; the **root** target is **ML-DSA-87 + Ed448** (L5,
alg 31). Two different suites, two different surfaces — do not conflate.

---

## 3. Gaps / risks (concrete failure modes)

| # | Risk | Trigger | Failure mode | Severity |
|---|------|---------|--------------|----------|
| R1 | **PGPy can't parse v6/PQC armor** | PQC root public/private armor reaches any PGPy site: `pgpy_backend.py:135,166,197`; `did.py:108`; `verifier.py` PGPy branch | `from_blob` raises. In `verify` it's swallowed → **silent `False`** (`pgpy_backend.py:181`); in `fingerprint_from_armor` → `BackendError`; in `did.py` → placeholder DID. | **High** — silent verification failure is the worst case (looks like a bad signature, not a backend mismatch). |
| R2 | **GnuPG can't verify ML-DSA** | Bunker/detach-sig login with a PQC root | `_verify_with_gnupg` (`verifier.py:205-238`) returns `False`; PQC logins rejected even when valid. | **High** — blocks the bunker path for PQC. |
| R3 | **Default `backend_type=PGPY` everywhere** | `identity.py:49`, `pqc_identity.py:91`, `verifier.py:245,300`, `service/app.py:243` | Even with a PQC profile on disk, callers that don't thread `SEQUOIA` route to PGPy and fail. | **High** — wide blast radius; many call sites hardcode the default. |
| R4 | **`SequoiaBackend.sign` can't sign a passphrase-protected key** | PQC root generated with a passphrase (`sequoia_backend.py:149-152`), then `_sign_profile`/challenge | `NotImplementedError` (`sequoia_backend.py:186-191`). | **High** — forces a passphrase-less root until sq-keystore signing lands; an unprotected private key on disk is a custody downgrade. |
| R5 | **40-hex fingerprint assumptions** | v6 fp is 64 hex | Docstrings/Field descriptions say 40 (`base.py:21,27`; `models.py:99`; `keystore.py:27`). No hard validator found, so data flows, but any external/UI consumer that truncates/validates 40 will corrupt a 64-hex fp. | **Medium** — works today (TEXT columns, no validators) but fragile; audit UI/CLI/peer-registry consumers. |
| R6 | **DID is RSA-only** | Any non-RSA root (already true for classical Ed25519) | Placeholder DID, no verifiable key (`did.py:251-272`). | **Medium** — pre-existing; PQC makes it unavoidable. |
| R7 | **Phone signer (OpenPGP.js) has no PQC** | PQC root held on phone | Can't load/sign; bunker custody can't go PQC. | **Medium** — external dep (browser/JS PQC gap). |
| R8 | **Cross-backend interop assumption is now false** | `CRYPTO_SPEC.md:52` claims "A key generated by PGPy can be verified by GnuPG and vice versa" | A Sequoia v6/PQC key is verifiable by **neither** PGPy nor GnuPG — only by Sequoia. | **Medium** — spec text is stale; verification MUST be Sequoia-routed for PQC. |
| R9 | **`available()` is silent** | `sq` missing on a host | `get_backend(SEQUOIA)` raises `BackendError`, but any path that defaults to PGPy never notices the root is PQC. | **Low/Medium** — operational; add a doctor check. |
| R10 | **Draft instability** | `draft-ietf-openpgp-pqc-17` not yet an RFC | Code points (alg 31, etc.) / armor framing can change pre-publication. | **Low** (additive/reversible) — but never claim final-standard conformance. |

---

## 4. Recommended migration sequence (concrete)

Ordered, additive-first, each step independently revertible. This complements
`PQC_ROOT_MIGRATION.md §6` (remaining work) and `ROOT_ROTATION_CEREMONY.md`.

**S1 — Make verification PQC-aware (do this FIRST; unblocks everything).**
Add a Sequoia branch to the server verify path. In `authentik/verifier.py`,
route v6/PQC armor (detect by fingerprint width / `sq inspect` algo, not by
guessing) to `SequoiaBackend.verify` instead of the PGPy/GnuPG branches
(`verifier.py:261-265,289-293`). Mirror the same routing in `pgpy_backend`
callers that currently swallow the parse failure (R1). *Reversible: a new branch,
classical paths untouched.*

**S2 — Thread the backend through, kill the hardcoded PGPy default.**
For root-touching call sites, resolve the backend from the **profile**
(`profile.crypto_backend`), exactly as `verify_profile_signature` already does
(`profile.py:245`). Fix the defaults at `identity.py:49`, `pqc_identity.py:91`,
`verifier.py:245,300`. *Reversible: default stays PGPy when the profile is
classical.*

**S3 — Solve protected-key signing (R4).** Implement passphrase signing in
`SequoiaBackend.sign` (`sequoia_backend.py:186-191`) via the `sq` keystore
(import the protected key, sign through the agent), OR formally adopt a
passphrase-less root + OS-level custody. Decide before any real root key is
generated. *Blocks self-sign + challenge for a protected PQC root.*

**S4 — Fingerprint-width hygiene (R5).** Update docstrings/Field descriptions
(`base.py:21,27`; `models.py:99`; `keystore.py:27`) to "40 (v4) or 64 (v6) hex".
Grep the wider tree (CLI, peer registry, skchat/skcomms consumers) for `[:40]`,
`== 40`, `len(...) == 40`. *Pure hygiene; no behavior change.*

**S5 — DID PQC representation (R6).** Add a non-RSA path in `did.py`
(`from_profile` / `_build_jwk`), using `SequoiaBackend._primary_algo`
(`sequoia_backend.py:237-246`) to detect the algo; for PQC emit a
`publicKeyMultibase` of the OpenPGP cert (or a clearly-labeled draft PQC JWK)
rather than a placeholder. Label any PQC DID as pre-standard. *Additive; classical
DIDs unchanged.*

**S6 — Additive subkey dry-run (per ceremony doc Phase 1).** On a *scratch*
classical key, prove `sq` can attach PQC subkeys and that capauth verifies the
result via S1's Sequoia branch. Keep the classical primary. *Fully reversible.*

**S7 — Bunker/phone PQC (R7) — DEFERRED, external.** Track the OpenPGP.js / WASM-
liboqs gap. Bunker logins remain classical until a PQC-capable phone signer
exists. Do not gate S1–S6 on this.

**S8 — Root-rotation ceremony — GATED, requires Chef.** Only after S1–S6 are
green: run `ROOT_ROTATION_CEREMONY.md` with Chef's real key
(`02BC0EB3CAD31DB691A753C70C5629AB893F9746`). Cross-sign old↔new, transition (do
**not** delete the classical key), grace period. **This is the only step that
makes the root non-classical, and it is out of scope for the additive phase.**

**Honest end-state after S1–S6 (pre-ceremony):** capauth *can* generate, sign
with, store, verify, and (partially) represent a PQC root — but the **live root
is still classical**, the **bunker path is still classical**, and we are issuing
against a **pre-RFC draft**. Nothing here is "quantum-proof" or globally PQ; each
surface's posture is classical-or-hybrid as enumerated above.
