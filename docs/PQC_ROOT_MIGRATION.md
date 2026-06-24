# PQC Root Migration (#3)

Migrating capauth's root PGP identity toward post-quantum (PQ) signing.

**Status: IN PROGRESS — ADDITIVE PHASE ONLY.** The live root identity is still
**classical**. No root-key rotation ceremony has been performed. Nothing in this
document should be read as a claim that the root is post-quantum today.

> **Standards honesty.** This work is built against
> **draft-ietf-openpgp-pqc-17** (Standards Track, currently in the RFC Editor
> queue — **NOT yet an RFC**). We are issuing keys against a *pre-RFC draft*.
> Algorithm code points and on-wire formats can still change before publication.
> Classical-vs-hybrid posture is described **per surface** below. We do not claim
> "quantum-proof", global/unconditional PQ, end-to-end PQ across all surfaces, or
> CNSA-2.0 compliance.

---

## 1. Goal and sequencing (additive-first, ceremony-later)

**Goal:** give capauth a backend that can host a post-quantum **signing** root,
and migrate the root PGP identity onto it — *eventually*. The signing capability
is what matters: the live root certifies and signs, so an encryption-only PQ
story does not migrate the root.

**Sequencing is deliberate and in two phases:**

1. **Additive + reversible (current phase).** Land a PQC-capable crypto backend
   alongside the existing classical backend, behind the `CryptoBackend` ABC. Add
   the algorithm enum, suite id, and factory wiring. Prove
   generate → sign → verify end-to-end with tests. The classical PGPy backend
   remains the default and remains fully functional; nothing about the live root
   changes. This is opt-in and removable.

2. **Rotation ceremony (deliberate later step).** Only after the additive layer
   is proven do we perform the **root-key rotation ceremony** with Chef's
   **real** root key
   (`02BC0EB3CAD31DB691A753C70C5629AB893F9746`). Until that ceremony runs, the
   root identity is classical. The ceremony is intentionally *not* part of this
   phase.

This mirrors the posture already shipped at the per-message layer (Q7, see §8):
PQ is added as an opt-in composite, never as a forced cutover.

---

## 2. Backend decision rationale

The root **signs and certifies**. The backend therefore must support PQ
*signatures* (ML-DSA / SLH-DSA), not merely PQ encryption.

### GnuPG — DISQUALIFIED

GnuPG's post-quantum support is **encryption-only** (ML-KEM / "Kyber"
key-encapsulation). It **cannot sign or certify** with ML-DSA or SLH-DSA. An
encryption-only PQ backend cannot host a PQ signing root, which is the entire
point of #3. (Reference state: GnuPG dev line at 2.5.20; stable 2.6 not shipped.)

### Sequoia `sq` — SELECTED

Sequoia's `sq` is the **only** evaluated backend that can host a PQC **signing**
root. It can generate, sign, and verify with ML-DSA composite suites end-to-end
(verified — see §6). That signing capability is the deciding factor.

---

## 3. `sq` build provenance (reproducible)

Built on **.158**. System Rust and system OpenSSL are left untouched; the build
is isolated.

| Item | Value |
|------|-------|
| Binary | `sq 1.4.0-pqc.1` (`sequoia-openpgp 2.2.0-pqc.1`) |
| Source | crates.io |
| Install cmd | `cargo install sequoia-sq --version 1.4.0-pqc.1 --locked --no-default-features --features crypto-openssl` |
| Rust toolchain | `rustc 1.96.0` via `rustup` (system `rustc 1.75` too old; Sequoia needs ≥ 1.79) |
| Crypto provider | linuxbrew **OpenSSL 3.6.2** (native ML-KEM / ML-DSA / SLH-DSA) |
| Installed binary | `~/.cargo/bin/sq` |
| Build script | `~/pqc-build/build-sq.sh` |
| Build log | `~/pqc-build/build.log` |

### Build environment

```sh
OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3
BINDGEN_EXTRA_CLANG_ARGS="-I$OPENSSL_DIR/include"
PKG_CONFIG_PATH=$OPENSSL_DIR/lib/pkgconfig
CARGO_TARGET_DIR=~/pqc-build/target
```

### Build dependencies (apt)

```
pkg-config  capnproto  clang  libsqlite3-dev  patchelf
```

### Runtime durability (rpath)

The binary is patched so it runs without `LD_LIBRARY_PATH`:

```sh
patchelf --set-rpath /home/linuxbrew/.linuxbrew/opt/openssl@3/lib ~/.cargo/bin/sq
```

This pins `sq` to the linuxbrew OpenSSL 3.6.2 that provides the PQ primitives.

---

## 4. Algorithm mapping

How a capauth `Algorithm` maps to an `sq` cipher-suite and the resulting OpenPGP
key algorithms. Code points are from **draft-ietf-openpgp-pqc-17** (pre-RFC).

| capauth `Algorithm` | suite id | `sq` cipher-suite | Primary (sign/certify) | Encryption subkey | Standards / level | draft code point |
|---|---|---|---|---|---|---|
| `HYBRID_ED448_MLDSA87` | `mldsa87-ed448-v2` | `mldsa87-ed448` | ML-DSA-87 + Ed448 (FIPS 204 / RFC 8032; NIST L5; certify+sign+auth) | ML-KEM-1024 + X448 (FIPS 203; L5) | RFC 9580 v6 | 31 (sig), 36 (enc) |
| — | — | `mldsa65-ed25519` | ML-DSA-65 + Ed25519 (FIPS 204 / RFC 8032; L3) | ML-KEM-768 + X25519 (FIPS 203) | RFC 9580 v6 | 30 (sig), 35 (enc) |
| classical | (existing) | `cv25519` | Ed25519 (RFC 8032) | X25519 | classical | n/a |
| classical | (existing) | `rsa2k`/`rsa3k`/`rsa4k` | RSA | RSA | classical | n/a |

**Notes:**

- The **strongest standards-track root** in this build is **`mldsa87-ed448`** ⇒
  primary **ML-DSA-87 + Ed448** plus an **ML-KEM-1024 + X448** encryption subkey.
  It **requires `--profile rfc9580`** (OpenPGP v6). v6 / RFC 9580 fingerprints
  are **64 hex characters**, not 40.
- There is **no standalone SLH-DSA primary** in this `sq` build. SLH-DSA
  (FIPS 205, draft code points 32–34) exists only at the `liboqs` layer
  (see §6), not as an `sq key generate` suite.
- These are **hybrid composite** algorithms: the signature/KEM combines a PQ
  scheme with a classical one (e.g. ML-DSA-87 **+** Ed448). Security holds if
  *either* component holds.

---

## 5. What landed (capauth `main`, commit `34dbcf0`)

Additive, reversible. Classical PGPy backend remains default.

**Backend**
- `src/capauth/crypto/sequoia_backend.py` — `SequoiaBackend` implements the
  `CryptoBackend` ABC (`generate_keypair` / `sign` / `verify` /
  `fingerprint_from_armor`) by driving the `sq` subprocess.

**Models / enums / factory**
- `src/capauth/models.py` — new `Algorithm.HYBRID_ED448_MLDSA87`
  (`"hybrid-ed448-mldsa87"`, OpenPGP composite sig code point 31, L5); suite id
  `"mldsa87-ed448-v2"`; `CryptoBackendType.SEQUOIA`.
- `src/capauth/crypto/__init__.py` — `get_backend(SEQUOIA)` wired into the
  factory.

**Tests** — `tests/test_sequoia_backend.py`, 4 TDD tests:
1. keygen → primary public-key algorithm is **ML-DSA-87**
2. sign / verify round-trip **+ tamper detection** (modified data fails verify)
3. fingerprint round-trip
4. factory returns `SequoiaBackend` for `CryptoBackendType.SEQUOIA`

**Surrounding code (context, unchanged by this phase)**
- `CryptoBackend` ABC: `src/capauth/crypto/base.py`
- Classical backend: `src/capauth/crypto/pgpy_backend.py`
- Profile init: `profile.py` (`init_profile` → `backend.generate_keypair`)
- Challenge sign/verify: `identity.py`
- Hybrid Q7 challenge: `pqc_identity.py`
- Bunker remote-signer + DID: `docs/CRYPTO_SPEC.md`, `did.py`

### Verified `sq` invocations

```sh
# generate a v6 PQ root (no passphrase; emits key + revocation cert)
sq key generate --own-key --name N --email E \
  --cipher-suite mldsa87-ed448 --profile rfc9580 \
  --without-password --output KEY --rev-cert REV

# derive the public cert from the secret key file
sq key delete --cert-file KEY --output CERT

# inspect (prints 'Fingerprint:' and 'Public-key algo:')
sq inspect FILE

# detached sign / verify
sq sign   --signer-file KEY  --signature-file SIG DATA
sq verify --signer-file CERT --signature-file SIG DATA
```

---

## 6. Remaining work

1. **Protected-key signing.** `sq sign` has **no `--password` flag**. Signing
   with a passphrase-protected key must go through the `sq` keystore or another
   mechanism — path **to be investigated**. This blocks using a protected root
   key for live signing through the subprocess backend.

2. **Additive composite subkeys.** Attach PQ composite subkeys to the existing
   classical root *additively* (reversible), rather than rotating the primary —
   the same additive principle as the per-message layer. Design TBD.

3. **Root-key rotation ceremony.** The deliberate later step: rotate the live
   root onto a PQ primary, performed with Chef's real root key
   (`02BC0EB3CAD31DB691A753C70C5629AB893F9746`). Until this runs, the root is
   classical.

4. **capauth revisit.** Revisit how the rest of capauth (profile init, identity
   challenge sign/verify, DID, bunker remote-signer) consumes the new
   v6 / 64-hex-fingerprint PQ keys, and whether/how to surface the Sequoia
   backend beyond the additive enum.

**Available without a rebuild:** `liboqs 0.14.0` already ships **ML-DSA-87**,
**ML-KEM-1024**, and the full **FIPS 205 SLH-DSA** family. SLH-DSA is therefore
reachable at the `liboqs` layer even though it is not an `sq key generate` suite
in this build.

---

## 7. Honest status (per surface)

| Surface | Classical | Hybrid / PQ | Notes |
|---|---|---|---|
| **Root PGP identity** | ✅ live | ❌ | **STILL CLASSICAL.** No ceremony performed. Fingerprint `02BC0EB3CAD31DB691A753C70C5629AB893F9746`. |
| Sequoia backend (capauth) | — | ✅ additive, opt-in | `SequoiaBackend` landed (`34dbcf0`); generate/sign/verify proven; not the default; classical PGPy still default. |
| `sq` PQ keygen/sign/verify | — | ✅ verified | ML-DSA-87 + Ed448 (v6 / RFC 9580), end-to-end. |
| Protected-key signing | — | ⏳ not yet | `sq sign` has no `--password`; keystore path TBD. |
| Composite subkeys on root | — | ⏳ planned | Additive, reversible; design TBD. |
| Per-message / DID challenge (Q7) | ✅ | ✅ additive | `skcomms.pqsig` ML-DSA-65 + Ed25519 composite; `capauth.pqc_identity`. Opt-in. Shipped — sksecurity ledger Entry #8. |

**Bottom line:** the additive PQ *signing* capability exists and is tested. The
**root remains classical** until the rotation ceremony. All of this is built
against a **pre-RFC draft** (draft-ietf-openpgp-pqc-17), so formats may change.

---

## 8. Already shipped (Q7, separate from the root)

Distinct from the root effort, the **per-message + DID/challenge** signature
layer already ships post-quantum, **additive / opt-in**:

- `skcomms.pqsig` = **ML-DSA-65 + Ed25519** composite signatures.
- `capauth.pqc_identity` = hybrid challenge.
- Recorded in the **sksecurity ledger, Entry #8.**

This is *not* the root. It demonstrates the additive pattern that the root
migration follows.

---

## References

- **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
- **FIPS 204** — Module-Lattice-Based Digital Signature Standard (ML-DSA).
- **FIPS 205** — Stateless Hash-Based Digital Signature Standard (SLH-DSA).
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA): Ed25519, Ed448.
- **RFC 9580** — OpenPGP (v6 keys; the `--profile rfc9580` target).
- **draft-ietf-openpgp-pqc-17** — Post-Quantum Cryptography in OpenPGP
  (Standards Track, **in the RFC Editor queue, not yet an RFC**). Code points:
  30 ML-DSA-65+Ed25519, 31 ML-DSA-87+Ed448, 32–34 SLH-DSA standalone,
  35 ML-KEM-768+X25519, 36 ML-KEM-1024+X448.
