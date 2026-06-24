# Sovereign Root-Key Rotation Ceremony

### Post-Quantum Migration of the CapAuth Root PGP Identity

**Version:** 0.1.0 (DRAFT runbook) | **Classification:** Operational / Sensitive | **Last Updated:** 2026-06-24

---

## ⛔ STOP — REQUIRES CHEF

**Nothing in this runbook runs without Chef driving it.**

The sovereign root key (classical primary, fingerprint
`02BC0EB3CAD31DB691A753C70C5629AB893F9746`) is the trust anchor for the entire
SKWorld identity fabric. **No command in this document that touches the live
root may be executed by an agent, a script, a cron job, or anyone other than
Chef, physically present and deliberately performing the ceremony.**

Every section that operates on the live root opens with a **`STOP — REQUIRES
CHEF`** gate. Agents preparing this ceremony MUST halt at each gate and hand
control to Chef. Preparation, dry-runs on **throwaway scratch keys**, and
verification tooling are agent-safe; the live root is not.

**Current state of the world (do not misrepresent):** the live root identity is
**STILL CLASSICAL** (Ed-curve PGP). It has **NOT** been migrated to
post-quantum. This runbook is the deliberate, later, Chef-driven event that
*would* change that — it has not happened yet.

---

## Honesty / Scope Notes (read before writing or saying anything about this)

- **Standards basis.** The PQC algorithms here are:
  - **ML-DSA** (signatures) — **FIPS 204**, NIST Level 5 at the 87 parameter set.
  - **ML-KEM** (key encapsulation) — **FIPS 203**, Level 5 at 1024.
  - **SLH-DSA** (stateless hash-based signatures) — **FIPS 205** (available at
    the liboqs 0.14.0 layer; **not** offered as a standalone OpenPGP primary in
    the current `sq` build).
  - **Ed448 / Ed25519** classical signatures — **RFC 8032**.
  - **OpenPGP v6 / RFC 9580** is the packet/profile format used for v6 keys.
- **Pre-RFC.** The OpenPGP PQC bindings follow **draft-ietf-openpgp-pqc-17**
  (Standards Track, in the RFC Editor queue, **NOT yet an RFC**). We are issuing
  against a **pre-RFC draft**; code points may still move. Treat every PQC cert
  produced here as **experimental until the draft becomes an RFC**.
- **Per-surface honesty.** State the algorithm *per surface*:
  - After the **additive phase**: the root primary is **still classical**
    (certify/sign on the Ed primary); PQC exists only on **attached subkeys**.
  - After the **optional full rotation**: the new primary is **hybrid
    ML-DSA-87+Ed448** (composite — both must verify), with a hybrid
    ML-KEM-1024+X448 encryption subkey.
- **Forbidden phrasing.** Do **not** write or say: *"quantum-proof"*,
  unscoped *"end-to-end"*, any claim of *global / unconditional* post-quantum
  protection, or *"CNSA 2.0"* compliance. These are inaccurate and out of scope.

---

## Backend: why Sequoia `sq`, not GnuPG

| Backend | PQC signing/certify? | Verdict |
|---------|----------------------|---------|
| **GnuPG** (dev 2.5.20; stable 2.6 not shipped) | **No** — its PQC support is **encryption-only** (ML-KEM/Kyber). It **cannot** sign or certify with ML-DSA or SLH-DSA. | **DISQUALIFIED** for a PQC signing root. |
| **Sequoia `sq`** | **Yes** — hosts a PQC **signing** root. | **The only viable backend.** |

The `sq` binary in use is a custom PQC-enabled build:

- `sq 1.4.0-pqc.1` (`sequoia-openpgp 2.2.0-pqc.1`), installed via:
  ```
  cargo install sequoia-sq --version 1.4.0-pqc.1 \
    --locked --no-default-features --features crypto-openssl
  ```
- Toolchain: `rustc 1.96.0` via rustup (system rustc 1.75 is too old; Sequoia
  needs ≥ 1.79). **System rust is untouched.**
- Built against linuxbrew OpenSSL `3.6.2` (native ML-KEM / ML-DSA / SLH-DSA).
  Build env:
  ```
  OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3
  BINDGEN_EXTRA_CLANG_ARGS="-I$OPENSSL_DIR/include"
  PKG_CONFIG_PATH=$OPENSSL_DIR/lib/pkgconfig
  CARGO_TARGET_DIR=~/pqc-build/target
  ```
- apt build deps: `pkg-config capnproto clang libsqlite3-dev patchelf`.
- Durability: rpath patched so `sq` runs without `LD_LIBRARY_PATH`:
  ```
  patchelf --set-rpath /home/linuxbrew/.linuxbrew/opt/openssl@3/lib ~/.cargo/bin/sq
  ```
- Binary: `~/.cargo/bin/sq`. Build script: `~/pqc-build/build-sq.sh`; log:
  `~/pqc-build/build.log`.

**Verify the tool before trusting it:**
```
sq version            # expect 1.4.0-pqc.1 / sequoia-openpgp 2.2.0-pqc.1  (NOT `sq --version`)
sq key generate --help | grep -A2 cipher-suite   # expect mldsa65-ed25519, mldsa87-ed448
```

### Cipher suites available in this build

- `mldsa65-ed25519` — ML-DSA-65 + Ed25519 (draft code point 30)
- `mldsa87-ed448` — ML-DSA-87 + Ed448 (draft code point 31) ← **root choice**
- Classical: `cv25519`, `rsa2k`, `rsa3k`, `rsa4k`
- **No standalone SLH-DSA primary** in this build (SLH-DSA lives only at the
  liboqs layer).

**Strongest standards-track root = `mldsa87-ed448`** → primary
**ML-DSA-87 + Ed448** (FIPS 204, NIST L5; certify + sign + auth) plus an
encryption subkey **ML-KEM-1024 + X448** (FIPS 203, L5). This **requires
`--profile rfc9580`** (OpenPGP v6). **v6 fingerprints are 64 hex characters**
(not 40).

### Where the code already is (capauth main `34dbcf0`)

- `src/capauth/crypto/sequoia_backend.py` — `SequoiaBackend` implements the
  `CryptoBackend` ABC (`generate_keypair` / `sign` / `verify` /
  `fingerprint_from_armor`) by shelling out to `sq`.
- `src/capauth/models.py` — `Algorithm.HYBRID_ED448_MLDSA87`
  (`"hybrid-ed448-mldsa87"`), suite id `"mldsa87-ed448-v2"`,
  `CryptoBackendType.SEQUOIA`.
- `src/capauth/crypto/__init__.py` — `get_backend(SEQUOIA)` wired.
- `tests/test_sequoia_backend.py` — 4 TDD tests (keygen → ML-DSA-87, sign/verify
  + tamper, fingerprint round-trip, factory).

---

## Phase Map

```
  [ Phase 0 ]  Preconditions & backups        (agent-prep OK; backups by Chef)
       │
  [ Phase 1 ]  ADDITIVE — attach PQC subkeys   ← DO THIS FIRST. Fully reversible.
       │        to the EXISTING classical root.   Remove NOTHING.
       │
       ▼
  [ Phase 2 ]  VERIFY the additive result      (round-trip + capauth profile)
       │
       ▼
  [ Phase 3 ]  OPTIONAL full rotation to a new  ← Only after Phase 1+2 proven.
                mldsa87-ed448 primary, with        Cross-sign old↔new.
                cross-signing for continuity.
```

**Order is mandatory: ADDITIVE FIRST.** The additive phase keeps the classical
key intact and adds reversible PQC capability. Full primary rotation is a
separate, optional, higher-risk decision that is only considered after the
additive phase is proven and stable.

---

## Phase 0 — Preconditions & Backups

> ### ⛔ STOP — REQUIRES CHEF
> The backups below cover the **live** `~/.capauth/identity` and root secret
> material. **Chef performs the backups.** Do not let an agent read, copy, or
> exfiltrate root private key material.

**Checklist (all must be true before any later phase):**

1. **`sq` verified** — `sq version` reports `1.4.0-pqc.1`; help shows
   `mldsa87-ed448`. (Agent-safe.)
2. **Backup of the existing identity directory.** Chef snapshots
   `~/.capauth/identity` to offline media:
   ```
   # run by Chef
   tar -czf ~/capauth-identity-backup-$(date +%Y%m%d-%H%M%S).tgz -C ~ .capauth/identity
   # then copy the .tgz to OFFLINE media; verify it lists/extracts; store securely
   ```
3. **Backup of the classical root secret + revocation cert** (wherever Chef
   holds it — keystore, bunker phone, offline). Confirm at least **two**
   independent copies exist (redundancy mantra: if you need one, get two).
4. **Record the existing classical root fingerprint** and confirm it matches
   the known value:
   ```
   02BC0EB3CAD31DB691A753C70C5629AB893F9746
   ```
   Confirm against the live key:
   ```
   sq inspect ~/.capauth/identity/<root-public>.asc | grep -i Fingerprint
   ```
   The printed primary fingerprint MUST equal the value above. **If it does not
   match, STOP** — you are not looking at the real root; abort and re-check.
5. **Working copy on scratch.** Chef exports a copy of the root key into an
   isolated working directory (e.g. `~/ceremony-$(date +%Y%m%d)/`) so the
   ceremony never edits the canonical store in place.
6. **Revocation cert on hand** for the classical root (so the key can be
   revoked if anything goes wrong mid-ceremony).
7. **Witnessed.** Chef performs this deliberately, not under time pressure,
   ideally with the operation logged in the sksecurity ledger afterward.

If **any** item is unmet, **do not proceed**.

---

## Phase 1 — ADDITIVE: attach PQC subkeys to the existing classical root

**This is the first real operation, and it is fully reversible.** It keeps the
classical primary `02BC0EB3CAD31DB691A753C70C5629AB893F9746` as the trust
anchor and **adds** PQC subkey capability. **Nothing is removed.** If the new
subkeys are ever unwanted, they can be revoked or simply not used, and the
classical key is exactly as it was.

> ### ⛔ STOP — REQUIRES CHEF
> Everything below touches the live root. **Only Chef runs these commands**,
> in the isolated working directory from Phase 0, on the **working copy** of the
> key — never on the canonical store in place.

> ### ⚠️ Capability note (must be resolved before the live run)
> `sq sign` in this build has **no `--password` flag**. Protected-key signing
> (and therefore protected-key editing) must go through the **`sq` keystore** or
> another path. **Before touching the live root, confirm on a throwaway key the
> exact subkey-add invocation that works with a passphrase-protected primary in
> this `sq` build.** If the protected-key add path is not yet proven, **STOP and
> resolve it first** — do not improvise on the live root. The commands below are
> the *intended shape*; the precise protected-key flags are TBD pending that
> investigation.

### 1.1 Dry-run on a throwaway scratch key (agent-safe — do this first)

Prove the whole additive flow end-to-end on a disposable key before going
anywhere near the root:

```
mkdir -p ~/ceremony-scratch && cd ~/ceremony-scratch

# disposable classical primary, mimicking the root's shape
sq key generate --own-key \
  --name "scratch root" --email scratch@example.invalid \
  --cipher-suite cv25519 --without-password \
  --output scratch-key.pgp --rev-cert scratch-rev.pgp

sq inspect scratch-key.pgp            # note the primary fingerprint + algo
```

Then exercise the additive subkey-add path against `scratch-key.pgp` until it is
fully understood. Only graduate to the live root once the scratch run is clean.

**Automated harness:** `python scripts/pqc_ceremony_dryrun.py` runs this entire
flow on throwaway keys in an isolated temp `SEQUOIA_HOME` (touches no real key),
proving Phases 1–3 end-to-end — generate classical v6 root → generate PQC root →
cross-sign both directions → sign/verify continuity + tamper-reject → additive
PQC subkey with the primary fingerprint unchanged. It prints PASS/FAIL per step
and exits non-zero on any regression. **Run it before any live ceremony.** (The
one path it does *not* exercise is the passphrase-protected keystore flow — that
remains the single open item for the live run.)

### 1.2 Add PQC subkeys to the (working copy of the) classical root

> ### ⛔ STOP — REQUIRES CHEF
> Operate on the **working copy** (`~/ceremony-YYYYMMDD/root-key.pgp`), not the
> canonical store.

Intended additions to the existing classical primary:

- a **PQC signing** subkey (ML-DSA, e.g. ML-DSA-87) — for PQC-capable
  signatures while the classical primary still certifies; and/or
- a **PQC encryption** subkey (ML-KEM-1024 + X448) — so the root can *receive*
  PQC-protected material.

Use `sq key subkey add` against the working-copy key. The exact invocations are
now **confirmed** (validated end-to-end by `scripts/pqc_ceremony_dryrun.py`, all
PASS) — for an **unprotected** working copy:

```
# PQC signing subkey (ML-DSA-87 + Ed448)
sq key subkey add --cert-file root-key.pgp --can-sign \
  --cipher-suite mldsa87-ed448 --without-password --output root+sig.pgp

# PQC encryption subkey (ML-KEM-1024 + X448) on top
sq key subkey add --cert-file root+sig.pgp --can-encrypt universal \
  --cipher-suite mldsa87-ed448 --without-password --output root+sig+kem.pgp
```

For a **passphrase-protected** primary, seed `sq`'s password cache via the
*global* flags and protect the new subkeys with the same passphrase:
`sq --password-file PW --batch key subkey add --cert-file … --new-password-file PW …`
(this is exactly what `SequoiaBackend.add_pqc_subkeys()` does). The classical
primary's own key, certification capability, and fingerprint **do not change** —
you are only appending subkey packets.

> **⚠️ v4→v6 gate.** `sq` refuses PQC algorithms on a **v4** key
> (`can't use algorithms for v4 keys`). The existing classical root is v4-era, so
> "additive PQC subkeys on the live root as-is" is **not possible** — re-issuing
> the identity as a v6/RFC 9580 key is part of the Phase-3 rotation, not a pure
> additive step. The additive path above applies to a **v6** classical key.

### 1.3 Reversibility (keep this true at all times in Phase 1)

- The classical primary and its fingerprint are **unchanged**.
- The original key file from Phase 0 backup is untouched and restorable.
- New subkeys can be **revoked** (subkey revocation) or discarded by reverting
  to the Phase-0 backup.
- **Roll back at any point** by restoring `~/.capauth/identity` from the Phase-0
  tarball. No third party, no server, no irreversible step is involved.

**Do not publish or import the modified key into the canonical store until
Phase 2 verification passes.**

---

## Phase 2 — Verification (additive result)

> Verification commands that operate on **public** certs are agent-safe.
> Anything requiring the private key is **Chef-only**.

Run all of these and confirm each before declaring Phase 1 done.

### 2.1 Inspect

```
sq inspect ~/ceremony-YYYYMMDD/root-key.pgp
```
Confirm:
- **Primary `Fingerprint:` still equals `02BC0EB3CAD31DB691A753C70C5629AB893F9746`** (classical primary unchanged).
- The new subkey(s) are listed with the expected **`Public-key algo:`**
  (ML-DSA / ML-KEM as added) and the expected capability flags.

### 2.2 Sign / verify round-trip

Export the public cert and prove a sign→verify cycle:
```
# public cert from the key file
sq key delete --cert-file ~/ceremony-YYYYMMDD/root-key.pgp \
  --output ~/ceremony-YYYYMMDD/root-cert.asc

echo "ceremony round-trip $(date -u +%FT%TZ)" > /tmp/rt.txt

# sign with the (Chef-held) key, verify with the public cert
sq sign --signer-file ~/ceremony-YYYYMMDD/root-key.pgp \
  --signature-file /tmp/rt.sig /tmp/rt.txt
sq verify --signer-file ~/ceremony-YYYYMMDD/root-cert.asc \
  --signature-file /tmp/rt.sig /tmp/rt.txt          # MUST report a good signature
```
A **tamper check** must also fail: modify `/tmp/rt.txt` by one byte and confirm
`sq verify` **rejects** it.

> Note: `sq sign` has no `--password` flag in this build — protected-key signing
> goes through the `sq` keystore or the path confirmed in Phase 1.0. Use the same
> proven path here.

### 2.3 CapAuth profile verify

Confirm CapAuth accepts the identity end-to-end through its own backend:
```
capauth profile verify
```
This exercises `SequoiaBackend.verify` (capauth `34dbcf0`,
`crypto/sequoia_backend.py`) and the challenge sign/verify path
(`identity.py` / `pqc_identity.py`). It must pass against the additive key.

### 2.4 Acceptance

Phase 1 is **accepted** only when 2.1–2.3 all pass **and** the classical primary
fingerprint is unchanged. Chef then (and only then) decides whether to import
the additive key into the canonical `~/.capauth/identity`. The Phase-0 backup
remains the rollback target.

---

## Phase 3 — OPTIONAL full rotation to a new ML-DSA-87+Ed448 primary

**Optional. Higher risk. Only after Phase 1+2 are proven and stable.** This
issues a **new** sovereign primary whose *primary* signing/certification is
post-quantum (hybrid), and cross-signs it with the old classical root so trust
flows across the boundary for continuity.

> ### ⛔ STOP — REQUIRES CHEF
> This is the single highest-consequence operation in the SKWorld trust fabric.
> **Chef alone**, deliberately, witnessed. Do not let this be automated.

### 3.1 Generate the new hybrid primary

```
sq key generate --own-key \
  --name "Chef / SKWorld sovereign root (v2)" \
  --email <root-email> \
  --cipher-suite mldsa87-ed448 \
  --profile rfc9580 \
  --without-password \
  --output ~/ceremony-YYYYMMDD/root-v2-key.pgp \
  --rev-cert ~/ceremony-YYYYMMDD/root-v2-rev.pgp
```
- `--profile rfc9580` is **required** for the v6 PQC key.
- Resulting primary = **ML-DSA-87 + Ed448** (composite signature: *both* the
  ML-DSA and the Ed448 signature must verify). Add an encryption subkey
  **ML-KEM-1024 + X448** for receiving PQC-protected material.
- **`--without-password` produces an unprotected key file** — only acceptable on
  isolated/offline media that Chef immediately protects (move into the keystore
  / bunker, or add protection). Do not leave an unprotected sovereign primary on
  disk.
- The new primary has a **64-hex-character v6 fingerprint**. Record it.

```
sq inspect ~/ceremony-YYYYMMDD/root-v2-key.pgp   # expect ML-DSA-87+Ed448, 64-hex fpr
```

### 3.2 Cross-sign old ↔ new (continuity bridge)

So verifiers trust the new root via the old, and vice-versa:

- **Old certifies new:** use the classical root
  (`02BC0EB3CAD31DB691A753C70C5629AB893F9746`) to certify the new v2 primary's
  identity. This is the load-bearing link — anyone who trusted the old root can
  now derive trust in the new one.
- **New certifies old:** use the new ML-DSA-87+Ed448 primary to certify the old
  classical primary, asserting both belong to the same sovereign identity.

The cross-sign path in this build is **`sq pki vouch add`** (there is no
`sq pki certify` subcommand). Confirmed working, file-based (validated by
`scripts/pqc_ceremony_dryrun.py`):

```
# OLD certifies NEW (the load-bearing continuity link):
sq pki vouch add --certifier-file old-root.pgp \
  --cert-file new-root.cert --email <root-email> --output new.cert.by-old

# NEW (PQC) certifies OLD (reverse direction):
sq pki vouch add --certifier-file new-root.pgp \
  --cert-file old-root.cert --email <root-email> --output old.cert.by-new
```

**Verify the certifications actually authenticate** (`sq inspect` does NOT verify
them — it prints "Certifications have NOT been verified!"). Use the WoT engine
with the certifier pinned as trust-root in an isolated home:

```
sq --home "$SCRATCH/sqhome" --keyring old-root.cert --keyring new.cert.by-old \
   --trust-root <OLD_FPR> \
   pki authenticate --cert <NEW_FPR> --email <root-email> --show-paths
# → "[ ✓ ] <root-email>", exit 0; --show-paths shows the path via OLD's signature
```

Both directions authenticate `[ ✓ ]` in the dry-run. Prove on disposable keys
(Phase 1.1 / `pqc_ceremony_dryrun.py`) before touching the live roots.

### 3.3 Transition, do not delete

- **Do not destroy the classical root.** Keep it (offline, backed up) so old
  signatures remain verifiable and the continuity bridge holds.
- Publish the new primary + the cross-signatures through the normal channels
  (DID / `did.py`, capauth profile, sksecurity ledger entry).
- Issue a **revocation** for the classical root **only** as a deliberate,
  separate, later decision — and even then prefer a "superseded by <v2
  fingerprint>" stance over hard destruction, to preserve historical
  verifiability.

### 3.4 Verify the rotation

Repeat **all** of Phase 2 against the new primary:
- `sq inspect` shows **ML-DSA-87 + Ed448** primary, ML-KEM-1024+X448 enc subkey,
  64-hex v6 fingerprint.
- Sign/verify round-trip + tamper-reject on the new primary.
- `capauth profile verify` passes against the new identity.
- The **cross-signatures verify in both directions** (old verifies new's cert,
  new verifies old's cert).

Only when every check passes is the rotation considered complete — and even then
the classical key is retained, not erased.

---

## Rollback Procedure

Rollback is always available because the additive phase removes nothing and the
backups are intact.

**During Phase 1 (additive):**
1. Stop. Do not import the modified key into `~/.capauth/identity`.
2. Restore the identity directory from the Phase-0 tarball:
   ```
   # run by Chef
   tar -xzf ~/capauth-identity-backup-<ts>.tgz -C ~
   ```
3. (If the additive key was already imported and you only want to undo the
   subkeys) revoke the added subkeys with their subkey-revocation, or restore
   from backup. The classical primary fingerprint is unchanged either way.
4. `capauth profile verify` to confirm the restored classical identity is healthy.

**During Phase 3 (full rotation), before publishing/revoking the old root:**
1. Stop. The old classical root is still the live anchor — simply do not publish
   the new primary and do not issue the old-root revocation.
2. Discard the `~/ceremony-YYYYMMDD/` working directory (it contains only the new
   candidate primary, which nothing trusts yet).
3. Restore `~/.capauth/identity` from backup if it was touched.

**After Phase 3 publish (degraded path):** if the new primary is published but
later found faulty, the **classical root is still valid and retained** — fall
back to it as the anchor, and revoke the *new* primary (using its
`root-v2-rev.pgp` revocation cert) rather than the classical one. This is why the
classical root is never destroyed.

---

## Post-Ceremony

- Log the ceremony in the **sksecurity ledger** (continues the PQC series; the
  per-message hybrid work was Entry #8).
- Update `docs/CRYPTO_SPEC.md` and the relevant MEMORY note **per surface** —
  state precisely which surfaces are now hybrid vs. still classical.
- Re-confirm the honesty rules: cite **FIPS 203/204/205**, **RFC 8032/9580**;
  note this is issued against **draft-ietf-openpgp-pqc-17** (pre-RFC);
  never claim "quantum-proof" or global PQ protection.

---

## Quick Reference — `sq` invocations

```
# tool sanity
sq version

# generate hybrid v6 PQC primary (Phase 3)
sq key generate --own-key --name N --email E \
  --cipher-suite mldsa87-ed448 --profile rfc9580 \
  --without-password --output KEY --rev-cert REV

# derive public cert from a key file
sq key delete --cert-file KEY --output CERT

# inspect (prints Fingerprint: and Public-key algo:)
sq inspect FILE

# sign / verify (no --password in this build; use keystore for protected keys)
sq sign   --signer-file KEY  --signature-file SIG DATA
sq verify --signer-file CERT --signature-file SIG DATA
```

**Remember:** every line that touches the live root is gated behind
**⛔ STOP — REQUIRES CHEF**. Additive first, reversible always, nothing
automated.
