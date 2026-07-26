# Sovereign Root-Key Rotation Ceremony

### Post-Quantum Migration of the CapAuth Root PGP Identity

**Version:** 1.0.0 | **Classification:** Operational / Sensitive | **Last Updated:** 2026-07-26

---

## ⛔ STOP - REQUIRES CHEF

**Nothing in this runbook runs without Chef driving it.**

The sovereign root key (classical primary, fingerprint
`02BC0EB3CAD31DB691A753C70C5629AB893F9746`) is the trust anchor for the entire
SKWorld identity fabric. **No command in this document that touches the live
root may be executed by an agent, a script, a cron job, or anyone other than
Chef, physically present and deliberately performing the ceremony.**

Every section that operates on the live root opens with a **`STOP - REQUIRES
CHEF`** gate. Agents preparing this ceremony MUST halt at each gate and hand
control to Chef. Preparation, dry-runs on **throwaway scratch keys**, and
verification tooling are agent-safe; the live root is not. **Rehearse the whole
ceremony on a disposable key first** (see **Throwaway-Key Rehearsal** below) so
the live event is practiced, not improvised.

**Current state of the world (do not misrepresent):** the live root identity is
**STILL CLASSICAL** (Ed-curve PGP). It has **NOT** been migrated to
post-quantum. This runbook is the deliberate, later, Chef-driven event that
*would* change that - it has not happened yet.

---

## Honesty / Scope Notes (read before writing or saying anything about this)

- **Standards basis.** The PQC algorithms here are:
  - **ML-DSA** (signatures) - **FIPS 204**, NIST Level 5 at the 87 parameter set.
  - **ML-KEM** (key encapsulation) - **FIPS 203**, Level 5 at 1024.
  - **SLH-DSA** (stateless hash-based signatures) - **FIPS 205** (available at
    the liboqs 0.14.0 layer; **not** offered as a standalone OpenPGP primary in
    the current `sq` build).
  - **Ed448 / Ed25519** classical signatures - **RFC 8032**.
  - **OpenPGP v6 / RFC 9580** is the packet/profile format used for v6 keys.
- **Pre-RFC.** The OpenPGP PQC bindings follow **draft-ietf-openpgp-pqc-17**
  (Standards Track, in the RFC Editor queue, **NOT yet an RFC**). We are issuing
  against a **pre-RFC draft**; code points may still move. Treat every PQC cert
  produced here as **experimental until the draft becomes an RFC**.
- **Per-surface honesty.** State the algorithm *per surface*:
  - After the **additive phase**: the root primary is **still classical**
    (certify/sign on the Ed primary); PQC exists only on **attached subkeys**.
  - After the **optional full rotation**: the new primary is **hybrid
    ML-DSA-87+Ed448** (composite - both must verify), with a hybrid
    ML-KEM-1024+X448 encryption subkey.
- **Forbidden phrasing.** Do **not** write or say: *"quantum-proof"*,
  unscoped *"end-to-end"*, any claim of *global / unconditional* post-quantum
  protection, or *"CNSA 2.0"* compliance. These are inaccurate and out of scope.

---

## Backend: why Sequoia `sq`, not GnuPG

| Backend | PQC signing/certify? | Verdict |
|---------|----------------------|---------|
| **GnuPG** (dev 2.5.20; stable 2.6 not shipped) | **No** - its PQC support is **encryption-only** (ML-KEM/Kyber). It **cannot** sign or certify with ML-DSA or SLH-DSA. | **DISQUALIFIED** for a PQC signing root. |
| **Sequoia `sq`** | **Yes** - hosts a PQC **signing** root. | **The only viable backend.** |

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

- `mldsa65-ed25519` - ML-DSA-65 + Ed25519 (draft code point 30)
- `mldsa87-ed448` - ML-DSA-87 + Ed448 (draft code point 31) ← **root choice**
- Classical: `cv25519`, `rsa2k`, `rsa3k`, `rsa4k`
- **No standalone SLH-DSA primary** in this build (SLH-DSA lives only at the
  liboqs layer).

**Strongest standards-track root = `mldsa87-ed448`** → primary
**ML-DSA-87 + Ed448** (FIPS 204, NIST L5; certify + sign + auth) plus an
encryption subkey **ML-KEM-1024 + X448** (FIPS 203, L5). This **requires
`--profile rfc9580`** (OpenPGP v6). **v6 fingerprints are 64 hex characters**
(not 40).

### Where the code already is (capauth main `34dbcf0`)

- `src/capauth/crypto/sequoia_backend.py` - `SequoiaBackend` implements the
  `CryptoBackend` ABC (`generate_keypair` / `sign` / `verify` /
  `fingerprint_from_armor`) by shelling out to `sq`.
- `src/capauth/models.py` - `Algorithm.HYBRID_ED448_MLDSA87`
  (`"hybrid-ed448-mldsa87"`), suite id `"mldsa87-ed448-v2"`,
  `CryptoBackendType.SEQUOIA`.
- `src/capauth/crypto/__init__.py` - `get_backend(SEQUOIA)` wired.
- `tests/test_sequoia_backend.py` - 4 TDD tests (keygen → ML-DSA-87, sign/verify
  + tamper, fingerprint round-trip, factory).

---

## Phase Map

```
  [ Phase 0 ]  Preconditions & backups        (agent-prep OK; backups by Chef)
       │
  [ Phase 1 ]  ADDITIVE - attach PQC subkeys   ← DO THIS FIRST. Fully reversible.
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

## Phase 0 - Preconditions & Backups

> ### ⛔ STOP - REQUIRES CHEF
> The backups below cover the **live** `~/.capauth/identity` and root secret
> material. **Chef performs the backups.** Do not let an agent read, copy, or
> exfiltrate root private key material.

**Checklist (all must be true before any later phase):**

1. **`sq` verified** - `sq version` reports `1.4.0-pqc.1`; help shows
   `mldsa87-ed448`. (Agent-safe.)
2. **Two-track backup - know which track covers what.** The recoverable state
   splits into two tracks with different custody rules. Both must be current
   before any later phase.

   - **Track A - root key material (Chef, offline, manual).** The classical
     root **private key**, any subkeys, and the **revocation certificates** are
     Chef's offline custody and are **never** written to an automated backup.
     The automated `scripts/capauth-backup.sh` **deliberately refuses** to copy
     `private.asc` / `.gnupg` / `*.key` material (see its own header and
     `docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md` Step 1). Chef snapshots the
     identity directory to offline media by hand:
     ```
     # run by Chef, to OFFLINE media only
     tar -czf ~/capauth-identity-backup-$(date +%Y%m%d-%H%M%S).tgz -C ~ .capauth/identity
     # copy the .tgz to TWO independent offline media; do not leave it on the box
     ```
     Confirm at least **two** independent copies exist (redundancy mantra: if
     you need one, get two). Include the classical root **revocation cert**
     (documented path `~/.capauth/identity/root-revocation.asc`, constant
     `REVOCATION_CERT_FILENAME` in `src/capauth/custody.py`) and, once Phase 3
     produces them, the new primary's rev-cert (`root-v2-rev.pgp`) and any
     subkey-revocation certs.

   - **Track B - identity STATE (automated, no key material).** The
     verification-service keystore (`keys.db` - enrolled consumer public keys /
     fingerprints), the bunker pairing sessions (`bunker_sessions.json`), and
     the Authentik Postgres DB have their own automated, retained backup:
     `scripts/capauth-backup.sh` (the `capauth-backup` timer shipped under coord
     `0555cef0`). It writes a timestamped, `0700` artifact dir with a
     `MANIFEST.txt` carrying a sha256 per file, and holds **no** private key
     material. Take a fresh one immediately before the ceremony:
     ```
     scripts/capauth-backup.sh              # writes ~/.capauth/backups/capauth-backup-<ts>/
     ```
     Its confirm-gated inverse is `scripts/capauth-restore.sh` (see Rollback).
3. **Record the existing classical root fingerprint** and confirm it matches
   the known value:
   ```
   02BC0EB3CAD31DB691A753C70C5629AB893F9746
   ```
   Confirm against the live key:
   ```
   sq inspect ~/.capauth/identity/<root-public>.asc | grep -i Fingerprint
   ```
   The printed primary fingerprint MUST equal the value above. **If it does not
   match, STOP** - you are not looking at the real root; abort and re-check.
4. **Working copy on scratch.** Chef exports a copy of the root key into an
   isolated working directory (e.g. `~/ceremony-$(date +%Y%m%d)/`) so the
   ceremony never edits the canonical store in place.
5. **Revocation cert on hand** for the classical root (so the key can be
   revoked if anything goes wrong mid-ceremony).
6. **Witnessed.** Chef performs this deliberately, not under time pressure,
   ideally with the operation logged in the sksecurity ledger afterward.

If **any** item is unmet, **do not proceed**.

### Verify the backups before trusting them (a backup you have not restored is not a backup)

Do all of these and confirm each **before** touching any key:

1. **Track A tarball lists and extracts.** Prove the offline snapshot is
   readable and round-trips into a throwaway location (never over the live store):
   ```
   tar -tzf ~/capauth-identity-backup-<ts>.tgz | head        # lists cleanly
   mkdir -p /tmp/ba-verify && tar -xzf ~/capauth-identity-backup-<ts>.tgz -C /tmp/ba-verify
   # confirm the extracted PUBLIC cert's primary fingerprint matches the live root:
   sq inspect /tmp/ba-verify/.capauth/identity/<root-public>.asc | grep -i Fingerprint
   #   -> MUST equal 02BC0EB3CAD31DB691A753C70C5629AB893F9746
   rm -rf /tmp/ba-verify                                      # do not leave key copies around
   ```
2. **Track B artifact verifies fail-closed.** `scripts/capauth-restore.sh` checks
   every artifact against the `MANIFEST.txt` sha256 **before** writing anything;
   `--dry-run` runs that verification and touches nothing:
   ```
   scripts/capauth-restore.sh --latest --dry-run   # "verification passed, nothing was written."
   ```
   A checksum mismatch aborts (fail-closed) and restores nothing.
3. **Custody doctor is green.** `capauth doctor custody` (module
   `src/capauth/custody.py`, `run_custody_checks`) is the automated pre-flight
   gate. It exits non-zero on any **FAIL** and verifies, read-only and without
   reading any private key: identity material present, private key perms are
   `0600`, the key is not revoked/expired, a **root revocation cert exists** at
   `root-revocation.asc`, the keystore passes a SQLite integrity check, a
   **recent backup exists** (coord `0555cef0`), and that **backup is restorable**
   (it copies the backup's public key to a throwaway temp dir and checks the
   fingerprint against the live key without touching live state):
   ```
   capauth doctor custody       # or bare `capauth doctor`; must exit 0 (no FAIL)
   ```

If the tarball will not extract, the restore dry-run does not verify, or
`capauth doctor custody` reports any **FAIL**, **do not proceed** - you do not
have a proven rollback path yet.

---

## Phase 1 - ADDITIVE: attach PQC subkeys to the existing classical root

**This is the first real operation, and it is fully reversible.** It keeps the
classical primary `02BC0EB3CAD31DB691A753C70C5629AB893F9746` as the trust
anchor and **adds** PQC subkey capability. **Nothing is removed.** If the new
subkeys are ever unwanted, they can be revoked or simply not used, and the
classical key is exactly as it was.

> ### ⛔ STOP - REQUIRES CHEF
> Everything below touches the live root. **Only Chef runs these commands**,
> in the isolated working directory from Phase 0, on the **working copy** of the
> key - never on the canonical store in place.

> ### ✅ Capability note - RESOLVED (2026-07-17, throwaway rehearsal, card c061110f)
> `sq sign` in this build has no subcommand-level `--password` flag, but the
> **global** `--password-file FILE` (optionally with `--batch`) seeds `sq`'s
> password cache and unlocks a passphrase-protected primary for **every**
> operation that needs the secret key, including `key subkey add` and `sign`.
> Proven end to end on a passphrase-protected throwaway v6 cv25519 primary
> with sq 1.4.0-pqc.1:
>
> ```
> # protected primary: add ML-DSA-87+Ed448 signing subkey
> sq --password-file PW --batch key subkey add --cert-file root-key.pgp \
>   --can-sign --cipher-suite mldsa87-ed448 \
>   --new-password-file PW --output root+sig.pgp
>
> # then ML-KEM-1024+X448 encryption subkey on top
> sq --password-file PW --batch key subkey add --cert-file root+sig.pgp \
>   --can-encrypt universal --cipher-suite mldsa87-ed448 \
>   --new-password-file PW --output root+sig+kem.pgp
> ```
>
> Verified in the rehearsal: primary fingerprint unchanged, all secret
> material (old and new packets) stays Encrypted, a wrong password is
> rejected (`Found no suitable key`), `--batch` is optional when
> `--password-file` is given (interactive pinentry-style prompt is the
> default without it), and protected-key signing works with the same
> global flags (`sq --password-file PW --batch sign --signer-file ...`).
> Step 6 of `scripts/pqc_ceremony_dryrun.py` now regression-tests this
> exact path. No gpg-agent preset is needed; `sq` does not use gpg-agent.

### 1.1 Dry-run on a throwaway scratch key (agent-safe - do this first)

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
proving Phases 1-3 end-to-end - generate classical v6 root → generate PQC root →
cross-sign both directions → sign/verify continuity + tamper-reject → additive
PQC subkey with the primary fingerprint unchanged. It prints PASS/FAIL per step
and exits non-zero on any regression. **Run it before any live ceremony.**
Step 6 covers the passphrase-protected subkey-add path (global
`--password-file`/`--batch`), so the former "protected keystore flow" open
item is now exercised automatically as well.

### 1.2 Add PQC subkeys to the (working copy of the) classical root

> ### ⛔ STOP - REQUIRES CHEF
> Operate on the **working copy** (`~/ceremony-YYYYMMDD/root-key.pgp`), not the
> canonical store.

Intended additions to the existing classical primary:

- a **PQC signing** subkey (ML-DSA, e.g. ML-DSA-87) - for PQC-capable
  signatures while the classical primary still certifies; and/or
- a **PQC encryption** subkey (ML-KEM-1024 + X448) - so the root can *receive*
  PQC-protected material.

Use `sq key subkey add` against the working-copy key. The exact invocations are
now **confirmed** (validated end-to-end by `scripts/pqc_ceremony_dryrun.py`, all
PASS) - for an **unprotected** working copy:

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
(this is exactly what `SequoiaBackend.add_pqc_subkeys()` does). This protected
path is **empirically proven** (2026-07-17 throwaway rehearsal + harness step 6,
see the resolved capability note above). The classical
primary's own key, certification capability, and fingerprint **do not change** -
you are only appending subkey packets.

> **⚠️ v4→v6 gate.** `sq` refuses PQC algorithms on a **v4** key
> (`can't use algorithms for v4 keys`). The existing classical root is v4-era, so
> "additive PQC subkeys on the live root as-is" is **not possible** - re-issuing
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

## Phase 2 - Verification (additive result)

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

> Note: `sq sign` has no `--password` flag in this build - protected-key signing
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

Phase 1 is **accepted** only when 2.1-2.3 all pass **and** the classical primary
fingerprint is unchanged. Chef then (and only then) decides whether to import
the additive key into the canonical `~/.capauth/identity`. The Phase-0 backup
remains the rollback target.

---

## Phase 3 - OPTIONAL full rotation to a new ML-DSA-87+Ed448 primary

**Optional. Higher risk. Only after Phase 1+2 are proven and stable.** This
issues a **new** sovereign primary whose *primary* signing/certification is
post-quantum (hybrid), and cross-signs it with the old classical root so trust
flows across the boundary for continuity.

> ### ⛔ STOP - REQUIRES CHEF
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
- **`--without-password` produces an unprotected key file** - only acceptable on
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
  identity. This is the load-bearing link - anyone who trusted the old root can
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
them - it prints "Certifications have NOT been verified!"). Use the WoT engine
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
  separate, later decision - and even then prefer a "superseded by <v2
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

Only when every check passes is the rotation considered complete - and even then
the classical key is retained, not erased.

---

## Throwaway-Key Rehearsal - practice the WHOLE ceremony safely

**Do this before the real ceremony.** The point is to run every muscle of the
ceremony end to end (Phase 0 backup/restore, additive subkey, full rotation,
cross-sign, revocation, and custody verify) against a **disposable key**, so the
real event is muscle memory rather than a first attempt. A rehearsal is
**agent-safe and does not need Chef** - because, by construction, it **never
touches the real root**.

> ### 🔒 Rehearsal safety rules (all mandatory)
> - **Clearly-labeled throwaway key only.** Every rehearsal key uses an
>   unmistakable label and an `.invalid` email, e.g. name
>   `"REHEARSAL THROWAWAY - DO NOT TRUST"`, email `rehearsal@example.invalid`.
>   A rehearsal key must be impossible to confuse with the sovereign root.
> - **Never the real root.** Do not read, copy, export, or point any rehearsal
>   command at `~/.capauth/identity` or the live fingerprint
>   `02BC0EB3CAD31DB691A753C70C5629AB893F9746`. The rehearsal generates its own
>   throwaway root and works only on that.
> - **Isolated homes.** Run in a throwaway `SEQUOIA_HOME` **and** a throwaway
>   `CAPAUTH_HOME` so nothing writes to the real cert store, keystore, or
>   backups. Destroy the whole scratch tree at the end.
> - **No real key material, ever.** The rehearsal produces only throwaway keys;
>   never paste real secrets or the real revocation cert into a rehearsal.

### R.0 The automated core (run this first, every time)

`scripts/pqc_ceremony_dryrun.py` already rehearses the load-bearing `sq`
operations against throwaway keys in a fresh `tempfile.mkdtemp` with an isolated
`SEQUOIA_HOME` (it touches **no** real key). It proves, PASS/FAIL per step and
non-zero exit on any regression:

1. generate an OLD classical v6 root, 2. generate a NEW ML-DSA-87+Ed448 PQC root
(+ ML-KEM-1024+X448 subkey), 3. **cross-sign** both directions (`sq pki vouch
add`) and cryptographically authenticate each (`sq pki authenticate`),
4. sign/verify continuity + tamper-reject, 5. **additive** PQC subkey with the
primary fingerprint **unchanged**, 6. the passphrase-**protected** subkey-add
path (global `--password-file --batch`).

```
python scripts/pqc_ceremony_dryrun.py        # expect "RESULT: ALL PASS", exit 0
# optional: keep the scratch tree to inspect it
python scripts/pqc_ceremony_dryrun.py --workdir /tmp/ceremony-rehearsal
```

**If R.0 does not report ALL PASS, stop - the tooling is not ready for a live
ceremony.** R.0 covers the `sq` half of the ceremony. R.1-R.4 below add the
human muscle memory (backup/restore, revocation, custody doctor) on top.

### R.1 Rehearse Phase 0 (backup + verified restore) against a scratch home

Prove the backup/restore round-trip without going near live state by pointing
the scripts at a throwaway `CAPAUTH_HOME`:

```
export CAPAUTH_HOME=$(mktemp -d)/rehearsal-capauth
mkdir -p "$CAPAUTH_HOME/service"
# seed a disposable keystore so there is something to back up (no key material)
sqlite3 "$CAPAUTH_HOME/service/keys.db" \
  'CREATE TABLE keys(fpr TEXT); INSERT INTO keys VALUES ("REHEARSAL");'

scripts/capauth-backup.sh                       # writes $CAPAUTH_HOME/backups/capauth-backup-<ts>/
scripts/capauth-restore.sh --latest --dry-run   # fail-closed sha256 verify, writes nothing
scripts/capauth-restore.sh --latest --yes       # non-interactive restore round-trip
# cleanup
rm -rf "$CAPAUTH_HOME"; unset CAPAUTH_HOME
```

You are rehearsing the exact fail-closed verify and the confirm gate you will
rely on for real rollback (Track B), on data that is entirely disposable.

### R.2 Rehearse the additive subkey + full rotation on a throwaway root

Run the ceremony's `sq` steps by hand on a labeled throwaway root, in an
isolated home, so the invocations are familiar fingers-on-keys:

```
export SEQUOIA_HOME=$(mktemp -d)/rehearsal-sq
cd "$(mktemp -d)"

# throwaway classical v6 root (stands in for the live classical root)
sq key generate --own-key \
  --name "REHEARSAL THROWAWAY - DO NOT TRUST" --email rehearsal@example.invalid \
  --cipher-suite cv25519 --profile rfc9580 --without-password \
  --output rehearsal-root.pgp --rev-cert rehearsal-root-rev.pgp
sq inspect rehearsal-root.pgp                    # note the throwaway fingerprint

# ADDITIVE: add an ML-DSA-87+Ed448 signing subkey; primary fingerprint UNCHANGED
sq key subkey add --cert-file rehearsal-root.pgp --can-sign \
  --cipher-suite mldsa87-ed448 --without-password --output rehearsal-root+sig.pgp
sq inspect rehearsal-root+sig.pgp                # confirm primary fpr identical

# FULL ROTATION: new hybrid PQC primary + cross-sign both directions
sq key generate --own-key \
  --name "REHEARSAL THROWAWAY v2 - DO NOT TRUST" --email rehearsal@example.invalid \
  --cipher-suite mldsa87-ed448 --profile rfc9580 --without-password \
  --output rehearsal-v2.pgp --rev-cert rehearsal-v2-rev.pgp
sq key delete --cert-file rehearsal-root.pgp --output rehearsal-root.cert
sq key delete --cert-file rehearsal-v2.pgp   --output rehearsal-v2.cert
sq pki vouch add --certifier-file rehearsal-root.pgp \
  --cert-file rehearsal-v2.cert --email rehearsal@example.invalid \
  --output rehearsal-v2.by-old         # OLD certifies NEW (continuity link)
```

Follow the same authenticate + verify checks as Phase 3.2 / 3.4, then rehearse
**revocation** so you have done it before it matters. `sq key revoke` *creates*
a revocation certificate for a cert (it self-signs by default); merging that
cert into the key is what actually marks it revoked. Practice on the throwaway:

```
# rehearse creating a revocation cert for the throwaway v2 primary
sq key revoke --cert-file rehearsal-v2.pgp \
  --reason superseded --message "rehearsal only" --output rehearsal-v2-revocation.asc
# (keygen also emitted rehearsal-v2-rev.pgp above; either is a valid rev cert)
```

> If a `sq` subcommand flag differs in your build, fall back to the exact,
> build-verified invocations in `scripts/pqc_ceremony_dryrun.py` (steps 3-5) -
> that harness is the source of truth for the working syntax.

### R.3 Rehearse the custody doctor gate

Point the custody doctor at the throwaway home and read the report format you
will check for real in Phase 0:

```
CAPAUTH_HOME=<throwaway-home> capauth doctor custody   # read the OK/WARN/FAIL report
```

### R.4 Tear down

```
rm -rf "$SEQUOIA_HOME"; unset SEQUOIA_HOME
# remove the scratch working dir and every rehearsal-*.pgp / .cert produced above
```

**Nothing from a rehearsal is ever published, imported into the canonical store,
or trusted.** A clean rehearsal (R.0 ALL PASS, R.1 round-trip OK, R.2/R.3
walked by hand) is the signal that the live, Chef-driven ceremony is de-risked.

---

## Rollback Procedure

Rollback is always available because the additive phase removes nothing and the
backups are intact. Roll back on the **same two tracks** the Phase-0 backups
cover: **Track A** (root key material) is Chef restoring the offline tarball by
hand; **Track B** (identity STATE) is the confirm-gated
`scripts/capauth-restore.sh`.

**During Phase 1 (additive):**
1. Stop. Do not import the modified key into `~/.capauth/identity`.
2. Restore the identity directory (Track A) from the Phase-0 tarball:
   ```
   # run by Chef
   tar -xzf ~/capauth-identity-backup-<ts>.tgz -C ~
   ```
3. (If the additive key was already imported and you only want to undo the
   subkeys) revoke the added subkeys with their subkey-revocation, or restore
   from backup. The classical primary fingerprint is unchanged either way.
4. If the verification-service **state** was disturbed, restore Track B from the
   Phase-0 artifact. `capauth-restore.sh` verifies every file against the
   `MANIFEST.txt` sha256 **before** writing (fail-closed), copies each live
   target aside to `<target>.pre-restore-<ts>` first, and only proceeds after an
   explicit `RESTORE` confirmation (or `--yes`):
   ```
   scripts/capauth-restore.sh --latest --dry-run   # verify first, write nothing
   scripts/capauth-restore.sh --latest             # then confirm with RESTORE
   ```
5. `capauth profile verify` **and** `capauth doctor custody` to confirm the
   restored classical identity and custody state are healthy (doctor must exit 0).

**During Phase 3 (full rotation), before publishing/revoking the old root:**
1. Stop. The old classical root is still the live anchor - simply do not publish
   the new primary and do not issue the old-root revocation.
2. Discard the `~/ceremony-YYYYMMDD/` working directory (it contains only the new
   candidate primary, which nothing trusts yet).
3. Restore `~/.capauth/identity` from backup if it was touched.

**After Phase 3 publish (degraded path):** if the new primary is published but
later found faulty, the **classical root is still valid and retained** - fall
back to it as the anchor, and revoke the *new* primary (using its
`root-v2-rev.pgp` revocation cert) rather than the classical one. This is why the
classical root is never destroyed.

---

## Post-Ceremony

- Log the ceremony in the **sksecurity ledger** (continues the PQC series; the
  per-message hybrid work was Entry #8).
- Update `docs/CRYPTO_SPEC.md` and the relevant MEMORY note **per surface** -
  state precisely which surfaces are now hybrid vs. still classical.
- Re-confirm the honesty rules: cite **FIPS 203/204/205**, **RFC 8032/9580**;
  note this is issued against **draft-ietf-openpgp-pqc-17** (pre-RFC);
  never claim "quantum-proof" or global PQ protection.

---

## Quick Reference - `sq` invocations

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
**⛔ STOP - REQUIRES CHEF**. Additive first, reversible always, nothing
automated.
