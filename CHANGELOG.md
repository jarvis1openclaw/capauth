# Changelog

All notable changes to `capauth` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`capauth.testing`: the gpg signing test seam, promoted from `tests/conftest.py`
  into shipped, importable code.** Since `0d412ab`, `issue_token` and
  `mint_audience_token` RAISE rather than storing an unsigned token, and
  `decide()` rejects unsigned tokens. Both are correct, but they made real gpg (a
  secret key present, an agent unlocked) a hard dependency of any test that
  expects an ALLOW. A GitHub Actions runner has neither, so downstream suites went
  red at the mint or 403'd at the gate. CapAuth's own suite was insulated only
  because the stub was private to its `tests/conftest.py`, where no consumer could
  reach it. It is now shipped:
  - `capauth.testing.capauth_signing_stub` — autouse fixture; a consuming repo
    turns it on for its whole suite with one line in its `tests/conftest.py`:
    `from capauth.testing import capauth_signing_stub  # noqa: F401`.
  - `capauth.testing.stub_token_signing` — the same thing, non-autouse, for
    opting in per test or per module.
  - `capauth.testing.signing_stub()` — a plain context manager, for use outside
    pytest.
  - `capauth.testing.install_signing_stub(monkeypatch)` — the building block, for
    applying the seam at a point of the caller's own choosing.
  - The seam stubs the **gpg subprocess boundary only**: three attributes of
    `capauth.tokens` (`_get_issuer_fingerprint`, `_pgp_sign_payload`, and the
    `verify_manifest` that module imported). It weakens **nothing**. Its stand-in
    signature is a digest of the exact payload bytes, accepted only for those
    bytes and only from the one issuer it signs as, so with the seam active an
    unsigned token is still denied for `skcode.dispatch`, a tampered payload is
    still denied, a signature lifted from another token is still denied, and a
    well-formed signature declaring a different issuer is still denied. The
    verified-tier enrollment floor, `signature_verifies`, and the
    raise-on-signing-failure behaviour are all untouched.
  - It cannot be switched on by accident in a deployed process: nothing in
    CapAuth's runtime imports it, importing it requires `pytest` (a dev extra, not
    a runtime or `service` dependency), it registers no `pytest11` entry point so
    pytest never auto-loads it, importing it patches nothing, every activation is
    lexically scoped and reverts, and there is deliberately no env var or global
    flag that enables it.
  - `tests/conftest.py` now imports the shipped fixture rather than carrying a
    second copy. New suite `tests/test_testing_helper.py` pins every claim above,
    including one control that runs in a fresh subprocess (empty `sys.modules`, no
    pytest session) and asserts its own isolation before asserting that
    `issue_token` still raises on a genuine signing failure.

### Fixed

- **`tests/test_identity_class.py` did not enroll under the card N10 proof rules**,
  so ten of its cases failed on `main` from the moment `09a6d6f3` merged. Its
  `_enroll` helper still passed a placeholder armored pubkey with no `proof` /
  `attestation`, which `enroll_device` now correctly refuses. It builds real
  keypairs and real challenge signatures via the existing conftest helpers
  instead. No production code involved; the identity-class ceiling itself was
  never broken.
- **`enroll_device` accepted `verified` / `attested` as a caller-asserted claim,
  never checked** (card N10 `09a6d6f3`). `Enrollment.proof` and
  `Enrollment.attestation` were stored on the record but neither was ever
  verified, so `decide()` gated its most sensitive capabilities
  (`agentrun.execute`, `change.deploy`, `skcode.dispatch`, all VERIFIED-only)
  on a mode nobody had proven. `enroll_device` now requires, before
  persisting the `Enrollment`, at the two non-`tofu` modes:
  - **`verified`**: `proof` must be a real signature by the presented
    `pubkey`'s own private key over
    `verified_challenge(fingerprint, subject)`, proving possession of that
    key.
  - **`attested`**: `operator_pubkey` + `attestation` must be a real
    signature by that operator key over
    `attested_challenge(fingerprint, subject)`, proving a vouching operator,
    not the device itself, attests to this exact fingerprint/subject pair.
  - Both challenges are domain-separated (distinct string prefixes) so a
    genuine attestation can never be replayed as a verified proof under a
    different claimed mode, and both are bound to the *canonical* subject, so
    a proof made for one identity cannot be reused for another. `tofu` is
    unaffected (needs no proof by design). Any failure (missing, garbage,
    wrong-key, wrong-subject-binding, or evidence shaped for the other mode)
    raises `PairingError` and nothing is persisted. Verification runs through
    the existing `CryptoBackend.verify()`, fully in-memory.
  - **`provision_subject`** (`capauth.provisioning`) no longer falls back to
    `pubkey or subject`, which let the bare subject string stand in as if it
    were key material. When no real device `pubkey` is given it now mints a
    real throwaway Ed25519 keypair and self-proves it against the exact
    challenge `enroll_device` re-derives, discarding the private half
    immediately; when a real `pubkey` is given, new optional `proof` /
    `operator_pubkey` / `attestation` kwargs pass through untouched rather
    than being fabricated on the caller's behalf.
- **Publishing to PyPI could not work at all.** The workflow triggers only on
  a `v*` tag push, but the `tag` job that supplies the version is gated on
  `github.ref == 'refs/heads/main'`, so on the only path that actually runs it
  is always skipped and `needs.tag.outputs.version` is always empty. An empty
  `SETUPTOOLS_SCM_PRETEND_VERSION` makes setuptools-scm derive from git
  instead, and any dirt in the CI checkout (a regenerated `egg-info`, for one)
  then produces a dev version with a local segment. PyPI rejects that with a
  400, and by then the tag has already been cut. Observed live: `v0.3.0` was
  tagged and published nothing, emitting
  `0.3.1.dev0+gc16c51c.d20260815`. The version now falls back to the tag name,
  so a tag-triggered publish is deterministic regardless of tree cleanliness.
  Same family as the skcoord release outage; the sibling repos want checking
  for the identical shape.

### Added

- **Identity classes: a structural ceiling over capability grants**
  (`capauth.identity_class`, card `fc6500cb`). `IdentityClass` carries
  `allowed_capabilities`, `forbidden_capabilities` and a minimum
  `EnrollmentMode`, with four classes: `operator`, `agent`, `node`,
  `edge-device`. The `node` class forbids `Capability.ALL` (`"*"`),
  `Capability.TOKEN_ISSUE` and `Capability.IDENTITY_SIGN`, and allows inference
  plus read scopes only: no operator secrets, no agent signing, no minting.
  - `authz.decide` evaluates the class FIRST, before the capability rule, the
    enrollment mode, and any token read, so a node-class subject holding a
    valid, signed `Capability.ALL` token is still denied `token:issue`. A
    ceiling a token can raise is not a ceiling.
  - Assignment is stored (`<base_dir>/identity/classes.json`), never asserted by
    the caller, via `assign_identity_class` / `resolve_identity_class`.
  - Back-compatible: a subject with no class assignment skips every new branch
    and decides exactly as before. An unusable assignment (corrupt file, unknown
    class name) denies, and every new branch still emits the AUDIT obligation.

- **`store` parameter on `issue_token` / `mint_audience_token` /
  `mint_agent_audience_token`** (default `True`). `store=False` mints a token
  without writing a file to `home/security/tokens`. An audience token is
  self-contained (verified by signature, never looked up in the store), so
  persisting one file per mint is pointless and was the substrate of the
  operator-audience flood; the per-request mint path uses `store=False`. Card
  `e793b6bc`.

- **`tokens.prune_expired_tokens(home)` GC for the token store.** `_store_token`
  writes one file per issued token and nothing reaped them, so the per-request
  operator-audience mint path flooded `home/security/tokens` (observed: 38k files /
  153MB of expired 12h-TTL tokens, none read). The GC deletes proven-expired token
  files, keeps valid and non-expiring ones, and leaves an unreadable/mid-write file
  alone so it can never race a concurrent mint into loss. A trailing `Z` UTC suffix
  is normalized before parsing so GC works on Python 3.10 (whose `fromisoformat`
  predates `Z` support).
- **Operator session moved into capauth** (`capauth.pairing.operator_session`).
  A device-bound, revocable session token is now minted and verified here
  rather than in a downstream consumer, so every surface (dashboard, CLI, and
  a future messaging door) can present the same credential instead of each
  asserting its own idea of who the human is. capauth already owns device
  pairing, so the session belongs beside it.

### Fixed

- **Missing `approved` key read as approved.** The lifted session verifier
  treated an absent `approved` field as if the device had been approved, so a
  record that never went through approval could still verify. It now fails
  closed, pinned by a regression test.

### Added

- **One-shot canonical-subject store migration** (`capauth.pairing.canonicalize`,
  driven by `scripts/migrate_canonical_subjects.py`). Rewrites pre-existing
  device records and capability tokens onto the canonical fqid grammar from
  `IDENTITY_NAMING_STANDARD.md`. `enroll_device` already canonicalizes new
  enrollments; this closes the gap for records that predate it. A live dry-run
  against a real fleet store planned 253 device-sidecar rewrites, collapsing to
  143 distinct non-canonical subjects.
  - Ships `--dry-run` (the default) that prints the full plan and writes
    nothing, and is idempotent: a second `--execute` run is a no-op.
  - Device sidecars are edited in place, touching only the per-device
    `subject` field and leaving the surrounding v1 peer record byte-verbatim,
    with a one-time `subject_migrated_from` / `subject_migrated_at` stamp.
  - **Capability tokens are re-issued, never edited in place.** A PGP signature
    covers the whole payload including `subject`, so patching that field would
    leave a signature that verifies against the wrong bytes: an inconsistency
    more deceptive than the one being fixed. A non-canonical active token is
    re-issued with a fresh `token_id` (original `expires_at` preserved) and the
    old one revoked. Revoked and expired tokens are deliberately left alone,
    since re-issuing them would restore a dead grant.

### Fixed

- `authz._subject_tokens` now dual-reads legacy and canonical subject
  spellings, mirroring the dual-read `list_devices` already had. Without it a
  legacy caller would resolve its migrated device but then miss the
  exact-match token lookup, and `decide()` correlates the two by exact string.

- **Docs described a CLI that does not exist.** `SOP.md` and `README.md` told
  operators to run `capauth did generate` and `capauth did identity-card`. **There
  is no `did` command group**; `capauth.cli:main` has exactly 16 top-level commands
  and `did` is not one of them, so both invocations exit non-zero. Replaced with the
  real surfaces: the `capauth.did.DIDDocumentGenerator` library API, and skcapstone's
  `did_show` / `did_publish` / `did_identity_card` MCP tools. `docs/ARCHITECTURE.md`
  corrected too.
- **SOP section 5 documented the wrong deployment.** It described a single Tier 2
  SKStacks/Traefik cluster workload behind a Cloudflare Tunnel. What a fleet node
  actually runs is a loopback console script under `capauth-authz.service`
  (`capauth-service --host 127.0.0.1 --port 8420`), with no ingress at all. Section 5
  now separates three scenarios and labels which one is live here. It also corrects
  the claim that the standalone default bind is `0.0.0.0`: the code default is
  `127.0.0.1`, and `0.0.0.0` triggers a startup warning.
- **SOP quoted `SemVer: 0.2.3`**, a number that matched nothing. `pyproject.toml` is
  `dynamic = ["version"]` via setuptools-scm, the newest release tag is `v0.2.20`,
  and `src/capauth/__init__.py` hardcodes `0.2.15`. Section 9 now says where the
  version comes from and flags the hardcoded literal as an open **code** follow-up.
- **SOP named a test gate CI does not run** (`black --check`). Section 4 now cites
  `ci.yml` verbatim and explains why the narrower `pytest.yml` is not a substitute.
- Documented that there is **no `/health` route**; `/capauth/v1/status` is the probe.

### Added

- **`docs-evidence` block + `.github/workflows/docs-check.yml`** (tiers 1,2). Nine
  executable checks pin the documented entry points, the `127.0.0.1:8420` defaults,
  the two named routes, the setuptools-scm version source, the CI gate, and the
  **absence** of both `/health` and a `did` CLI group. All nine were negative-tested
  by breaking the underlying fact (16 mutations, all correctly non-zero).

- **sk-standards doc set** — `SOP.md` (9 sections + mermaid architecture &
  challenge-response diagrams), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this `CHANGELOG.md`; README cross-link block + stated
  maturity tier + CRYPTOGRAPHY_STANDARD compliance line. Per the sk-standards
  `SK_REPO_DOC_STANDARD` (coord `237f38a1`).

- **`docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md`**: cold-machine bootstrap +
  disaster-recovery runbook. Codifies the **restore-not-regenerate** identity
  rule, the fixed chicken-and-egg restore order (offline root key into gpg, prime
  gpg-agent, unseal skvault, restore `~/.capauth/` home, restore per-agent
  profiles + `identity.json`, restore the service keystore, start + verify
  `capauth-service`, re-pair bunker devices, restore the `.13` edge), the DR /
  rotation paths (root compromise vs single-agent compromise vs key-loss), and a
  top-to-bottom operator checklist with `REQUIRES CHEF` markers on every step that
  touches secret key material. No secret is written into the doc. Coord `d7dca00c`.

- **`scripts/provision_agent_profiles.py` `--allow-new-keys` guard**: the
  provisioner now **refuses to mint a fresh keypair** for a missing agent profile
  unless `--allow-new-keys` is passed explicitly, preventing an accidental
  identity fork on a restore (minting over an agent that already had a key breaks
  every consumer enrolled against its real fingerprint). A no-flag run only reads
  existing fingerprints and rewrites the non-key `identity.json` dual-URI fields
  (`capauth_uri`, `fqid`), and prints a loud identity-forking warning when a
  profile is missing. Coord `d7dca00c`.

- **Vendored `tools/build-sq.sh`**: the Sequoia PQC (`sq`) build script now lives
  in-repo (pinned `sq 1.4.0-pqc.1` / `sequoia-openpgp 2.2.0-pqc.1`), autodetecting
  the OpenSSL prefix (with an OpenSSL >= 3.5 gate), autodetecting `libclang`
  (llvm18/20/21) to dodge the `bindgen` layout bug, and patching the binary rpath.
  The PQC signing backend now builds without an external script. Commit `f1846a4`.

- **DID `capabilityInvocation` / `capabilityDelegation`**: both verification
  relationships are now declared in all three DID tiers (`did:key`, mesh
  `did:web`, public `did:web`). Commit `bc7ada2`.

- **T3 composite root-identity path — additive + GATED** (`pqc_root_identity.py`).
  A clearly feature-flagged path that signs/verifies a composite **ML-DSA-87 + Ed448**
  (FIPS 204 + RFC 8032) identity attestation via the Sequoia backend. The signing
  side is **gated closed by default** (`t3_gate_open()` ⇒ `False`;
  `sign_identity_attestation()` raises `RootRotationGateError` before touching any
  key material); it opens only via explicit opt-in
  (`CAPAUTH_ALLOW_T3_COMPOSITE_ROOT=1` or `allow_gated=True`), reserved for the
  Chef-driven rotation ceremony. The classical Ed25519/RSA root path is untouched
  (PGPy stays the default). Hybrid = **either-leg** → quantum-resistant, never
  "quantum-proof"; pre-RFC `draft-ietf-openpgp-pqc-17` (sig code point 31). Tier:
  live root **T0 classical**, this path **proven-but-gated**. TDD:
  `tests/test_pqc_t3_gate.py` (gate-default-closed + classical-untouched without
  `sq`; composite sign→verify roundtrip + tamper/wrong-key reject with `sq`).
  Docs: `docs/PQC_ROOT_MIGRATION.md` §5a. Epic `PQC-MIGRATION` (coord `7b1bcaee`).

### Security

- **Revoked / expired signing-key rejection**: the `pgpy` and `gnupg` verify
  paths now reject a signing key that carries a revocation signature or is expired
  **before** the signature check (`KeyRevokedError` / `KeyExpiredError`), closing
  the gap where the default PGPy path silently accepted a revoked or expired
  signer. Also fixes a `gnupg` `sign()` `ImportResult.ok` crash. 14 new tests.
  Commit `f1846a4`. (Scope note: this rejects keys whose own material shows
  revocation/expiry; full external revocation-certificate enforcement in the
  default verify path is still an open item, tracked in the DR runbook as G1.)

- **`verify_challenge` TTL + replay guard**: challenge verification enforces a
  default max challenge age of 5 minutes (`DEFAULT_MAX_CHALLENGE_AGE_SECONDS = 300`,
  with clock-skew tolerance; older challenges raise `ChallengeExpiredError`) and
  accepts an optional single-use `replay_guard`. The bare primitive stays
  replayable within the TTL unless a guard is supplied; `InMemoryReplayGuard` is
  the single-process reference (`ChallengeReplayError` on reuse), and the
  verification service uses a durable nonce store. 25 new tests. Commit `f1846a4`.

### Crypto / PQC (recent, pre-changelog history)

- **Honest PQC representation for v6 roots** — no false `RSA` label on a v6 PQC root.
- **PQC root proven end-to-end through capauth** — Sequoia (`sq`) backend signs and
  verifies ML-DSA-87 + Ed448 (FIPS 204) / ML-KEM-1024 + X448 (FIPS 203) composite v6
  keys (RFC 9580). The **live root remains classical** until the gated root-rotation
  ceremony; migration is additive + reversible. Epic `PQC-MIGRATION` (coord `e1d6ba2a`).

## [0.2.3]

Current published line. Highlights from the working tree:

### Added

- **Unified agent-identity resolver** (`resolve_agent_identity()`, `agent_identity.py`)
  — the single canonical dual-URI (`capauth:<a>@skworld.io`) + FQID
  (`<a>@<op>.<realm>`) resolver every SK package delegates to; operator-vs-agent
  separation; `skcapstone doctor` `identity:*` invariants.
- **Bunker remote-signer** — phone holds the key and signs logins; relay E2E-encrypted
  (X25519 + HKDF + AES-GCM); proven with Chef's real root key.
- **Authentik custom stage** (`authentik-capauth` image) — passwordless PGP login to
  OIDC apps; cap7 deploy LIVE; the four build/migrate gotchas documented.
- **DID three tiers** (`did:key` / `did:web` mesh / `did:web` public) with the
  private-key-never-touched, no-`100.x`-IP, and tier-3 publish-gate invariants.
- **Per-agent signing-key fix** — agents sign with their own capauth/identity key, not
  the operator's.

### Security

- Honest-claim posture: the live identity root is **classical** (Ed25519 / RSA-4096,
  Shor-breakable) — documented, not overclaimed. PQC signing is available + proven but
  not yet the live default.

[Unreleased]: https://github.com/smilinTux/capauth/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/smilinTux/capauth/releases/tag/v0.2.3
