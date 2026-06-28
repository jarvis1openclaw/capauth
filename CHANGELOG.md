# Changelog

All notable changes to `capauth` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **sk-standards doc set** — `SOP.md` (9 sections + mermaid architecture &
  challenge-response diagrams), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this `CHANGELOG.md`; README cross-link block + stated
  maturity tier + CRYPTOGRAPHY_STANDARD compliance line. Per the sk-standards
  `SK_REPO_DOC_STANDARD` (coord `237f38a1`).

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
