# CapAuth Bulletproof Deployment Plan

Status: PLAN (synthesized 2026-07-09 from two independent assessment passes, key claims spot-checked against the tree at v0.2.3 on main)

CapAuth is the identity root of the SK ecosystem. Every consumer (skchat, skcomms, skmemory, skcapstone, sksso on .13, forgejo) delegates identity here, so "bulletproof" for this repo is a higher bar than for any peripheral service.

## 1. Current State

Honest summary: strong crypto core and docs, manual and single-instance deployment.

What is genuinely solid:

- Canonical resolver (`src/capauth/agent_identity.py`), clean seal/unseal with deterministic headless semantics, three-backend crypto abstraction, gated-closed PQC composite-root path with honest-claims discipline enforced in code (`pqc_root_identity.py` raises `RootRotationGateError` unless `CAPAUTH_ALLOW_T3_COMPOSITE_ROOT` is set).
- 536 test functions across 36 files; 132 crypto-path tests pass locally; 11 Sequoia PQC tests pass where the custom `sq` exists. Pinned cross-implementation vectors keep Python and JS bunker crypto byte-identical.
- Secrets hygiene is real: no committed secrets found, signing key gitignored with rationale, compose hard-fails on unset secrets, `deploy.sh` generates secrets and smoke-tests the standup, release creds live in GH Actions secrets.
- Service-layer auth has TTL plus single-use nonce replay protection; keystore is PII-minimal.
- Exceptional deploy docs: `Dockerfile.authentik-capauth` and `docs/authentik-capauth.md` capture live-proven failure modes with fixes and commit references.

What is not bulletproof:

- The default PGPy verify path accepts revoked and expired keys (verified: no revocation or expiry handling in `src/capauth/crypto/pgpy_backend.py`; PGPy itself prints "Revocation checks are not yet implemented"). Revocation is the documented compromise-recovery mechanism, and the verifier cannot honor it.
- Neither container image (`ghcr.io/smilintux/capauth`, `ghcr.io/smilintux/authentik-capauth`) is built by CI. Builds are manual, the build script default tag is a year stale (2025.12.3 vs the Dockerfile's 2026.5.3), and the live .13 image (cap7 per fleet records) may not be reproducible from main.
- capauth-service is a single container: SQLite keystore, in-memory bunker broker, in-memory rate limiter and OIDC cache. A restart drops all bunker pairings and in-flight logins. This directly violates the redundancy mantra for the fleet's identity root.
- The only PQC-capable backend shells out to a hand-built `sq 1.4.0-pqc.1` whose build recipe lives outside the repo; all PQC signing paths skip in CI, so their loss would be silent.
- Key custody failure has already happened once: commit 456cb3a records that the 2026-06-22 Nextcloud code-signing key was never stored and is unrecoverable (whole-disk plus KeePass modulus sweep confirmed). The issued cert from PR #1054 had to be discarded and a fresh CSR resubmitted. Custody is now KeePass plus `~/.nextcloud/certificates/`, but nothing automated verifies custody preconditions for any key, including the classical root (fp 02BC...9746).
- No k8s/RKE2 manifests in this repo; the live .13 Authentik deployment is wired via the skstacks sksso descriptor in another repo, and the standup docs are manual outlines.
- The Authentik login web component is disabled in the image build (esbuild chunk-splitting bug), so any rebuilt image ships with the browser PGP login form not rendering; PGP login is API-proven only.
- ci.yml runs the full suite including tests that pytest.yml documents as genuinely failing (3 QR-login bugs) plus an integration test needing a sibling package, so one workflow is likely permanently red next to a green one. Coverage uploads with no threshold. JS vitest suites (including the bunker crypto round-trip) never run in CI.
- Repo hygiene: a 36MB PostScript junk file tracked at root as `urllib.error`, 72 tracked `.pyc` files (including cpython-313/314 bytecode), `.coverage` committed, tracked and dirty `egg-info`, root-owned `build/` in the working tree.
- PGPy is unmaintained and Python 3.13 incompatible; the sk_pgp replacement has no dependency, flag, or migration boundary in this repo.
- `seal.py` uses `--trust-model always`, takes recipients purely from env vars, silently retries encrypt-only when signing fails, and `unseal()` never verifies signatures. Documented behavior-preserving choices from the skingest lift, but weaker than the rest of the core.
- Library-level `verify_challenge` never checks challenge age or single-use; replay protection exists only in the service layer.
- `docs/ROOT_ROTATION_CEREMONY.md` is a v0.1.0 DRAFT; the gating discipline is excellent but recovery and backup custody are not a rehearsed procedure.
- Observability is docker HEALTHCHECKs plus optional sk-alert wiring; no metrics endpoint anywhere in the service.

## 2. Target: What Bulletproof Means for CapAuth

Concretely, this repo is bulletproof when:

1. Reproducible from scratch: a cold machine (or a fresh RKE2 node) can stand up capauth-service, the authentik-capauth image, and the sq PQC toolchain from this repo alone: CI-published images with pinned digests, in-repo build recipes, and an executable runbook (not a manual outline). The exact live image is rebuildable from a tagged commit.
2. Secrets never in git: already true; stays true, and is enforced (gitignore rationale kept, compose hard-fails everywhere including forgejo, secret scanning stays clean).
3. HA, no single point of failure: capauth-service can run with 2+ replicas. Keystore on shared Postgres (skmem-pg pattern), bunker sessions and rate limits in a shared store, restart of any single instance loses nothing. "If you need one, get two."
4. Cryptographically correct at the edges: revoked or expired keys fail verification on every backend; sealing cannot be silently redirected or stripped of provenance; library primitives are replay-safe or loudly documented as requiring the nonce store.
5. CI-gated, honestly: one green-by-construction required gate; no permanently red workflow; known failures fixed or xfail-annotated in the suite; coverage threshold on crypto paths; JS crypto suites and the sequoia backend exercised in CI; images built and pushed on tag.
6. Observable and self-recovering: a /metrics endpoint, sk-alert rules for service, bunker, and .13 stage health, container restart policies plus k8s liveness, and state that survives restarts.
7. Key custody is verified, not hoped: automated doctor checks prove the root revocation cert exists, backups are current and restorable, and the Nextcloud signing key has a verified second home. The rotation ceremony is a rehearsed v1.0 runbook. Commit 456cb3a never happens again.

## 3. Gap Analysis (severity-ordered)

| # | Sev | Area | Gap (verified) |
|---|-----|------|----------------|
| G1 | critical | Revocation/expiry | Default PGPy backend performs no revocation or expiry checks; revoked keys still authenticate. Ceremony rollback relies on revocation certs the verifier ignores. |
| G2 | critical | Image CI | No workflow builds or pushes either container image; manual builds, stale script defaults, live cap7 image possibly not reproducible from main. |
| G3 | high | HA / SPOF | Single container, SQLite keystore, in-memory bunker broker and rate limiter; restart drops all pairings and in-flight logins fleet-wide. |
| G4 | high | PQC reproducibility | Custom sq build recipe lives outside the repo; all PQC signing tests skip in CI; capability rests on binaries on two hosts. |
| G5 | high | Key custody | Custody failure already occurred (456cb3a, key lost, cert discarded, re-CSR pending). No automated custody checks for the root, its revocation cert, backups, or the Nextcloud signing key. Ceremony runbook is DRAFT v0.1.0. |
| G6 | high | Deploy path | No k8s manifests or executable Authentik standup runbook in-repo; live .13 wiring lives in another repo; blueprint exists but is not wired into the story. |
| G7 | high | Login UI | Web component disabled in the Authentik image build (esbuild bug); rebuilds ship a degraded browser login with no tracked fix. |
| G8 | high | PGPy dead end | Default hard dependency is unmaintained and Python 3.13 incompatible; no sk_pgp migration boundary coded. |
| G9 | medium | CI honesty | ci.yml likely permanently red (3 real QR-login failures plus sibling-package integration test) beside green pytest.yml; no coverage threshold; JS suites never run in CI. |
| G10 | medium | seal.py trust | `--trust-model always`, env-var-only recipients, silent encrypt-only fallback, unverified signatures on unseal. |
| G11 | medium | Library replay | `verify_challenge` ignores challenge age; primitive is indefinitely replayable without the service nonce store. |
| G12 | medium | GnuPG coverage | Positive-path GnuPG backend tests self-skip outside real keyrings; never run in CI. |
| G13 | medium | Observability | No metrics endpoint; no alerting for the .13 stage, keystore, or broker. |
| G14 | medium | Bunker hardening | Broker is an explicit SPIKE with deferred hardening, already used for real logins (capauth-skstack41). |
| G15 | medium | Repo hygiene | 36MB `urllib.error` junk file, 72 tracked .pyc, committed `.coverage`, dirty tracked egg-info, root-owned `build/`. |
| G16 | low | Forgejo compose | Falls back to change-me secret defaults instead of hard-failing like the capauth-service compose. |
| G17 | low | Fixture labeling | `browser-extension/tests/fixtures/test_key.json` holds a synthetic armored key with no explicit throwaway marker. |

## 4. Remediation Roadmap

Phases are ordered by deploy-criticality. Items marked [P] are parallelizable within their phase. Cross-phase parallelism is fine wherever no dependency is noted.

### Phase 0: Truth and hygiene (unblocks everything, all parallel)

- [P] Purge repo junk: `urllib.error`, tracked .pyc, `.coverage`, egg-info, extend .gitignore, document the root-owned `build/` cleanup (G15, G17).
- [P] Fix the 3 QR-login test failures and the sibling-package integration skip, then consolidate ci.yml and pytest.yml into one honest required gate with a coverage floor (G9).
- [P] Wire the JS vitest suites (bunker crypto round-trip, stage component) into CI (G9).

### Phase 1: Crypto correctness (the identity core must be right before it is highly available, all parallel)

- [P] Revocation and expiry enforcement in the default verify path (G1). Highest-value single change in the plan.
- [P] seal.py trust and provenance hardening (G10).
- [P] Library-level challenge TTL, or a loud replay-unsafe contract plus a default-on max age (G11).
- [P] Hermetic GnuPG backend tests with a throwaway GNUPGHOME (G12).

### Phase 2: Reproducible builds (a cold machine can rebuild exactly what runs live)

- Image CI: build and push both images to ghcr on tag with digests recorded (G2). No hard dependency, but land Phase 0 hygiene first so images and clones are not bloated.
- [P] In-repo sq PQC build recipe (Dockerfile or script) plus a CI job that caches the binary and runs the sequoia and PQC-root suites (G4).
- [P] Fix or fork around the esbuild chunk-splitting bug so the Authentik login web component ships enabled; if unfixable short-term, gate the image build on an explicit KNOWN-DEGRADED marker (G7).

### Phase 3: Deployable and redundant (depends on Phase 2 images)

- k8s manifests plus an executable standup runbook for authentik-capauth and capauth-service, wiring in the existing blueprint (G6). Depends on image CI.
- HA design and shared-state keystore: replace SQLite with a Postgres-backed keystore behind the existing interface, plus shared rate-limit state; document the 2-replica topology (G3).
- Bunker session persistence and restart survivability, building on the HA store (G3, G14). Depends on the HA keystore work.
- [P] Metrics endpoint and sk-alert rules (G13).
- [P] Forgejo compose hard-fail on default secrets (G16).

### Phase 4: Custody and future-proofing (Chef-gated where it touches live keys)

- Automated key custody doctor checks: root revocation cert present, identity backup current and restorable, Nextcloud signing key verified in two homes (G5).
- Ceremony runbook to v1.0 with a full rehearsal on throwaway keys; depends on the doctor checks existing as preconditions (G5).
- [P] sk_pgp migration boundary: optional backend registration plus a feature flag and a Python 3.13 CI leg proving the escape path (G8).

Exit criteria for the initiative: one green required CI gate including PQC and JS suites, images pulled by digest from ghcr, a rehearsed cold-machine standup from the runbook alone, 2 replicas serving logins with one killed mid-flight and no pairing loss, a revoked key failing auth end to end, and `capauth doctor` custody checks green.

## 5. Task List

Each task is sized for one subagent (hours). Dependencies reference exact task titles.

1. capauth: purge tracked junk and bytecode from the repo (medium)
2. capauth: fix QR-login test failures and consolidate CI into one honest gate (medium)
3. capauth: run the JS vitest suites in CI (medium)
4. capauth: enforce revocation and expiry checks on the default verify path (critical)
5. capauth: harden seal.py trust model and provenance semantics (medium)
6. capauth: add library-level challenge TTL and replay contract (medium)
7. capauth: hermetic GnuPG backend positive-path tests (medium)
8. capauth: CI build and publish of both container images to ghcr (critical)
9. capauth: in-repo reproducible sq PQC build recipe plus CI coverage (high)
10. capauth: re-enable the Authentik login web component in the image build (high)
11. capauth: k8s manifests and executable standup runbook for the .13 deployment (high, depends on image CI)
12. capauth: HA design and shared-state Postgres keystore for capauth-service (high)
13. capauth: bunker session persistence and restart survivability (high, depends on the HA keystore)
14. capauth: metrics endpoint and sk-alert observability rules (medium)
15. capauth: hard-fail forgejo compose on default secrets (low)
16. capauth: automated key custody doctor checks (high)
17. capauth: root rotation ceremony runbook to v1.0 with throwaway-key rehearsal (high, depends on custody doctor checks)
18. capauth: sk_pgp migration boundary and Python 3.13 escape path (high)

Full descriptions and acceptance criteria are carried in the coordination tasks created alongside this plan.
