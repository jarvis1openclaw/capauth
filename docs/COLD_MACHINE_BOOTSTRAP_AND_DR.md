# Cold-Machine Bootstrap and Disaster Recovery Runbook

**Version:** 0.1.0 (DRAFT runbook) | **Classification:** Operational / Sensitive | **Last Updated:** 2026-07-18

**Coord:** `d7dca00c` (critical). **Companion docs:**
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) (rotation, not restore),
[PQC_ROOT_MIGRATION.md](PQC_ROOT_MIGRATION.md) (the `sq` PQC backend),
[deploy-plan/capauth-bulletproof-deploy.md](deploy-plan/capauth-bulletproof-deploy.md) (why this matters),
[authentik-capauth.md](authentik-capauth.md) and
[AUTHENTIK_DEPLOYMENT_SKSSO.md](AUTHENTIK_DEPLOYMENT_SKSSO.md) (the .13 edge).

---

## What this runbook is (and is not)

This is the procedure for standing capauth **back up on a blank machine** and for
recovering from **key loss or compromise**. capauth is the identity root of the
whole SK ecosystem: every consumer (skchat, skcomms, skmemory, skcapstone, sksso
on the .13 edge, Forgejo) delegates identity here, so a botched restore forks
identities fleet-wide.

It is **not** the rotation ceremony. Migrating the root onto a post-quantum
primary is a separate, deliberate, Chef-driven event covered by
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md). This document is about
getting the **existing** identity back, unchanged, in the right order.

### The one rule that governs everything here

> **RESTORE, do not regenerate.** Every private key, profile, and fingerprint
> that a consumer is already enrolled against must come back **byte-identical**
> from the sovereign backup. Minting a fresh keypair for an agent that already
> had one forks its identity and silently breaks every enrolled consumer. There
> is exactly one command in the SK tree that will mint a fresh agent key
> (`scripts/provision_agent_profiles.py`); it is now **guarded closed** and must
> never be run as part of a restore (see Step 5 and the guard note at the end).

> ### STOP - REQUIRES CHEF (root private key material)
> Recovering the **root private key** and unsealing the sovereign vault touch
> secret material that only Chef holds and only Chef may handle. Every step below
> that reads a private key or unseals the vault is marked **REQUIRES CHEF**.
> Prep, tooling, and public-only verification are operator-safe; the secrets are
> not. **No secret is written into this document.**

---

## The chicken-and-egg problem (read before touching anything)

There is a hard ordering dependency that makes the naive "just run the installer"
approach fail:

- **skvault is sealed to Chef's PGP key.** No vaulted secret is reachable until
  the key that unseals it is present. That key is (part of) the root identity.
- **The root private key therefore cannot come from the vault.** It must be
  restored from **offline custody** first (it is the thing that unlocks the
  vault, not something stored inside it).
- Agent profiles, the keystore, the service secrets, the bunker pairings, and the
  .13 edge credentials all depend on the vault (or on the root) already being
  available.

So the restore order is fixed and non-negotiable:

```
  offline custody
        |  (root private key + revocation cert)
        v
  1. root key into the local gpg keyring  -----------------.
        |                                                   |  REQUIRES CHEF
        v                                                   |
  2. gpg-agent unlocked (vault key live)  <----------------'
        |
        v
  3. skvault unseal  (now that the root can decrypt it)
        |
        v
  4. capauth home (~/.capauth/identity) restored from backup
        |
        v
  5. operator identity.json + per-agent capauth profiles restored (NOT minted)
        |
        v
  6. service keystore data restored (or accepted as rebuildable)
        |
        v
  7. capauth-service started + verified
        |
        v
  8. bunker devices re-paired (in-memory pairings are gone after any restart)
        |
        v
  9. .13 edge: cloudflared tunnel creds + DNS + cookie domain
```

Do the steps **in this order**. Skipping ahead (e.g. running the installer's
profile provisioner before the real profiles are restored) is what forks the
fleet.

---

## Part A - Prerequisites and install (operator-safe)

Everything in Part A is safe for an operator or an agent to run. It touches no
secret key material; it just gets the tooling on the blank box.

### A.1 System packages

capauth itself is pure Python. The PQC `sq` backend needs a build toolchain.

```sh
# Debian / Ubuntu
sudo apt install -y python3-venv git pkg-config capnproto clang libsqlite3-dev patchelf gnupg
# Arch / Manjaro
sudo pacman -S --needed python git pkgconf capnproto clang sqlite gnupg   # patchelf only for non-system OpenSSL
```

- `gnupg` is required: the default crypto backend and the SEAL/vault layer both
  drive the system `gpg` keyring and `gpg-agent`.
- OpenSSL **>= 3.5** must be present for the PQC primitives (native ML-KEM /
  ML-DSA / SLH-DSA). `tools/build-sq.sh` hard-fails below 3.5.

### A.2 The SK venv and capauth

All SK* packages install into the shared venv at `~/.skenv/`:

```sh
python3 -m venv ~/.skenv
export PATH="$HOME/.skenv/bin:$PATH"

# from a clone of this repo:
~/.skenv/bin/pip install -e .            # or: ~/.skenv/bin/pip install capauth[all]
capauth --help                           # sanity
```

### A.3 The PQC `sq` backend (only needed for PQC signing / the ceremony)

The classical restore path does **not** need `sq`. Build it only if this machine
must host PQC signing (the additive subkeys or the rotation ceremony). The
canonical, autodetecting build script is in-repo:

```sh
bash tools/build-sq.sh          # installs sq into ~/.cargo/bin/sq
sq version                      # expect: 1.4.0-pqc.1 / sequoia-openpgp 2.2.0-pqc.1  (NOT `sq --version`)
```

`tools/build-sq.sh` pins `sq 1.4.0-pqc.1`, autodetects the OpenSSL prefix
(linuxbrew keg when complete, else system OpenSSL with the >= 3.5 gate),
sets `CARGO_TARGET_DIR=~/pqc-build/target`, and patches the binary's rpath so it
runs without `LD_LIBRARY_PATH`. Full provenance:
[PQC_ROOT_MIGRATION.md](PQC_ROOT_MIGRATION.md) section 3.

> **libclang / bindgen gotcha (hit on .41, 2026-07-17).** The locked
> `bindgen 0.71.1` emits opaque structs against **libclang >= 22** (the `ossl`
> crate then fails to build with E0080 layout errors). Fix: install a versioned
> clang (Arch: `clang18`) and export `LIBCLANG_PATH=/usr/lib/llvm18/lib` before
> running the script. `tools/build-sq.sh` autodetects `llvm18/20/21` and sets
> this for you; override `LIBCLANG_PATH` if your paths differ.

Rust: `rustc >= 1.79` via rustup (system rust is left untouched; the reference
builds used 1.96.0 on .158 and nightly 1.98.0 on .41).

### A.4 Where every artifact lives (know your targets before restoring)

| Artifact | Path | Notes |
|---|---|---|
| Operator / root capauth home | `~/.capauth/` (override `CAPAUTH_HOME`) | `resolve_capauth_home()` in `src/capauth/__init__.py` |
| Root identity dir | `~/.capauth/identity/` | `profile.json`, `public.asc`, `private.asc` (0600) |
| Live classical root fingerprint | `02BC0EB3CAD31DB691A753C70C5629AB893F9746` | still classical; see PQC_ROOT_MIGRATION.md |
| Operator identity | `~/.skcapstone/identity/identity.json` | `role: operator`; shared, not per-agent |
| Per-agent capauth profile | `~/.skcapstone/agents/<agent>/capauth/identity/profile.json` | fingerprint lives here |
| Per-agent wire identity | `~/.skcapstone/agents/<agent>/identity/identity.json` | `capauth_uri`, `fqid`, `fingerprint` |
| Cluster realm / operator | `~/.skcapstone/cluster.json` (or `/etc/skcapstone/cluster.json`) | drives the FQID |
| Service keystore (SQLite) | `~/.capauth/service/keys.db` | `DEFAULT_DB_PATH` in `service/keystore.py` |
| Service secrets | `deploy/capauth-service/.env` | admin token, JWT secret, optional server key |
| System gpg keyring | `~/.gnupg/` | holds the PGP secret keys SEAL/unseal use |

---

## Part B - Cold-machine bootstrap (the ordered restore)

This is the chicken-and-egg chain executed top to bottom. Do not reorder.

### Step 1 - Restore the root private key from OFFLINE custody

> ### STOP - REQUIRES CHEF

The root key does **not** come from skvault (the vault is sealed *to* it). It
comes from Chef's offline custody: the redundant copies required by
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) Phase 0 (two independent
copies, the redundancy mantra). Bring in **both** the secret key and its
**revocation certificate**.

```sh
# run by Chef, from the offline copy
gpg --import /path/to/offline/root-secret.asc
gpg --import /path/to/offline/root-revocation.asc   # keep the rev cert on hand

# Confirm this is the real root before trusting anything downstream:
gpg --list-secret-keys --fingerprint | grep -i 02BC0EB3CAD31DB691A753C70C5629AB893F9746
```

If the fingerprint does **not** match `02BC0EB3CAD31DB691A753C70C5629AB893F9746`,
**STOP** - you are not looking at the real root. Abort and re-check custody.

> **Custody has failed once before.** Commit `456cb3a` records that the
> 2026-06-22 Nextcloud code-signing key was never stored and was unrecoverable.
> Verify a **second** independent copy of the root exists before proceeding, and
> do not destroy any copy during recovery.

### Step 2 - Unlock gpg-agent (make the vault key live)

> ### STOP - REQUIRES CHEF

The SEAL/unseal layer (`src/capauth/seal.py`) is deliberately headless-safe:
`unseal()` runs `gpg` with `--pinentry-mode cancel`, so it only decrypts from an
**already-unlocked** gpg-agent cache and returns `None` when locked (locked ==
sealed, never blocks). So the root key must be **cached in the agent** before any
unseal will work:

```sh
# run by Chef - primes the agent cache by signing a throwaway
echo test | gpg --local-user 02BC0EB3CAD31DB691A753C70C5629AB893F9746 --sign -o /dev/null
```

### Step 3 - Unseal skvault (now reachable)

> ### STOP - REQUIRES CHEF

With the root key live in the agent, the sovereign vault (skvault, KeePass sealed
to Chef's PGP key) is finally decryptable. Follow the skvault multi-node join
procedure to re-seal / open the vault on this node (`skingest unlock` opens the
sealed corpus; the vault itself is a separate KeePass DB). Everything downstream
(service secrets, edge credentials) can be pulled from the vault from here.

- SEAL recipient config: `CAPAUTH_PGP_RECIPIENT` (falls back to
  `SKINGEST_PGP_RECIPIENT`); signer `CAPAUTH_PGP_SIGNER` (falls back to
  `SKINGEST_PGP_SIGNER`, default `lumina@skworld.io`). Set these to the restored
  recipient(s) so freshly written secrets seal to the right key.

**Chef decision:** which vault entries this machine needs, and whether to seal
new material to the classical root or to a per-agent key.

### Step 4 - Restore the capauth home from backup

> ### STOP - REQUIRES CHEF (private key files)

Restore the operator/root identity directory from the sovereign backup. This is
the Phase-0 tarball from the ceremony doc, or the Syncthing-replicated
`~/.capauth/` (capauth replicates the identity across mesh nodes via `capauth
sync` / `--sync`).

```sh
# from the backup tarball (created per ROOT_ROTATION_CEREMONY.md Phase 0):
tar -xzf /path/to/capauth-identity-backup-<ts>.tgz -C ~
chmod 600 ~/.capauth/identity/private.asc     # enforce perms after extract

capauth profile show                          # confirm entity + fingerprint
capauth profile verify                         # PGP self-signature must verify
```

If you replicate via Syncthing instead, let `~/.capauth/` sync in, then run the
same two verify commands. Do **not** run `capauth init` on this machine - that
generates a *new* keypair and would fork the operator identity.

### Step 5 - Restore agent profiles and identity.json (do NOT mint)

> ### STOP - REQUIRES CHEF (per-agent private keys)

Every agent's `~/.skcapstone/agents/<agent>/capauth/` profile (including its
`private.asc`) and the operator `~/.skcapstone/identity/identity.json` must be
restored **from backup**, byte-identical. Restore the per-agent capauth homes and
the shared identity file from the sovereign backup / Syncthing exactly as in
Step 4.

**Do not** run `scripts/provision_agent_profiles.py` to "recreate" missing
profiles. On a wiped machine every profile is missing, and the script's old
behavior was to silently mint a fresh Ed25519 keypair per agent - forking all of
them. The script is now **guarded**: it refuses to generate keys unless
`--allow-new-keys` is passed, and prints a loud identity-forking warning. After
the real profiles are restored, it is safe to run it **without** the flag purely
to (re)write the derived `identity.json` dual-URI fields:

```sh
# SAFE after profiles are restored: only rewrites identity.json non-key fields,
# reads existing fingerprints, never mints. Refuses (loudly) on any missing profile.
python scripts/provision_agent_profiles.py --dry-run     # preview
python scripts/provision_agent_profiles.py               # apply (no --allow-new-keys)
```

Verify the resolver sees the restored identities, not placeholders:

```sh
skcapstone doctor        # the identity:* checks: resolver importable, self resolves
                         # agent-aware, shared=operator, NO @capauth.local placeholders,
                         # per-agent files present
```

**Only** pass `--allow-new-keys` when genuinely enrolling a brand-new agent that
was never enrolled anywhere - never during a restore.

### Step 6 - Restore (or accept rebuild of) the service keystore

The verification service keystore is SQLite at `~/.capauth/service/keys.db`
(`service/keystore.py`). It is PII-minimal and holds enrolled consumer public
keys. Restore it from backup if you have one:

```sh
mkdir -p ~/.capauth/service
cp /path/to/backup/keys.db ~/.capauth/service/keys.db
```

If no keystore backup exists, it rebuilds as consumers re-enroll (each consumer
re-presents its public key on next login). **Note the SPOF caveat**
(deploy-plan G3): the current service is a single container with SQLite plus
in-memory bunker broker and rate limiter - a restart drops all bunker pairings
and in-flight logins. Restoring `keys.db` recovers enrolled keys but **not**
live bunker pairings (see Step 8).

**Where these backups come from (scheduled automation).**
`scripts/capauth-backup.sh` produces the very artifacts this step restores: an
online (consistent) snapshot of `keys.db` plus, when configured, a `pg_dump` of
the .13 Authentik Postgres (Step 9). It writes timestamped dirs under
`~/.capauth/backups` with N-day rotation, an optional off-box rsync target, and a
`MANIFEST.txt` (sizes + sha256, no secrets). It **never** copies the root private
key - that stays in offline custody (Step 1). Enable it (not part of any deploy
step) with the two units in `deploy/capauth-service/systemd/`:

```sh
mkdir -p ~/.config/systemd/user
cp deploy/capauth-service/systemd/capauth-backup.{service,timer} ~/.config/systemd/user/
# edit ExecStart path + optional EnvironmentFile (~/.capauth/backup.env) for
# CAPAUTH_AUTHENTIK_PG_* / PGPASSWORD / CAPAUTH_BACKUP_REMOTE
systemctl --user daemon-reload
systemctl --user enable --now capauth-backup.timer   # daily 03:30, persistent
systemctl --user start capauth-backup.service        # one-off manual run
capauth-backup.sh --dry-run                          # preview, touches nothing
```

### Step 7 - Start and verify capauth-service

Bring the verification service up. The deploy tooling is in-repo:

```sh
cd deploy/capauth-service
# deploy.sh auto-generates .env from .env.example with random admin/JWT secrets
# if .env is missing. For a restore, drop the REAL secrets from skvault into .env
# first (CAPAUTH_ADMIN_TOKEN, CAPAUTH_JWT_SECRET, optional CAPAUTH_SERVER_KEY_ARMOR)
# so existing tokens keep validating.
./deploy.sh --test        # start + smoke test
./deploy.sh --status      # GET /capauth/v1/status
```

**Chef decision:** whether to reuse the prior `CAPAUTH_JWT_SECRET` (keeps issued
tokens valid) or rotate it (invalidates every outstanding session). Pull the
prior value from skvault to reuse it.

**Verify the identity signs and verifies end to end** (the acceptance test for a
good restore):

```sh
capauth export-pubkey -o /tmp/self.pub.asc
capauth verify --pubkey /tmp/self.pub.asc      # challenge-response round-trip must pass
capauth profile verify                          # self-signature integrity
```

> **Revocation caveat (deploy-plan G1).** The default PGPy verify path does **not
> yet** check revocation or expiry (PGPy prints "Revocation checks are not yet
> implemented"). During a compromise recovery this means the verifier will still
> accept a **revoked** key until this gap is closed. Treat revocation as a
> distribution + re-enrollment action (Part C.1), not something the default
> verifier enforces on its own.

### Step 8 - Re-pair bunker devices

The bunker broker (`src/capauth/service/bunker.py`) is an **in-memory** WebSocket
relay: all phone-to-desktop pairings are lost on any service restart, so on a
cold machine there are none. The **phone signer holds the actual key** (encrypted
in the phone's keyvault); the desktop/service never sees it, so nothing secret is
lost - the pairing just has to be re-established.

```sh
# per docs/CAPAUTH_BUNKER_REMOTE_SIGNER.md:
# 1. Desktop/extension -> Key Custody -> "Create pairing QR" (or POST $BASE/bunker/session)
# 2. Phone signer PWA -> scan/paste the capauth-bunker://<broker>/<session>?... URI -> Connect
# 3. Both sides show "paired"; do one remote-signed login to confirm.
```

Set `CAPAUTH_BUNKER_HOST` to the reachable broker/Funnel host so the pairing URI
points somewhere the phone can reach. Full procedure and the E2E-encrypted relay
details: [CAPAUTH_BUNKER_REMOTE_SIGNER.md](CAPAUTH_BUNKER_REMOTE_SIGNER.md).

### Step 9 - Restore the .13 edge (Authentik / sksso)

The public SSO edge on .13 is the Authentik custom-stage image
(`authentik-capauth`) fronting capauth. Its **runtime wiring** (cloudflared
tunnel credentials, DNS records, and the auth cookie domain) lives in the
**skstacks** repo's sksso descriptor, not here - this repo builds the image and
documents the stage. Authoritative docs:

- [authentik-capauth.md](authentik-capauth.md) - building the custom image
  (`AK_VERSION`, venv install, frontend rebuild, the four build/migrate gotchas).
- [AUTHENTIK_DEPLOYMENT_SKSSO.md](AUTHENTIK_DEPLOYMENT_SKSSO.md) - manual
  stage-create + flow-binding; `CAPAUTH_SERVICE_ID` is the public host
  (e.g. `sso.skstack01.douno.it`).

Edge restore checklist (from skvault / the skstacks descriptor):

- **cloudflared tunnel credentials** - restore the tunnel `credentials.json` /
  token from skvault; re-run the tunnel so the named tunnel resolves.
- **DNS records** - re-point the public SSO host (CNAME to the tunnel) in the
  managing Cloudflare zone (`skworld.io` / `douno.it` as applicable).
- **Cookie domain** - Authentik's `AUTHENTIK_COOKIE_DOMAIN` / `CAPAUTH_SERVICE_ID`
  must match the public host or logins set a cookie the browser rejects.

**Chef decision + secrets:** the tunnel token, the exact zone/records, and the
cookie domain are edge secrets/config held in skvault and the skstacks repo;
restore them from there. This runbook links the authoritative sources rather than
duplicating them.

---

## Part C - Disaster recovery (key loss / compromise)

### C.1 Root key compromise -> revoke + rotate

If the **root** is believed compromised:

1. **Publish the revocation certificate** you kept in custody (Step 1) through
   every distribution channel (DID docs, peer registry, keyservers if used).
   Remember the default verifier does not yet honor revocation (G1), so this is
   primarily about consumers and humans, and about forcing re-enrollment.
2. **Rotate** onto a new primary. This is the
   [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) - additive first,
   Chef-driven, cross-signed old<->new for continuity. Do **not** improvise key
   generation outside that ceremony.
3. **Re-enroll consumers** against the new fingerprint (the service keystore and
   each consumer's pinned fingerprint must be updated).
4. Retain the old key (offline) so historical signatures stay verifiable; prefer
   a "superseded by <new fpr>" stance over destruction.

### C.2 Agent key compromise (single agent)

Scope is one agent, not the root:

1. Revoke and re-issue **only** that agent's profile. Restore from backup if the
   compromise is a machine loss (not a key leak); mint a genuinely new key
   **only** if the old one is actually leaked, using
   `provision_agent_profiles.py --allow-new-keys --agent <name>` and then
   re-enrolling that agent's consumers against the new fingerprint.
2. Do not touch other agents or the root.

### C.3 Key **loss** (no compromise, machine wiped)

This is the Part B restore. The key was never leaked, only the machine is gone -
so **restore byte-identical from backup**, do not rotate. If **no** backup of a
given key exists, that identity is unrecoverable (this happened once, commit
`456cb3a`); the only path forward is a fresh key + full re-enrollment, treated as
C.1/C.2.

### C.4 Post-restore verification (must all pass)

The restored identity is only trusted once every one of these passes:

- `capauth profile verify` - self-signature integrity, root and each agent.
- `capauth verify --pubkey <self>.pub.asc` - a live sign -> verify round-trip,
  plus a tamper check (flip one byte, confirm verify **rejects**).
- `skcapstone doctor` - `identity:*` checks green, no `@capauth.local`
  placeholders, per-agent files present.
- `gpg --list-secret-keys` shows the root fingerprint
  `02BC0EB3CAD31DB691A753C70C5629AB893F9746` and each restored agent key.
- `capauth-service` `--status` returns healthy and a real consumer login
  succeeds end to end.

---

## Part D - Operator checklist (top to bottom)

Tick each; do not skip ahead. **CHEF** marks a step only Chef performs.

```
PREREQS (operator-safe)
[ ] A.1  System packages installed (python3-venv, gnupg, + sq build deps if PQC needed)
[ ] A.2  ~/.skenv venv created; capauth installed (pip -e . or capauth[all]); `capauth --help` works
[ ] A.3  (PQC only) tools/build-sq.sh run; `sq version` == 1.4.0-pqc.1 (libclang gotcha handled)
[ ] A.4  Restore targets/paths reviewed; backup media on hand

ORDERED RESTORE (the chicken-and-egg chain)
[ ] 1  CHEF  Root secret + revocation cert imported from OFFLINE custody
[ ] 1  CHEF  gpg fingerprint == 02BC0EB3CAD31DB691A753C70C5629AB893F9746 (else STOP)
[ ] 1        Second independent custody copy confirmed to exist
[ ] 2  CHEF  gpg-agent primed (test sign) so unseal can read the cache
[ ] 3  CHEF  skvault unsealed; CAPAUTH_PGP_RECIPIENT/SIGNER set to restored key
[ ] 4  CHEF  ~/.capauth/identity restored from backup; private.asc chmod 600
[ ] 4        `capauth profile show` + `capauth profile verify` pass
[ ] 5  CHEF  Per-agent capauth profiles + operator identity.json restored (NOT minted)
[ ] 5        provision_agent_profiles.py run WITHOUT --allow-new-keys (identity.json only)
[ ] 5        `skcapstone doctor` identity:* green, no placeholders
[ ] 6        Service keystore keys.db restored (or accepted as rebuildable)
[ ] 7        Real service secrets loaded into deploy/capauth-service/.env from skvault
[ ] 7        capauth-service started (deploy.sh --test); /capauth/v1/status healthy
[ ] 7        `capauth verify` round-trip + tamper-reject pass
[ ] 8        Bunker devices re-paired; one remote-signed login confirmed
[ ] 9  CHEF  .13 edge: cloudflared tunnel creds restored, DNS re-pointed, cookie domain set

POST-RESTORE VERIFICATION (Part C.4 - all must pass)
[ ] profile verify (root + agents) | verify round-trip + tamper | doctor green
[ ] gpg secret keys present | service healthy | real consumer login succeeds
```

---

## Open items (mark before calling this v1.0)

- **Full cold-machine rehearsal on a scratch VM/container is PENDING.** The
  additive/rotation crypto flow is already rehearsed on throwaway keys by
  `scripts/pqc_ceremony_dryrun.py` (isolated `SEQUOIA_HOME`, touches no real
  key), but a full Part B walk-through on a blank box with **throwaway** root and
  agent keys has not yet been transcribed. Acceptance criterion 4 of coord
  `d7dca00c` requires that rehearsal + a linked transcript. Do it before
  promoting this runbook past DRAFT.
- **Revocation enforcement (G1)** is still open in the default verify path;
  until it lands, Part C.1 revocation is a distribution/re-enrollment action, not
  something the verifier enforces.
- **Service HA (G3)** - the single-container keystore + in-memory broker means a
  restart loses bunker pairings and in-flight logins. Until the Postgres-backed
  keystore lands, Steps 6 and 8 are expected to require re-enrollment / re-pair.
- **Live backup rehearsal is CHEF-only.** The scheduled backup automation now
  exists (`scripts/capauth-backup.sh` + `deploy/capauth-service/systemd/`,
  covered in Step 6) and has been validated end to end against a throwaway
  scratch DB. The end-to-end **restore drill against real key material** (coord
  `0555cef0` acceptance criterion 2: wipe a scratch volume, restore, start
  service, confirm a previously enrolled key still authenticates) touches live
  identity state and is a Chef-only action, not run by automation.
```
