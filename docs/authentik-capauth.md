# authentik-capauth — CapAuth PGP stage baked into Authentik

`authentik-capauth` is a **custom Authentik server image** that bakes the CapAuth
PGP passwordless flow stage directly into Authentik. With it, an Authentik
authentication/authorization flow can present a **PGP challenge (fingerprint +
nonce/QR)** in place of a password box — the native sovereign login experience —
while still issuing standard OIDC to every downstream app Authentik fronts.

- **Standalone CapAuth** is the verification service + CLI in this repo
  (`ghcr.io/smilintux/capauth`, now public on ghcr). It turns a signed challenge
  into OIDC claims and runs on its own — see the top-level
  [README](../README.md) and [ARCHITECTURE](ARCHITECTURE.md).
- **authentik-capauth** (this doc) is a *different* artifact: the upstream
  Authentik server image with the CapAuth stage compiled in, so CapAuth becomes a
  first-class flow stage inside Authentik instead of a sidecar.

Published image: **`ghcr.io/smilintux/authentik-capauth`** (public on ghcr; tags
`2026.5.3`, `2026.5.3-cap3`, `latest`).

---

## What the image adds over stock Authentik

Two pieces are compiled into the upstream `ghcr.io/goauthentik/server` image:

| Layer | Source in this repo | What it is |
|---|---|---|
| **Django backend app** | `src/capauth/authentik/` | The `CapAuthStage` model + flow executor (`CapAuthStageView`), API ViewSet/serializer, nonce store, verifier, claims mapper. Registered as the `capauth` Django app. |
| **Lit web component** | `web/stages/capauth/` | The `ak-stage-capauth` front-end component, rebuilt into Authentik's flow-interface bundle. Renders the fingerprint input then the nonce/QR challenge and submits the signed response back to the flow executor. |

At **runtime** the baked-in stage still needs the **capauth service reachable**
for PGP key enrollment/verification — the stage handles the Authentik flow plumbing,
but the cryptographic verification path is CapAuth's. See
[AUTHENTIK_CUSTOM_STAGE.md](AUTHENTIK_CUSTOM_STAGE.md) for the full stage contract
(challenge/response payloads, `CAPAUTH_*` env, nonce cache).

---

## Building the image

The build is driven by [`Dockerfile.authentik-capauth`](../Dockerfile.authentik-capauth)
in the repo root. It is a two-stage build pinned to an Authentik version:

```bash
docker build -f Dockerfile.authentik-capauth \
  -t ghcr.io/smilintux/authentik-capauth:2026.5.3 \
  -t ghcr.io/smilintux/authentik-capauth:latest .

docker push ghcr.io/smilintux/authentik-capauth:2026.5.3
docker push ghcr.io/smilintux/authentik-capauth:latest
```

### `AK_VERSION`

```dockerfile
ARG AK_VERSION=2026.5.3
```

`AK_VERSION` tracks the **latest stable Authentik release** and is used in **both**
build stages (the frontend clone branch *and* the final base image). Override it to
build against a different Authentik:

```bash
docker build -f Dockerfile.authentik-capauth \
  --build-arg AK_VERSION=2025.12.6 \
  -t ghcr.io/smilintux/authentik-capauth:2025.12.6 .
```

### Stage 1 — rebuild the Authentik frontend (`node:24`)

1. Shallow-clone `goauthentik/authentik` at branch `version/${AK_VERSION}`.
2. `npm install` (not `npm ci` — the lockfile may need regeneration after the
   component is added).
3. Copy `web/stages/capauth/` → `web/src/flow/stages/capauth/`.
4. **Register the component** by appending an import to
   `web/src/flow/index.entrypoint.ts`:
   ```ts
   import "#flow/stages/capauth/CapAuthStage";
   ```
5. `npm run build` — produces the rebuilt `web/dist/` bundle.

### Stage 2 — final image (`FROM ghcr.io/goauthentik/server:${AK_VERSION}`)

1. **Install capauth into Authentik's venv, version-agnostically.** The venv's
   Python *minor* version changes across Authentik releases (2026.5.x ships
   **python3.14**, earlier shipped python3.13), so the site-packages dir is
   detected at build time rather than hardcoded:
   ```dockerfile
   RUN VENV_SP="$(ls -d /ak-root/.venv/lib/python3.*/site-packages | head -1)" && \
       pip install --no-cache-dir --no-deps --target "$VENV_SP" /app/capauth && \
       pip install --no-cache-dir --target "$VENV_SP" PGPy
   ```
   Most CapAuth deps (pydantic, httpx, click, …) already live in Authentik's venv;
   only **PGPy** is missing, so it's the one extra install.
2. Copy the rebuilt frontend: `COPY --from=web-builder .../web/dist/ /web/dist/`
   (overwrites the stock flow-interface bundle).
3. Copy `authentik-custom/user_settings.py` → `/data/user_settings.py`. Authentik
   loads this at startup via `_update_settings("data.user_settings")`. It registers
   capauth in **`TENANT_APPS`**, which means Authentik's normal migrate picks up the
   capauth app in dependency order:
   ```python
   TENANT_APPS = [
       "capauth.apps.CapauthConfig",
   ]
   ```

> The repo still contains `authentik-custom/capauth_migrate.py` as a **historical
> artifact** — it is **no longer copied into the image** (see Lessons #2 below).

---

## Deploying it (SKStacks v2)

SKStacks v2 wires this through the **`sksso`** app descriptor:

1. Override the image to the custom build:
   ```yaml
   deploy:
     image: ghcr.io/smilintux/authentik-capauth:2026.5.3   # or :latest / :2026.5.3-cap3
   ```
2. **For Authentik 2026.x, override the migration-Job command** to use the
   lifecycle migrator instead of a bare `ak migrate` (see Lessons #4):
   ```yaml
   deploy:
     migrate:
       command: ["python", "-m", "lifecycle.migrate"]
   ```
   This is the skrender migration-Job command-override (skstacks commit `bad48a9`).

3. **ghcr packages must be public.** The `capauth` and `authentik-capauth` packages
   were made public via an **org-level** policy
   (Org Settings → Packages → Package creation → Containers → Public). There is **no
   REST API** for this — it must be set in the org UI.

> **Status:** the build and migrate path are proven in the SKStacks v2 dev/deploy
> loop. This document describes the procedure; it does **not** assert a specific
> production-cluster deployment succeeded.

For the manual (non-SKStacks) stage-binding steps — creating the CapAuth Stage,
adding it to a flow, setting `CAPAUTH_*` env and a shared nonce cache — see
[AUTHENTIK_DEPLOYMENT_SKSSO.md](AUTHENTIK_DEPLOYMENT_SKSSO.md) and
[AUTHENTIK_CUSTOM_STAGE.md](AUTHENTIK_CUSTOM_STAGE.md).

---

## Lessons / gotchas (hard-won)

These four fixes are the reason the image builds and migrates cleanly on a fresh
Authentik 2026.x database. Each cites the commit that landed it.

### 1. `ModuleNotFoundError: capauth` — hardcoded venv path (`ca62bed`)

The Dockerfile originally installed capauth into a hardcoded
`/ak-root/.venv/lib/python3.13/site-packages`. Authentik **2026.5.x ships
python3.14**, so capauth landed on the wrong path and Django couldn't import it.
**Fix:** detect the real site-packages dir at build time with the glob
`ls -d /ak-root/.venv/lib/python3.*/site-packages | head -1`.

### 2. Migration ran too early on a fresh DB (`90a2dd8`)

An early `lifecycle/system_migrations/capauth_migrate.py` ran `ak migrate capauth`
**before the base schema existed**, failing on a fresh DB with
`relation "authentik_version_history" does not exist`. **Fix:** drop that
system-migration entirely and register capauth in `TENANT_APPS` (via
`user_settings.py`) so Authentik's **normal** migrate runs the capauth app in
dependency order — fresh-DB-safe. (`capauth_migrate.py` remains in the repo as a
historical artifact but is no longer copied into the image.)

### 3. `FieldError`: `CapAuthStage.name` clashes with `Stage.name` (`624225f`)

```
Local field 'name' in class 'CapAuthStage' clashes with field of the same name
from base class 'Stage'
```

CapAuth had redefined the `name` field that Authentik's base `Stage` model already
provides. **Fix:** remove the redefinition from **both**
`src/capauth/authentik/stage.py` (the model) and
`src/capauth/migrations/0001_initial.py` (the frozen migration state).
`CapAuthStage` now inherits `Stage.name`.

### 4. `lifecycle.migrate` — the root cause (the big one)

Authentik **2026.x** requires the `authentik_version_history` table, and that table
is created by Authentik's **server-startup pre-migrations**
(`lifecycle/system_migrations/`: `install_id.py`, `version_history_create.py`,
`version_history_update.py`) — **not** by Django migrations. A bare `ak migrate` /
`migrate_schemas` against a **fresh 2026.x DB** fails because core migration
`0058_setup` queries `authentik_admin.VersionHistory` before it exists.

**Fix:** run **`python -m lifecycle.migrate`** — it runs the pre-migrations
*first*, then the full migrate. This is why the SKStacks `sksso` descriptor
overrides `deploy.migrate.command` for 2026.x (see above).

> Stock Authentik **2024.10** migrates fine via a bare `ak migrate`; **only 2026.x**
> needs `lifecycle.migrate`.

---

## See also

- [AUTHENTIK_CUSTOM_STAGE.md](AUTHENTIK_CUSTOM_STAGE.md) — stage contract, payloads, env, nonce cache.
- [AUTHENTIK_DEPLOYMENT_SKSSO.md](AUTHENTIK_DEPLOYMENT_SKSSO.md) — manual stage-create + flow-binding steps.
- [AUTHENTIK_FORGEJO_DEPLOYMENT.md](AUTHENTIK_FORGEJO_DEPLOYMENT.md) — end-to-end Authentik → Forgejo OIDC walkthrough.
- [`Dockerfile.authentik-capauth`](../Dockerfile.authentik-capauth) — the build itself.
