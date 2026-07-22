# Publishing CapAuth to the Nextcloud App Store — SOP

This is the complete, step-by-step procedure for publishing the **CapAuth**
Nextcloud app (app id `capauth`) to the official App Store at
<https://apps.nextcloud.com>.

> **Legend**
> 🔵 **CHEF** = requires Chef's Nextcloud and/or GitHub account (a human must do it).
> ⚙️ = automatable / can be done by an agent.
> 🔑 = touches the private signing key — handle as a secret.

All paths below are relative to this app directory:
`src/capauth/integrations/nextcloud/` in the `capauth` repo.

---

## ✅ PUBLISHED — LIVE (2026-07-20)

**CapAuth 0.3.0 is live on the App Store: <https://apps.nextcloud.com/apps/capauth>**
(page returns HTTP 200; the store lists `capauth` / "CapAuth" with release `0.3.0`).

The full publish chain is DONE and the pipeline is proven end to end:

| # | Step | State |
|---|------|-------|
| 0 | App Store account | ✅ `chefboyrdave2.1` (**login username = the EMAIL `chefboyrdave2.1@gmail.com`**, not the short handle — see gotcha #2). Password reset 2026-07-20; new pw + API token in skvault entry **`Nextcloud App Store (apps.nextcloud.com)`**. |
| 0 | App Store **API token** | ✅ generated at *My account → API-Token* 2026-07-20. Secret; stored in skvault + repo secret `NEXTCLOUD_APPSTORE_TOKEN`. |
| 1a | Code-signing keypair + CSR (CN=`capauth`, RSA-4096, modulus `8e394ab0…`) | ✅ key in KeePass + `~/.nextcloud/certificates/capauth.key`; also repo secret `NEXTCLOUD_APP_SIGNING_KEY`. |
| 1b | Cert-request PR → `nextcloud/app-certificate-requests` | ✅ **#1054 MERGED 2026-06-29** (approved). |
| 1c | Signed `capauth.crt` | ✅ at `~/.nextcloud/certificates/capauth.crt` (valid Jul 2026 → Oct 2036, modulus matches key). |
| 2 | `info.xml` (v0.3.0) + screenshot | ✅ validates vs XSD; screenshot HTTP 200. |
| 1d | **Register app id** `POST /api/v1/apps` | ✅ **HTTP 201** — see gotcha #1: this is a REQUIRED explicit step, NOT implicit. |
| 4a | Host release tarball (GitHub release) | ✅ tag `nextcloud-v0.3.0` on `smilinTux/capauth` (asset download URL HTTP 200). |
| 4b | Sign tarball (base64 SHA-512) | ✅ |
| 4d | Create release `POST /api/v1/apps/releases` | ✅ **HTTP 201**. |
| 5 | CI auto-publish on `nextcloud-v*` tag | ✅ repo secrets `NEXTCLOUD_APPSTORE_TOKEN` + `NEXTCLOUD_APP_SIGNING_KEY` set 2026-07-21. Future releases auto-publish. |

### ⚠️ Gotchas learned during the real publish (2026-07-20) — READ THESE

1. **The app id is NOT auto-registered on first release.** The old note in this
   SOP (§1d) that "the first authenticated release POST claims the id" was WRONG.
   `POST /api/v1/apps/releases` returns `400 ["App capauth does not exist, you
   need to register it first"]`. You MUST first `POST /api/v1/apps` with the
   certificate **and a signature of the app-id STRING** (`printf 'capauth' |
   openssl dgst -sha512 -sign capauth.key | openssl base64 -A`). Signing the cert
   body instead gives `400 ["Signature is invalid"]`. Correct call returns `201`.
   This is a one-time step per app; it's done for `capauth`, so CI only needs the
   release POST going forward.
2. **Login username is the account EMAIL** (`chefboyrdave2.1@gmail.com`), not the
   short handle `chefboyrdave2.1`. Logging in with the short handle gives
   "username and/or password not correct" and, after a few tries, "Too many
   failed login attempts. Try again later." (~15 min lockout).
3. **Password reset URL** is `https://apps.nextcloud.com/password/reset/`
   (the `/account/password/reset/` path 404s). The reset email lands on
   `chefboyrdave2.1@gmail.com` with a `/password/reset/key/<token>/` link.

Nothing is blocking. This section is retained as the proven runbook for the next
release (and for publishing other SK apps to the store — see the sk-standards
reference).

---

## 0. One-time prerequisites

| Item | Owner | Notes |
|------|-------|-------|
| 🔵 Nextcloud App Store account | CHEF | Sign up / log in at <https://apps.nextcloud.com>. Used to register the app id and to upload releases. |
| 🔵 GitHub account with **public email** | CHEF | The cert-request PR must come from an account whose profile shows an email (Nextcloud emails the signed cert there). Settings → Profile → "Public email". |
| ⚙️ `openssl` | — | Already used to generate the key/CSR (OpenSSL 3.x). |
| ⚙️ `krankerl` *(optional)* | — | `cargo install --git https://github.com/ChristophWurst/krankerl` — or use the bundled `build-release.sh` (no krankerl needed). |
| ⚙️ `xmllint`, `curl`, `rsync`, `tar` | — | Used by `build-release.sh`. |

---

## 1. App-id registration + code-signing certificate

Nextcloud requires (a) the app id `capauth` to be registered, and (b) a
self-generated RSA code-signing certificate whose **Common Name equals the app
id**. You sign every release with the private key; the App Store verifies it
against the public cert Nextcloud signs for you.

### 1a. Generate the keypair + CSR  ⚙️🔑  — **ALREADY DONE**

The keypair and CSR have already been generated in `certificates/`:

```bash
# (for reference — already run)
openssl req -nodes -newkey rsa:4096 \
    -keyout certificates/capauth.key \
    -out    certificates/capauth.csr \
    -subj   "/CN=capauth"
```

- `certificates/capauth.key` — 🔑 **private key. gitignored. NEVER commit.**
- `certificates/capauth.csr` — public CSR, **committed** (safe to share).

Verify the CN if ever in doubt:

```bash
openssl req -in certificates/capauth.csr -noout -subject
# => subject=CN=capauth
```

> **Where the key must live for tooling.** Both `krankerl` and the upstream
> conventions expect `~/.nextcloud/certificates/capauth.{key,crt}`. Copy them:
> ```bash
> mkdir -p ~/.nextcloud/certificates
> cp certificates/capauth.key ~/.nextcloud/certificates/capauth.key
> chmod 600 ~/.nextcloud/certificates/capauth.key
> # capauth.crt arrives in step 1c
> ```

> 🔑 **Key custody (CHEF decision).** Store `capauth.key` in the SK secret
> store / password manager. If it leaks, anyone can publish a malicious
> `capauth` release under our name. If lost, you must re-CSR (step 1b) and ask
> Nextcloud to revoke the old cert.

### 1b. Submit the CSR as a PR  🔵  — **NEEDS CHEF'S GITHUB ACCOUNT**

Open a PR against <https://github.com/nextcloud/app-certificate-requests>:

1. In that repo, create a new file at path **`capauth/capauth.csr`**
   (the directory and file are both the app id).
2. Paste the **exact** contents of `certificates/capauth.csr` (the full
   `-----BEGIN CERTIFICATE REQUEST-----` … `-----END …-----` block — see
   `CSR-PR.md` in this directory for the ready-to-paste body and PR text).
3. PR title: `Add certificate for capauth`.
4. PR body: a one-line description + a link to the public source repo
   (`https://github.com/smilintux/capauth`). You do **not** need to @-mention
   anyone — maintainers are subscribed and will pick it up.
5. Ensure your GitHub profile shows a **public email** (Nextcloud sends the
   signed cert there, and/or attaches it to the PR).

### 1c. Receive + commit the signed cert  🔵→⚙️

When the PR is merged, Nextcloud returns `capauth.crt` (signed certificate).

```bash
# Save it next to the key for tooling:
cp <downloaded>/capauth.crt ~/.nextcloud/certificates/capauth.crt
# AND commit it to the repo (the .crt is public and IS tracked):
cp <downloaded>/capauth.crt certificates/capauth.crt
git add certificates/capauth.crt
git commit -m "nextcloud: add signed App Store certificate"
```

The CI workflow reads `certificates/capauth.crt` from the repo and the private
key from the `NEXTCLOUD_APP_SIGNING_KEY` secret (step 5).

### 1d. Register the app id  ⚙️🔑  — **REQUIRED, explicit, one-time**

> ⚠️ **Corrected 2026-07-20.** This is NOT implicit. `POST /api/v1/apps/releases`
> fails with `400 ["App capauth does not exist, you need to register it first"]`
> until you have explicitly registered the id. Do this once per app.

Register by POSTing the certificate plus a signature **of the app-id string**
(not the cert body — that gives `400 ["Signature is invalid"]`):

```bash
APP_ID=capauth
KEY=~/.nextcloud/certificates/${APP_ID}.key
CERT=~/.nextcloud/certificates/${APP_ID}.crt
ID_SIG=$(printf '%s' "$APP_ID" | openssl dgst -sha512 -sign "$KEY" | openssl base64 -A)

curl -sS -X POST https://apps.nextcloud.com/api/v1/apps \
  -H "Authorization: Token ${NEXTCLOUD_APPSTORE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg c "$(cat "$CERT")" --arg s "$ID_SIG" \
        '{certificate:$c, signature:$s}')"
# => HTTP 201 (registered).  Already done for `capauth`.
```

Requires the cert from 1c and that `info.xml` `<id>` matches the cert CN
(`capauth`). After this, `POST /api/v1/apps/releases` (step 4d) succeeds.

---

## 2. `info.xml` compliance — **DONE + VALIDATED**

`appinfo/info.xml` has been audited and corrected against the live schema
<https://apps.nextcloud.com/schema/apps/info.xsd> and **passes
`xmllint --schema`**. See `INFO-XML-CHANGES.md` for the full diff and rationale.
Summary of what changed:

- `licence`: `agpl` → **`AGPL-3.0-or-later`** (SPDX, matches `composer.json`,
  matches Nextcloud server's own licence).
- Added required/recommended elements: `<documentation>`, second `<category>`
  (`integration`), `<website>`, `<discussion>`, `<repository>`, `<screenshot>`.
- **Removed the `<settings>` block** — it referenced
  `OCA\CapAuth\Settings\AdminSettings` / `AdminSection` classes that **do not
  exist** in `lib/`. Shipping it would break app installation. (Add it back only
  once those classes are implemented.)
- Reordered elements to the schema's required sequence.
- Bumped `<version>` `0.3.0-dev` → **`0.3.0`** (App Store rejects non-semver /
  dev-suffixed stable versions; `-dev` is not a valid pre-release identifier —
  use `-alpha.N` / `-beta.N` / `-rc.N` for beta-channel releases).

Re-validate any time:

```bash
curl -fsS https://apps.nextcloud.com/schema/apps/info.xsd -o /tmp/info.xsd
xmllint --noout --schema /tmp/info.xsd appinfo/info.xml
# => appinfo/info.xml validates
```

> 🔵 **Screenshot (CHEF, before first stable release).** `info.xml` points
> `<screenshot>` at
> `https://raw.githubusercontent.com/smilintux/capauth/main/src/capauth/integrations/nextcloud/screenshots/login.png`.
> Drop a real `screenshots/login.png` (the "Sign in with CapAuth" login page) at
> that path and commit it, **or** edit the URL. The store fetches it over HTTPS
> (must be `https://`, ≤ 2 MiB). A release with a 404 screenshot URL is rejected.

---

## 3. Build the release tarball

The archive must contain a **single top-level folder `capauth/`** with
`appinfo/info.xml` inside — GitHub's auto source tarballs do NOT match this, so
we build our own. This app vendors **no runtime PHP deps** and ships
hand-written JS/CSS (no JS build step), so the tarball is just the curated app
tree minus dev/test/signing files (see `.nextcloudignore`).

### Option A — bundled script (no krankerl)  ⚙️

```bash
./build-release.sh            # -> build/artifacts/capauth.tar.gz  (+ validates info.xml)
```

### Option B — krankerl  ⚙️

```bash
krankerl package              # -> build/artifacts/capauth.tar.gz
```

Both honour `.nextcloudignore` and produce `build/artifacts/capauth.tar.gz`.
Verify the layout + that no secrets leaked:

```bash
tar tzf build/artifacts/capauth.tar.gz | head        # first entry must be 'capauth/'
tar tzf build/artifacts/capauth.tar.gz | grep -E 'certificates|\.key|tests/'  # must be EMPTY
```

> **Note on signing models.** The App Store does **not** use
> `occ integrity:sign-app`/`signature.json` for App Store uploads — that flow is
> for *shipped* (core-bundled) apps. App Store releases are verified by an
> **external base64 signature** of the whole tarball (step 4b). We use that
> model.

---

## 4. Manual submission (first release / no CI)

### 4a. Host the tarball at a stable HTTPS URL  ⚙️🔵

The store **downloads** the tarball from a URL you provide; it does not accept a
file upload. Easiest: attach `capauth.tar.gz` to a GitHub Release.

```bash
# tag + release (CHEF's GitHub account or a PAT with repo scope):
git tag nextcloud-v0.3.0 && git push origin nextcloud-v0.3.0
gh release create nextcloud-v0.3.0 build/artifacts/capauth.tar.gz \
    --title "CapAuth Nextcloud app 0.3.0" --notes "App Store release"
# download URL is then:
# https://github.com/smilintux/capauth/releases/download/nextcloud-v0.3.0/capauth.tar.gz
```

### 4b. Sign the tarball  ⚙️🔑

```bash
openssl dgst -sha512 -sign ~/.nextcloud/certificates/capauth.key \
    build/artifacts/capauth.tar.gz | openssl base64 -A
# copy the base64 string  (or: ./build-release.sh --sign  writes it to .sig.b64)
```

### 4c. Get the App Store API token  🔵  — **NEEDS CHEF'S NEXTCLOUD ACCOUNT**

Log in to <https://apps.nextcloud.com> → **My account → API-Token** → copy.

### 4d. Create the release  🔵 (token) / ⚙️ (call)

**Web UI:** <https://apps.nextcloud.com/developer/apps/releases/new> — paste the
download URL, the base64 signature, leave "nightly" unchecked for a stable
release.

**Or REST API:**

```bash
curl -sSf -X POST https://apps.nextcloud.com/api/v1/apps/releases \
  -H "Authorization: Token ${NEXTCLOUD_APPSTORE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
        "download": "https://github.com/smilintux/capauth/releases/download/nextcloud-v0.3.0/capauth.tar.gz",
        "signature": "<base64-signature-from-4b>",
        "nightly": false
      }'
```

The store downloads the tarball, recomputes the hash, and verifies the signature
against your `capauth.crt`. On success the app appears at
<https://apps.nextcloud.com/apps/capauth>.

- `"nightly": true` publishes to the **nightly** channel.
- A `<version>` ending in `-alpha.N` / `-beta.N` / `-rc.N` auto-targets the
  **beta** channel; a plain `X.Y.Z` targets **stable**.

---

## 5. CI — release on tag (optional, recommended)

`.github/workflows/nextcloud-appstore.yml` (in the capauth repo root) automates
**build → sign → GitHub Release → App Store POST** on any `nextcloud-v*` tag.

### Required GitHub repo secrets  🔵  — **NEEDS CHEF**

In `smilintux/capauth` → Settings → Secrets and variables → Actions:

| Secret | Value |
|--------|-------|
| 🔑 `NEXTCLOUD_APP_SIGNING_KEY` | Full PEM contents of `certificates/capauth.key`. |
| `NEXTCLOUD_APPSTORE_TOKEN` | The API token from step 4c. |

Then cut a release:

```bash
# bump <version> in appinfo/info.xml first, commit, then:
git tag nextcloud-v0.3.0
git push origin nextcloud-v0.3.0
```

The workflow installs the cert from the repo + the key from the secret, builds
with krankerl, signs, creates the GitHub Release that hosts the tarball, and
POSTs the new release to `apps.nextcloud.com`.

---

## Quick reference — exact commands

```bash
# generate keypair + CSR (CN MUST equal app id)         [done]
openssl req -nodes -newkey rsa:4096 -keyout certificates/capauth.key \
        -out certificates/capauth.csr -subj "/CN=capauth"

# build the tarball
./build-release.sh                 # or: krankerl package

# sign the tarball
openssl dgst -sha512 -sign ~/.nextcloud/certificates/capauth.key \
        build/artifacts/capauth.tar.gz | openssl base64 -A

# publish
curl -X POST https://apps.nextcloud.com/api/v1/apps/releases \
  -H "Authorization: Token $NEXTCLOUD_APPSTORE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"download":"<url>","signature":"<b64>","nightly":false}'
```

## Actions that require Chef (account-gated) — checklist

- [ ] 🔵 Create / confirm a **Nextcloud App Store account** (apps.nextcloud.com).
- [ ] 🔵 Set a **public email** on the GitHub account that opens the cert PR.
- [ ] 🔵 Open the **CSR PR** to `nextcloud/app-certificate-requests` (file
      `capauth/capauth.csr`, contents = `certificates/capauth.csr`).
- [ ] 🔵 Receive the signed **`capauth.crt`**, commit it to `certificates/`.
- [ ] 🔵 Add a real **`screenshots/login.png`** (or fix the `<screenshot>` URL).
- [ ] 🔵 Generate the **App Store API token** (My account → API-Token).
- [ ] 🔵 (CI) Add repo secrets **`NEXTCLOUD_APP_SIGNING_KEY`** + **`NEXTCLOUD_APPSTORE_TOKEN`**.
- [ ] 🔑 Securely **store/back up `capauth.key`** (SK secret store).
- [ ] 🔵 Tag **`nextcloud-v0.3.0`** (or run the manual POST) to cut the first release.
```
