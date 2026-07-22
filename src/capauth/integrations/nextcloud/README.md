# CapAuth for Nextcloud

**Passwordless PGP authentication for Nextcloud.** Sign in with your sovereign
PGP key. No passwords, no OAuth flows, just cryptographic proof of identity.

> Published on the Nextcloud App Store: <https://apps.nextcloud.com/apps/capauth>
> Project site: <https://capauth.io>

---

## What it does

CapAuth is a real Nextcloud **user backend** (not merely a 2FA second factor).
The client signs a server-issued challenge nonce with their PGP private key,
CapAuth verifies the signature against the registered public key, and issues a
Nextcloud session. The private key never leaves the user's device.

### Features

- **Passwordless PRIMARY login** via PGP challenge-response (no password, no
  Authentik, no OAuth).
- **"Sign in with CapAuth"** button on the login page.
- **Bearer token authentication** for API requests.
- **Auto-provisioning** of users from CapAuth identity claims.
- **Group synchronisation**: CapAuth teams map to Nextcloud groups.

---

## Requirements

- Nextcloud **27 - 34**
- PHP **8.1+**

---

## Install

### From the App Store (recommended)

Settings → Apps → search **CapAuth** → Download and enable. Or:

```bash
occ app:install capauth
occ app:enable capauth
```

### From source

Clone into your Nextcloud `apps/` (or `custom_apps/`) directory as `capauth`:

```bash
cd /path/to/nextcloud/apps
git clone https://github.com/smilinTux/capauth.git capauth-src
cp -r capauth-src/src/capauth/integrations/nextcloud capauth
occ app:enable capauth
```

---

## Configuration (admin)

Point the app at your CapAuth verifier and enable the backend:

```bash
occ config:app:set capauth verifier_url   --value "https://capauth.example.org"
occ config:app:set capauth auto_provision --value "yes"      # optional
occ config:app:set capauth group_sync     --value "yes"      # optional
```

Then the **Sign in with CapAuth** button appears on the login page.

## How to sign in (user)

1. Click **Sign in with CapAuth** on the Nextcloud login page.
2. Your CapAuth client receives a challenge nonce and signs it with your PGP
   private key (the key never leaves your device).
3. CapAuth verifies the signature and Nextcloud issues your session.

---

## Support

- **Documentation & project:** <https://capauth.io>
- **Issues / bugs:** <https://github.com/smilinTux/capauth/issues>
- **Discussion:** <https://github.com/smilinTux/capauth/discussions>

## License

AGPL-3.0-or-later. Built by [SKWorld](https://capauth.io).

## Maintainers / publishing

Publishing this app to the Nextcloud App Store is documented in
[`PUBLISHING.md`](./PUBLISHING.md). Releases auto-publish from CI on a
`nextcloud-v*` tag.
