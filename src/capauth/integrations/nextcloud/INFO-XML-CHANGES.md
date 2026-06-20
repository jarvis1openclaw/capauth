# `appinfo/info.xml` — App Store compliance audit + changes

Audited against the live schema
<https://apps.nextcloud.com/schema/apps/info.xsd> and validated with
`xmllint --noout --schema info.xsd appinfo/info.xml` → **`validates`**.

## Changes (vs `feat/nextcloud-passwordless-primary` base)

| # | Element | Before | After | Why |
|---|---------|--------|-------|-----|
| 1 | `<licence>` | `agpl` | `AGPL-3.0-or-later` | `agpl` is a *deprecated* short form. SPDX form matches `composer.json` (`AGPL-3.0-or-later`) and Nextcloud server's own licence. |
| 2 | `<version>` | `0.3.0-dev` | `0.3.0` | `-dev` is not a valid semver pre-release identifier; the store rejects it for a stable release. Use `-alpha.N`/`-beta.N`/`-rc.N` for the beta channel. |
| 3 | `<author>` | `mail` only | `mail` + `homepage` | Adds the optional `homepage` attribute. |
| 4 | `<documentation>` | — | added (user/admin/developer) | Recommended; improves the store listing. |
| 5 | `<category>` | `security` | `security` + `integration` | Adds a second valid category (an auth/SSO integration). Both are in the schema enum. |
| 6 | `<website>` | — | `https://capauth.io` | Recommended store metadata. |
| 7 | `<discussion>` | — | GitHub discussions URL | Optional; gives users a support channel. |
| 8 | `<repository>` | — | `https://github.com/smilintux/capauth.git` | Recommended; links the source. |
| 9 | `<screenshot>` | — | raw.githubusercontent URL | **Recommended for visibility.** Must be `https://`, ≤ 2 MiB. NOTE: the target `screenshots/login.png` still needs to be committed (see PUBLISHING.md). |
| 10 | `<settings>` | `AdminSettings` + `AdminSection` | **removed** | 🚩 **Correctness fix.** It referenced `OCA\CapAuth\Settings\AdminSettings` / `AdminSection`, which **do not exist** in `lib/`. Schema-valid but would throw on app load/install. Re-add only when the classes exist. |
| 11 | `<navigations/>` | empty element | **removed** | Empty/no-op; this app has no navigation entries. |
| 12 | element order | mixed | schema sequence | The XSD enforces a strict child order (`…namespace, types, documentation, category, website, discussion, bugs, repository, screenshot, dependencies, background-jobs…`). Reordered to match; `<types>` moved up before `<documentation>`. |
| 13 | `<description>` | indented plain text | de-indented + Markdown | App Store renders the description as Markdown; leading indentation was being rendered as code blocks. |

## Still required before first stable publish

- 🔵 Commit a real `screenshots/login.png` (or change/remove the `<screenshot>`
  URL) — a 404 screenshot URL fails store validation.
- The `<background-jobs>` job class `OCA\CapAuth\BackgroundJob\PruneExpiredNonces`
  **exists** (`lib/BackgroundJob/PruneExpiredNonces.php`) ✓.

## Full diff

See `git diff feat/nextcloud-passwordless-primary -- appinfo/info.xml`, or the
table above. The complete corrected file is `appinfo/info.xml`.
