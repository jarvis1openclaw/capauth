# CapAuth Enterprise Managed Keys / Keyrings — Research & Decision Doc

**Status:** Research + recommendation. Changes no code.
**Date:** 2026-06-22
**Scope:** How CapAuth can support enterprise-managed identities/keys (Entra ID,
AD, smartcards, HSMs, OS keystores) so an org can adopt CapAuth-based agents
using their *existing* IT-managed credentials — without forcing every user to
hand-roll a sovereign PGP key. Additive only: sovereign-by-default stays the
core; enterprise-managed is an opt-in mode.

---

## 0. What CapAuth does today (the plug-point)

CapAuth auth is a **challenge–response over a server-issued nonce**:

1. Verifier issues a random 32-byte challenge (`identity.create_challenge`).
2. Prover signs the challenge bytes with their PGP **private key**
   (`identity.respond_to_challenge` → `backend.sign(...)`).
3. Verifier checks the **detached PGP signature** against the prover's public
   key and confirms `responder_fingerprint == challenge.to_fingerprint`
   (`identity.verify_challenge` → `backend.verify(...)`).

Two facts make enterprise integration tractable:

- **There is already a clean signer abstraction.** Every crypto op flows through
  `CryptoBackend` (`src/capauth/crypto/base.py`): `sign(data, priv, pass)`,
  `verify(data, sig, pub)`, `fingerprint_from_armor(armor)`,
  `generate_keypair(...)`. Two impls exist (`pgpy_backend`, `gnupg_backend`).
  This is *exactly* the seam a managed-key signer plugs into.
- **The identity model is a fingerprint allow-list, not a CA.** Verification
  asserts "this signature came from *this specific key*." Enterprise PKI asserts
  "this cert chains to a CA we trust." That gap is the central design decision
  (Section B).

Two leaks to fix before any managed-key work, both visible in the current API:

- `respond_to_challenge` takes `private_key_armor` + `passphrase` *as
  arguments*. Managed keys never produce armor and never take a passphrase —
  the signer must be **reference-based** (a handle/URI), not material-based.
- `verify_challenge` hard-requires `responder_fingerprint ==
  challenge.to_fingerprint`. Cert-chain verification has no PGP fingerprint to
  match; this check needs a pluggable verification policy.

---

## (A) Realistic integration surfaces for the "signer" abstraction

CapAuth needs to generalize `CryptoBackend.sign` from "give me armored private
key material" to "**produce a signature using key reference X, wherever it
lives**." The reference forms, ranked by enterprise reach per unit of effort:

### A1. PKCS#11 (smartcards + HSMs) — **highest reach, lowest effort, signs *as PGP***

PKCS#11 is the universal C interface to smartcards/HSMs. The private key never
leaves the token; you call `C_Sign` and get bytes back. Critically, GnuPG already
bridges to it: drop `scdaemon-program /usr/bin/gnupg-pkcs11-scd` into
`gpg-agent.conf` and gpg-agent will sign through any PKCS#11 token, producing a
genuine **OpenPGP** signature. The PKCS#11 interface is restricted to *using*
existing keys — "neither new key generation nor key transfer is possible," so
extraction is structurally prevented.
([gnupg-pkcs11-scd manpage](https://manpages.debian.org/testing/gnupg-pkcs11-scd/gnupg-pkcs11-scd.1.en.html),
[Simon Josefsson — OpenPGP smartcard w/ GNOME](https://blog.josefsson.org/2021/05/01/openpgp-smartcard-with-gnome-on-debian-11-bullseye/),
[DigiCert — Sign with GPG using GnuPG PKCS#11](https://docs.digicert.com/en/software-trust-manager/code-signing/sign-with-third-party-signing-tools/gpg-signing/sign-with-gpg-using-gnupg-pkcs11.html))

This covers: YubiKeys, Nitrokeys, enterprise smartcards, network HSMs
(Thales/Entrust/SoftHSM), and TPM-via-PKCS#11. **Most enterprise key material is
reachable through one interface.**

> YubiKey nuance: the **OpenPGP applet** holds 1 sig + 1 enc + 1 auth slot and
> speaks native OpenPGP card protocol — gpg-agent talks to it with *zero*
> PKCS#11 needed; this is the easiest path and gives real PGP signatures. The
> **PIV applet** issues X.509 and is reached via PKCS#11/CNG; PIV and OpenPGP
> share one CCID interface and only one applet is selected at a time.
> ([Securing SSH with OpenPGP or PIV](https://developers.yubico.com/PIV/Guides/Securing_SSH_with_OpenPGP_or_PIV.html),
> [OpenSC #1849](https://github.com/OpenSC/OpenSC/issues/1849))

### A2. Cloud KMS / Key Vault sign-API — **high reach in cloud/agent estates, medium effort**

Azure Key Vault, Azure Managed HSM, AWS KMS, and GCP Cloud KMS all expose a
**sign-a-digest** REST call. The private key is created in and never leaves the
HSM; you POST a digest, you get a raw signature back.
([Azure KV `sign`](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign),
[AWS — digital signing with KMS asymmetric keys](https://aws.amazon.com/blogs/security/digital-signing-asymmetric-keys-aws-kms/),
[GCP — `gcloud kms asymmetric-sign`](https://cloud.google.com/sdk/gcloud/reference/kms/asymmetric-sign))

**The catch and the fix:** KMS returns a *raw* RSA/ECDSA signature, not an
OpenPGP packet. But an OpenPGP signature *is* a packet wrapping exactly that raw
value — for RSA the MPI of `m^d mod n`, for ECDSA the MPIs of `r` and `s`
([RFC 9580 §5.2](https://www.rfc-editor.org/rfc/rfc9580.html),
[OpenPGP for app developers — signatures](https://openpgp.dev/book/signatures.html)).
So the signer hashes locally, asks KMS to sign the digest, then assembles the
OpenPGP packet around the returned bytes. This is a solved, shipping pattern:
[`pgpkms`](https://pypi.org/project/pgpkms/) and
[`hf/kmspgp`](https://github.com/hf/kmspgp) already produce GnuPG-compatible
OpenPGP signatures from AWS KMS RSA keys. **CapAuth can do the same for its
challenge bytes** — and the verifier needs no changes, because the output is a
valid PGP signature over a valid public key.

This is the cleanest fit for the **agent** angle: per-agent keys live in a Key
Vault/KMS the org controls, agents sign via API with workload identity, no key
files on disk anywhere.

### A3. OS keystores — **medium reach, medium effort, platform-specific**

- **Windows CNG / Cert Store / TPM-backed keys.** Keys marked non-exportable
  live in the TPM via the Microsoft Platform Crypto Provider; all ops go through
  hardware. Virtual smart cards make a TPM key look like a PKCS#11/CNG smartcard.
  ([Polansky — TPM-backed certs on Windows](https://polansky.co/blog/tpm-backed-certificates-windows/),
  [Argon — TPM certs Part 1: Platform Crypto Provider](https://argonsys.com/microsoft-cloud/library/setting-up-tpm-protected-certificates-using-a-microsoft-certificate-authority-part-1-microsoft-platform-crypto-provider/))
  Reachable via CNG directly, or via PKCS#11 (collapses into A1).
- **macOS Keychain / Secure Enclave.** `kSecAttrTokenIDSecureEnclave` keys are
  hardware-bound and non-extractable; you sign with `SecKeyCreateSignature`
  (e.g. `.ecdsaSignatureMessageX962SHA256`).
  ([Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
  [`kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave))
  Note: SE is **EC P-256 only**, so this is inherently an X.509/ECDSA path, not
  PGP (reinforces Section B).
- **Linux gpg-agent / keyring.** Already native to the `gnupg_backend`. gpg-agent
  + scdaemon (A1) is the Linux managed-key story.

### A4. Verdict on (A)

| Surface | Reach | Effort | Signs as PGP? | Build order |
|---|---|---|---|---|
| **PKCS#11 via gpg-agent/scdaemon** | Very high (all smartcards+HSMs) | Low | **Yes, natively** | **1st** |
| **Cloud KMS / Key Vault sign-API** | High (cloud + agents) | Medium | Yes, assemble packet locally | **2nd** |
| Windows CNG / TPM | Medium | Medium | Via PKCS#11 → A1 | piggyback A1 |
| macOS Secure Enclave | Medium | Medium | No (EC-only → X.509) | with Section B |
| Linux gpg-agent | High (already there) | ~0 | Yes | done |

**The single highest-leverage move:** add a `gpg-agent`/PKCS#11-backed signer
mode to the GnuPG backend (reference key by fingerprint/grip, let gpg-agent reach
the card/HSM). It's mostly config, it produces native PGP signatures, the
verifier is unchanged, and it instantly covers YubiKey fleets, smartcards, and
network HSMs. KMS (A2) is the second build for the cloud/agent estate.

---

## (B) PGP-only vs add X.509 — **recommendation: add X.509 challenge-response (additive)**

### The reality

Enterprises overwhelmingly issue **X.509** certificates, not PGP keys: AD
Certificate Services, Intune/SCEP enrollment, PIV/CAC smartcards, Entra-issued
device certs. If CapAuth stays PGP-only, "drop CapAuth agents into a corp env and
it just works with existing IT credentials" is **false** — IT would have to
provision a parallel PGP fleet (Section D below shows that's niche).

### There is direct precedent — this is a solved auth pattern

X.509 challenge-response is exactly how smartcard logon and PIV/CAC work:
client-cert TLS authentication *is* "sign a server nonce with the cert's private
key." The PIV Card Authentication Key runs "an asymmetric key challenge/response
protocol"; the server issues a nonce, the card signs, the server verifies.
([Keeper — PIV/CAC/smart cards](https://docs.keeper.io/en/keeper-connection-manager/authentication/piv-cac-smart-cards),
[Authentic8 — CAC and PIV support](https://support.authentic8.com/support/solutions/articles/16000106953-smart-card-cac-and-piv-support))
CapAuth's nonce flow is already this shape; only the signature format and
verification model change.

### What changes: the verification model (the real work)

| | PGP (today) | X.509 (added) |
|---|---|---|
| Signature | Detached OpenPGP packet | CMS/PKCS#7 detached, or raw ECDSA/RSA + cert |
| Identity = | Key **fingerprint** (allow-list) | Cert **subject/SAN** + **chain to a trusted CA** |
| Trust decision | "Is this fingerprint enrolled?" | "Does this cert chain to our CA, is it unrevoked (CRL/OCSP), and does its subject map to an allowed identity?" |
| Revocation | PGP revocation cert / allow-list removal | CRL / OCSP / short-lived certs |

So a second verifier path is needed: instead of `fingerprint ==
to_fingerprint`, it builds the cert path to a configured **trust anchor / CA
bundle**, checks validity + revocation, then maps subject/SAN → CapAuth
identity. This is standard X.509 path validation — "verify signature with the
next cert's public key … until a trust anchor is reached"
([RFC 4158](https://datatracker.ietf.org/doc/html/rfc4158),
[Keyfactor — chain of trust](https://www.keyfactor.com/blog/certificate-chain-of-trust/)).
The fundamental difference is well understood: X.509 uses hierarchical CA chains
to eliminate per-peer fingerprint checking; PGP uses fingerprint/web-of-trust
([X.509 vs PGP PKI review](https://en.wikipedia.org/wiki/X.509)).

### Recommendation

**Add an X.509 / cert-based challenge-response mode as a sibling verifier, gated
by an explicit `verification_mode: pgp | x509` (or per-realm policy).** Keep PGP
fingerprint allow-list as the sovereign default. The crypto signer abstraction
(A) already covers *producing* X.509/PKCS#11 signatures; the net-new work is the
**verifier policy** that swaps fingerprint-match for CA-chain validation +
subject→identity mapping. This is the single change that turns "works with our
existing IT credentials" from false to true.

> Honest caveat: this introduces a CA as a trust authority — philosophically the
> opposite of sovereign self-issuance. That's fine *as an opt-in enterprise
> mode*; it must never become the default or a requirement for the sovereign path
> (see Section E).

---

## (C) Two enterprise on-ramps — **build (ii) federation first, (i) direct-sign second**

### (i) CapAuth signs challenges with enterprise-managed keys directly

CapAuth's signer reaches the org's smartcard/HSM/KMS (Section A) and/or verifies
X.509 against the org CA (Section B). The user authenticates with the exact
credential IT already gave them.

- **Pro:** truest "just works"; no new identity for the user; hardware-backed.
- **Con:** requires the X.509 verifier + per-platform signer plumbing;
  per-environment integration (PKCS#11 lib, CA bundle, OCSP). Heaviest lift.

### (ii) CapAuth federates to Entra ID and mints sovereign/agent keys ("SSO in, sovereign key out")

Enterprise users sign in via **Entra ID over OIDC** (Entra is a standard OIDC
provider; you register an app, point a relying party at its OIDC discovery
metadata). On first successful enterprise SSO, **CapAuth generates and binds a
sovereign keypair (and/or per-agent key) to that verified enterprise identity.**

- This is the well-trodden IdP-broker pattern. Authentik/Keycloak federate to
  Entra by registering an app in Entra (redirect URI →
  `.../broker/<alias>/endpoint`) and configuring the broker as an OIDC relying
  party against Entra's discovery doc.
  ([Skycloak — Entra through a Keycloak lens](https://skycloak.io/blog/learning-microsoft-entra-id-through-a-keycloak-lens-oidc/),
  [Entra External ID — custom OIDC federation](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-custom-oidc-federation-customers),
  [IAMWorkz — connect Entra with Keycloak](https://iamworkz.com/connect-microsoft-entra-id-with-keycloak/))
- CapAuth is already **becoming an OIDC IdP** (`service/oidc/provider.py`) and
  already has an **Authentik custom stage** (`src/capauth/authentik/`). Adding
  Entra as an *upstream* IdP is consistent with that direction and reuses
  existing OIDC plumbing.

- **Pro:** dramatically lower integration cost — no PKCS#11/CA plumbing, no
  per-platform signer; Day-1 SSO with the org's existing IdP; **preserves the
  sovereign core** because the *output* is still a CapAuth-native sovereign/agent
  key. Best of both: enterprise on-ramp + sovereign identity.
- **Con:** trust roots in Entra at enrollment (a federation dependency, not a
  per-signature one); the sovereign key is *bootstrapped from* enterprise auth
  rather than self-asserted — acceptable, since after binding the key stands on
  its own.

### Recommendation

**Build (ii) federation first.** It is the cleanest, lowest-risk enterprise
on-ramp, it is *additive and sovereignty-preserving* (enterprise SSO bootstraps a
real sovereign/agent key that then operates independently), and it leverages
CapAuth's existing OIDC/Authentik investment. Reserve **(i) direct-sign** for
customers with hard requirements — hardware-bound non-exportable keys,
air-gapped/regulated, or smartcard-mandated (PIV/CAC) environments — where
federation isn't enough and the X.509 verifier (B) + PKCS#11 signer (A1) earn
their keep.

---

## (D) Managed PGP at scale — feasible, but niche; don't bet OOTB on it

If we stay PGP for enterprise: the pieces exist. **WKD/WKS** publishes and
auto-discovers org public keys from the corp domain over HTTPS; a "Web Key
Service" automates publishing for larger orgs, and products like FlowCrypt EKM
and YAWKS add corporate key management, escrow, and rotation
([GnuPG wiki — WKD](https://wiki.gnupg.org/WKD),
[GnuPG — hosting a WKD](https://www.gnupg.org/blog/20161027-hosting-a-web-key-directory.html),
[FlowCrypt WKD server](https://flowcrypt.com/docs/technical/wkd-server/latest/technical-overview.html)).
Smartcard-provisioned PGP (YubiKey OpenPGP fleets) is real and gives
hardware-backed PGP signatures with no key on disk.

**But:** this means standing up a *parallel* PGP PKI alongside the org's existing
X.509 estate — key escrow/rotation, WKD hosting, fleet smartcard provisioning,
one-identity-per-YubiKey-OpenPGP-slot limits. That's a real program of work the
org doesn't already run. **Verdict: viable for PGP-committed shops and a nice
"sovereign-but-managed" option, but NOT the out-of-the-box enterprise answer.**
The OOTB answer is (C-ii) federation + (B) X.509, which meet the org where it
already is.

---

## (E) Where enterprise compatibility conflicts with sovereignty — and how to keep both first-class

The tension is real and worth naming honestly:

| Axis | Sovereign default | Enterprise-managed mode |
|---|---|---|
| Who issues identity | You generate it; no one issues it to you | Org CA / Entra issues or gatekeeps it |
| Trust root | Your fingerprint, self-asserted | CA chain / Entra tenant |
| Key custody | You hold it (or your token does) | Org HSM/Key Vault may hold/escrow it |
| Revocation | You revoke | IT can revoke/disable centrally |
| Offline | Works offline (PGP) | OCSP/CRL/IdP may need connectivity |

These genuinely conflict. The design rule that keeps both first-class:

1. **Sovereign is the default and the floor.** Every install works fully with a
   self-generated key and zero enterprise infra. Enterprise modes are *opt-in
   flags*, never prerequisites. (Mirrors the existing DID three-tier model:
   self-contained `did:key` works with zero infrastructure.)
2. **One abstraction, many signers.** Keep `CryptoBackend` as the only seam;
   `pgpy`/`gnupg` are sovereign signers, `pkcs11`/`kms`/`cng`/`secure-enclave`
   are managed signers. The rest of CapAuth never knows the difference.
3. **Pluggable verification policy, explicit per realm.** `pgp-fingerprint`
   (sovereign) and `x509-ca-chain` (enterprise) are sibling verifiers selected by
   config, not a global switch that downgrades sovereign users.
4. **Federation bootstraps sovereignty, doesn't replace it.** In (C-ii) the
   enterprise SSO mints a *real* sovereign/agent key the user then owns; the
   Entra dependency is at enrollment, not on every auth. An org user can later
   "graduate" to fully sovereign by detaching the federation binding.
5. **Disclose custody.** If a key lives in an org HSM/escrow, the profile must
   say so (`key_custody: self | org-hsm | escrowed`). Sovereignty includes
   *knowing* who can touch your key.

Net: enterprise compatibility is **additive surface area on the signer and
verifier seams**, not a change to the core. Sovereign-by-default and
enterprise-managed-by-option coexist because they are different implementations
of the same two interfaces.

---

## Prioritized sprint items (additive; never compromise the sovereign core)

**P0 — make the signer reference-based (unblocks everything)**
1. Refactor `respond_to_challenge` / `CryptoBackend.sign` to accept a **key
   reference** (URI/handle), not raw armor+passphrase. Sovereign signers resolve
   the ref to local material; managed signers resolve it to a token/vault handle.
   Keep the old signature as a thin compat shim.
2. Add a `Signer` resolver/registry keyed by scheme:
   `pgp:`, `gpg-agent:`, `pkcs11:`, `kms:azure|aws|gcp`, `cng:`, `secure-enclave:`.

**P1 — highest reach per effort (Section A1)**
3. **gpg-agent + PKCS#11 signer mode** in `gnupg_backend`: reference key by
   fingerprint/keygrip, sign through scdaemon/`gnupg-pkcs11-scd`. Produces native
   PGP signatures → **verifier unchanged**. Covers YubiKey OpenPGP, smartcards,
   network HSMs. Document the `gpg-agent.conf` recipe.

**P1 — the federation on-ramp (Section C-ii, recommended first big feature)**
4. **Entra ID (OIDC) as an upstream IdP** in `service/oidc` + Authentik stage:
   on verified enterprise SSO, mint/bind a sovereign or per-agent CapAuth key.
   Reuses existing OIDC IdP code. This is the OOTB "drop into a corp env" win.

**P2 — the cloud/agent signer (Section A2)**
5. **KMS/Key Vault signer**: hash challenge locally → vault `sign` digest →
   assemble OpenPGP packet around the raw signature (pattern proven by
   `pgpkms`/`kmspgp`). Verifier unchanged. Best fit for per-agent keys the org
   controls + workload identity (Section "agent angle").

**P2 — enterprise verification (Section B)**
6. **X.509 challenge-response verifier**: sibling to the PGP verifier; CA-chain
   path validation + CRL/OCSP + subject/SAN→identity mapping; selected by
   `verification_mode`. Unlocks PIV/CAC, AD CS, Intune/SCEP, Secure Enclave EC.

**P3 — polish / niche**
7. Windows CNG + macOS Secure Enclave native signer adapters (or document
   PKCS#11 bridges).
8. `key_custody` field in the profile + doctor check.
9. (Optional, PGP-committed shops) WKD/WKS on a corp domain + YubiKey-OpenPGP
   fleet provisioning guide.

---

## The agent angle (SKWorld) — cleanest credential model for agents joining an org

When *agents* (not humans) join an org, the cloud-native answer is **workload
identity, not hand-rolled per-agent PGP**:

- **SPIFFE/SPIRE** is the platform-agnostic standard: each workload gets a
  short-lived SVID (X.509 cert or JWT) after **attestation** (the agent's runtime
  environment is verified before an ID is issued); compromised agents simply stop
  getting new SVIDs and existing ones expire in minutes.
  ([SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/),
  [Palo Alto — what is SPIFFE](https://www.paloaltonetworks.com/cyberpedia/what-is-spiffe))
- **Azure Managed Identity / Entra Workload Identity Federation** lets a workload
  authenticate to Entra with no stored secret, by federating an external token
  (incl. a SPIFFE SVID) — explicitly works for workloads running *outside* Azure.
  ([Entra + SPIFFE federation](https://thomasvanlaere.com/posts/2024/05/spiffe-and-entra-workload-identity-federation/))
- **Kubernetes service-account tokens** are the in-cluster attestation primitive
  SPIRE consumes.

**Recommendation for SKWorld agents in an org:** prefer **per-agent keys in an
org-controlled HSM/Key Vault, signed via workload identity** (maps directly to
CapAuth's KMS signer, P2-#5) **or SPIFFE SVIDs verified via the X.509 verifier**
(P2-#6) — *not* a bespoke PGP key per agent, which reintroduces the
secret-on-disk and provisioning problems cloud-native identity exists to kill.
This dovetails with CapAuth's own agent-identity layer (`agent_identity.py`,
`capauth:<agent>@skworld.io`): the **wire identity stays CapAuth-native; the
*credential backing it* is the org's managed key.** Best of both — sovereign
addressing, enterprise custody.

---

## Sources

- [gnupg-pkcs11-scd manpage (Debian)](https://manpages.debian.org/testing/gnupg-pkcs11-scd/gnupg-pkcs11-scd.1.en.html)
- [Simon Josefsson — OpenPGP smartcard with GNOME](https://blog.josefsson.org/2021/05/01/openpgp-smartcard-with-gnome-on-debian-11-bullseye/)
- [DigiCert — Sign with GPG using GnuPG PKCS#11](https://docs.digicert.com/en/software-trust-manager/code-signing/sign-with-third-party-signing-tools/gpg-signing/sign-with-gpg-using-gnupg-pkcs11.html)
- [Yubico — Securing SSH with OpenPGP or PIV](https://developers.yubico.com/PIV/Guides/Securing_SSH_with_OpenPGP_or_PIV.html)
- [OpenSC #1849 — PIV vs OpenPGP applet, one at a time](https://github.com/OpenSC/OpenSC/issues/1849)
- [Azure Key Vault — `sign` REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign)
- [AWS — Digital signing with KMS asymmetric keys](https://aws.amazon.com/blogs/security/digital-signing-asymmetric-keys-aws-kms/)
- [AWS KMS — asymmetric keys (key never leaves)](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html)
- [GCP — `gcloud kms asymmetric-sign`](https://cloud.google.com/sdk/gcloud/reference/kms/asymmetric-sign)
- [`pgpkms` (PyPI) — KMS keys as OpenPGP signatures](https://pypi.org/project/pgpkms/)
- [`hf/kmspgp` — AWS KMS asymmetric keys as PGP/GPG keys](https://github.com/hf/kmspgp)
- [RFC 9580 — OpenPGP (signature packet structure)](https://www.rfc-editor.org/rfc/rfc9580.html)
- [OpenPGP for application developers — Signatures](https://openpgp.dev/book/signatures.html)
- [Polansky — Creating TPM-backed certificates on Windows](https://polansky.co/blog/tpm-backed-certificates-windows/)
- [Argon — TPM-protected certs Part 1 (Platform Crypto Provider)](https://argonsys.com/microsoft-cloud/library/setting-up-tpm-protected-certificates-using-a-microsoft-certificate-authority-part-1-microsoft-platform-crypto-provider/)
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple — `kSecAttrTokenIDSecureEnclave`](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave)
- [Keeper — PIV/CAC/smart cards (challenge/response)](https://docs.keeper.io/en/keeper-connection-manager/authentication/piv-cac-smart-cards)
- [Authentic8 — CAC and PIV support (client-cert TLS)](https://support.authentic8.com/support/solutions/articles/16000106953-smart-card-cac-and-piv-support)
- [RFC 4158 — X.509 certification path building](https://datatracker.ietf.org/doc/html/rfc4158)
- [Keyfactor — Certificate chain of trust](https://www.keyfactor.com/blog/certificate-chain-of-trust/)
- [Wikipedia — X.509 (vs PGP trust model)](https://en.wikipedia.org/wiki/X.509)
- [Skycloak — Learning Entra ID through a Keycloak lens (OIDC)](https://skycloak.io/blog/learning-microsoft-entra-id-through-a-keycloak-lens-oidc/)
- [Entra External ID — custom OIDC federation](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-custom-oidc-federation-customers)
- [IAMWorkz — Connect Entra ID with Keycloak](https://iamworkz.com/connect-microsoft-entra-id-with-keycloak/)
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [Palo Alto — What is SPIFFE](https://www.paloaltonetworks.com/cyberpedia/what-is-spiffe)
- [Thomas Van Laere — SPIFFE and Entra Workload Identity Federation](https://thomasvanlaere.com/posts/2024/05/spiffe-and-entra-workload-identity-federation/)
- [GnuPG wiki — WKD](https://wiki.gnupg.org/WKD)
- [GnuPG — Hosting a Web Key Directory](https://www.gnupg.org/blog/20161027-hosting-a-web-key-directory.html)
- [FlowCrypt — WKD server (enterprise EKM)](https://flowcrypt.com/docs/technical/wkd-server/latest/technical-overview.html)
</content>
</invoke>
