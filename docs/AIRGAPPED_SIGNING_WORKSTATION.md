# Air-Gapped Offline Signing Workstation Runbook

**Version:** 1.0.0 | **Classification:** Operational / Sensitive | **Last Updated:** 2026-07-26

**Coord:** `932fba09` (security / key-custody DOCS). **Companion docs:**
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) (the ceremony this box hosts),
[COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md) (restore/DR on a networked node),
[PQC_ROOT_MIGRATION.md](PQC_ROOT_MIGRATION.md) (the `sq` PQC backend and build provenance).

---

## ⛔ STOP - REQUIRES CHEF

**No live-root operation on this workstation runs without Chef driving it, physically present.**

This document says **WHERE** the sovereign root-key operations of
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) should happen (an offline,
never-networked workstation) and **HOW** to get a reproducible `sq 1.4.0-pqc.1`
onto it with no network. The ceremony itself, its phase gates, and its honesty
rules are unchanged and authoritative in that doc. Every `STOP - REQUIRES CHEF`
gate there applies here verbatim. The only operations this runbook authorizes an
agent to perform unattended are:

- building/verifying the `sq` toolchain (touches no key), and
- the **throwaway** `.invalid`-labelled ceremony rehearsal (touches no real key).

The live root (classical primary, fingerprint
`02BC0EB3CAD31DB691A753C70C5629AB893F9746`) is **still classical** and has **not**
been migrated. Nothing here changes that. **No secret material appears in this
document.**

---

## 1. What this box is, and the threat model

### 1.1 The box

A dedicated, **permanently offline** workstation whose only job is sovereign
root-key operations: the additive PQC subkey step, the optional full rotation to
an ML-DSA-87+Ed448 primary, cross-signing, and revocation-cert generation
(all defined in [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md)).

Minimum spec / properties (all mandatory):

- **No network interface is ever brought up.** No Ethernet cable, Wi-Fi disabled
  in firmware where possible, Bluetooth off, no cellular/WWAN module active. If
  the hardware cannot physically remove or disable radios, treat that as a
  finding, not an acceptable state.
- **No persistent inbound/outbound path of any kind** except **labelled removable
  media** (the sneakernet, section 3). USB mass-storage only; no USB
  networking/tethering gadgets.
- **Local user account, full-disk encryption at rest.** The disk holds the build
  toolchain and, transiently during a ceremony, working copies of key material.
- **A real console** (keyboard + display), so pinentry and manual confirmations
  happen locally. No remote console, no KVM-over-IP, no serial-over-LAN.
- **Clock set manually.** With no NTP, set the RTC by hand before a ceremony so
  signature timestamps and key-expiry math are sane. Record the offset if the RTC
  drifts.
- Enough CPU/RAM to build Sequoia: the build is Rust + OpenSSL bindgen, so budget
  several GB RAM and a multi-core CPU. `tools/build-sq.sh` caps parallel codegen
  at 8 jobs and reuses `~/pqc-build/target` across retries.

A laptop with the radios physically removed, or a small-form-factor desktop with
no NIC populated, both qualify. A live-USB OS that boots to RAM with the internal
disk untouched is an acceptable variant when custody of a persistent disk is a
concern; if you use one, the toolchain and working material live on encrypted
removable media, not on the host.

### 1.2 Why offline for root ops (threat model)

The root key is the trust anchor for the entire SKWorld identity fabric; every
consumer (skchat, skcomms, skmemory, skcapstone, sksso) derives trust from it
(see [COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md)
"chicken-and-egg problem"). What an air gap buys, and what it explicitly does
**not**:

**Mitigates:**

- **Remote key exfiltration.** A network-borne compromise of the box (RCE, a
  malicious dependency phoning home, a backdoored build tool) cannot ship the
  root secret anywhere if there is no network to ship it over. The private key
  never touches an internet-reachable host during generation, signing, or
  cross-signing.
- **Supply-chain callback at build time.** Building `sq` from **pre-transferred,
  checksum-verified** sources with `cargo` in offline mode (section 2) means the
  build cannot silently pull an unpinned or substituted crate from crates.io.
- **Live-service blast radius.** A signing box that is never a server cannot be
  pivoted to from a compromised online capauth-service, keystore, or edge node.

**Does NOT mitigate (out of scope / handled elsewhere):**

- **Physical theft / evil-maid.** The air gap is not tamper resistance. Full-disk
  encryption, custody of the box, and custody of removable media (section 5) are
  what cover this. A hardware signer (bunker / PIV-CAC, see
  [CAPAUTH_BUNKER_REMOTE_SIGNER.md](CAPAUTH_BUNKER_REMOTE_SIGNER.md) and
  [ENTERPRISE_MANAGED_KEYS.md](ENTERPRISE_MANAGED_KEYS.md)) is the stronger answer
  where the key must never exist as a file at all.
- **Malicious media.** A USB stick carried in is an attack surface. Section 3
  constrains it (data-only, checksum + signature verified, one-directional
  discipline) but an air gap alone does not sanitise what you plug in.
- **Operator error.** Reconnecting the box "just once" defeats the entire model.
  Section 5 makes re-connection a prohibited action, not a judgement call.

The design goal: **the root private key is generated, held, and used only on a
machine that has no path to the internet, and only under Chef's hand.**

---

## 2. Getting a reproducible `sq 1.4.0-pqc.1` onto the box with NO network

The pinned target (identical to `tools/build-sq.sh` and
[PQC_ROOT_MIGRATION.md](PQC_ROOT_MIGRATION.md) section 3):

```
sq            1.4.0-pqc.1   (sequoia-openpgp 2.2.0-pqc.1, crates.io, --locked)
Rust          rustc >= 1.79 (reference: 1.96.0 on .158; nightly 1.98.0 on .41)
Crypto        OpenSSL >= 3.5 (native ML-KEM / ML-DSA / SLH-DSA)
build deps    pkg-config capnproto clang libsqlite3-dev patchelf   (Debian/Ubuntu)
              pkgconf capnproto clang sqlite                        (Arch/Manjaro)
```

There are two supported ways to land `sq` on the air-gapped box. **Path A
(offline source build) is preferred** because it reproduces the binary on the box
from pinned, verified sources. **Path B (verified prebuilt binary) is the
fallback** when the box cannot host a full Rust/OpenSSL build toolchain.

Both paths obey the same iron rule: **nothing crosses onto the box except via a
labelled USB stick whose contents are checksum-verified (and signature-verified
where a signing key is available) before use.** The staging box that assembles the
transfer bundle is a **networked** box you already trust (e.g. .158 or .41); it is
NOT the air-gapped box and NEVER connects to the air-gapped box.

### 2.1 Path A - offline reproducible source build (preferred)

**On the networked staging box** (has internet, has Rust + cargo):

1. Vendor the exact locked crate graph for the pinned `sq`. This resolves
   `sequoia-sq 1.4.0-pqc.1` with `--locked` and downloads every transitive crate
   into a self-contained `vendor/` tree, so the air-gapped build pulls nothing:

   ```sh
   mkdir -p ~/sq-airgap-bundle && cd ~/sq-airgap-bundle
   cargo new --bin sq-vendor-shim && cd sq-vendor-shim
   cargo add sequoia-sq@=1.4.0-pqc.1 \
     --no-default-features --features crypto-openssl
   cargo generate-lockfile           # pins the full graph -> Cargo.lock
   cargo vendor ../vendor            # downloads all sources into ../vendor/
   ```

   `cargo vendor` prints the `[source]` replacement stanza to add to a
   `.cargo/config.toml`; capture it (section 2.1 step 3). [ASSUMED: `cargo vendor`
   and the offline-build flow below are standard cargo behaviour, not something
   this repo wraps. The pinned crate/version/features come straight from the
   VERIFIED `tools/build-sq.sh`.]

2. Also stage the **Rust toolchain** for offline install (the air-gapped box may
   have no rustc, or one too old). Either:
   - carry the distro `rustc`/`cargo` packages (>= 1.79) for the box's OS, or
   - use a rustup offline bundle: on the staging box, `rustup component`/`rustup
     toolchain` artifacts for the target triple, copied into the bundle. [ASSUMED:
     exact rustup-offline packaging is environment-specific; the version floor
     (>= 1.79) and reference toolchains are VERIFIED from `tools/build-sq.sh`.]

3. Assemble the transfer bundle with the in-repo build script and a `.cargo`
   config that points cargo at the vendored sources:

   ```sh
   cd ~/sq-airgap-bundle
   cp <capauth-repo>/tools/build-sq.sh .
   cp <capauth-repo>/scripts/pqc_ceremony_dryrun.py .     # for the offline rehearsal (section 4)
   mkdir -p dot-cargo
   cat > dot-cargo/config.toml <<'EOF'
   [source.crates-io]
   replace-with = "vendored-sources"
   [source.vendored-sources]
   directory = "vendor"
   EOF
   # Optionally also stage a copy of the OpenSSL >= 3.5 dev packages/keg for the box's OS.
   ```

4. **Checksum and (where possible) sign the bundle**, then write it to labelled
   media:

   ```sh
   cd ~
   tar -czf sq-airgap-bundle.tgz sq-airgap-bundle
   sha256sum sq-airgap-bundle.tgz > sq-airgap-bundle.tgz.sha256
   # Sign the manifest with a NON-ROOT key you already trust (e.g. an agent key or
   # the operator's day key) so the air-gapped box can verify provenance offline.
   # Do NOT use the sovereign root for this.
   sq sign --signer-file <trusted-non-root-key> \
     --signature-file sq-airgap-bundle.tgz.sha256.sig sq-airgap-bundle.tgz.sha256
   ```

   Copy `sq-airgap-bundle.tgz`, its `.sha256`, the `.sig`, and the **public cert**
   of the signing key onto a **freshly-wiped, labelled** USB stick (section 3.1).

**On the air-gapped box** (offline, verify before trusting):

5. Mount the media read-only, verify the checksum, and verify the signature
   against the carried public cert before extracting anything:

   ```sh
   sha256sum -c sq-airgap-bundle.tgz.sha256          # must print: OK
   # if a system sq/gpg is already present, verify provenance too:
   sq verify --signer-file <trusted-non-root>.cert \
     --signature-file sq-airgap-bundle.tgz.sha256.sig sq-airgap-bundle.tgz.sha256
   tar -xzf sq-airgap-bundle.tgz && cd sq-airgap-bundle
   ```

   If either check fails, **STOP** - the bundle is not trustworthy; re-stage it.

6. Install the offline Rust toolchain (step 2 artifacts), then run the **in-repo**
   build in offline mode. `tools/build-sq.sh` calls `cargo install ... --locked`;
   pointing `CARGO_HOME` at the vendored `.cargo` config and setting
   `CARGO_NET_OFFLINE=true` makes that install resolve **only** from the vendored
   sources, with no network:

   ```sh
   export CARGO_NET_OFFLINE=true                     # cargo may not touch the network
   export CARGO_HOME="$PWD/dot-cargo"                # use the vendored [source] replacement
   export CARGO_INSTALL_ROOT="$HOME/.cargo"          # sq lands in ~/.cargo/bin
   # OpenSSL: if not autodetected, point OSSL at the >= 3.5 prefix you staged:
   #   export OSSL=/path/to/openssl-3.5-prefix
   bash build-sq.sh
   ```

   `build-sq.sh` autodetects the OpenSSL prefix (linuxbrew keg when complete, else
   system OpenSSL behind the >= 3.5 gate), pins `LIBCLANG_PATH` (the llvm18/20/21
   bindgen gotcha is handled for you), and patchelf-pins the rpath so `sq` runs
   without `LD_LIBRARY_PATH`. [VERIFIED: all of this is in `tools/build-sq.sh`. The
   `CARGO_NET_OFFLINE`/`CARGO_HOME` wrapping is the standard cargo mechanism layered
   on top; the script itself is unmodified.]

7. **Verify the tool before trusting it** (identical to the ceremony doc):

   ```sh
   sq version                                        # expect 1.4.0-pqc.1 / sequoia-openpgp 2.2.0-pqc.1
                                                     # (NOT `sq --version`)
   sq key generate --help | grep -A2 cipher-suite    # expect mldsa65-ed25519, mldsa87-ed448
   ```

> **Honest note on "reproducible".** "Reproducible" here means the build is
> **deterministic in its inputs**: a pinned crate version, `--locked` lockfile, a
> pinned toolchain floor, and vendored sources verified by checksum/signature, so
> the same inputs produce a functionally identical `sq` that passes `sq version`
> and the ceremony rehearsal (section 4). It does **not** claim a bit-for-bit
> identical binary across machines. Bit-reproducibility of the Rust+OpenSSL build
> is not asserted or required by the acceptance criterion. [VERIFIED scope; the
> bit-repro caveat is ASSUMED-honest, standard for cargo builds.]

### 2.2 Path B - verified prebuilt binary (fallback)

When the air-gapped box cannot host the build toolchain, carry a `sq` binary that
was built (per `tools/build-sq.sh`) on a trusted box, and verify it offline:

1. **On the staging box:** build `sq` with `tools/build-sq.sh`, confirm
   `sq version` == `1.4.0-pqc.1`, then checksum + sign the binary exactly as in
   section 2.1 step 4 (non-root signing key).
2. **On the air-gapped box:** `sha256sum -c` the binary, verify the signature
   against the carried public cert, place it on `PATH`, and re-run the section 2.1
   step 7 verification (`sq version`, cipher-suite grep). A binary built against a
   non-system OpenSSL prefix must either have its rpath already patched (the script
   does this) or the matching OpenSSL runtime must be present on the box.

Path B trades the on-box source rebuild for a smaller footprint; it still proves
provenance by checksum + signature and still verifies the tool before use. Prefer
Path A when the box can build.

---

## 3. The sneakernet workflow (moving material in and signatures out)

The only channel to and from this box is **labelled removable media, carried by
hand**. The box is never plugged into a network to move a file "just this once".

### 3.1 Media discipline

- **Dedicated, labelled sticks.** Keep at least three physically-labelled USB
  sticks with distinct roles, and never repurpose them ad hoc:
  - `TOOLCHAIN-IN` - carries the section 2 bundle onto the box.
  - `CEREMONY-IN` - carries public certs / CSRs / detached material to be signed
    **onto** the box.
  - `CEREMONY-OUT` - carries produced **signatures, public certs, and
    cross-signatures off** the box.
  Redundancy mantra: if you need one `-OUT` stick, prepare two, and write the
  output to both (the ceremony's own "two independent copies" rule for anything
  that matters).
- **Wipe before each use** (section 5.2) so no stale material rides along.
- **Data only.** Mount `noexec,nosuid,nodev` where the OS supports it; never
  execute directly off the stick, copy in and verify first.
- **One direction per stick per operation.** Do not carry an `-IN` stick back out
  with new material on it; use `CEREMONY-OUT`. This keeps "what came in" and "what
  went out" auditable.

### 3.2 What moves which way

**IN (onto the air-gapped box), each verified by checksum/signature before use:**

- the section 2 toolchain bundle (once);
- **public** certs of any counterpart keys needed for cross-signing (e.g. the
  public cert of the new v2 primary when the old root certifies it, and vice
  versa - both are public in [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md)
  Phase 3.2);
- any **detached material to be signed** (a CSR-equivalent, a document digest, a
  release manifest) - the data, never a private key.

**OUT (off the air-gapped box):**

- **detached signatures** (`.sig` files) produced by `sq sign --signature-file`;
- **public certs** derived on the box (`sq key delete --cert-file KEY --output
  CERT` produces the public cert from a key file - the ceremony's own idiom);
- **cross-signature certs** (`sq pki vouch add ... --output ...`);
- **revocation certificates** (public by design; keep custody tight anyway).

**NEVER out:** the root **private** key, any working-copy `*.pgp` that still
contains secret packets, passphrase files, or the `SEQUOIA_HOME`/working
directory. Root private-key custody stays with Chef on offline media
(Track A of [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) Phase 0 and
[COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md) Step 1);
it is never written to `CEREMONY-OUT`.

### 3.3 Verify-on-arrival, both ends

Every file that crosses is checksum-verified on arrival, and signature-verified
when a trusted signing key exists for it (same pattern as section 2.1 steps 4-5):

```sh
sha256sum -c <bundle>.sha256                         # on the receiving side, must be OK
sq verify --signer-file <trusted>.cert \
  --signature-file <bundle>.sig <bundle>             # provenance, where applicable
```

A checksum or signature failure aborts the operation. This mirrors the
fail-closed posture of `scripts/capauth-restore.sh` (verify against the
`MANIFEST.txt` sha256 **before** writing anything) documented in
[COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md) Step 6.

---

## 4. End-to-end THROWAWAY ceremony on the air-gapped box (proves it works offline)

**This is the acceptance test: a clean offline box runs a whole ceremony end to
end, build through root-cert ops, with no network.** It reuses the
[ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) "Throwaway-Key Rehearsal"
verbatim, on a clearly-labelled `.invalid` throwaway key, so it is **agent-safe
and needs no Chef** (by construction it never touches the real root).

> ### 🔒 Rehearsal safety rules (from ROOT_ROTATION_CEREMONY.md, all mandatory)
> - Clearly-labelled throwaway key only: name `"REHEARSAL THROWAWAY - DO NOT
>   TRUST"`, email `rehearsal@example.invalid`. Impossible to confuse with the root.
> - Never read, copy, export, or point any command at `~/.capauth/identity` or the
>   live fingerprint `02BC0EB3CAD31DB691A753C70C5629AB893F9746`.
> - Isolated `SEQUOIA_HOME` **and** `CAPAUTH_HOME`; destroy the scratch tree at the
>   end. No real key material, ever.

### 4.1 Prove the network really is down first

Before starting, confirm the box has no route out. If any of these succeeds in
reaching a network, **STOP - the box is not air-gapped**:

```sh
ip -brief address                                    # expect loopback only; no up NIC with a routable addr
ip route                                             # expect no default route
ping -c1 -W1 1.1.1.1 2>&1 || echo "no network - GOOD"
```

### 4.2 R.0 - the automated core (build proof + crypto proof, offline)

`scripts/pqc_ceremony_dryrun.py` (carried in the section 2 bundle) rehearses the
load-bearing `sq` operations against throwaway keys in a fresh temp
`SEQUOIA_HOME`, touching **no** real key. Running it **offline** on this box
proves both the toolchain built correctly and the whole ceremony crypto path works
with no network:

```sh
sq version                                           # gate: must be 1.4.0-pqc.1 (else the build failed)
python pqc_ceremony_dryrun.py                        # expect "RESULT: ALL PASS", exit 0
# optional: keep the scratch tree to inspect it
python pqc_ceremony_dryrun.py --workdir /tmp/ceremony-rehearsal
```

[VERIFIED: `scripts/pqc_ceremony_dryrun.py` exists in-repo and, per
ROOT_ROTATION_CEREMONY.md section R.0, exercises: (1) generate OLD classical v6
root, (2) generate NEW ML-DSA-87+Ed448 PQC root + ML-KEM-1024+X448 subkey,
(3) cross-sign both directions (`sq pki vouch add`) + authenticate (`sq pki
authenticate`), (4) sign/verify continuity + tamper-reject, (5) additive PQC
subkey with the primary fingerprint unchanged, (6) the passphrase-protected
subkey-add path. PASS/FAIL per step, non-zero exit on regression.]

**If R.0 does not report ALL PASS, stop** - the offline toolchain is not proven
ready. This single command is the crux of the acceptance criterion: it is a
complete throwaway ceremony (generate → additive → rotate → cross-sign →
authenticate → tamper-reject) executed entirely on the offline box.

### 4.3 R.1-R.4 - the by-hand muscle memory (offline)

Follow [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) sections R.1-R.4 on
the box, unchanged, using the isolated `SEQUOIA_HOME`/`CAPAUTH_HOME` and the
labelled throwaway root. The load-bearing offline steps (abbreviated; the ceremony
doc is authoritative):

```sh
export SEQUOIA_HOME=$(mktemp -d)/rehearsal-sq
cd "$(mktemp -d)"

# throwaway classical v6 root (stands in for the live classical root)
sq key generate --own-key \
  --name "REHEARSAL THROWAWAY - DO NOT TRUST" --email rehearsal@example.invalid \
  --cipher-suite cv25519 --profile rfc9580 --without-password \
  --output rehearsal-root.pgp --rev-cert rehearsal-root-rev.pgp
sq inspect rehearsal-root.pgp                        # note the throwaway fingerprint

# ADDITIVE: ML-DSA-87+Ed448 signing subkey; primary fingerprint UNCHANGED
sq key subkey add --cert-file rehearsal-root.pgp --can-sign \
  --cipher-suite mldsa87-ed448 --without-password --output rehearsal-root+sig.pgp
sq inspect rehearsal-root+sig.pgp                    # confirm primary fpr identical

# FULL ROTATION: new hybrid PQC primary + cross-sign (OLD certifies NEW)
sq key generate --own-key \
  --name "REHEARSAL THROWAWAY v2 - DO NOT TRUST" --email rehearsal@example.invalid \
  --cipher-suite mldsa87-ed448 --profile rfc9580 --without-password \
  --output rehearsal-v2.pgp --rev-cert rehearsal-v2-rev.pgp
sq key delete --cert-file rehearsal-root.pgp --output rehearsal-root.cert
sq key delete --cert-file rehearsal-v2.pgp   --output rehearsal-v2.cert
sq pki vouch add --certifier-file rehearsal-root.pgp \
  --cert-file rehearsal-v2.cert --email rehearsal@example.invalid \
  --output rehearsal-v2.by-old                       # OLD certifies NEW (continuity link)
```

Then the authenticate + tamper checks (Phase 3.2 / 3.4) and a rehearsal
revocation (`sq key revoke ... --reason superseded`). **Simulate the sneakernet
too:** write `rehearsal-v2.cert` and `rehearsal-v2.by-old` to `CEREMONY-OUT`,
carry them off, and verify them on the staging box. That proves the full
in-and-out media round-trip, not just the crypto.

Tear down (R.4):

```sh
rm -rf "$SEQUOIA_HOME"; unset SEQUOIA_HOME
# remove the scratch working dir and every rehearsal-*.pgp / .cert produced above
```

**A clean run (4.1 network-down confirmed, 4.2 R.0 ALL PASS offline, 4.3 walked by
hand + media round-trip) is the proof that this air-gapped box can host the real,
Chef-driven ceremony.** Nothing from a rehearsal is ever published, imported into
a canonical store, or trusted.

### 4.4 Graduating to the live ceremony (Chef only)

> ### ⛔ STOP - REQUIRES CHEF
> Only after 4.1-4.3 pass does the real ceremony happen, and only with Chef
> driving it on this box. The live event follows
> [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) Phase 0-3 in order:
> Chef brings the root working copy in on `CEREMONY-IN` (from offline custody, not
> from any network), performs the additive/rotation/cross-sign steps here, and
> carries **only public** certs/signatures/cross-sigs/rev-certs out on
> `CEREMONY-OUT`. The root private key never leaves the box over anything but the
> same offline-custody media it arrived on. Import/publish of the results into the
> live fleet happens **later, on networked nodes**, never by connecting this box.

---

## 5. Hygiene: media, wipe, custody, re-connection prohibition

### 5.1 Custody

- The box lives in Chef's physical custody (locked storage between ceremonies).
  Full-disk encryption is on; the box is powered off, not merely locked, when not
  in use.
- The labelled `-IN` / `-OUT` / `TOOLCHAIN` sticks are custodied with the box and
  logged: which stick carried what, when, in which direction.
- Any working copy of root key material that transits the box during a live
  ceremony is Chef's Track-A offline custody material
  ([ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) Phase 0); it is returned
  to that custody and wiped from the box afterward.

### 5.2 Wipe

- **Before each use**, wipe the removable media so nothing stale crosses. For
  bulk data on a stick: repartition + fresh filesystem, or a full overwrite pass;
  for individual sensitive files use a shred-style overwrite. On flash media,
  wear-levelling means overwrite is best-effort, so treat any stick that has
  carried sensitive material as sensitive for its whole life (do not later reuse a
  `CEREMONY` stick as a casual data stick).
- **After a live ceremony**, destroy the on-box working tree (the
  `SEQUOIA_HOME`/`ceremony-YYYYMMDD` directory) exactly as the ceremony's teardown
  says. The persistent build toolchain (`sq`, `~/pqc-build/target`) may stay; only
  key-bearing working material is destroyed.
- Media that has carried root **private** key material and is being retired is
  physically destroyed, not just wiped.

### 5.3 Re-connection prohibition (non-negotiable)

- **This box is never connected to any network again once it is designated the
  signing workstation.** Not for updates, not "just to grab one package", not to
  sync a clock. All future inputs arrive via the verified sneakernet (section 3).
- If the box is **ever** connected to a network, even briefly, it is
  **decommissioned as a signing workstation**: treat any key material that was on
  it as potentially exposed, follow the compromise path in
  [COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md) Part C.1
  (revoke + rotate), and rebuild a fresh air-gapped box from scratch. There is no
  "clean it up and keep using it" option.
- Toolchain updates (a newer `sq`, a security fix) are delivered by re-running
  section 2 (build/verify a new bundle on the staging box, sneakernet it in),
  never by connecting the box.

---

## 6. Quick reference

```
# prove offline
ip route ; ping -c1 -W1 1.1.1.1 || echo "no network - GOOD"

# build sq offline from the vendored bundle (Path A)
export CARGO_NET_OFFLINE=true CARGO_HOME="$PWD/dot-cargo"
bash build-sq.sh
sq version                                # expect 1.4.0-pqc.1 / sequoia-openpgp 2.2.0-pqc.1

# verify anything that crossed the sneakernet
sha256sum -c <bundle>.sha256              # must be OK
sq verify --signer-file <trusted>.cert --signature-file <b>.sig <b>

# prove the whole ceremony offline (throwaway, agent-safe)
python pqc_ceremony_dryrun.py             # expect RESULT: ALL PASS, exit 0
```

**Remember:** the live root is **still classical**; every live-root line is gated
behind **⛔ STOP - REQUIRES CHEF**; this box never touches a network; and only
**public** material ever leaves it. Additive first, reversible always, nothing
automated. See [ROOT_ROTATION_CEREMONY.md](ROOT_ROTATION_CEREMONY.md) and
[COLD_MACHINE_BOOTSTRAP_AND_DR.md](COLD_MACHINE_BOOTSTRAP_AND_DR.md).
