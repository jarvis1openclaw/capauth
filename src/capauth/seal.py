"""
capauth.seal — the SEAL primitive: gpg-agent encryption-at-rest for sovereign secrets.

This is CapAuth's canonical seal/unseal layer, lifted (behavior-preserving) from
skingest's `crypto.py`. CapAuth owns SEAL; skvault owns the VAULT (and uses this
module); skingest is pure ingestion (and uses this module).

Sovereignty model:
  • Your keys (gpg keyring on your own machine), your infra, your memory. No corporate
    cloud, no third-party KMS.
  • Asymmetric: seal to a recipient's PUBLIC key; only the matching PRIVATE key (held by
    you) unseals. An agent can write sacred content it cannot read back without you
    present.

gpg-agent semantics (UNCHANGED):
  • `seal()` armors to ALL recipients and optionally signs for provenance.
  • `unseal()` uses `--pinentry-mode cancel`: it decrypts ONLY from the gpg-agent cache
    (vault unlocked) and returns None when locked. It NEVER pops a pinentry or blocks — so
    locked == sealed, deterministic in headless contexts (Hermes/cron/search).

Trust model (HARDENED — card 0f1f218d):
  Recipients are resolved to a FULL FINGERPRINT before sealing, and the encryption is
  pinned to that fingerprint (the exact-key `<FPR>!` selector). This closes the keyring
  substitution gap that `--trust-model always` + a bare uid left open:
    • A recipient configured as a full fingerprint (40 hex / v4, or 64 hex / v6) MUST be
      present in the keyring verbatim; a same-uid key swapped in under a DIFFERENT
      fingerprint no longer matches, so seal() fails closed rather than silently
      redirecting sacred content to the attacker's key.
    • A recipient configured as a uid/email is resolved to its fingerprint, and an
      AMBIGUOUS uid (two distinct primary keys carrying the same uid) is rejected rather
      than letting gpg pick one arbitrarily.
  Residual assumption: for uid-configured recipients we still trust that the keyring's
  single matching key is the intended one (TOFU). Pin by full fingerprint to remove that
  assumption entirely — this module prefers and rewards fingerprint pinning.

Provenance (HARDENED — card 0f1f218d):
  • The encrypt-only fallback (signer key locked/absent) is NO LONGER silent. It always
    logs loudly + emits a runtime warning, and callers can forbid it with
    `allow_unsigned=False` (seal then fails closed instead of dropping provenance).
  • `seal_meta()` returns a `SealResult` so callers can detect whether the seal is signed,
    by which fingerprint, and to which recipient fingerprints.
  • `unseal_verify()` decrypts AND verifies the seal's signature (still headless-
    deterministic), exposing the signer fingerprint/uid and validity. Revoked/expired
    signer keys are reported as invalid; `require_good_signature=True` fails closed.

Config (env, behavior-preserving):
  CAPAUTH_PGP_RECIPIENT  — comma-separated key ids / fingerprints / uid emails to seal to.
                           Falls back to SKINGEST_PGP_RECIPIENT (the live vault's var)
                           so existing deployments keep working unchanged.
                           PREFER full fingerprints here for substitution resistance.
  CAPAUTH_PGP_SIGNER     — signer uid for provenance (default: lumina@skworld.io).
                           Falls back to SKINGEST_PGP_SIGNER. Set empty to disable signing.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import warnings
from dataclasses import dataclass, field

CIPHER_PREFIX = "-----BEGIN PGP MESSAGE-----"

_DEFAULT_SIGNER = "lumina@skworld.io"

logger = logging.getLogger("capauth.seal")


class SealTrustError(RuntimeError):
    """Recipient resolution failed closed: ambiguous uid, missing pinned key, or no key.

    Raised instead of silently sealing to the wrong (or an attacker-substituted) key.
    Subclasses RuntimeError so existing callers that only catch RuntimeError keep working.
    """


class ProvenanceError(RuntimeError):
    """Signing was requested but failed, and the unsigned fallback was forbidden.

    Raised (instead of silently dropping the signature) when `allow_unsigned=False`.
    """


@dataclass
class SealResult:
    """Structured result of a seal operation, so callers can audit provenance."""

    ciphertext: str
    signed: bool
    signer_fpr: str | None = None
    recipient_fprs: list[str] = field(default_factory=list)


@dataclass
class UnsealResult:
    """Structured result of a verify-enabled unseal.

    `plaintext` is None when the vault is locked (headless == sealed) or decrypt failed.
    `valid` is True only when a signature is present AND good AND the signer key is
    neither revoked nor expired.
    """

    plaintext: str | None
    signed: bool = False
    valid: bool = False
    signer_fpr: str | None = None
    signer_uid: str | None = None
    revoked: bool = False
    expired: bool = False


def _env(name: str, legacy: str, default: str = "") -> str:
    """Read CAPAUTH_* first, then fall back to the legacy SKINGEST_* var."""
    val = os.environ.get(name)
    if val is None:
        val = os.environ.get(legacy)
    return default if val is None else val


def gpg_available() -> bool:
    """True if the `gpg` binary is on PATH."""
    return shutil.which("gpg") is not None


def recipients() -> list[str]:
    """Configured seal recipients (CAPAUTH_PGP_RECIPIENT, falling back to SKINGEST_*)."""
    raw = _env("CAPAUTH_PGP_RECIPIENT", "SKINGEST_PGP_RECIPIENT", "")
    return [r.strip() for r in raw.split(",") if r.strip()]


def _signer() -> str:
    """Configured signer uid (CAPAUTH_PGP_SIGNER, falling back to SKINGEST_*)."""
    return _env("CAPAUTH_PGP_SIGNER", "SKINGEST_PGP_SIGNER", _DEFAULT_SIGNER)


def _normalize_fpr(text: str) -> str | None:
    """Return the canonical uppercase hex fingerprint if `text` IS one, else None.

    Accepts optional `0x` prefix and embedded spaces (as `gpg --fingerprint` prints them).
    A fingerprint is 40 hex chars (v4) or 64 hex chars (v6).
    """
    s = text.strip().replace(" ", "")
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) in (40, 64) and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.upper()
    return None


def _list_primary_fprs(selector: str) -> list[str]:
    """Full primary-key fingerprints of every key matching `selector` in the keyring.

    Uses `--with-colons` so parsing is stable. Each `pub` record starts a key block; the
    following `fpr` record carries that key's full fingerprint. Returns one fingerprint
    per matching primary key (so a uid shared by two keys yields two fingerprints).
    """
    if not gpg_available():
        return []
    r = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-keys", selector],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return []
    fprs: list[str] = []
    in_pub = False
    for line in r.stdout.splitlines():
        parts = line.split(":")
        rec = parts[0]
        if rec == "pub":
            in_pub = True
        elif rec == "fpr" and in_pub:
            fprs.append(parts[9])
            in_pub = False  # only take the primary key's fingerprint, not subkeys
    return fprs


def resolve_recipient(recipient: str) -> str:
    """Resolve one configured recipient to a pinned full fingerprint (fail-closed).

    • If `recipient` is itself a full fingerprint, it MUST be present in the keyring
      verbatim (a substituted same-uid key under a different fingerprint won't match) —
      otherwise SealTrustError.
    • If it's a uid/email/short id, it is resolved to a fingerprint; an AMBIGUOUS uid
      (two distinct primary keys) is rejected rather than silently picking one.

    Returns the uppercase 40/64-hex fingerprint to seal to.
    """
    pinned = _normalize_fpr(recipient)
    found = {f.upper() for f in _list_primary_fprs(recipient)}
    if pinned is not None:
        # Fingerprint pinning: require that exact key. Match on suffix so a full v4
        # fingerprint still resolves a key looked up by that same fingerprint.
        for f in found:
            if f == pinned or f.endswith(pinned) or pinned.endswith(f):
                return f
        raise SealTrustError(
            f"pinned recipient fingerprint not in keyring (substitution or missing key): "
            f"{recipient}"
        )
    if not found:
        raise SealTrustError(f"no public key in keyring for recipient: {recipient}")
    if len(found) > 1:
        raise SealTrustError(
            f"ambiguous recipient '{recipient}' matches {len(found)} distinct keys "
            f"({', '.join(sorted(found))}); pin by full fingerprint to disambiguate"
        )
    return next(iter(found))


def resolve_recipients(rcpts: list[str]) -> list[str]:
    """Resolve every configured recipient to a pinned fingerprint (fail-closed)."""
    return [resolve_recipient(r) for r in rcpts]


def have_recipient_key() -> bool:
    """True if a public key for EVERY configured recipient resolves cleanly.

    Now backed by the hardened resolver, so an ambiguous uid or a substituted/missing
    pinned key reports False rather than a false-positive True.
    """
    if not (gpg_available() and recipients()):
        return False
    try:
        resolve_recipients(recipients())
    except SealTrustError:
        return False
    return True


def _signer_fpr(signer: str) -> str | None:
    """Full fingerprint of the signer's SECRET key, or None if absent."""
    if not (signer and gpg_available()):
        return None
    r = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys", signer],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if parts[0] == "fpr":
            return parts[9]
    return None


def seal_meta(
    plaintext: str,
    *,
    to: list[str] | None = None,
    sign_by: str | None = None,
    allow_unsigned: bool = True,
) -> SealResult:
    """Seal `plaintext` and return structured provenance metadata.

    Recipients are resolved to pinned fingerprints (fail-closed on ambiguity/substitution).
    If signing is requested but the signer key is locked/absent, the fallback to
    encrypt-only is loudly logged + warned; with `allow_unsigned=False` it raises
    ProvenanceError instead of silently dropping provenance.
    """
    rcpts = to if to is not None else recipients()
    if not rcpts:
        raise RuntimeError("no PGP recipient configured (CAPAUTH_PGP_RECIPIENT)")

    rcpt_fprs = resolve_recipients(rcpts)

    signer = sign_by if sign_by is not None else _signer()
    signer_fpr = _signer_fpr(signer) if signer else None

    # Build the encrypt command. Recipients are pinned to the resolved full PRIMARY
    # fingerprint: gpg selects that key's encryption subkey but cannot substitute a
    # different key for the same uid (a swapped-in key has a different fingerprint and no
    # longer matches). We deliberately do NOT append the exact-key `!` selector — that
    # would force the primary key itself for encryption and break normal subkey selection.
    # --trust-model always is retained ONLY so a validly-pinned but not web-of-trust-signed
    # key is still usable; substitution resistance now comes from fingerprint pinning, not
    # from gpg's trust database.
    cmd = ["gpg", "--batch", "--yes", "--armor", "--trust-model", "always"]
    for f in rcpt_fprs:
        cmd += ["--recipient", f]

    signed = bool(signer)
    if signed:
        cmd += ["--local-user", signer, "--sign"]
    cmd += ["--encrypt"]

    r = subprocess.run(cmd, input=plaintext.encode(), capture_output=True)
    if r.returncode != 0:
        if signed:
            # Signing can fail if the signer key is locked/absent. Do NOT drop provenance
            # silently — this was the write-only-provenance gap in card 0f1f218d.
            stderr = r.stderr.decode()[:200]
            if not allow_unsigned:
                raise ProvenanceError(
                    f"seal signing failed and unsigned fallback disabled "
                    f"(signer={signer!r}): {stderr}"
                )
            logger.warning(
                "seal(): signer %r unavailable (%s); FALLING BACK to encrypt-only — "
                "sealed content will carry NO provenance signature",
                signer,
                stderr,
            )
            warnings.warn(
                f"seal(): provenance dropped — signer {signer!r} locked/absent, "
                f"sealed encrypt-only",
                RuntimeWarning,
                stacklevel=2,
            )
            unsigned = seal_meta(plaintext, to=rcpts, sign_by="", allow_unsigned=allow_unsigned)
            return SealResult(
                ciphertext=unsigned.ciphertext,
                signed=False,
                signer_fpr=None,
                recipient_fprs=rcpt_fprs,
            )
        raise RuntimeError(f"gpg encrypt failed: {r.stderr.decode()[:160]}")

    return SealResult(
        ciphertext=r.stdout.decode(),
        signed=signed,
        signer_fpr=signer_fpr,
        recipient_fprs=rcpt_fprs,
    )


def seal(
    plaintext: str,
    *,
    to: list[str] | None = None,
    sign_by: str | None = None,
    allow_unsigned: bool = True,
) -> str:
    """
    Armored PGP ciphertext, sealed to ALL `to` recipients (any one's private key unseals).
    Optionally signed by `sign_by` for provenance.

    Defaults: recipients = recipients(); signer = CAPAUTH_PGP_SIGNER (or lumina@skworld.io).
    Recipients are resolved to pinned fingerprints and fail closed on ambiguity/substitution.
    If signing fails (signer key locked/absent) the encrypt-only fallback is loudly
    logged/warned (no longer silent); pass `allow_unsigned=False` to fail closed instead.

    Returns the armored ciphertext string (backward-compatible). Use `seal_meta()` for the
    structured provenance result.
    """
    return seal_meta(plaintext, to=to, sign_by=sign_by, allow_unsigned=allow_unsigned).ciphertext


def unseal(ciphertext: str) -> str | None:
    """
    Unseal armored PGP using the cached private key. Uses --pinentry-mode cancel:
    decrypts ONLY from the gpg-agent cache (vault unlocked) and returns None when
    locked — it NEVER pops a pinentry / blocks. Non-ciphertext is passed through
    unchanged. This makes the seal deterministic in headless contexts: locked == sealed.

    NOTE: this does NOT verify the seal's signature. Use `unseal_verify()` when you need
    to authenticate the sealer's provenance.
    """
    if not ciphertext.startswith(CIPHER_PREFIX):
        return ciphertext  # not encrypted — passthrough
    r = subprocess.run(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "cancel", "--decrypt"],
        input=ciphertext.encode(),
        capture_output=True,
    )
    if r.returncode != 0:
        return None
    return r.stdout.decode()


def unseal_verify(
    ciphertext: str,
    *,
    require_good_signature: bool = False,
) -> UnsealResult:
    """
    Unseal AND verify the seal's signature, exposing the signer's provenance.

    Preserves headless determinism: uses --pinentry-mode cancel, so a locked vault yields
    UnsealResult(plaintext=None, ...) and NEVER blocks on pinentry.

    Signature verification is read from gpg's --status-fd stream:
      • VALIDSIG           → good signature; carries the signer's primary-key fingerprint
      • GOODSIG            → carries the signer uid
      • REVKEYSIG/EXPKEYSIG → signer key revoked/expired ⇒ valid=False (fail-closed)
      • BADSIG             → tampered ⇒ valid=False

    `valid` is True only when a signature is present, good, and the signer key is neither
    revoked nor expired. With `require_good_signature=True`, a decrypt that succeeds (vault
    unlocked) but whose signature is missing/invalid raises VerificationError — provenance
    is then mandatory. A LOCKED vault still returns plaintext=None (never raises), so
    headless callers keep their deterministic locked==sealed contract.
    """
    if not ciphertext.startswith(CIPHER_PREFIX):
        return UnsealResult(plaintext=ciphertext)  # passthrough, unsigned

    # Capture gpg's status stream on a dedicated fd (temp file to avoid pipe deadlock).
    import tempfile

    with tempfile.TemporaryFile() as statusf:
        r = subprocess.run(
            [
                "gpg",
                "--batch",
                "--quiet",
                "--status-fd",
                str(statusf.fileno()),
                "--pinentry-mode",
                "cancel",
                "--decrypt",
            ],
            input=ciphertext.encode(),
            capture_output=True,
            pass_fds=(statusf.fileno(),),
        )
        statusf.seek(0)
        status = statusf.read().decode(errors="replace")

    if r.returncode != 0:
        # Locked vault or decrypt failure — headless deterministic: sealed.
        return UnsealResult(plaintext=None)

    signed = False
    valid = False
    revoked = False
    expired = False
    signer_fpr: str | None = None
    signer_uid: str | None = None

    for line in status.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line[len("[GNUPG:] ") :].split()
        if not parts:
            continue
        tag = parts[0]
        if tag == "VALIDSIG":
            signed = True
            valid = True
            # VALIDSIG <sig-key-fpr> ... <primary-key-fpr>; prefer the primary fpr.
            signer_fpr = parts[-1] if len(parts) >= 11 else parts[1]
        elif tag == "GOODSIG":
            signed = True
            if len(parts) >= 3:
                signer_uid = " ".join(parts[2:])
        elif tag == "REVKEYSIG":
            signed = True
            valid = False
            revoked = True
            if len(parts) >= 3:
                signer_uid = " ".join(parts[2:])
        elif tag == "EXPKEYSIG":
            signed = True
            valid = False
            expired = True
            if len(parts) >= 3:
                signer_uid = " ".join(parts[2:])
        elif tag == "BADSIG":
            signed = True
            valid = False
            if len(parts) >= 3:
                signer_uid = " ".join(parts[2:])

    if revoked or expired:
        valid = False

    if require_good_signature and not valid:
        from capauth.exceptions import VerificationError

        raise VerificationError(
            "unseal_verify: good signature required but "
            + (
                "signer key revoked"
                if revoked
                else "signer key expired"
                if expired
                else "signature missing or invalid"
            )
        )

    return UnsealResult(
        plaintext=r.stdout.decode(),
        signed=signed,
        valid=valid,
        signer_fpr=signer_fpr,
        signer_uid=signer_uid,
        revoked=revoked,
        expired=expired,
    )


def is_ciphertext(text: str) -> bool:
    """True if `text` is PGP armor (starts with the PGP MESSAGE header)."""
    return isinstance(text, str) and text.startswith(CIPHER_PREFIX)


def _has_secret_key(uid: str) -> bool:
    return subprocess.run(["gpg", "--list-secret-keys", uid], capture_output=True).returncode == 0


# --- Deprecated aliases (kept for ONE release; remove after callers migrate) -------------
# Old names from skingest.crypto. `encrypt`/`decrypt` are exact aliases of `seal`/`unseal`.


def encrypt(plaintext: str, to: list[str] | None = None, sign_by: str | None = None) -> str:
    """Deprecated alias for seal(). Will be removed after one release."""
    warnings.warn(
        "capauth.seal.encrypt is deprecated; use capauth.seal.seal",
        DeprecationWarning,
        stacklevel=2,
    )
    return seal(plaintext, to=to, sign_by=sign_by)


def decrypt(ciphertext: str) -> str | None:
    """Deprecated alias for unseal(). Will be removed after one release."""
    warnings.warn(
        "capauth.seal.decrypt is deprecated; use capauth.seal.unseal",
        DeprecationWarning,
        stacklevel=2,
    )
    return unseal(ciphertext)


__all__ = [
    "seal",
    "seal_meta",
    "unseal",
    "unseal_verify",
    "SealResult",
    "UnsealResult",
    "SealTrustError",
    "ProvenanceError",
    "gpg_available",
    "recipients",
    "resolve_recipient",
    "resolve_recipients",
    "have_recipient_key",
    "is_ciphertext",
    "encrypt",  # deprecated alias
    "decrypt",  # deprecated alias
    "CIPHER_PREFIX",
]
