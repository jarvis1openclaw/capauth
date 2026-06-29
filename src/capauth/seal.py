"""
capauth.seal — the SEAL primitive: gpg-agent encryption-at-rest for sovereign secrets.

This is CapAuth's canonical seal/unseal layer, lifted verbatim (behavior-preserving)
from skingest's `crypto.py`. CapAuth owns SEAL; skvault owns the VAULT (and uses this
module); skingest is pure ingestion (and uses this module).

Sovereignty model:
  • Your keys (gpg keyring on your own machine), your infra, your memory. No corporate
    cloud, no third-party KMS.
  • Asymmetric: seal to a recipient's PUBLIC key; only the matching PRIVATE key (held by
    you) unseals. An agent can write sacred content it cannot read back without you
    present.

gpg-agent semantics (UNCHANGED from the original):
  • `seal()` (was `encrypt()`) armors to ALL recipients, optionally signs for provenance,
    and falls back to encrypt-only if the signer key is locked/absent.
  • `unseal()` (was `decrypt()`) uses `--pinentry-mode cancel`: it decrypts ONLY from the
    gpg-agent cache (vault unlocked) and returns None when locked. It NEVER pops a pinentry
    or blocks — so locked == sealed, deterministic in headless contexts (Hermes/cron/search).

Config (env, behavior-preserving):
  CAPAUTH_PGP_RECIPIENT  — comma-separated key ids / uid emails to seal to.
                           Falls back to SKINGEST_PGP_RECIPIENT (the live vault's var)
                           so existing deployments keep working unchanged.
  CAPAUTH_PGP_SIGNER     — signer uid for provenance (default: lumina@skworld.io).
                           Falls back to SKINGEST_PGP_SIGNER. Set empty to disable signing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import warnings

CIPHER_PREFIX = "-----BEGIN PGP MESSAGE-----"

_DEFAULT_SIGNER = "lumina@skworld.io"


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


def have_recipient_key() -> bool:
    """True if a public key for EVERY configured recipient is in the keyring."""
    if not (gpg_available() and recipients()):
        return False
    for r in recipients():
        if subprocess.run(["gpg", "--list-keys", r], capture_output=True).returncode != 0:
            return False
    return True


def seal(plaintext: str, *, to: list[str] | None = None, sign_by: str | None = None) -> str:
    """
    Armored PGP ciphertext, sealed to ALL `to` recipients (any one's private key unseals).
    Optionally signed by `sign_by` for provenance.

    Defaults: recipients = recipients(); signer = CAPAUTH_PGP_SIGNER (or lumina@skworld.io).
    If signing fails (signer key locked/absent), retries encrypt-only — behavior preserved.
    """
    rcpts = to or recipients()
    if not rcpts:
        raise RuntimeError("no PGP recipient configured (CAPAUTH_PGP_RECIPIENT)")
    cmd = ["gpg", "--batch", "--yes", "--armor", "--trust-model", "always"]
    for r in rcpts:
        cmd += ["--recipient", r]
    signer = sign_by if sign_by is not None else _signer()
    if signer:
        cmd += ["--local-user", signer, "--sign"]
    cmd += ["--encrypt"]
    r = subprocess.run(cmd, input=plaintext.encode(), capture_output=True)
    if r.returncode != 0:
        # signing can fail if the signer key is locked/absent — retry encrypt-only
        if signer:
            return seal(plaintext, to=rcpts, sign_by="")
        raise RuntimeError(f"gpg encrypt failed: {r.stderr.decode()[:160]}")
    return r.stdout.decode()


def unseal(ciphertext: str) -> str | None:
    """
    Unseal armored PGP using the cached private key. Uses --pinentry-mode cancel:
    decrypts ONLY from the gpg-agent cache (vault unlocked) and returns None when
    locked — it NEVER pops a pinentry / blocks. Non-ciphertext is passed through
    unchanged. This makes the seal deterministic in headless contexts: locked == sealed.
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
    "unseal",
    "gpg_available",
    "recipients",
    "have_recipient_key",
    "is_ciphertext",
    "encrypt",  # deprecated alias
    "decrypt",  # deprecated alias
    "CIPHER_PREFIX",
]
