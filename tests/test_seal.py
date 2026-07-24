"""
test_seal.py — the capauth.seal gpg-agent seal primitive.

SAFETY: every test runs against a THROWAWAY gpg key in a temp GNUPGHOME
(monkeypatched env). NEVER touches the real ~/.config/skmemory key or the
live gpg-agent. The throwaway key has an EMPTY passphrase so it decrypts from
the (per-temp-home) agent cache without a pinentry prompt — modelling the
"vault unlocked" state.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")

TEST_UID = "Seal Throwaway <seal-throwaway@capauth.local>"
TEST_EMAIL = "seal-throwaway@capauth.local"


@pytest.fixture()
def throwaway_gpg(tmp_path, monkeypatch):
    """
    Isolated GNUPGHOME with one no-passphrase key, wired as the seal recipient.
    Yields the recipient email. Tears down its own gpg-agent on exit.
    """
    gnupghome = tmp_path / "gnupg"
    gnupghome.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupghome))
    # Point the seal module's recipient resolution at the throwaway key.
    monkeypatch.setenv("CAPAUTH_PGP_RECIPIENT", TEST_EMAIL)
    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", "")  # no signing in tests
    monkeypatch.delenv("SKINGEST_PGP_RECIPIENT", raising=False)
    monkeypatch.delenv("SKINGEST_PGP_SIGNER", raising=False)

    batch = (
        "%no-protection\n"
        "Key-Type: eddsa\n"
        "Key-Curve: ed25519\n"
        "Subkey-Type: ecdh\n"
        "Subkey-Curve: cv25519\n"
        f"Name-Real: Seal Throwaway\n"
        f"Name-Email: {TEST_EMAIL}\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    r = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--gen-key"],
        input=batch.encode(),
        capture_output=True,
        env={**__import__("os").environ, "GNUPGHOME": str(gnupghome)},
    )
    assert r.returncode == 0, r.stderr.decode()
    yield TEST_EMAIL
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True,
                   env={**__import__("os").environ, "GNUPGHOME": str(gnupghome)})


def test_gpg_available(throwaway_gpg):
    from capauth.seal import gpg_available

    assert gpg_available() is True


def test_recipients_from_env(throwaway_gpg):
    from capauth.seal import recipients

    assert recipients() == [TEST_EMAIL]


def test_have_recipient_key(throwaway_gpg):
    from capauth.seal import have_recipient_key

    assert have_recipient_key() is True


def test_seal_produces_armor(throwaway_gpg):
    from capauth.seal import is_ciphertext, seal

    ct = seal("the queen's sovereign secret")
    assert is_ciphertext(ct)
    assert ct.startswith("-----BEGIN PGP MESSAGE-----")


def test_seal_unseal_roundtrip(throwaway_gpg):
    from capauth.seal import seal, unseal

    plaintext = "if you need one, get two"
    ct = seal(plaintext)
    assert unseal(ct) == plaintext


def test_is_ciphertext_detects_armor(throwaway_gpg):
    from capauth.seal import is_ciphertext

    assert is_ciphertext("-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----") is True
    assert is_ciphertext("plain text") is False
    assert is_ciphertext("") is False
    assert is_ciphertext(None) is False  # type: ignore[arg-type]


def test_unseal_passthrough_non_ciphertext(throwaway_gpg):
    from capauth.seal import unseal

    # Non-ciphertext is returned unchanged (passthrough), matching legacy decrypt().
    assert unseal("not encrypted") == "not encrypted"


def test_unseal_locked_returns_none(throwaway_gpg):
    from capauth.seal import seal, unseal

    ct = seal("sealed while unlocked")
    # Simulate LOCKED vault: remove the secret key entirely so the agent cache
    # cannot satisfy the decrypt; --pinentry-mode cancel => returncode != 0 => None.
    import os

    fp = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys", TEST_EMAIL],
        capture_output=True, text=True, env={**os.environ},
    ).stdout
    fpr = next(l.split(":")[9] for l in fp.splitlines() if l.startswith("fpr"))
    subprocess.run(
        ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
         "--delete-secret-keys", fpr],
        capture_output=True, env={**os.environ},
    )
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True)
    assert unseal(ct) is None


def test_deprecated_aliases(throwaway_gpg):
    """encrypt/decrypt remain as deprecated aliases for one release (warn + still work)."""
    from capauth.seal import decrypt, encrypt, unseal

    with pytest.warns(DeprecationWarning):
        ct = encrypt("legacy name still works")
    assert unseal(ct) == "legacy name still works"

    armored = encrypt.__doc__  # alias exists
    assert armored is not None
    with pytest.warns(DeprecationWarning):
        assert decrypt(ct) == "legacy name still works"


# --- Hardened trust model + provenance (card 0f1f218d) -----------------------------------


def _throwaway_fpr():
    """Full primary fingerprint of the throwaway key currently in GNUPGHOME."""
    import os

    out = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-keys", TEST_EMAIL],
        capture_output=True, text=True, env={**os.environ},
    ).stdout
    return next(l.split(":")[9] for l in out.splitlines() if l.startswith("fpr"))


# --- Trust model: recipient resolution + substitution resistance -------------------------


def test_resolve_recipient_uid_to_fingerprint(throwaway_gpg):
    """A uid resolves to its full primary fingerprint."""
    from capauth.seal import resolve_recipient

    assert resolve_recipient(TEST_EMAIL) == _throwaway_fpr()


def test_seal_pins_to_full_fingerprint(throwaway_gpg, monkeypatch):
    """A recipient configured as a full fingerprint seals + round-trips (trusted accept)."""
    from capauth.seal import resolve_recipient, seal, unseal

    fpr = _throwaway_fpr()
    monkeypatch.setenv("CAPAUTH_PGP_RECIPIENT", fpr)
    assert resolve_recipient(fpr) == fpr
    ct = seal("pinned by fingerprint")
    assert unseal(ct) == "pinned by fingerprint"


def test_pinned_fingerprint_substitution_fails_closed(throwaway_gpg, monkeypatch):
    """A pinned fingerprint NOT in the keyring is rejected (substitution/missing key)."""
    from capauth.seal import SealTrustError, resolve_recipient, seal

    # A syntactically valid but absent v4 fingerprint models a substituted keyring.
    bogus = "DEADBEEF" * 5  # 40 hex chars, not our key
    monkeypatch.setenv("CAPAUTH_PGP_RECIPIENT", bogus)
    with pytest.raises(SealTrustError):
        resolve_recipient(bogus)
    with pytest.raises(SealTrustError):
        seal("must not seal to a substituted key")


def test_ambiguous_uid_rejected(throwaway_gpg, monkeypatch):
    """Two distinct keys sharing a uid make that uid ambiguous → fail closed."""
    import os

    from capauth.seal import SealTrustError, resolve_recipient

    # Generate a SECOND no-passphrase key with the SAME uid/email.
    batch = (
        "%no-protection\n"
        "Key-Type: eddsa\nKey-Curve: ed25519\n"
        "Subkey-Type: ecdh\nSubkey-Curve: cv25519\n"
        "Name-Real: Seal Throwaway\n"
        f"Name-Email: {TEST_EMAIL}\n"
        "Expire-Date: 0\n%commit\n"
    )
    r = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--gen-key"],
        input=batch.encode(), capture_output=True, env={**os.environ},
    )
    assert r.returncode == 0, r.stderr.decode()
    with pytest.raises(SealTrustError):
        resolve_recipient(TEST_EMAIL)


# --- Provenance: encrypt-only fallback signaling -----------------------------------------


def test_fallback_signals_when_signer_absent(throwaway_gpg, monkeypatch):
    """Signer configured but absent → loud warning + signed=False (no silent drop)."""
    from capauth.seal import seal_meta

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", "no-such-signer@capauth.local")
    with pytest.warns(RuntimeWarning):
        res = seal_meta("content that loses provenance")
    assert res.signed is False
    assert res.signer_fpr is None
    assert res.recipient_fprs == [_throwaway_fpr()]


def test_fallback_forbidden_raises(throwaway_gpg, monkeypatch):
    """allow_unsigned=False fails closed instead of dropping provenance."""
    from capauth.seal import ProvenanceError, seal_meta

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", "no-such-signer@capauth.local")
    with pytest.raises(ProvenanceError):
        seal_meta("provenance required", allow_unsigned=False)


def test_seal_meta_reports_signer(throwaway_gpg, monkeypatch):
    """When signing works, seal_meta reports signed=True + the signer fingerprint."""
    from capauth.seal import seal_meta

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", TEST_EMAIL)
    res = seal_meta("signed for provenance")
    assert res.signed is True
    assert res.signer_fpr == _throwaway_fpr()


# --- Provenance: unseal_verify authenticates the sealer ----------------------------------


def test_unseal_verify_good_signature(throwaway_gpg, monkeypatch):
    """A signed seal verifies: valid=True and the signer fingerprint is exposed."""
    from capauth.seal import seal, unseal_verify

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", TEST_EMAIL)
    ct = seal("provenance-carrying secret")
    res = unseal_verify(ct)
    assert res.plaintext == "provenance-carrying secret"
    assert res.signed is True
    assert res.valid is True
    assert res.signer_fpr == _throwaway_fpr()


def test_unseal_verify_unsigned_seal(throwaway_gpg):
    """An unsigned seal decrypts but reports signed=False / valid=False."""
    from capauth.seal import seal, unseal_verify

    ct = seal("no signature here")  # fixture sets signer="" → unsigned
    res = unseal_verify(ct)
    assert res.plaintext == "no signature here"
    assert res.signed is False
    assert res.valid is False
    assert res.signer_fpr is None


def test_unseal_verify_require_good_signature_on_unsigned(throwaway_gpg):
    """require_good_signature fails closed when provenance is absent (vault unlocked)."""
    from capauth.exceptions import VerificationError
    from capauth.seal import seal, unseal_verify

    ct = seal("unsigned but caller demands provenance")
    with pytest.raises(VerificationError):
        unseal_verify(ct, require_good_signature=True)


def test_unseal_verify_tampered_fails_closed(throwaway_gpg, monkeypatch):
    """A tampered signed ciphertext does not yield plaintext (fail closed)."""
    from capauth.seal import seal, unseal_verify

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", TEST_EMAIL)
    ct = seal("tamper target")
    lines = ct.splitlines()
    # Corrupt a byte deep in the armored body (not the header/checksum lines).
    body = len(lines) // 2
    lines[body] = ("A" if lines[body][:1] != "A" else "B") + lines[body][1:]
    tampered = "\n".join(lines) + "\n"
    res = unseal_verify(tampered)
    assert res.plaintext is None
    assert res.valid is False


def test_unseal_verify_locked_returns_none(throwaway_gpg, monkeypatch):
    """Headless determinism: a locked vault yields plaintext=None, never blocks."""
    import os

    from capauth.seal import seal, unseal_verify

    monkeypatch.setenv("CAPAUTH_PGP_SIGNER", TEST_EMAIL)
    ct = seal("sealed while unlocked")
    fpr = _throwaway_fpr()
    subprocess.run(
        ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
         "--delete-secret-keys", fpr],
        capture_output=True, env={**os.environ},
    )
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True)
    res = unseal_verify(ct)
    assert res.plaintext is None
