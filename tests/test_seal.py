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
