"""Tests for revoked-key and expired-key rejection on the verify path.

Covers coord card a93b0528: the default PGPy backend must reject
signatures from revoked or expired keys with distinct error types,
and verify_challenge must propagate those errors. GnuPG backend
behavior is asserted behind a skipif (system gpg2 required).

Covers:
  - PGPy: signature from a key with an attached revocation cert fails
  - PGPy: signature from an expired key fails
  - PGPy: signature from a revoked signing subkey fails
  - Distinct exceptions: KeyRevokedError vs KeyExpiredError vs plain False
  - verify_challenge surfaces the distinct errors
  - GnuPG backend rejects revoked/expired keys (skipif no gpg2)
"""

from __future__ import annotations

import shutil
import warnings
from datetime import datetime, timedelta, timezone

import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
    SymmetricKeyAlgorithm,
)

from capauth.crypto.pgpy_backend import PGPyBackend
from capauth.exceptions import KeyExpiredError, KeyRevokedError, VerificationError
from capauth.identity import create_challenge, respond_to_challenge, verify_challenge
from capauth.models import CryptoBackendType

PASSPHRASE = "test-revocation-passphrase-2026"
DATA = b"sovereignty is not negotiable"


def _new_ed25519_key(
    name: str,
    email: str,
    created: datetime | None = None,
    key_expiration: timedelta | None = None,
) -> pgpy.PGPKey:
    """Build a raw PGPy Ed25519 signing key for fixture surgery."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519, created=created)
        uid = pgpy.PGPUID.new(name, email=email)
        kwargs = {}
        if key_expiration is not None:
            kwargs["key_expiration"] = key_expiration
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.Certify},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
            **kwargs,
        )
    return key


def _sign(key: pgpy.PGPKey, data: bytes) -> str:
    """Produce a PGP signed message the way PGPyBackend.sign does."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.new(data, cleartext=False)
        message |= key.sign(message)
    return str(message)


@pytest.fixture(scope="module")
def backend() -> PGPyBackend:
    return PGPyBackend()


@pytest.fixture(scope="module")
def revoked_key() -> dict:
    """A key that signed DATA, then had a revocation cert attached."""
    key = _new_ed25519_key("Revoked Rita", "rita@test.io")
    signature = _sign(key, DATA)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Reason: PGPy caches key.pubkey (same object every access), so
        # the clean armor must be captured BEFORE attaching the
        # revocation signature.
        clean_public_armor = str(key.pubkey)
        detached_signature = str(key.sign(DATA))
        rev_sig = key.revoke(key, sigtype=SignatureType.KeyRevocation)
        pub = key.pubkey
        pub |= rev_sig
    return {
        "private": key,
        "public_armor": str(pub),
        "clean_public_armor": clean_public_armor,
        "detached_signature": detached_signature,
        "signature": signature,
        "fingerprint": str(key.fingerprint).replace(" ", ""),
    }


@pytest.fixture(scope="module")
def expired_key() -> dict:
    """A backdated key whose expiration is already in the past."""
    created = datetime.now(timezone.utc) - timedelta(days=2)
    key = _new_ed25519_key(
        "Expired Eddie",
        "eddie@test.io",
        created=created,
        key_expiration=timedelta(days=1),
    )
    signature = _sign(key, DATA)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        detached_signature = str(key.sign(DATA))
    return {
        "private": key,
        "public_armor": str(key.pubkey),
        "signature": signature,
        "detached_signature": detached_signature,
        "fingerprint": str(key.fingerprint).replace(" ", ""),
    }


class TestPGPyRevokedKey:
    """Revocation certificate attached to the key must fail verification."""

    def test_revoked_key_raises_key_revoked_error(self, backend, revoked_key):
        with pytest.raises(KeyRevokedError):
            backend.verify(DATA, revoked_key["signature"], revoked_key["public_armor"])

    def test_revoked_error_is_a_verification_error(self, backend, revoked_key):
        """Callers catching VerificationError still catch revocation."""
        with pytest.raises(VerificationError):
            backend.verify(DATA, revoked_key["signature"], revoked_key["public_armor"])

    def test_same_key_without_revocation_still_verifies(self, backend, revoked_key):
        """Sanity: only the attached revocation cert flips the outcome."""
        valid = backend.verify(DATA, revoked_key["signature"], revoked_key["clean_public_armor"])
        assert valid is True


class TestPGPyExpiredKey:
    """Expired key material must fail verification."""

    def test_expired_key_raises_key_expired_error(self, backend, expired_key):
        with pytest.raises(KeyExpiredError):
            backend.verify(DATA, expired_key["signature"], expired_key["public_armor"])

    def test_expired_error_is_a_verification_error(self, backend, expired_key):
        with pytest.raises(VerificationError):
            backend.verify(DATA, expired_key["signature"], expired_key["public_armor"])

    def test_expired_error_is_not_revoked_error(self, backend, expired_key):
        """Distinct types: expired must not masquerade as revoked."""
        with pytest.raises(KeyExpiredError) as excinfo:
            backend.verify(DATA, expired_key["signature"], expired_key["public_armor"])
        assert not isinstance(excinfo.value, KeyRevokedError)


class TestPGPyRevokedSigningSubkey:
    """A revoked signing subkey must fail even if the primary is clean."""

    def test_revoked_signing_subkey_rejected(self, backend):
        key = _new_ed25519_key("Subkey Sam", "sam@test.io")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sub = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
            key.add_subkey(sub, usage={KeyFlags.Sign})
            message = pgpy.PGPMessage.new(DATA, cleartext=False)
            message |= sub.sign(message)
            signature = str(message)
            rev_sig = key.revoke(sub, sigtype=SignatureType.SubkeyRevocation)
            pub = key.pubkey
            # Reason: PGPy's `key |= sig` silently drops SubkeyRevocation
            # sigs; attach to the subkey object, as armor parsing does.
            pub.subkeys[str(sub.fingerprint.keyid)] |= rev_sig
        with pytest.raises(KeyRevokedError):
            backend.verify(DATA, signature, str(pub))

    def test_revoked_unrelated_subkey_does_not_block_primary(self, backend):
        """Edge: revoking an encryption subkey must not break primary sigs."""
        key = _new_ed25519_key("Enc Erin", "erin@test.io")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sub = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
            key.add_subkey(sub, usage={KeyFlags.EncryptCommunications})
            signature = _sign(key, DATA)
            rev_sig = key.revoke(sub, sigtype=SignatureType.SubkeyRevocation)
            pub = key.pubkey
            pub.subkeys[str(sub.fingerprint.keyid)] |= rev_sig
        assert backend.verify(DATA, signature, str(pub)) is True


class TestVerifyChallengePropagation:
    """verify_challenge must surface the distinct error types."""

    def _challenge_pair(self, key_info):
        challenge = create_challenge("A" * 40, key_info["fingerprint"])
        private_armor = str(key_info["private"])
        response = respond_to_challenge(
            challenge, private_armor, "", backend_type=CryptoBackendType.PGPY
        )
        return challenge, response

    def test_verify_challenge_raises_revoked(self, revoked_key):
        challenge, response = self._challenge_pair(revoked_key)
        with pytest.raises(KeyRevokedError):
            verify_challenge(challenge, response, revoked_key["public_armor"])

    def test_verify_challenge_raises_expired(self, expired_key):
        challenge, response = self._challenge_pair(expired_key)
        with pytest.raises(KeyExpiredError):
            verify_challenge(challenge, response, expired_key["public_armor"])

    def test_verify_challenge_clean_key_still_passes(self, revoked_key):
        challenge, response = self._challenge_pair(revoked_key)
        assert verify_challenge(challenge, response, revoked_key["clean_public_armor"]) is True


@pytest.mark.skipif(shutil.which("gpg") is None, reason="system gpg2 not available")
class TestGnuPGBackendKeyStatus:
    """GnuPG backend must reject revoked/expired signer keys too."""

    def _gpg_backend(self, tmp_path):
        from capauth.crypto.gnupg_backend import GnuPGBackend

        home = tmp_path / "gnupghome"
        home.mkdir(mode=0o700, exist_ok=True)
        backend = GnuPGBackend(gnupg_home=str(home))
        if not backend.available():
            pytest.skip("python-gnupg or gpg2 unusable on this host")
        return backend

    def test_gnupg_rejects_revoked_key(self, tmp_path, revoked_key):
        """gpg emits REVKEYSIG for a revoked signer; backend raises."""
        backend = self._gpg_backend(tmp_path)
        with pytest.raises(KeyRevokedError):
            backend.verify(DATA, revoked_key["detached_signature"], revoked_key["public_armor"])

    def test_gnupg_rejects_expired_key(self, tmp_path, expired_key):
        """gpg emits EXPKEYSIG for an expired signer; backend raises."""
        backend = self._gpg_backend(tmp_path)
        with pytest.raises(KeyExpiredError):
            backend.verify(DATA, expired_key["detached_signature"], expired_key["public_armor"])

    def test_gnupg_clean_key_still_verifies(self, tmp_path, revoked_key):
        """Sanity: same signature, pre-revocation pubkey, verifies fine."""
        backend = self._gpg_backend(tmp_path)
        valid = backend.verify(
            DATA, revoked_key["detached_signature"], revoked_key["clean_public_armor"]
        )
        assert valid is True
