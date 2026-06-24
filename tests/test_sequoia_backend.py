"""Tests for the Sequoia (sq) PQC crypto backend.

The Sequoia backend issues post-quantum OpenPGP signing identities (ML-DSA-87 +
Ed448 composite primary, ML-KEM-1024 + X448 encryption subkey) by shelling out
to the `sq` CLI (sequoia-sq 1.4.0-pqc, crypto-openssl). It is the only backend
that can host a PQC *signing* root — GnuPG's PQC is encryption-only.

These tests require `sq` to be installed (skipped otherwise).
"""

from __future__ import annotations

import pytest

from capauth.crypto.sequoia_backend import SequoiaBackend, SequoiaError
from capauth.models import Algorithm


@pytest.fixture(scope="module")
def backend() -> SequoiaBackend:
    be = SequoiaBackend()
    if not be.available():
        pytest.skip("sq (sequoia-sq pqc) not available on this host")
    return be


def test_generate_keypair_pqc_primary_is_mldsa87(backend: SequoiaBackend) -> None:
    """A PQC keypair has an ML-DSA-87 signing primary + armored key material."""
    bundle = backend.generate_keypair(
        name="Root Test",
        email="root-test@skworld.io",
        passphrase="",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )

    assert bundle.algorithm == Algorithm.HYBRID_ED448_MLDSA87
    assert "BEGIN PGP PRIVATE KEY BLOCK" in bundle.private_armor
    assert "BEGIN PGP PUBLIC KEY BLOCK" in bundle.public_armor
    # v6 (RFC 9580) fingerprints are 64 hex chars.
    assert len(bundle.fingerprint) == 64
    assert all(c in "0123456789ABCDEF" for c in bundle.fingerprint)
    # The primary key's public-key algorithm must be the PQC composite.
    assert "ML-DSA-87" in backend._primary_algo(bundle.public_armor)


def test_sign_then_verify_roundtrips(backend: SequoiaBackend) -> None:
    """A PQC detached signature verifies; a tampered message does not."""
    bundle = backend.generate_keypair(
        name="Sig Test",
        email="sig-test@skworld.io",
        passphrase="",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    data = b"sovereign attestation payload"
    sig = backend.sign(data, bundle.private_armor, "")

    assert "BEGIN PGP SIGNATURE" in sig
    assert backend.verify(data, sig, bundle.public_armor) is True
    # A tampered message must not verify.
    assert backend.verify(b"tampered payload", sig, bundle.public_armor) is False


def test_fingerprint_from_armor_matches_generated(backend: SequoiaBackend) -> None:
    """fingerprint_from_armor agrees with the bundle fingerprint, pub and priv."""
    bundle = backend.generate_keypair(
        name="FP Test",
        email="fp-test@skworld.io",
        passphrase="",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    assert backend.fingerprint_from_armor(bundle.public_armor) == bundle.fingerprint
    assert backend.fingerprint_from_armor(bundle.private_armor) == bundle.fingerprint


def test_sign_with_passphrase_protected_key_roundtrips(
    backend: SequoiaBackend,
) -> None:
    """A passphrase-protected PQC key signs (via the password cache) and verifies.

    The signer key is encrypted with a passphrase (generated through the same
    ``--new-password-file`` path the backend uses). ``sign()`` must unlock it
    non-interactively and produce a signature the public cert verifies.
    """
    passphrase = "c0rrect-horse-battery-staple"
    bundle = backend.generate_keypair(
        name="Protected Sig",
        email="protected@skworld.io",
        passphrase=passphrase,
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    data = b"protected sovereign attestation"
    sig = backend.sign(data, bundle.private_armor, passphrase)

    assert "BEGIN PGP SIGNATURE" in sig
    assert backend.verify(data, sig, bundle.public_armor) is True
    # Tamper still fails even on the protected-key path.
    assert backend.verify(b"tampered", sig, bundle.public_armor) is False


def test_sign_protected_key_wrong_passphrase_raises(
    backend: SequoiaBackend,
) -> None:
    """Signing a protected key with the wrong passphrase raises (never fakes success)."""
    bundle = backend.generate_keypair(
        name="Protected Wrong",
        email="protected-wrong@skworld.io",
        passphrase="the-real-one",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    with pytest.raises(SequoiaError):
        backend.sign(b"payload", bundle.private_armor, "not-the-passphrase")


def test_add_pqc_subkeys_is_additive_and_back_compatible(
    backend: SequoiaBackend,
) -> None:
    """ML-DSA-87 + ML-KEM-1024 subkeys attach to a classical key, reversibly.

    The original classical (cv25519) primary fingerprint is unchanged, the new
    PQC subkeys are present (FIPS 204 signing + FIPS 203 KEM), and the classical
    key still produces a verifiable signature (back-compat preserved).
    """
    passphrase = "classical-root-pw"
    classical = backend.generate_keypair(
        name="Classical Root",
        email="classical@skworld.io",
        passphrase=passphrase,
        algorithm=Algorithm.ED25519,
    )
    # Sanity: the starting key is classical (no PQC algos yet).
    before_algos = backend._subkey_algos(classical.public_armor)
    assert not any("ML-DSA" in a or "ML-KEM" in a for a in before_algos)

    augmented = backend.add_pqc_subkeys(classical.private_armor, passphrase)

    # Original primary fingerprint preserved (additive, not a new identity).
    assert augmented.fingerprint == classical.fingerprint
    assert backend.fingerprint_from_armor(augmented.public_armor) == classical.fingerprint

    # New PQC subkeys present on both private and public material.
    pub_algos = backend._subkey_algos(augmented.public_armor)
    assert any("ML-DSA-87" in a for a in pub_algos), pub_algos
    assert any("ML-KEM-1024" in a for a in pub_algos), pub_algos

    # Classical subkeys still intact (nothing removed → reversible).
    assert any(a.startswith("Ed25519") for a in pub_algos), pub_algos
    assert any(a.startswith("X25519") for a in pub_algos), pub_algos

    # Back-compat: the augmented key still signs + verifies (classical leg).
    data = b"back-compat attestation"
    sig = backend.sign(data, augmented.private_armor, passphrase)
    assert backend.verify(data, sig, augmented.public_armor) is True


def test_factory_returns_sequoia_backend() -> None:
    """get_backend(SEQUOIA) returns a SequoiaBackend instance."""
    from capauth.crypto import get_backend
    from capauth.models import CryptoBackendType

    be = get_backend(CryptoBackendType.SEQUOIA)
    assert isinstance(be, SequoiaBackend)
