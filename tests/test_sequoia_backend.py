"""Tests for the Sequoia (sq) PQC crypto backend.

The Sequoia backend issues post-quantum OpenPGP signing identities (ML-DSA-87 +
Ed448 composite primary, ML-KEM-1024 + X448 encryption subkey) by shelling out
to the `sq` CLI (sequoia-sq 1.4.0-pqc, crypto-openssl). It is the only backend
that can host a PQC *signing* root — GnuPG's PQC is encryption-only.

These tests require `sq` to be installed (skipped otherwise).
"""

from __future__ import annotations

import pytest

from capauth.crypto.sequoia_backend import SequoiaBackend
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


def test_factory_returns_sequoia_backend() -> None:
    """get_backend(SEQUOIA) returns a SequoiaBackend instance."""
    from capauth.crypto import get_backend
    from capauth.models import CryptoBackendType

    be = get_backend(CryptoBackendType.SEQUOIA)
    assert isinstance(be, SequoiaBackend)
