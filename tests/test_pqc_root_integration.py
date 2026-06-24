"""End-to-end integration: a post-quantum (Sequoia) root through the capauth stack.

Proves that an ML-DSA-87+Ed448 PQC root works through the real capauth identity
flow — sovereign profile creation (self-signed) and challenge-response — not just
the backend in isolation. Requires `sq` (skipped otherwise).

The live root migration remains gated on Chef; this exercises the *capability* on
throwaway keys in a tmp base dir.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth import identity as identity_mod
from capauth import profile as profile_mod
from capauth.crypto.sequoia_backend import SequoiaBackend
from capauth.models import Algorithm, CryptoBackendType


@pytest.fixture(scope="module")
def _sq() -> None:
    if not SequoiaBackend().available():
        pytest.skip("sq (sequoia-sq pqc) not available on this host")


def _make_pqc_profile(base_dir: Path, passphrase: str = ""):
    return profile_mod.init_profile(
        name="PQC Root",
        email="pqc-root@skworld.io",
        passphrase=passphrase,
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
        backend_type=CryptoBackendType.SEQUOIA,
        base_dir=base_dir,
    )


def test_init_profile_with_pqc_root(_sq, tmp_path: Path) -> None:
    """A PQC sovereign profile is created, self-signed, with a 64-hex fingerprint."""
    prof = _make_pqc_profile(tmp_path)

    assert prof.key_info.algorithm == Algorithm.HYBRID_ED448_MLDSA87
    assert len(prof.key_info.fingerprint) == 64
    assert prof.crypto_backend == CryptoBackendType.SEQUOIA
    assert prof.signature, "profile should be self-signed"
    # Key material was written to disk.
    assert Path(prof.key_info.public_key_path).exists()
    assert Path(prof.key_info.private_key_path).exists()
    assert "BEGIN PGP PUBLIC KEY BLOCK" in Path(prof.key_info.public_key_path).read_text()


def test_pqc_root_challenge_roundtrip(_sq, tmp_path: Path) -> None:
    """A PQC root signs a challenge and the signature verifies (and tamper fails)."""
    prof = _make_pqc_profile(tmp_path)
    fpr = prof.key_info.fingerprint
    pub = Path(prof.key_info.public_key_path).read_text()
    priv = Path(prof.key_info.private_key_path).read_text()

    challenge = identity_mod.create_challenge(from_fingerprint=fpr, to_fingerprint=fpr)
    response = identity_mod.respond_to_challenge(
        challenge, priv, "", backend_type=CryptoBackendType.SEQUOIA
    )
    assert (
        identity_mod.verify_challenge(
            challenge, response, pub, backend_type=CryptoBackendType.SEQUOIA
        )
        is True
    )


def test_pqc_root_protected_challenge_roundtrip(_sq, tmp_path: Path) -> None:
    """The protected-key path works through the stack: a passphrase-protected PQC
    root signs + verifies a challenge."""
    passphrase = "sovereign-test-pass"
    prof = _make_pqc_profile(tmp_path, passphrase=passphrase)
    fpr = prof.key_info.fingerprint
    pub = Path(prof.key_info.public_key_path).read_text()
    priv = Path(prof.key_info.private_key_path).read_text()

    challenge = identity_mod.create_challenge(from_fingerprint=fpr, to_fingerprint=fpr)
    response = identity_mod.respond_to_challenge(
        challenge, priv, passphrase, backend_type=CryptoBackendType.SEQUOIA
    )
    assert (
        identity_mod.verify_challenge(
            challenge, response, pub, backend_type=CryptoBackendType.SEQUOIA
        )
        is True
    )
