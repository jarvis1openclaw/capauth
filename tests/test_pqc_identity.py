"""Tests for hybrid PQ challenge-response (PQC Q7 / Phase 2) — capauth.

Proves:
  * A hybrid response carries BOTH the classical PGP signature AND a hybrid
    Ed25519 + ML-DSA-65 composite over the same challenge.
  * verify_challenge_hybrid accepts a valid hybrid response (both legs) and a
    classical-only response (either-or transition).
  * A tampered challenge and a forged hybrid leg are rejected.
  * require_hybrid rejects a classical-only response (anti-downgrade).
  * The ROOT PGP key is untouched: the classical path
    (identity.verify_challenge) is byte-for-byte unchanged and still verifies.
"""

from __future__ import annotations

import pytest

from capauth.crypto import get_backend
from capauth.exceptions import VerificationError
from capauth.identity import create_challenge, respond_to_challenge, verify_challenge
from capauth.models import Algorithm

pqsig = pytest.importorskip("skcomms.pqsig")
from capauth import pqc_identity  # noqa: E402

pytestmark = pytest.mark.skipif(not pqsig.is_available(), reason="liboqs (oqs) not available")

PASS_A = "alice-2026"
PASS_B = "bob-2026"


@pytest.fixture(scope="module")
def alice_keys():
    return get_backend().generate_keypair("Alice", "a@capauth.local", PASS_A, Algorithm.ED25519)


@pytest.fixture(scope="module")
def bob_keys():
    return get_backend().generate_keypair("Bob", "b@capauth.local", PASS_B, Algorithm.ED25519)


@pytest.fixture(scope="module")
def bob_hybrid():
    return pqsig.generate_keypair()


def test_hybrid_response_carries_both_legs(alice_keys, bob_keys, bob_hybrid):
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = pqc_identity.respond_to_challenge_hybrid(
        challenge, bob_keys.private_armor, PASS_B, hybrid_keypair=bob_hybrid
    )
    assert resp.sig_suite == "mldsa65-ed25519-v2"
    assert resp.is_hybrid is True
    assert resp.signature  # classical PGP leg still present
    assert resp.hybrid_signature and resp.hybrid_ed25519_pub and resp.hybrid_mldsa_pub


def test_hybrid_roundtrip_verifies(alice_keys, bob_keys, bob_hybrid):
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = pqc_identity.respond_to_challenge_hybrid(
        challenge, bob_keys.private_armor, PASS_B, hybrid_keypair=bob_hybrid
    )
    assert pqc_identity.verify_challenge_hybrid(challenge, resp, bob_keys.public_armor) is True


def test_hybrid_tampered_challenge_rejected(alice_keys, bob_keys, bob_hybrid):
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = pqc_identity.respond_to_challenge_hybrid(
        challenge, bob_keys.private_armor, PASS_B, hybrid_keypair=bob_hybrid
    )
    resp.challenge_hex = resp.challenge_hex[:-2] + (
        "00" if resp.challenge_hex[-2:] != "00" else "11"
    )
    with pytest.raises(VerificationError):
        pqc_identity.verify_challenge_hybrid(challenge, resp, bob_keys.public_armor)


def test_hybrid_forged_pq_leg_rejected(alice_keys, bob_keys, bob_hybrid):
    """Swapping in a different ML-DSA pubkey fails the hybrid leg."""
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = pqc_identity.respond_to_challenge_hybrid(
        challenge, bob_keys.private_armor, PASS_B, hybrid_keypair=bob_hybrid
    )
    import base64

    other = pqsig.generate_keypair()
    resp.hybrid_mldsa_pub = base64.b64encode(other.mldsa_pub).decode("ascii")
    assert pqc_identity.verify_challenge_hybrid(challenge, resp, bob_keys.public_armor) is False


def test_classical_response_still_accepted_either_or(alice_keys, bob_keys):
    """A classical-only response verifies via the hybrid verifier (transition)."""
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = respond_to_challenge(challenge, bob_keys.private_armor, PASS_B)
    assert resp.is_hybrid is False
    assert pqc_identity.verify_challenge_hybrid(challenge, resp, bob_keys.public_armor) is True


def test_require_hybrid_rejects_classical(alice_keys, bob_keys):
    """Anti-downgrade: a classical response is rejected when hybrid is required."""
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = respond_to_challenge(challenge, bob_keys.private_armor, PASS_B)
    with pytest.raises(VerificationError):
        pqc_identity.verify_challenge_hybrid(
            challenge, resp, bob_keys.public_armor, require_hybrid=True
        )


def test_root_pgp_path_unchanged(alice_keys, bob_keys):
    """The classical identity.verify_challenge path is untouched (root PGP)."""
    challenge = create_challenge(alice_keys.fingerprint, bob_keys.fingerprint)
    resp = respond_to_challenge(challenge, bob_keys.private_armor, PASS_B)
    # classical default suite, no hybrid fields
    assert resp.sig_suite == "ed25519-v1"
    assert resp.hybrid_signature is None
    assert verify_challenge(challenge, resp, bob_keys.public_armor) is True
