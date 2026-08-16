"""Tests for the WebCrypto ECDSA device-key proof widening of ``_proof_verifies``.

Sev2 ``inc-c72a9120``: card N10 (83c1fa2) made ``enroll_device(mode="verified")``
require a real ``proof``, but ``_proof_verifies`` only ever accepted a PGP
signature. skchat's operator devices are WebCrypto ECDSA P-256 keys (base64 DER
SPKI, P1363 or DER signature) -- they physically could not produce an
acceptable proof, so every enrollment silently landed with zero capabilities.

This widens the KEY TYPE accepted, not the requirement: ``verified`` still
needs a real, matching signature over the exact
:func:`capauth.pairing.verified_challenge` bytes; ``attested`` is untouched;
``tofu`` is untouched. Every test below uses a real ``cryptography`` P-256
keypair and a real signature -- no mocked verifier -- because a mocked
verifier proves nothing about a verifier.
"""

from __future__ import annotations

import base64

import pytest

from capauth.pairing import (
    EnrollmentMode,
    PairingError,
    enroll_device,
    list_devices,
)
from capauth.pairing.kernel import _proof_verifies, verified_challenge
from capauth.pairing.store import fingerprint_for

from .conftest import enrolled_device_key_credentials, enrolled_verified_credentials

SUBJECT = "nia@chef.skworld.io"


# ---------------------------------------------------------------------------
# happy path: both real-world signature shapes verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sig_encoding", ["p1363", "der"])
def test_enroll_device_accepts_verified_with_a_real_device_key_proof(tmp_path, sig_encoding):
    pubkey, proof = enrolled_device_key_credentials(SUBJECT, sig_encoding=sig_encoding)
    enr = enroll_device(
        pubkey,
        ["skchat.send"],
        mode="verified",
        base_dir=tmp_path,
        subject=SUBJECT,
        proof=proof,
    )
    assert enr.mode == EnrollmentMode.VERIFIED
    assert enr.proof == proof
    devices = list_devices(base_dir=tmp_path, include_revoked=True)
    assert devices == []  # enroll_device only creates the pending Enrollment


# ---------------------------------------------------------------------------
# fingerprint derivation the client must independently reproduce
# ---------------------------------------------------------------------------


def test_device_key_fingerprint_is_sha256_of_the_b64_pubkey_string():
    """Confirms the note in the incident report: for a non-PGP key,
    ``fingerprint_for`` is ``sha256(pubkey_b64_string).hexdigest()[:40].upper()``.
    A client (skchat/Flutter) recomputing the challenge must match this exactly
    or its proof silently fails to verify.
    """
    import hashlib

    pubkey, _proof = enrolled_device_key_credentials(SUBJECT)
    expected = hashlib.sha256(pubkey.encode("utf-8")).hexdigest()[:40].upper()
    assert fingerprint_for(pubkey) == expected


# ---------------------------------------------------------------------------
# fail-closed: wrong bytes, wrong key, malformed key/signature, missing
# ---------------------------------------------------------------------------


def test_enroll_device_refuses_device_key_proof_over_different_bytes(tmp_path):
    """A signature that is real, made by the right key, just over the WRONG
    bytes (not this enrollment's verified_challenge) must not verify."""
    import cryptography.hazmat.primitives.asymmetric.ec as ec
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_b64 = base64.b64encode(spki).decode("ascii")
    wrong_sig = private_key.sign(b"not the challenge", ec.ECDSA(hashes.SHA256()))
    proof_b64 = base64.b64encode(wrong_sig).decode("ascii")

    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pubkey_b64,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=proof_b64,
        )
    assert list_devices(base_dir=tmp_path) == []


def test_enroll_device_refuses_device_key_signed_by_a_different_key(tmp_path):
    """A real signature, over the RIGHT bytes, just made by a DIFFERENT
    device's private key than the presented pubkey -- proves possession of
    someone else's key, not this one's."""
    pubkey, _own_proof = enrolled_device_key_credentials(SUBJECT)
    _other_pubkey, other_key_proof = enrolled_device_key_credentials(SUBJECT)

    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=other_key_proof,
        )


def test_enroll_device_refuses_device_key_proof_bound_to_a_different_subject(tmp_path):
    pubkey, proof_for_someone_else = enrolled_device_key_credentials(
        "someone-else@chef.skworld.io"
    )
    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=proof_for_someone_else,
        )


def test_enroll_device_refuses_garbage_device_pubkey_without_raising(tmp_path):
    """A malformed 'pubkey' (not valid DER, not PGP armor) must fail closed --
    refused with PairingError, never an unhandled parse exception."""
    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            "not-base64-der-and-not-pgp!!!",
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=base64.b64encode(b"whatever").decode("ascii"),
        )
    assert list_devices(base_dir=tmp_path) == []


def test_enroll_device_refuses_garbage_device_proof_without_raising(tmp_path):
    """A real device pubkey, but a proof that is not a parseable signature at
    all -- must fail closed rather than raise."""
    pubkey, _proof = enrolled_device_key_credentials(SUBJECT)
    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof="###not-base64-and-not-a-signature###",
        )


def test_proof_verifies_device_key_rejects_empty_signature_bytes():
    """A zero-length 'signature' (edge of the P1363-vs-DER length branch)
    must not verify and must not raise."""
    pubkey, _proof = enrolled_device_key_credentials(SUBJECT)
    challenge = verified_challenge(fingerprint_for(pubkey), SUBJECT)
    assert _proof_verifies(pubkey, base64.b64encode(b"").decode("ascii"), challenge) is False


# ---------------------------------------------------------------------------
# key-type isolation: a PGP-armored key must never be verified by the ECDSA
# path, and a device key must never be handed to the PGP backend
# ---------------------------------------------------------------------------


def test_enroll_device_refuses_ecdsa_proof_presented_against_a_pgp_pubkey(tmp_path):
    """pubkey is PGP-armored (routes to the PGP backend) but the proof is a
    real ECDSA signature, not a PGP detached signature -- must be refused,
    not accidentally accepted by either verifier."""
    pgp_pubkey, _pgp_proof = enrolled_verified_credentials(SUBJECT)
    _device_pubkey, ecdsa_proof = enrolled_device_key_credentials(SUBJECT)

    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pgp_pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=ecdsa_proof,
        )


def test_enroll_device_refuses_pgp_proof_presented_against_a_device_pubkey(tmp_path):
    """pubkey is a device (ECDSA) key (routes to the ECDSA verifier) but the
    proof is a real PGP-armored detached signature -- must be refused."""
    device_pubkey, _ecdsa_proof = enrolled_device_key_credentials(SUBJECT)
    _pgp_pubkey, pgp_proof = enrolled_verified_credentials(SUBJECT)

    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            device_pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=pgp_proof,
        )


# ---------------------------------------------------------------------------
# existing PGP path: unregressed (still verifies, still rejects a bad sig)
# ---------------------------------------------------------------------------


def test_pgp_path_still_accepts_a_real_matching_proof(tmp_path):
    pubkey, proof = enrolled_verified_credentials(SUBJECT)
    enr = enroll_device(
        pubkey, ["s"], mode="verified", base_dir=tmp_path, subject=SUBJECT, proof=proof
    )
    assert enr.mode == EnrollmentMode.VERIFIED


def test_pgp_path_still_rejects_a_bad_signature(tmp_path):
    pubkey, _proof = enrolled_verified_credentials(SUBJECT)
    with pytest.raises(PairingError, match="verified enrollment requires"):
        enroll_device(
            pubkey,
            ["s"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof="-----BEGIN PGP SIGNATURE-----\nnot-real\n-----END PGP SIGNATURE-----\n",
        )
