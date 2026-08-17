"""The supported proof-construction helper, round-tripped through the REAL verifier.

Card N10 (``83c1fa2``) made ``proof`` mandatory for ``verified`` enrollment and
``operator_pubkey`` + ``attestation`` mandatory for ``attested``, but shipped no
supported way to BUILD either. ``capauth.pairing.proof`` is that constructor.

Every test here calls the real :func:`capauth.pairing.enroll_device` with real
keys and real signatures. Nothing is mocked, and no verifier is stubbed: a
mocked verifier proves nothing about a verifier, and this whole module exists to
assert that the helper's output satisfies the one that actually runs.

The negative controls are the point. A constructor for a security requirement is
only trustworthy if the requirement still bites everywhere the constructor was
not used correctly, so each of these must STILL be refused by ``enroll_device``:
a proof over the wrong subject, over the wrong fingerprint, signed by a
different key, and no proof at all.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from capauth.crypto import get_backend
from capauth.models import Algorithm
from capauth.pairing import (
    EnrollmentMode,
    PairingError,
    ProofSigningError,
    approve,
    attested_challenge,
    build_attested_proof,
    build_verified_proof,
    enroll_device,
    enrollment_challenge,
    fingerprint_for,
    list_devices,
    verified_challenge,
)

from .conftest import TEST_EMAIL, TEST_NAME, TEST_PASSPHRASE

SUBJECT = "nia@chef.skworld.io"
OTHER_SUBJECT = "mallory@chef.skworld.io"


def _pgp_keypair():
    """A real, fast Ed25519 PGP keypair the caller legitimately holds."""
    return get_backend().generate_keypair(
        TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.ED25519
    )


def _device_keypair() -> tuple[str, ec.EllipticCurvePrivateKey]:
    """A real WebCrypto-shaped ECDSA P-256 device key: ``(b64 DER SPKI, private key)``."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki).decode("ascii"), private_key


# ---------------------------------------------------------------------------
# round trip: the helper's output satisfies enroll_device with no massaging
# ---------------------------------------------------------------------------


def test_verified_proof_round_trips_through_enroll_device(tmp_path):
    """The contract: build -> splat -> VERIFIED enrollment, no caller massaging."""
    bundle = _pgp_keypair()
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=SUBJECT,
    )

    enrollment = enroll_device(
        bundle.public_armor,
        ["skchat.send"],
        mode="verified",
        base_dir=tmp_path,
        subject=SUBJECT,
        **proof,
    )

    assert enrollment.mode is EnrollmentMode.VERIFIED
    assert enrollment.subject == SUBJECT
    assert enrollment.proof == proof.proof

    device = approve(enrollment.enrollment_id, "operator", base_dir=tmp_path)
    assert device.mode is EnrollmentMode.VERIFIED
    assert [d.device_id for d in list_devices(SUBJECT, base_dir=tmp_path)] == [device.device_id]


def test_verified_proof_round_trips_for_an_ecdsa_device_key(tmp_path):
    """The skchat/skcode device-key shape (non-PGP) round-trips identically."""
    pubkey_b64, private_key = _device_keypair()
    proof = build_verified_proof(pubkey_b64, private_key=private_key, subject=SUBJECT)

    enrollment = enroll_device(
        pubkey_b64,
        ["skchat.send"],
        mode="verified",
        base_dir=tmp_path,
        subject=SUBJECT,
        **proof,
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED


def test_verified_proof_accepts_a_pem_encoded_device_private_key(tmp_path):
    """A caller holding its EC key as PEM bytes does not have to load it itself."""
    pubkey_b64, private_key = _device_keypair()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    proof = build_verified_proof(pubkey_b64, private_key=pem, subject=SUBJECT)
    enrollment = enroll_device(
        pubkey_b64, ["skchat.send"], mode="verified", base_dir=tmp_path, subject=SUBJECT, **proof
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED


def test_attested_proof_round_trips_through_enroll_device(tmp_path):
    """An operator vouching for a device it does not hold the private key of."""
    device_pub, _device_priv = _device_keypair()
    operator = _pgp_keypair()

    proof = build_attested_proof(
        device_pub,
        operator_pubkey=operator.public_armor,
        operator_private_key=operator.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=SUBJECT,
    )

    enrollment = enroll_device(
        device_pub,
        ["skchat.prekey"],
        mode="attested",
        base_dir=tmp_path,
        subject=SUBJECT,
        **proof,
    )
    assert enrollment.mode is EnrollmentMode.ATTESTED
    assert enrollment.operator_pubkey == operator.public_armor
    assert enrollment.attestation == proof.attestation


def test_helper_defaults_subject_to_the_device_fingerprint_like_enroll_device(tmp_path):
    """An EXPLICIT subject on both sides agrees end to end.

    This test used to omit ``subject`` and rely on the builder and
    ``enroll_device`` deriving the same default. That default was removed: two
    individually reasonable defaults (capauth's 40-char fingerprint, skchat's
    16-char device id) produce different signed bytes, and the mismatch is
    invisible until the security boundary rejects it. The subject is now
    required, so the agreement is asserted rather than assumed.
    """
    bundle = _pgp_keypair()
    subject = fingerprint_for(bundle.public_armor)
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        subject=subject,
        passphrase=TEST_PASSPHRASE,
    )

    enrollment = enroll_device(
        bundle.public_armor, ["skchat.inbox"], mode="verified", base_dir=tmp_path, **proof
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED
    assert enrollment.subject == proof.subject


def test_helper_canonicalizes_a_legacy_subject_shape_the_same_way_enroll_device_does(tmp_path):
    """``operator:<fp>`` is challenged as the ``device:<fp>`` it is recorded as."""
    bundle = _pgp_keypair()
    fingerprint = fingerprint_for(bundle.public_armor)
    legacy = f"operator:{fingerprint}"

    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=legacy,
    )
    assert proof.subject == f"device:{fingerprint.lower()}"

    enrollment = enroll_device(
        bundle.public_armor,
        ["skchat.inbox"],
        mode="verified",
        base_dir=tmp_path,
        subject=legacy,
        **proof,
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED
    assert enrollment.subject == proof.subject


# ---------------------------------------------------------------------------
# enrollment_challenge: the public-key-only derivation (no secret involved)
# ---------------------------------------------------------------------------


def test_enrollment_challenge_matches_what_enroll_device_re_derives():
    """The bytes handed to a browser-held key are the ones capauth checks."""
    bundle = _pgp_keypair()
    fingerprint = fingerprint_for(bundle.public_armor)

    assert enrollment_challenge(bundle.public_armor, subject=SUBJECT) == verified_challenge(
        fingerprint, SUBJECT
    )
    assert enrollment_challenge(
        bundle.public_armor, subject=SUBJECT, mode="attested"
    ) == attested_challenge(fingerprint, SUBJECT)


def test_enrollment_challenge_domains_are_separated():
    """An attestation can never be replayed as a device self-proof."""
    bundle = _pgp_keypair()
    verified = enrollment_challenge(bundle.public_armor, subject=SUBJECT, mode="verified")
    attested = enrollment_challenge(bundle.public_armor, subject=SUBJECT, mode="attested")
    assert verified != attested


def test_enrollment_challenge_refuses_tofu_and_unknown_modes():
    bundle = _pgp_keypair()
    with pytest.raises(ProofSigningError):
        enrollment_challenge(bundle.public_armor, subject=SUBJECT, mode="tofu")
    with pytest.raises(PairingError):
        enrollment_challenge(bundle.public_armor, subject=SUBJECT, mode="not-a-mode")


def test_a_client_signed_challenge_enrolls_verified(tmp_path):
    """The browser case: capauth derives the bytes, the client signs them."""
    pubkey_b64, private_key = _device_keypair()
    challenge = enrollment_challenge(pubkey_b64, subject=SUBJECT)

    from cryptography.hazmat.primitives import hashes

    signature = base64.b64encode(private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))).decode(
        "ascii"
    )

    enrollment = enroll_device(
        pubkey_b64,
        ["skchat.send"],
        mode="verified",
        base_dir=tmp_path,
        subject=SUBJECT,
        proof=signature,
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED


# ---------------------------------------------------------------------------
# NEGATIVE CONTROLS: the requirement still bites. These are the load-bearing
# tests -- the helper must be a constructor, not a hole.
# ---------------------------------------------------------------------------


def test_a_proof_over_the_WRONG_SUBJECT_is_rejected(tmp_path):
    """Signed correctly, for the wrong identity: still refused."""
    bundle = _pgp_keypair()
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=OTHER_SUBJECT,
    )

    with pytest.raises(PairingError, match="verified enrollment requires 'proof'"):
        enroll_device(
            bundle.public_armor,
            ["skchat.send"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,  # NOT the subject the proof is bound to
            **proof,
        )
    assert list_devices(base_dir=tmp_path) == []


def test_a_proof_over_the_WRONG_FINGERPRINT_is_rejected(tmp_path):
    """A real signature over another key's fingerprint proves nothing about this one."""
    presented = _pgp_keypair()
    other = _pgp_keypair()

    # Sign the challenge for OTHER's fingerprint, using PRESENTED's private key,
    # so the signature itself is valid for the key being enrolled: only the
    # fingerprint binding is wrong.
    challenge = verified_challenge(fingerprint_for(other.public_armor), SUBJECT)
    forged = get_backend().sign(challenge, presented.private_armor, TEST_PASSPHRASE)

    with pytest.raises(PairingError, match="verified enrollment requires 'proof'"):
        enroll_device(
            presented.public_armor,
            ["skchat.send"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=forged,
        )
    assert list_devices(base_dir=tmp_path) == []


def test_a_proof_signed_by_a_DIFFERENT_KEY_is_rejected(tmp_path):
    """The signature is the proof: another key's signature is not this key's."""
    presented = _pgp_keypair()
    attacker = _pgp_keypair()

    challenge = verified_challenge(fingerprint_for(presented.public_armor), SUBJECT)
    forged = get_backend().sign(challenge, attacker.private_armor, TEST_PASSPHRASE)

    with pytest.raises(PairingError, match="verified enrollment requires 'proof'"):
        enroll_device(
            presented.public_armor,
            ["skchat.send"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=forged,
        )
    assert list_devices(base_dir=tmp_path) == []


@pytest.mark.parametrize("absent", [None, "", "   "])
def test_an_ABSENT_OR_EMPTY_proof_is_rejected(tmp_path, absent):
    bundle = _pgp_keypair()
    with pytest.raises(PairingError, match="verified enrollment requires 'proof'"):
        enroll_device(
            bundle.public_armor,
            ["skchat.send"],
            mode="verified",
            base_dir=tmp_path,
            subject=SUBJECT,
            proof=absent,
        )
    assert list_devices(base_dir=tmp_path) == []


def test_an_attestation_signed_by_a_DIFFERENT_OPERATOR_KEY_is_rejected(tmp_path):
    device_pub, _ = _device_keypair()
    claimed_operator = _pgp_keypair()
    actual_signer = _pgp_keypair()

    challenge = attested_challenge(fingerprint_for(device_pub), SUBJECT)
    forged = get_backend().sign(challenge, actual_signer.private_armor, TEST_PASSPHRASE)

    with pytest.raises(PairingError, match="attested enrollment requires"):
        enroll_device(
            device_pub,
            ["skchat.prekey"],
            mode="attested",
            base_dir=tmp_path,
            subject=SUBJECT,
            operator_pubkey=claimed_operator.public_armor,
            attestation=forged,
        )
    assert list_devices(base_dir=tmp_path) == []


def test_a_verified_proof_cannot_be_replayed_as_an_attestation(tmp_path):
    """Domain separation, end to end through the real enroll_device."""
    bundle = _pgp_keypair()
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=SUBJECT,
    )

    with pytest.raises(PairingError, match="attested enrollment requires"):
        enroll_device(
            bundle.public_armor,
            ["skchat.prekey"],
            mode="attested",
            base_dir=tmp_path,
            subject=SUBJECT,
            operator_pubkey=bundle.public_armor,
            attestation=proof.proof,
        )


# ---------------------------------------------------------------------------
# the helper RAISES rather than returning an unsigned/empty proof
# ---------------------------------------------------------------------------


def test_building_with_a_MISMATCHED_private_key_raises_instead_of_returning_a_proof():
    """The self-check against capauth's own verifier catches it at build time."""
    presented = _pgp_keypair()
    attacker = _pgp_keypair()

    with pytest.raises(ProofSigningError, match="does not satisfy capauth's own verifier"):
        build_verified_proof(
            presented.public_armor,
            private_key=attacker.private_armor,
            passphrase=TEST_PASSPHRASE,
            subject=SUBJECT,
        )


def test_building_with_a_WRONG_PASSPHRASE_raises():
    bundle = _pgp_keypair()
    with pytest.raises(ProofSigningError):
        build_verified_proof(
            bundle.public_armor,
            private_key=bundle.private_armor,
            passphrase="not-the-passphrase",
            subject=SUBJECT,
        )


def test_building_with_a_NON_KEY_raises_rather_than_returning_an_empty_proof():
    bundle = _pgp_keypair()
    with pytest.raises(ProofSigningError):
        build_verified_proof(
            bundle.public_armor,
            private_key="not a key at all",
            subject=fingerprint_for(bundle.public_armor),
        )

    pubkey_b64, _ = _device_keypair()
    with pytest.raises(ProofSigningError):
        build_verified_proof(
            pubkey_b64,
            private_key=b"-----BEGIN PRIVATE KEY-----\nnope\n",
            subject=fingerprint_for(pubkey_b64),
        )


def test_a_built_proof_is_never_empty():
    bundle = _pgp_keypair()
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=SUBJECT,
    )
    assert proof.proof
    assert dict(proof) == {"proof": proof.proof}
    assert "operator_pubkey" not in dict(proof)


# --- subject is REQUIRED (regression: two reasonable defaults, different bytes) ---


def test_subject_is_required_on_every_public_builder():
    """A derived default here silently changes the SIGNED BYTES.

    capauth's own default was the full 40-char `fingerprint_for` value. skchat,
    the helper's first caller, derives a 16-char device id. Both defensible in
    isolation. But a proof built with capauth's default, then handed to
    `enroll_device` with skchat's real subject, does not verify: the device signs
    honestly, capauth rejects, and the enrollment lands on the TOFU floor behind
    a success response with nothing raised. That is the exact silent downgrade
    card N10 exists to remove, reintroduced by the convenience meant to close it.

    Caught in review by clawd-43 on 2026-08-17, before any caller shipped it.
    """
    bundle = _pgp_keypair()

    for call in (
        lambda: enrollment_challenge(bundle.public_armor),
        lambda: build_verified_proof(
            bundle.public_armor,
            private_key=bundle.private_armor,
            passphrase=TEST_PASSPHRASE,
        ),
    ):
        with pytest.raises(TypeError, match="subject"):
            call()


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_an_explicitly_blank_subject_raises_rather_than_deriving_one(blank):
    """The signature makes it required; this makes a runtime None fail too.

    A caller can still thread an Optional down from its own config and hand us
    None. Falling back to a derived default there is the failure this module
    must never have.
    """
    bundle = _pgp_keypair()

    with pytest.raises(ProofSigningError, match="subject is required"):
        enrollment_challenge(bundle.public_armor, subject=blank)

    with pytest.raises(ProofSigningError, match="subject is required"):
        build_verified_proof(
            bundle.public_armor,
            private_key=bundle.private_armor,
            subject=blank,
            passphrase=TEST_PASSPHRASE,
        )


def test_two_different_subjects_produce_different_challenges():
    """The property the whole guard exists to protect, asserted directly."""
    bundle = _pgp_keypair()
    full = fingerprint_for(bundle.public_armor)

    assert enrollment_challenge(bundle.public_armor, subject=full) != enrollment_challenge(
        bundle.public_armor, subject=full[:16]
    ), "challenge must bind the subject, or a subject mismatch would go unnoticed"
