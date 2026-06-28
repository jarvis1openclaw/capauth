"""Tests for the T3 composite root-identity signing path (additive + GATED).

Two classes of test:

* **Gate logic** (no `sq` needed): the gate defaults closed; signing while
  gated raises *before* touching key material; the gate opens only via explicit
  opt-in; the classical default path is untouched.
* **Crypto roundtrip** (needs `sq`, skipped otherwise): with the gate explicitly
  opened, an ML-DSA-87 + Ed448 composite identity attestation signs and verifies,
  and tampering with the message or a payload field fails verification.

Honest framing: the live capauth root stays classical; this proves the gated
*capability* on throwaway keys only. Hybrid = either-leg; never "quantum-proof".
"""

from __future__ import annotations

import pytest

from capauth.models import Algorithm, CryptoBackendType
from capauth.pqc_root_identity import (
    T3_ALGORITHM,
    T3_GATE_ENV,
    T3_SIG_SUITE,
    RootRotationGateError,
    T3IdentityAttestation,
    sign_identity_attestation,
    t3_gate_open,
    t3_status,
    verify_identity_attestation,
)

# ---------------------------------------------------------------------------
# Gate logic — no `sq` required (raises before any key material is touched)
# ---------------------------------------------------------------------------


def test_gate_defaults_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """With nothing set, the gate is closed."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    assert t3_gate_open() is False


def test_sign_while_gated_raises_before_touching_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signing with the gate closed raises RootRotationGateError immediately.

    The bogus key material proves the gate is checked *before* any backend or key
    handling — a closed gate can never mint a composite root attestation.
    """
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    with pytest.raises(RootRotationGateError):
        sign_identity_attestation(
            subject="capauth:test@skworld.io",
            private_key_armor="not-a-real-key",
            passphrase="",
        )


def test_gate_opens_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A truthy env flag opens the gate; a falsey value keeps it closed."""
    monkeypatch.setenv(T3_GATE_ENV, "1")
    assert t3_gate_open() is True
    monkeypatch.setenv(T3_GATE_ENV, "true")
    assert t3_gate_open() is True
    monkeypatch.setenv(T3_GATE_ENV, "0")
    assert t3_gate_open() is False
    monkeypatch.setenv(T3_GATE_ENV, "")
    assert t3_gate_open() is False


def test_explicit_allow_gated_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit allow_gated argument wins over the environment, both ways."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    assert t3_gate_open(allow_gated=True) is True  # opens despite unset env
    monkeypatch.setenv(T3_GATE_ENV, "1")
    assert t3_gate_open(allow_gated=False) is False  # forced closed despite env


def test_status_is_honest_about_classical_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """t3_status names the classical root and the right suite, never overclaims."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    st = t3_status()
    assert st["gate_open"] is False
    assert st["composite_suite"] == T3_SIG_SUITE == "mldsa87-ed448-v2"
    assert st["algorithm"] == T3_ALGORITHM.value
    assert "classical" in str(st["live_root"]).lower()
    assert st["live_root_fingerprint"] == "02BC0EB3CAD31DB691A753C70C5629AB893F9746"
    # Honest claim wording: asserts quantum-RESISTANT, explicitly NOT
    # "quantum-proof", and says the root migration was not performed.
    claim = str(st["claim"]).lower()
    assert "quantum-resistant" in claim
    assert "not quantum-proof" in claim
    assert "not performed" in claim
    assert "FIPS 204" in st["standards"]


def test_classical_default_path_untouched() -> None:
    """Importing/using the T3 gate never changes the classical default backend.

    get_backend() with no argument must still be the pure-Python PGPy (classical)
    backend, and a classical Ed25519 sign/verify roundtrip must still work — the
    T3 path is purely additive.
    """
    from capauth.crypto import get_backend
    from capauth.crypto.pgpy_backend import PGPyBackend

    be = get_backend()  # default
    assert isinstance(be, PGPyBackend)
    assert get_backend(CryptoBackendType.PGPY).__class__ is PGPyBackend

    bundle = be.generate_keypair(
        name="Classical Untouched",
        email="classical-untouched@skworld.io",
        passphrase="",
        algorithm=Algorithm.ED25519,
    )
    data = b"classical path still works"
    sig = be.sign(data, bundle.private_armor, "")
    assert be.verify(data, sig, bundle.public_armor) is True
    assert be.verify(b"tampered", sig, bundle.public_armor) is False


# ---------------------------------------------------------------------------
# Crypto roundtrip — needs `sq` (skipped otherwise)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sq_backend():
    from capauth.crypto.sequoia_backend import SequoiaBackend

    be = SequoiaBackend()
    if not be.available():
        pytest.skip("sq (sequoia-sq pqc) not available on this host")
    return be


@pytest.fixture(scope="module")
def pqc_key(sq_backend):
    """A throwaway ML-DSA-87 + Ed448 keypair (NOT the live root)."""
    return sq_backend.generate_keypair(
        name="T3 Scratch Root",
        email="t3-scratch@skworld.io",
        passphrase="",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )


def test_composite_sign_verify_roundtrip(sq_backend, pqc_key) -> None:
    """Gate opened explicitly → composite sign→verify roundtrips; tamper fails."""
    att = sign_identity_attestation(
        subject="capauth:scratch@skworld.io",
        private_key_armor=pqc_key.private_armor,
        passphrase="",
        statement="sovereign-identity",
        allow_gated=True,  # explicit opt-in (ceremony/test path)
        backend=sq_backend,
    )

    assert isinstance(att, T3IdentityAttestation)
    assert att.suite == T3_SIG_SUITE
    assert "BEGIN PGP SIGNATURE" in att.signature_armor

    # Roundtrip verifies against the public cert.
    assert (
        verify_identity_attestation(att, pqc_key.public_armor, backend=sq_backend)
        is True
    )


def test_tampered_payload_field_fails_verify(sq_backend, pqc_key) -> None:
    """Mutating any signed field changes the canonical payload → verify fails."""
    att = sign_identity_attestation(
        subject="capauth:scratch@skworld.io",
        private_key_armor=pqc_key.private_armor,
        passphrase="",
        allow_gated=True,
        backend=sq_backend,
    )
    # Forge the subject while keeping the original signature.
    forged = T3IdentityAttestation(
        subject="capauth:attacker@skworld.io",
        statement=att.statement,
        issued_at=att.issued_at,
        suite=att.suite,
        signature_armor=att.signature_armor,
    )
    assert (
        verify_identity_attestation(forged, pqc_key.public_armor, backend=sq_backend)
        is False
    )


def test_wrong_key_fails_verify(sq_backend, pqc_key) -> None:
    """A valid attestation does not verify under an unrelated key."""
    other = sq_backend.generate_keypair(
        name="Other Root",
        email="other@skworld.io",
        passphrase="",
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    att = sign_identity_attestation(
        subject="capauth:scratch@skworld.io",
        private_key_armor=pqc_key.private_armor,
        passphrase="",
        allow_gated=True,
        backend=sq_backend,
    )
    assert (
        verify_identity_attestation(att, other.public_armor, backend=sq_backend)
        is False
    )


def test_protected_key_composite_attestation(sq_backend) -> None:
    """A passphrase-protected PQC key mints + verifies a composite attestation."""
    passphrase = "sovereign-scratch-pass"
    protected = sq_backend.generate_keypair(
        name="Protected T3",
        email="protected-t3@skworld.io",
        passphrase=passphrase,
        algorithm=Algorithm.HYBRID_ED448_MLDSA87,
    )
    att = sign_identity_attestation(
        subject="capauth:protected@skworld.io",
        private_key_armor=protected.private_armor,
        passphrase=passphrase,
        allow_gated=True,
        backend=sq_backend,
    )
    assert (
        verify_identity_attestation(att, protected.public_armor, backend=sq_backend)
        is True
    )
