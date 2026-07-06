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

import json
from datetime import datetime

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


# ===========================================================================
# Additional gate-state + attestation edge cases (no `sq` required)
#
# These exercise the gate state machine, the canonical-payload contract, the
# attestation serialisation, and the sign/verify plumbing using an injected
# fake backend — so they run on hosts without the Sequoia `sq` binary and
# never touch the classical root.
# ===========================================================================

from capauth.pqc_root_identity import (  # noqa: E402  (additive section import)
    ROOT_ROTATION_CEREMONY_DOC,
    T3_PAYLOAD_VERSION,
    _canonical_payload,
    _sequoia_backend,
)


class _FakeBackend:
    """Minimal stand-in for SequoiaBackend that records calls.

    Lets the gated sign/verify plumbing be exercised without `sq`: a closed
    gate must never reach ``sign`` here, and an open gate must hand the exact
    canonical payload to the backend.
    """

    def __init__(self, sig: str = "-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END PGP SIGNATURE-----", verify_result: bool = True) -> None:
        self.sig = sig
        self.verify_result = verify_result
        self.sign_calls: list[tuple] = []
        self.verify_calls: list[tuple] = []

    def sign(self, data: bytes, private_key_armor: str, passphrase: str) -> str:
        self.sign_calls.append((data, private_key_armor, passphrase))
        return self.sig

    def verify(self, data: bytes, signature_armor: str, public_key_armor: str) -> bool:
        self.verify_calls.append((data, signature_armor, public_key_armor))
        return self.verify_result


# --- gate-state truthiness edge cases ---------------------------------------


@pytest.mark.parametrize("value", ["yes", "on", "TRUE", "On", " YES ", "  true  ", "\tyes\n"])
def test_gate_open_extra_truthy_and_whitespace(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """All documented truthy spellings open the gate, after strip()+lower()."""
    monkeypatch.setenv(T3_GATE_ENV, value)
    assert t3_gate_open() is True


@pytest.mark.parametrize("value", ["enabled", "2", "y", "t", "off", "no", "false", "  ", "open"])
def test_gate_open_non_truthy_stays_closed(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Values outside the truthy set leave the gate closed (fail-safe default)."""
    monkeypatch.setenv(T3_GATE_ENV, value)
    assert t3_gate_open() is False


def test_gate_open_returns_real_bool_not_truthy_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """allow_gated coerces to an actual bool (so callers can rely on `is`)."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    assert t3_gate_open(allow_gated="anything-truthy") is True
    assert t3_gate_open(allow_gated=0) is False


def test_status_reflects_open_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """t3_status mirrors the live env-driven gate state when it is open."""
    monkeypatch.setenv(T3_GATE_ENV, "1")
    assert t3_status()["gate_open"] is True


# --- canonical payload contract (deterministic, sorted, compact) ------------


def test_canonical_payload_is_deterministic() -> None:
    """Same inputs → byte-identical canonical payload (stable for signing)."""
    a = _canonical_payload(subject="s", statement="hi", issued_at="2026-01-01T00:00:00Z", suite=T3_SIG_SUITE)
    b = _canonical_payload(subject="s", statement="hi", issued_at="2026-01-01T00:00:00Z", suite=T3_SIG_SUITE)
    assert a == b


def test_canonical_payload_structure_sorted_and_compact() -> None:
    """Payload is compact JSON, sorted keys, exactly the 5 bound fields."""
    raw = _canonical_payload(subject="capauth:x@skworld.io", statement="sovereign-identity", issued_at="2026-06-24T00:00:00Z", suite=T3_SIG_SUITE)
    parsed = json.loads(raw)
    assert set(parsed) == {"capauth_t3", "subject", "statement", "issued_at", "suite"}
    assert parsed["capauth_t3"] == T3_PAYLOAD_VERSION
    # Re-encoding with the same canonical options must reproduce the bytes.
    assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # Compact separators → no ", " or key-value ": " spacing artefacts.
    assert b'", "' not in raw
    assert b'": ' not in raw


@pytest.mark.parametrize("field", ["subject", "statement", "issued_at", "suite"])
def test_canonical_payload_each_field_is_bound(field: str) -> None:
    """Changing any one signed field changes the canonical bytes (tamper-evident)."""
    base = dict(subject="s", statement="st", issued_at="2026-01-01T00:00:00Z", suite=T3_SIG_SUITE)
    a = _canonical_payload(**base)
    mutated = dict(base, **{field: base[field] + "-X"})
    assert _canonical_payload(**mutated) != a


# --- attestation object contract --------------------------------------------


def _att(**over) -> T3IdentityAttestation:
    base = dict(
        subject="capauth:scratch@skworld.io",
        statement="sovereign-identity",
        issued_at="2026-06-24T00:00:00Z",
        suite=T3_SIG_SUITE,
        signature_armor="-----BEGIN PGP SIGNATURE-----\nX\n-----END PGP SIGNATURE-----",
    )
    base.update(over)
    return T3IdentityAttestation(**base)


def test_attestation_canonical_payload_matches_helper() -> None:
    """Attestation.canonical_payload() == _canonical_payload over its own fields."""
    att = _att()
    assert att.canonical_payload() == _canonical_payload(
        subject=att.subject, statement=att.statement, issued_at=att.issued_at, suite=att.suite
    )


def test_attestation_to_dict_is_honest_and_complete() -> None:
    """to_dict carries version + algorithm + all bound fields + the signature."""
    att = _att()
    d = att.to_dict()
    assert d["capauth_t3"] == T3_PAYLOAD_VERSION
    assert d["algorithm"] == T3_ALGORITHM.value
    assert d["suite"] == T3_SIG_SUITE
    assert d["subject"] == att.subject
    assert d["statement"] == att.statement
    assert d["issued_at"] == att.issued_at
    assert d["signature"] == att.signature_armor
    assert set(d) == {"capauth_t3", "subject", "statement", "issued_at", "suite", "algorithm", "signature"}


def test_attestation_is_frozen() -> None:
    """The attestation is immutable (frozen dataclass) — no post-hoc field swaps."""
    att = _att()
    with pytest.raises(Exception):
        att.subject = "capauth:attacker@skworld.io"  # type: ignore[misc]


# --- backend selection helper -----------------------------------------------


def test_sequoia_backend_passthrough_skips_discovery() -> None:
    """A supplied backend is returned as-is (no `sq` discovery/import needed)."""
    fake = _FakeBackend()
    assert _sequoia_backend(fake) is fake


def test_sequoia_backend_unavailable_raises_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auto-discovery with no usable `sq` raises a clear BackendError (not a crash)."""
    from capauth.crypto import sequoia_backend as sb
    from capauth.exceptions import BackendError

    monkeypatch.setattr(sb.SequoiaBackend, "available", lambda self: False)
    with pytest.raises(BackendError) as ei:
        _sequoia_backend(None)
    assert "Sequoia" in str(ei.value) or "sq" in str(ei.value)


def test_verify_surfaces_backend_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_identity_attestation with no backend + no `sq` raises BackendError."""
    from capauth.crypto import sequoia_backend as sb
    from capauth.exceptions import BackendError

    monkeypatch.setattr(sb.SequoiaBackend, "available", lambda self: False)
    with pytest.raises(BackendError):
        verify_identity_attestation(_att(), "PUBCERT")


# --- sign plumbing via injected backend (gate open, no sq) ------------------


def test_sign_with_open_gate_uses_canonical_payload_and_suite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Open gate → backend.sign receives the exact canonical payload; suite bound."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    fake = _FakeBackend()
    att = sign_identity_attestation(
        subject="capauth:scratch@skworld.io",
        private_key_armor="PRIV",
        passphrase="pw",
        statement="sovereign-identity",
        issued_at="2026-06-24T12:00:00Z",
        allow_gated=True,
        backend=fake,
    )
    assert att.suite == T3_SIG_SUITE
    assert att.issued_at == "2026-06-24T12:00:00Z"
    assert att.signature_armor == fake.sig
    # Exactly one sign call, over the canonical payload, with the passphrase.
    assert len(fake.sign_calls) == 1
    signed_bytes, priv, pw = fake.sign_calls[0]
    assert priv == "PRIV"
    assert pw == "pw"
    assert signed_bytes == _canonical_payload(
        subject="capauth:scratch@skworld.io",
        statement="sovereign-identity",
        issued_at="2026-06-24T12:00:00Z",
        suite=T3_SIG_SUITE,
    )


def test_sign_generates_rfc3339_z_timestamp_when_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When issued_at is None a Zulu RFC-3339 timestamp is generated and bound."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    fake = _FakeBackend()
    att = sign_identity_attestation(
        subject="capauth:scratch@skworld.io",
        private_key_armor="PRIV",
        allow_gated=True,
        backend=fake,
    )
    # Shape: YYYY-MM-DDTHH:MM:SSZ
    assert att.issued_at.endswith("Z")
    datetime.strptime(att.issued_at, "%Y-%m-%dT%H:%M:%SZ")  # raises if malformed


def test_closed_gate_never_reaches_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """A closed gate raises before the injected backend is ever touched."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    fake = _FakeBackend()
    with pytest.raises(RootRotationGateError) as ei:
        sign_identity_attestation(
            subject="capauth:scratch@skworld.io",
            private_key_armor="PRIV",
            allow_gated=False,  # force closed even if env were set
            backend=fake,
        )
    # Error names the ceremony doc; backend stayed untouched.
    assert ROOT_ROTATION_CEREMONY_DOC in str(ei.value)
    assert fake.sign_calls == []


# --- verify plumbing via injected backend (never gated) ---------------------


def test_verify_is_not_gated_and_passes_canonical_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify works with the gate CLOSED and hands the backend the canonical bytes."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    assert t3_gate_open() is False  # gate closed
    fake = _FakeBackend(verify_result=True)
    att = _att()
    assert verify_identity_attestation(att, "PUBCERT", backend=fake) is True
    assert len(fake.verify_calls) == 1
    data, sig, pub = fake.verify_calls[0]
    assert data == att.canonical_payload()
    assert sig == att.signature_armor
    assert pub == "PUBCERT"


def test_verify_returns_backend_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_identity_attestation propagates a backend False verdict verbatim."""
    monkeypatch.delenv(T3_GATE_ENV, raising=False)
    fake = _FakeBackend(verify_result=False)
    assert verify_identity_attestation(_att(), "PUBCERT", backend=fake) is False


def test_verify_tampered_field_changes_payload_handed_to_backend() -> None:
    """A forged field yields different bytes to the backend than the genuine one."""
    fake = _FakeBackend()
    genuine = _att(subject="capauth:scratch@skworld.io")
    forged = _att(subject="capauth:attacker@skworld.io")
    verify_identity_attestation(genuine, "PUB", backend=fake)
    verify_identity_attestation(forged, "PUB", backend=fake)
    assert fake.verify_calls[0][0] != fake.verify_calls[1][0]
