"""T3 composite **root identity** signatures — additive, GATED (default closed).

This module adds a *clearly feature-flagged* code path that can **sign and
verify a composite identity attestation** with the strongest standards-track
hybrid signature in the build: **ML-DSA-87 + Ed448** (FIPS 204 lattice signature
+ RFC 8032 EdDSA), the ``mldsa87-ed448`` suite hosted by
:class:`capauth.crypto.sequoia_backend.SequoiaBackend`.

Why a separate, gated path (read this)
--------------------------------------
The capauth **live root identity is still CLASSICAL** (Ed25519 / RSA-4096,
fingerprint ``02BC0EB3CAD31DB691A753C70C5629AB893F9746``). Producing a *root
identity attestation* with a post-quantum composite key is a **sovereign-trust
event** that only becomes live through the deliberate, Chef-driven **root-key
rotation ceremony** (``docs/ROOT_ROTATION_CEREMONY.md`` →
``docs/PQC_ROOT_MIGRATION.md``). Until that ceremony runs, the live root is
classical and this path MUST NOT be usable as a live identity signer.

So the signing side is **gated behind a feature flag that defaults CLOSED**:

* ``t3_gate_open()`` is ``False`` unless explicitly opened.
* :func:`sign_identity_attestation` raises :class:`RootRotationGateError` while
  the gate is closed — it cannot mint a live composite root attestation by
  default.
* The gate opens **only** via an explicit opt-in: the
  ``CAPAUTH_ALLOW_T3_COMPOSITE_ROOT`` environment flag, or an explicit
  ``allow_gated=True`` argument (used by ceremony tooling and tests). This is the
  software analogue of the ``⛔ STOP — REQUIRES CHEF`` gates in the ceremony
  runbook.

What this does NOT do
---------------------
* It does **NOT** touch, weaken, or replace the classical Ed25519 / RSA root
  path. The PGPy backend remains the default everywhere
  (:func:`capauth.crypto.get_backend`); nothing here re-routes it. The classical
  challenge-response (``identity.py``) is byte-for-byte unchanged.
* It does **NOT** migrate the live root or perform any ceremony. It proves the
  *capability* on whatever key material the caller supplies (in practice:
  throwaway / scratch keys), exactly as ``docs/ROOT_ROTATION_CEREMONY.md``
  Phase 1.1 prescribes.

Honest claims
-------------
* **Hybrid = either-leg.** The ML-DSA-87 + Ed448 composite is unforgeable while
  *either* leg holds. It is **quantum-resistant**, never "quantum-proof".
* **Pre-RFC.** OpenPGP PQC bindings follow **draft-ietf-openpgp-pqc-17**
  (Standards Track, in the RFC Editor queue, **not yet an RFC**; composite sig
  code point 31). Formats may still change.
* **Tier note.** Live root = **T0 classical**. This T3 composite identity path
  is **proven-but-gated** — capability tested, gate closed, no live migration.

Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), RFC 8032 (Ed25519/Ed448),
RFC 9580 (OpenPGP v6).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Algorithm

#: Environment flag that opens the gate. Default (unset / falsey) = CLOSED.
T3_GATE_ENV = "CAPAUTH_ALLOW_T3_COMPOSITE_ROOT"

#: Suite id of the composite identity signature (mirrors models suite ids).
T3_SIG_SUITE = "mldsa87-ed448-v2"

#: The hybrid composite algorithm (FIPS 204 ML-DSA-87 + RFC 8032 Ed448, L5).
T3_ALGORITHM = Algorithm.HYBRID_ED448_MLDSA87

#: Wire/format version of the canonical attestation payload.
T3_PAYLOAD_VERSION = "composite-identity/1.0"

#: Where the human gate (the ceremony) is documented.
ROOT_ROTATION_CEREMONY_DOC = "docs/ROOT_ROTATION_CEREMONY.md"

_TRUTHY = {"1", "true", "yes", "on"}


class RootRotationGateError(RuntimeError):
    """Raised when the T3 composite root-identity signing path is used while gated.

    The gate is closed by default and only opens via an explicit opt-in
    (``CAPAUTH_ALLOW_T3_COMPOSITE_ROOT`` or ``allow_gated=True``). This mirrors
    the ``⛔ STOP — REQUIRES CHEF`` gates in ``docs/ROOT_ROTATION_CEREMONY.md``:
    a live composite root attestation is a sovereign-trust event, not something
    an agent or default code path may mint.
    """


def t3_gate_open(allow_gated: bool | None = None) -> bool:
    """Report whether the T3 composite root-identity signing gate is open.

    Default is **closed**. The gate opens only when explicitly opted in:

    * ``allow_gated=True`` — an explicit caller override (ceremony tooling,
      tests). ``allow_gated=False`` forces closed regardless of the environment.
    * else the ``CAPAUTH_ALLOW_T3_COMPOSITE_ROOT`` env flag is truthy
      (``1``/``true``/``yes``/``on``).

    Args:
        allow_gated: Explicit override. ``None`` (default) defers to the env
            flag; ``True`` opens; ``False`` forces closed.

    Returns:
        bool: ``True`` iff the gate is open (signing permitted).
    """
    if allow_gated is not None:
        return bool(allow_gated)
    return os.environ.get(T3_GATE_ENV, "").strip().lower() in _TRUTHY


@dataclass(frozen=True)
class T3IdentityAttestation:
    """A gated composite (ML-DSA-87 + Ed448) identity attestation.

    Binds a ``subject`` (typically the signer's fingerprint or capauth URI) and a
    short ``statement`` under a single hybrid signature. ``signature_armor`` is an
    ASCII-armored OpenPGP detached signature over :meth:`canonical_payload`.
    """

    subject: str
    statement: str
    issued_at: str
    suite: str
    signature_armor: str

    def canonical_payload(self) -> bytes:
        """Deterministic bytes the signature covers (sorted-key, compact JSON)."""
        return _canonical_payload(
            subject=self.subject,
            statement=self.statement,
            issued_at=self.issued_at,
            suite=self.suite,
        )

    def to_dict(self) -> dict[str, str]:
        """JSON-serializable view (e.g. for a DID proof or ledger entry)."""
        return {
            "capauth_t3": T3_PAYLOAD_VERSION,
            "subject": self.subject,
            "statement": self.statement,
            "issued_at": self.issued_at,
            "suite": self.suite,
            "algorithm": T3_ALGORITHM.value,
            "signature": self.signature_armor,
        }


def _canonical_payload(*, subject: str, statement: str, issued_at: str, suite: str) -> bytes:
    """Canonical, deterministic payload bytes (stable across re-serialization)."""
    return json.dumps(
        {
            "capauth_t3": T3_PAYLOAD_VERSION,
            "subject": subject,
            "statement": statement,
            "issued_at": issued_at,
            "suite": suite,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sequoia_backend(backend=None):
    """Lazily obtain a runnable SequoiaBackend or raise a clear error."""
    if backend is not None:
        return backend
    from .crypto.sequoia_backend import SequoiaBackend

    be = SequoiaBackend()
    if not be.available():
        from .exceptions import BackendError

        raise BackendError(
            "T3 composite identity needs the Sequoia (sq) PQC backend. Build "
            "sequoia-sq (pqc) so `sq` is on PATH or at ~/.cargo/bin/sq "
            "(see docs/PQC_ROOT_MIGRATION.md)."
        )
    return be


def sign_identity_attestation(
    subject: str,
    private_key_armor: str,
    passphrase: str = "",
    *,
    statement: str = "sovereign-identity",
    issued_at: str | None = None,
    allow_gated: bool | None = None,
    backend=None,
) -> T3IdentityAttestation:
    """Sign a composite (ML-DSA-87 + Ed448) identity attestation — **GATED**.

    This is the gated, additive T3 path. It mints a hybrid composite signature
    over a canonical identity assertion, using a PQC ML-DSA-87 + Ed448 key driven
    by the Sequoia backend. It does **not** touch or weaken the classical root.

    The gate is **closed by default**: while
    :func:`t3_gate_open` is ``False`` this raises :class:`RootRotationGateError`
    *before* any key material is touched. Opening the gate is an explicit opt-in
    (the ``CAPAUTH_ALLOW_T3_COMPOSITE_ROOT`` env flag, or ``allow_gated=True``)
    reserved for the Chef-driven rotation ceremony and its tests.

    Args:
        subject: Identity being attested (fingerprint or capauth URI).
        private_key_armor: ASCII-armored PQC (ML-DSA-87 + Ed448) signer key.
        passphrase: Passphrase unlocking the signer; ``""`` if unprotected.
        statement: Short human-readable assertion bound into the payload.
        issued_at: RFC 3339 UTC timestamp; generated if ``None``.
        allow_gated: Explicit gate override (see :func:`t3_gate_open`).
        backend: Optional pre-built ``SequoiaBackend`` (else auto-discovered).

    Returns:
        T3IdentityAttestation: subject/statement/timestamp + armored composite sig.

    Raises:
        RootRotationGateError: If the gate is closed (the default).
        BackendError: If the Sequoia/`sq` backend is unavailable.
        SequoiaError: If signing fails (e.g. wrong passphrase).
    """
    if not t3_gate_open(allow_gated):
        raise RootRotationGateError(
            "T3 composite root-identity signing is GATED (closed by default). The "
            "live capauth root is still classical "
            "(02BC0EB3CAD31DB691A753C70C5629AB893F9746); minting a composite "
            "ML-DSA-87+Ed448 root attestation is a sovereign-trust event reserved "
            f"for the Chef-driven rotation ceremony ({ROOT_ROTATION_CEREMONY_DOC}). "
            f"To opt in explicitly, set {T3_GATE_ENV}=1 or pass allow_gated=True."
        )

    ts = issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _canonical_payload(
        subject=subject, statement=statement, issued_at=ts, suite=T3_SIG_SUITE
    )
    be = _sequoia_backend(backend)
    sig = be.sign(payload, private_key_armor, passphrase)
    return T3IdentityAttestation(
        subject=subject,
        statement=statement,
        issued_at=ts,
        suite=T3_SIG_SUITE,
        signature_armor=sig,
    )


def verify_identity_attestation(
    attestation: T3IdentityAttestation,
    public_key_armor: str,
    *,
    backend=None,
) -> bool:
    """Verify a composite identity attestation against a public cert.

    Verification is **not gated** — checking a signature never makes the root
    "live" and is always safe. (The *production* of a live composite root
    attestation is what the gate guards.) Re-derives the canonical payload from
    the attestation's own fields so a tampered field changes the bytes and fails.

    Args:
        attestation: The attestation to verify.
        public_key_armor: ASCII-armored PQC public cert of the claimed signer.
        backend: Optional pre-built ``SequoiaBackend`` (else auto-discovered).

    Returns:
        bool: ``True`` iff the composite signature verifies over the payload.
    """
    be = _sequoia_backend(backend)
    return be.verify(
        attestation.canonical_payload(),
        attestation.signature_armor,
        public_key_armor,
    )


def t3_status() -> dict[str, object]:
    """Honest, per-surface status of the T3 composite root-identity path.

    Returns a small dict suitable for an ``sksecurity``-style report. Makes the
    gate state and the classical-root reality explicit; never claims the root is
    post-quantum.
    """
    return {
        "surface": "root-identity-attestation",
        "tier": "T3 (proven-but-gated)",
        "live_root": "classical (Ed25519/RSA, Shor-breakable)",
        "live_root_fingerprint": "02BC0EB3CAD31DB691A753C70C5629AB893F9746",
        "composite_suite": T3_SIG_SUITE,
        "algorithm": T3_ALGORITHM.value,
        "hybrid_semantics": "either-leg (ML-DSA-87 OR Ed448 holds → unforgeable)",
        "gate_open": t3_gate_open(),
        "gate_env": T3_GATE_ENV,
        "ceremony_doc": ROOT_ROTATION_CEREMONY_DOC,
        "standards": ["FIPS 204", "FIPS 203", "RFC 8032", "RFC 9580"],
        "draft": "draft-ietf-openpgp-pqc-17 (pre-RFC; sig code point 31)",
        "claim": "quantum-resistant, NOT quantum-proof; root migration not performed",
    }


__all__ = [
    "T3_GATE_ENV",
    "T3_SIG_SUITE",
    "T3_ALGORITHM",
    "T3_PAYLOAD_VERSION",
    "ROOT_ROTATION_CEREMONY_DOC",
    "RootRotationGateError",
    "T3IdentityAttestation",
    "t3_gate_open",
    "sign_identity_attestation",
    "verify_identity_attestation",
    "t3_status",
]
