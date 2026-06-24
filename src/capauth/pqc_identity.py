"""Hybrid post-quantum challenge-response for capauth identity (PQC Q7 / Phase 2).

This is the **DID/challenge signing layer** — additive and opt-in. It lets a
capauth identity attach a hybrid Ed25519 + ML-DSA-65 signature (FIPS 204)
*alongside* the existing classical PGP challenge signature, so a verifier can
require both legs (quantum-resistant authentication) while classical-only peers
keep working unchanged (either-or verification during transition).

What this DOES NOT touch (important — read this)
------------------------------------------------
* It does **NOT** migrate the ROOT PGP identity key. The sovereign root and
  capauth's ``Algorithm`` key *generation* (``crypto/pgpy_backend.py``,
  ``gnupg_backend.py``) are untouched — that is the separate, gated Sequoia
  decision (plan §3 S1, §7 decisions 3-4).
* The hybrid signature uses a **per-agent ML-DSA-65 + Ed25519 key that is
  SEPARATE from, and never derived from, the PGP key.** The classical PGP
  signature is still produced by the existing backend over the SAME challenge
  bytes — both signatures bind the same identity assertion.

Construction
------------
The hybrid leg reuses the vetted ``skcomms.pqsig`` composite primitive (the
single source of the wire format + the "both legs required" AND gate). capauth
does not re-implement the lattice math or the composite framing — it composes
``skcomms.pqsig``. (If skcomms is not importable, the functions raise
``HybridSigUnavailable`` rather than silently degrading.)

The hybrid signature covers ``challenge.challenge_hex.encode("utf-8")`` — the
EXACT bytes the classical path signs (``identity.respond_to_challenge``), so the
two legs are over an identical transcript.
"""

from __future__ import annotations

import base64
from pathlib import Path

from .crypto import get_backend
from .exceptions import VerificationError
from .identity import respond_to_challenge, verify_challenge
from .models import (
    ChallengeRequest,
    ChallengeResponse,
    CryptoBackendType,
)

HYBRID_SIG_SUITE = "mldsa65-ed25519-v2"
CLASSICAL_SIG_SUITE = "ed25519-v1"


class HybridSigUnavailable(RuntimeError):
    """Raised when the hybrid-signature primitive (skcomms.pqsig) is missing."""


def _pqsig():
    """Import ``skcomms.pqsig`` lazily; raise loudly if unavailable.

    capauth composes skcomms' vetted primitive rather than re-implementing it.
    A missing backend is a hard error — never a silent downgrade to classical
    (the caller must explicitly choose the classical path for that).
    """
    try:
        from skcomms import pqsig  # type: ignore
    except Exception as exc:
        raise HybridSigUnavailable(
            "hybrid challenge signing needs skcomms.pqsig (Ed25519 + ML-DSA-65). "
            "Install skcomms + liboqs-python. capauth composes this primitive; it "
            "never re-implements the lattice math. The classical PGP "
            f"challenge path is unaffected. ({exc})"
        ) from exc
    return pqsig


def hybrid_keypair_for(agent: str, key_dir: Path | None = None):
    """Load-or-create the per-agent hybrid signing keypair (separate from PGP).

    Delegates to ``skcomms.pqsig.load_or_create_signer_keypair`` so the key is
    stored the same way the envelope signer's is. This is a DISTINCT key from
    the agent's PGP identity key.
    """
    return _pqsig().load_or_create_signer_keypair(agent, key_dir=key_dir)


def respond_to_challenge_hybrid(
    challenge: ChallengeRequest,
    private_key_armor: str,
    passphrase: str,
    *,
    hybrid_keypair=None,
    agent: str = "",
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> ChallengeResponse:
    """Respond to a challenge with BOTH a classical PGP sig and a hybrid sig.

    The classical PGP ``signature`` is produced exactly as
    :func:`capauth.identity.respond_to_challenge` does (so a classical verifier
    is satisfied), and a hybrid Ed25519 + ML-DSA-65 composite is ALSO attached
    over the same challenge bytes. The PGP root key is untouched.

    Args:
        challenge: The challenge to respond to.
        private_key_armor: The responder's PGP private key (classical leg).
        passphrase: Passphrase for the PGP key.
        hybrid_keypair: A ``skcomms.pqsig.HybridSigKeypair``. If ``None``, one is
            loaded/created for ``agent``.
        agent: Agent id for hybrid key persistence (required if no keypair).
        backend_type: PGP backend for the classical signature.

    Returns:
        ChallengeResponse with ``sig_suite="mldsa65-ed25519-v2"`` and both the
        classical ``signature`` and the hybrid fields populated.

    Raises:
        HybridSigUnavailable: if the hybrid primitive is missing.
    """
    pqsig = _pqsig()
    if hybrid_keypair is None:
        if not agent:
            raise ValueError("respond_to_challenge_hybrid needs hybrid_keypair or agent")
        hybrid_keypair = pqsig.load_or_create_signer_keypair(agent)

    # Classical PGP leg — unchanged path (back-compat).
    classical = respond_to_challenge(
        challenge, private_key_armor, passphrase, backend_type=backend_type
    )

    # Hybrid leg over the SAME bytes.
    data = challenge.challenge_hex.encode("utf-8")
    composite = pqsig.hybrid_sign(
        data, hybrid_keypair.ed25519_priv, hybrid_keypair.mldsa_priv
    )

    classical.sig_suite = HYBRID_SIG_SUITE
    classical.hybrid_signature = base64.b64encode(composite).decode("ascii")
    classical.hybrid_ed25519_pub = base64.b64encode(
        hybrid_keypair.ed25519_pub
    ).decode("ascii")
    classical.hybrid_mldsa_pub = base64.b64encode(
        hybrid_keypair.mldsa_pub
    ).decode("ascii")
    return classical


def verify_challenge_hybrid(
    challenge: ChallengeRequest,
    response: ChallengeResponse,
    public_key_armor: str,
    *,
    require_hybrid: bool = False,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> bool:
    """Verify a challenge response, accepting classical OR hybrid (either-or).

    Transition policy (additive):
      * If ``response.is_hybrid``: verify the hybrid composite (BOTH Ed25519 AND
        ML-DSA-65 legs must pass). The classical PGP signature is ALSO checked
        when a PGP key is supplied, so a hybrid response must satisfy both the
        classical and hybrid legs (defence in depth during transition).
      * Otherwise: verify the classical PGP signature exactly as
        :func:`capauth.identity.verify_challenge` — byte-for-byte unchanged for
        classical-only peers.
      * ``require_hybrid=True`` rejects a classical-only response (used once a
        peer is known hybrid-capable, to prevent silent downgrade).

    Args:
        challenge: The original challenge.
        response: The signed response.
        public_key_armor: The responder's PGP public key (classical leg).
        require_hybrid: Reject classical-only responses if True.
        backend_type: PGP backend for the classical signature.

    Returns:
        True iff the response verifies under the negotiated policy.

    Raises:
        VerificationError: on challenge/fingerprint mismatch (same as classical),
            or if ``require_hybrid`` and the response is not hybrid.
        HybridSigUnavailable: if a hybrid response is presented but the primitive
            is unavailable.
    """
    if require_hybrid and not response.is_hybrid:
        raise VerificationError(
            "hybrid signature required but response is classical-only "
            "(possible downgrade)"
        )

    if not response.is_hybrid:
        # Classical-only path — unchanged.
        return verify_challenge(
            challenge, response, public_key_armor, backend_type=backend_type
        )

    # Hybrid path. Reuse the classical structural checks (challenge id/hex/
    # fingerprint) by delegating the classical PGP verification first; this also
    # confirms the PGP leg binds the same identity. Then verify the hybrid legs.
    classical_ok = verify_challenge(
        challenge, response, public_key_armor, backend_type=backend_type
    )

    pqsig = _pqsig()
    data = challenge.challenge_hex.encode("utf-8")
    try:
        composite = base64.b64decode(response.hybrid_signature)
        ed_pub = base64.b64decode(response.hybrid_ed25519_pub)
        mldsa_pub = base64.b64decode(response.hybrid_mldsa_pub)
    except Exception as exc:
        raise VerificationError(f"malformed hybrid signature fields: {exc}") from exc

    hybrid_ok = pqsig.hybrid_verify(data, composite, ed_pub, mldsa_pub)
    return bool(classical_ok and hybrid_ok)


__all__ = [
    "HYBRID_SIG_SUITE",
    "CLASSICAL_SIG_SUITE",
    "HybridSigUnavailable",
    "hybrid_keypair_for",
    "respond_to_challenge_hybrid",
    "verify_challenge_hybrid",
]
