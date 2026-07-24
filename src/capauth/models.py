"""Pydantic models for CapAuth sovereign profiles and identity verification."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Type of sovereign entity."""

    HUMAN = "human"
    AI = "ai"
    ORGANIZATION = "organization"


class Algorithm(str, Enum):
    """Supported PGP / identity key algorithms.

    The ``ML_*`` / ``HYBRID_*`` members are **PQC Q0 crypto-agility stubs**:
    they are *declared* so the enum (and any serialized profile/DID) can name a
    post-quantum suite, but they are **not yet implemented**. Generating a key
    with one of these raises ``NotImplementedError`` in the crypto backends.
    They are wired to real algorithms in Phase 2 (Sequoia/liboqs migration).

    Classical members (``ED25519``, ``RSA4096``) remain the only working
    algorithms today. See ``docs/quantum-resistance-architecture.md`` §4.1.
    """

    # --- Classical (working today) ---
    ED25519 = "ed25519"
    RSA4096 = "rsa4096"

    # --- Post-quantum stubs (declared, NOT implemented — Phase 2) ---
    ML_KEM_768 = "ml-kem-768"  # FIPS 203 KEM (encryption)
    ML_DSA_65 = "ml-dsa-65"  # FIPS 204 signature
    HYBRID_X25519_MLKEM768 = "hybrid-x25519-mlkem768"  # OpenPGP composite alg 35 (KEM)
    HYBRID_ED25519_MLDSA65 = "hybrid-ed25519-mldsa65"  # OpenPGP composite alg 30 (sig)
    HYBRID_ED448_MLDSA87 = "hybrid-ed448-mldsa87"  # OpenPGP composite alg 31 (sig, L5)
    SLH_DSA_SHAKE_256 = "slh-dsa-shake-256"  # FIPS 205 hash-based root signer

    @property
    def is_post_quantum(self) -> bool:
        """True for any declared-but-unimplemented PQC stub algorithm."""
        return self in _POST_QUANTUM_ALGORITHMS

    @property
    def crypto_suite_id(self) -> str:
        """Map this algorithm to its ``skcomms.crypto_suites`` suite id.

        Lets the runtime self-report describe a capauth identity key with the
        same suite vocabulary as envelopes/groups. Classical algorithms map to
        their classical suite id; PQC stubs map to their (inactive) planned
        suite id.
        """
        return _ALGORITHM_SUITE_IDS.get(self, "ed25519-v1")


#: PQC algorithms that are declared but not yet implemented (Q0 scaffolding).
_POST_QUANTUM_ALGORITHMS: frozenset[Algorithm] = frozenset(
    {
        Algorithm.ML_KEM_768,
        Algorithm.ML_DSA_65,
        Algorithm.HYBRID_X25519_MLKEM768,
        Algorithm.HYBRID_ED25519_MLDSA65,
        Algorithm.HYBRID_ED448_MLDSA87,
        Algorithm.SLH_DSA_SHAKE_256,
    }
)

#: Algorithm → crypto-suite id (mirrors skcomms.crypto_suites).
_ALGORITHM_SUITE_IDS: dict[Algorithm, str] = {
    Algorithm.ED25519: "ed25519-v1",
    Algorithm.RSA4096: "rsa4096-v1",
    Algorithm.ML_KEM_768: "x25519-mlkem768-v2",
    Algorithm.HYBRID_X25519_MLKEM768: "x25519-mlkem768-v2",
    Algorithm.ML_DSA_65: "mldsa65-ed25519-v2",
    Algorithm.HYBRID_ED25519_MLDSA65: "mldsa65-ed25519-v2",
    Algorithm.HYBRID_ED448_MLDSA87: "mldsa87-ed448-v2",
    Algorithm.SLH_DSA_SHAKE_256: "slh-dsa-shake-256-v2",
}


class CryptoBackendType(str, Enum):
    """Available crypto backend implementations."""

    PGPY = "pgpy"
    GNUPG = "gnupg"
    SEQUOIA = "sequoia"  # PQC-capable (sq CLI); only backend that signs post-quantum
    SKPGP = "sk_pgp"  # PQC-capable (in-process sk_pgp lib); signing root without shelling to sq


class KeyInfo(BaseModel):
    """Metadata about a PGP keypair."""

    fingerprint: str = Field(description="Full PGP fingerprint: 40 (v4) or 64 (v6) hex")
    algorithm: Algorithm = Field(default=Algorithm.ED25519)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    public_key_path: str = Field(description="Path to exported public key (.asc)")
    private_key_path: str = Field(description="Path to encrypted private key (.asc)")


class EntityInfo(BaseModel):
    """Identity metadata for a sovereign entity."""

    entity_type: EntityType = Field(default=EntityType.HUMAN)
    name: str = Field(description="Display name")
    email: Optional[str] = Field(default=None, description="Contact email or AI identifier")
    handle: Optional[str] = Field(default=None, description="Unique handle (name@domain)")


class StorageConfig(BaseModel):
    """Storage configuration for a sovereign profile."""

    primary: str = Field(description="Primary storage path (e.g. ~/.capauth/)")


class SovereignProfile(BaseModel):
    """A sovereign entity's CapAuth profile — the decentralized replacement for a user account."""

    capauth_version: str = Field(default="0.1.0")
    profile_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity: EntityInfo
    key_info: KeyInfo
    storage: StorageConfig
    crypto_backend: CryptoBackendType = Field(default=CryptoBackendType.PGPY)
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signature: Optional[str] = Field(
        default=None, description="PGP signature over the profile JSON"
    )


class ChallengeRequest(BaseModel):
    """An identity verification challenge sent to a peer."""

    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    challenge_hex: str = Field(description="Random hex bytes the peer must sign")
    from_fingerprint: str = Field(description="Challenger's PGP fingerprint")
    to_fingerprint: str = Field(description="Target's PGP fingerprint")
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChallengeResponse(BaseModel):
    """A signed response to an identity verification challenge.

    Hybrid post-quantum fields (PQC Q7 / Phase 2) are **additive + optional**:
    a classical responder leaves them ``None`` and the classical PGP ``signature``
    is verified exactly as before. A hybrid-capable responder ALSO attaches a
    base64 ``skcomms.pqsig`` composite (Ed25519 + ML-DSA-65, FIPS 204) over the
    same challenge bytes, plus the two hybrid public keys, and sets
    ``sig_suite="mldsa65-ed25519-v2"``. The hybrid key is a **per-agent key,
    separate from and never derived from the PGP root** — the root PGP identity
    is NOT migrated here (that is the gated Sequoia decision).
    """

    challenge_id: str = Field(description="ID of the challenge being responded to")
    challenge_hex: str = Field(description="The original challenge hex")
    signature: str = Field(description="PGP signature over the challenge bytes")
    responder_fingerprint: str = Field(description="Responder's PGP fingerprint")
    created: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # --- Hybrid PQ (additive, optional — Phase 2 / Q7) ---
    sig_suite: str = Field(
        default="ed25519-v1",
        description="Signature suite id. 'ed25519-v1' (classical, default) or "
        "'mldsa65-ed25519-v2' (hybrid Ed25519+ML-DSA-65). The classical PGP "
        "signature is ALWAYS present for back-compat.",
    )
    hybrid_signature: Optional[str] = Field(
        default=None,
        description="base64 skcomms.pqsig composite over the challenge bytes "
        "(set only when sig_suite is hybrid).",
    )
    hybrid_ed25519_pub: Optional[str] = Field(
        default=None, description="base64 Ed25519 public key (hybrid leg)."
    )
    hybrid_mldsa_pub: Optional[str] = Field(
        default=None, description="base64 ML-DSA-65 public key (hybrid leg)."
    )

    @property
    def is_hybrid(self) -> bool:
        """Whether a verifiable hybrid signature is attached."""
        return (
            self.sig_suite == "mldsa65-ed25519-v2"
            and bool(self.hybrid_signature)
            and bool(self.hybrid_ed25519_pub)
            and bool(self.hybrid_mldsa_pub)
        )


# Django models for Authentik custom stage (loaded only when Django is available).
# Ensures CapAuthStage and CapAuthKeyRegistry are discovered when "capauth" is in INSTALLED_APPS.
try:
    from capauth.authentik.stage import CapAuthKeyRegistry, CapAuthStage  # noqa: F401
except ImportError:
    pass
