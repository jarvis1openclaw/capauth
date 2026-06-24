"""Abstract crypto backend interface for CapAuth.

Defines the contract that all PGP backend implementations must fulfill.
CapAuth supports multiple backends (PGPy pure-Python, system GnuPG)
through this abstraction so users can choose portability vs power.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models import Algorithm


@dataclass
class KeyBundle:
    """Result of keypair generation.

    Attributes:
        fingerprint: Full PGP fingerprint: 40 (v4) or 64 (v6) hex.
        public_armor: ASCII-armored public key block.
        private_armor: ASCII-armored private key block.
        algorithm: Algorithm used for generation.
    """

    fingerprint: str
    public_armor: str
    private_armor: str
    algorithm: Algorithm


class CryptoBackend(ABC):
    """Abstract interface for PGP cryptographic operations.

    Every CapAuth identity operation (key generation, signing,
    verification) flows through this interface so the underlying
    library can be swapped without touching business logic.
    """

    @abstractmethod
    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str,
        algorithm: Algorithm = Algorithm.RSA4096,
    ) -> KeyBundle:
        """Generate a new PGP keypair.

        Args:
            name: Display name for the UID.
            email: Email address for the UID.
            passphrase: Passphrase to protect the private key.
            algorithm: Key algorithm (Ed25519 or RSA-4096).

        Returns:
            KeyBundle: Generated key material and metadata.

        Raises:
            KeyGenerationError: If key creation fails.
        """

    @abstractmethod
    def sign(
        self,
        data: bytes,
        private_key_armor: str,
        passphrase: str,
    ) -> str:
        """Create a detached PGP signature over arbitrary data.

        Args:
            data: Raw bytes to sign.
            private_key_armor: ASCII-armored private key.
            passphrase: Passphrase to unlock the private key.

        Returns:
            str: ASCII-armored detached signature.

        Raises:
            CapAuthError: If signing fails.
        """

    @abstractmethod
    def verify(
        self,
        data: bytes,
        signature_armor: str,
        public_key_armor: str,
    ) -> bool:
        """Verify a detached PGP signature.

        Args:
            data: Original bytes that were signed.
            signature_armor: ASCII-armored detached signature.
            public_key_armor: ASCII-armored public key of the signer.

        Returns:
            bool: True if signature is valid, False otherwise.
        """

    @abstractmethod
    def fingerprint_from_armor(self, key_armor: str) -> str:
        """Extract the fingerprint from an ASCII-armored key.

        Args:
            key_armor: ASCII-armored public or private key.

        Returns:
            str: 40 (v4) or 64 (v6) hex fingerprint.

        Raises:
            CapAuthError: If the armor cannot be parsed.
        """

    # ------------------------------------------------------------------
    # Hybrid post-quantum KEM hooks (PQC-MIGRATION Q1, plan §4.3).
    #
    # Additive + non-breaking: existing signing backends (PGPy, GnuPG) inherit
    # the default ``NotImplementedError`` raisers below, so nothing they do
    # changes. A future hybrid-KEM-capable backend overrides these. The live
    # X25519+ML-KEM-768 implementation ships in ``skcomms.pqkem`` /
    # ``skcomms.pqkem_backend`` (co-located with the wire-format contract);
    # these hooks let capauth route KEM through the same backend abstraction.
    # ------------------------------------------------------------------

    #: Hybrid-KEM suite id this backend supports, or empty if KEM-incapable.
    kem_suite_id: str = ""

    def supports_kem(self) -> bool:
        """Whether this backend implements the hybrid-KEM hooks.

        Returns:
            bool: True only for KEM-capable backends (default False).
        """
        return bool(self.kem_suite_id)

    def kem_generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a hybrid KEM keypair -> ``(public_key, private_key)``.

        Raises:
            NotImplementedError: on backends that do not support KEM.
        """
        raise NotImplementedError(
            "this CryptoBackend does not support hybrid KEM; use a KEM-capable "
            "backend (see skcomms.pqkem_backend.LiboqsHybridKemBackend)"
        )

    def kem_encapsulate(self, peer_public_key: bytes, info: bytes = b"") -> tuple[bytes, bytes]:
        """Encapsulate to ``peer_public_key`` -> ``(ciphertext, shared_secret)``.

        Raises:
            NotImplementedError: on backends that do not support KEM.
        """
        raise NotImplementedError(
            "this CryptoBackend does not support hybrid KEM; use a KEM-capable "
            "backend (see skcomms.pqkem_backend.LiboqsHybridKemBackend)"
        )

    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes, info: bytes = b"") -> bytes:
        """Decapsulate ``ciphertext`` with ``private_key`` -> ``shared_secret``.

        Raises:
            NotImplementedError: on backends that do not support KEM.
        """
        raise NotImplementedError(
            "this CryptoBackend does not support hybrid KEM; use a KEM-capable "
            "backend (see skcomms.pqkem_backend.LiboqsHybridKemBackend)"
        )

    def available(self) -> bool:
        """Check whether this backend's dependencies are installed.

        Returns:
            bool: True if the backend can be used.
        """
        return True
