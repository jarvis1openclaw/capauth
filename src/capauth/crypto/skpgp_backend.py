"""sk_pgp (OpenPGP-PQC) crypto backend for CapAuth.

This is the **migration boundary** to the sibling ``sk_pgp`` library
(https://github.com/smilinTux/sk_pgp): a single ``CryptoBackend`` adapter so
capauth business logic depends on the stable ``CryptoBackend`` ABC rather than
importing ``sk_pgp`` directly at scattered call sites. Everything sk_pgp related
is confined to this module.

``sk_pgp`` reproduces the ``SequoiaBackend`` operations **in-process** (a Rust
extension over the Sequoia OpenPGP stack) instead of shelling out to the ``sq``
CLI, so this backend can host a post-quantum **signing** root (ML-DSA + Ed448 /
Ed25519 composites) with no external binary on ``PATH``.

Import contract
---------------
``sk_pgp`` is an *optional* dependency. This module imports without it: the
top-level import is guarded, and every operation that needs the library checks
:meth:`SKPgpBackend.available` first (or is reached only via the factory, which
gates on ``available()``). If ``sk_pgp`` is absent, ``available()`` returns
``False`` and the factory raises a clear ``BackendError``; nothing else in
capauth breaks.

Crypto behavior
---------------
This adapter changes **no** existing backend. It signs with detached armored
signatures (``sk_pgp.Key.sign_detached``) and verifies them
(``sk_pgp.Cert.verify_detached``); each backend verifies its own signatures, so
the round-trip stays internal to the boundary. No unprotected copy of a secret
key is ever written, and no key material is persisted here.
"""

from __future__ import annotations

from ..exceptions import BackendError, KeyGenerationError
from ..models import Algorithm
from .base import CryptoBackend, KeyBundle

try:  # pragma: no cover - exercised implicitly by available()
    import sk_pgp as _sk_pgp
except Exception:  # ImportError, or a broken/ABI-mismatched build
    _sk_pgp = None


#: capauth ``Algorithm`` -> sk_pgp ``Key.generate`` suite id.
#: Mirrors ``sequoia_backend._CIPHER_SUITES`` so the two PQC-capable backends
#: speak the same suite vocabulary. ``ED25519`` maps to the plain ``ed25519``
#: suite (sk_pgp accepts ``ed25519``/``cv25519`` for the classical curve).
_SUITES: dict[Algorithm, str] = {
    Algorithm.ED25519: "ed25519",
    Algorithm.RSA4096: "rsa4k",
    Algorithm.HYBRID_ED448_MLDSA87: "mldsa87-ed448",
    Algorithm.HYBRID_ED25519_MLDSA65: "mldsa65-ed25519",
    Algorithm.ML_DSA_65: "mldsa65-ed25519",
}


class SKPgpBackend(CryptoBackend):
    """CryptoBackend adapter over the in-process ``sk_pgp`` library.

    Unlike :class:`PGPyBackend`, this backend can generate and operate on
    post-quantum composite signing keys (ML-DSA + Ed448 / Ed25519) without an
    external ``sq`` binary. All ``sk_pgp`` access is funneled through here.
    """

    #: sk_pgp is a signing/verification adapter; it does not implement the
    #: hybrid-KEM hooks (those live in ``skcomms.pqkem_backend``). Leaving this
    #: empty keeps ``supports_kem()`` False and the base KEM hooks raising.
    kem_suite_id: str = ""

    def available(self) -> bool:
        """Whether the ``sk_pgp`` library imported successfully.

        Returns:
            bool: True only if ``sk_pgp`` is importable in this environment.
        """
        return _sk_pgp is not None

    def _require(self) -> None:
        """Raise a clear error if ``sk_pgp`` is not importable.

        Raises:
            BackendError: When the library is unavailable.
        """
        if _sk_pgp is None:
            raise BackendError(
                "sk_pgp backend unavailable. Install the sk_pgp library "
                "(OpenPGP-PQC) and ensure it imports in this interpreter."
            )

    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str,
        algorithm: Algorithm = Algorithm.RSA4096,
    ) -> KeyBundle:
        """Generate a keypair via ``sk_pgp.Key.generate``.

        Args:
            name: Display name for the UID.
            email: Email address for the UID.
            passphrase: Passphrase to protect the private key (``""`` = none).
            algorithm: Classical (Ed25519 / RSA-4096) or a supported PQC
                composite (ML-DSA-87+Ed448 / ML-DSA-65+Ed25519).

        Returns:
            KeyBundle: Generated key material and metadata.

        Raises:
            KeyGenerationError: On any sk_pgp failure.
            NotImplementedError: For a declared algorithm sk_pgp cannot issue.
        """
        self._require()
        suite = _SUITES.get(algorithm)
        if suite is None:
            raise NotImplementedError(
                f"algorithm {algorithm.value!r} is not mapped to an sk_pgp suite; "
                f"supported: {sorted(a.value for a in _SUITES)}"
            )
        userid = f"{name} <{email}>"
        # sk_pgp treats an empty/None password as "unprotected".
        password = passphrase if passphrase else None
        try:
            key = _sk_pgp.Key.generate(userid, suite, password)
            return KeyBundle(
                fingerprint=key.fingerprint,
                public_armor=key.cert.to_armor(),
                private_armor=key.to_armor(),
                algorithm=algorithm,
            )
        except Exception as exc:
            raise KeyGenerationError(f"sk_pgp key generation failed: {exc}") from exc

    def sign(
        self,
        data: bytes,
        private_key_armor: str,
        passphrase: str,
    ) -> str:
        """Create a detached armored signature over ``data`` via sk_pgp.

        Args:
            data: Raw bytes to sign.
            private_key_armor: ASCII-armored private key.
            passphrase: Passphrase to unlock the key (``""`` = unprotected).

        Returns:
            str: ASCII-armored detached signature.

        Raises:
            BackendError: On signing failure.
        """
        self._require()
        try:
            key = _sk_pgp.Key.from_bytes(private_key_armor.encode("utf-8"))
            password = passphrase if passphrase else None
            sig = key.sign_detached(data, password)
            # sk_pgp returns armored signature bytes; the ABC contract is str.
            if isinstance(sig, bytes):
                return sig.decode("utf-8")
            return sig
        except Exception as exc:
            raise BackendError(f"sk_pgp signing failed: {exc}") from exc

    def verify(
        self,
        data: bytes,
        signature_armor: str,
        public_key_armor: str,
    ) -> bool:
        """Verify a detached signature via sk_pgp.

        Non-raising: a malformed or non-verifying signature yields ``False``,
        matching :meth:`CryptoBackend.verify`'s contract.

        Args:
            data: Original bytes that were signed.
            signature_armor: ASCII-armored detached signature.
            public_key_armor: ASCII-armored signer's public key / cert.

        Returns:
            bool: True only if the signature is cryptographically valid.
        """
        self._require()
        try:
            cert = _sk_pgp.Cert.from_armor(public_key_armor)
            sig_bytes = (
                signature_armor.encode("utf-8")
                if isinstance(signature_armor, str)
                else signature_armor
            )
            # sk_pgp.Cert.verify_detached(sig, data) -> bool. For a hybrid
            # composite BOTH legs (ML-DSA + EdDSA) must verify.
            return bool(cert.verify_detached(sig_bytes, data))
        except Exception:
            return False

    def fingerprint_from_armor(self, key_armor: str) -> str:
        """Extract the primary-key fingerprint from armored key material.

        Accepts either a public cert or a secret key block.

        Args:
            key_armor: ASCII-armored public or private key.

        Returns:
            str: Primary-key fingerprint (upper hex, 40 v4 / 64 v6).

        Raises:
            BackendError: If the armor cannot be parsed.
        """
        self._require()
        try:
            return _sk_pgp.Cert.from_armor(key_armor).fingerprint
        except Exception:
            # Secret-key armor: parse as a Key and take its fingerprint.
            try:
                return _sk_pgp.Key.from_bytes(key_armor.encode("utf-8")).fingerprint
            except Exception as exc:
                raise BackendError(f"Failed to parse key armor: {exc}") from exc
