"""RSA signing key for the CapAuth OIDC Identity Provider.

This is the IdP's *token-signing* key — it signs the ID tokens (RS256 JWTs)
that OIDC clients (e.g. Authentik) verify against the published JWKS. It is
SEPARATE from users' PGP keys (which prove the login) and from the optional
server PGP key (which signs challenge nonces).

Persistence:
    The RSA private key is loaded from / generated into
    ``<capauth_home>/service/oidc_signing_key.pem`` so the same ``kid`` and key
    survive service restarts (clients cache JWKS by ``kid``).

Override the path with ``CAPAUTH_OIDC_SIGNING_KEY_PATH``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ... import resolve_capauth_home


def _b64url_uint(value: int) -> str:
    """Encode a non-negative integer as base64url (no padding) per RFC 7518."""
    length = (value.bit_length() + 7) // 8
    data = value.to_bytes(length, "big") if value else b"\x00"
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SigningKey:
    """The IdP RSA signing key, with JWKS export and a stable ``kid``.

    Args:
        path: PEM path for the private key. Defaults to
            ``<capauth_home>/service/oidc_signing_key.pem`` (or the
            ``CAPAUTH_OIDC_SIGNING_KEY_PATH`` env override).
        key_size: RSA modulus size used when generating a fresh key.
    """

    ALGORITHM = "RS256"

    def __init__(self, path: Optional[Path] = None, key_size: int = 2048) -> None:
        self.path = Path(path) if path else self._default_path()
        self._private_key = self._load_or_generate(key_size)
        self.kid = self._compute_kid()

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_path() -> Path:
        env = os.environ.get("CAPAUTH_OIDC_SIGNING_KEY_PATH")
        if env:
            return Path(env).expanduser()
        return resolve_capauth_home() / "service" / "oidc_signing_key.pem"

    def _load_or_generate(self, key_size: int) -> rsa.RSAPrivateKey:
        """Load the PEM private key, generating + persisting one if absent."""
        if self.path.exists():
            data = self.path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
            if not isinstance(key, rsa.RSAPrivateKey):  # pragma: no cover - defensive
                raise TypeError("OIDC signing key must be an RSA private key")
            return key

        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.path.write_bytes(pem)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - non-POSIX
            pass
        return key

    def _compute_kid(self) -> str:
        """Derive a stable key id from the public key (RFC 7638-ish thumbprint)."""
        pub = self.public_numbers()
        thumb_input = f"{pub['n']}:{pub['e']}".encode("ascii")
        return hashlib.sha256(thumb_input).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def private_pem(self) -> bytes:
        """The PEM-encoded private key bytes (for PyJWT ``encode``)."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_pem(self) -> bytes:
        """The PEM-encoded public key bytes (for PyJWT ``decode``)."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_numbers(self) -> dict[str, int]:
        """Return the RSA public modulus ``n`` and exponent ``e``."""
        numbers = self._private_key.public_key().public_numbers()
        return {"n": numbers.n, "e": numbers.e}

    def jwk(self) -> dict[str, Any]:
        """Return this key as a public JWK (for the JWKS document)."""
        pub = self.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": self.ALGORITHM,
            "kid": self.kid,
            "n": _b64url_uint(pub["n"]),
            "e": _b64url_uint(pub["e"]),
        }

    def jwks(self) -> dict[str, Any]:
        """Return the JWKS document (a key set with this single signing key)."""
        return {"keys": [self.jwk()]}
