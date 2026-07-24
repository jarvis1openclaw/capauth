"""Crypto backend abstraction for CapAuth.

Provides a factory function to get the right backend based on
user preference: PGPy (default, pure-Python), GnuPG (wraps system
gpg2 for hardware keys), Sequoia (`sq` CLI, PQC), or sk_pgp
(in-process OpenPGP-PQC).

Every backend is imported **lazily** inside :func:`get_backend`. This keeps
``import capauth.crypto`` free of heavy/optional dependencies: notably PGPy,
which imports the ``imghdr`` stdlib module that was removed in Python 3.13.
Eagerly importing PGPy here would make the whole crypto package (and the sk_pgp
migration path with it) unimportable on 3.13; lazy import confines that failure
to the PGPy backend alone.
"""

from __future__ import annotations

from ..models import CryptoBackendType
from .base import CryptoBackend, KeyBundle

__all__ = ["get_backend", "CryptoBackend", "KeyBundle"]


def get_backend(backend_type: CryptoBackendType = CryptoBackendType.PGPY) -> CryptoBackend:
    """Factory: return the requested crypto backend.

    Args:
        backend_type: Which backend to use. Defaults to PGPy.

    Returns:
        CryptoBackend: A ready-to-use backend instance.

    Raises:
        BackendError: If the requested backend is unavailable.
    """
    if backend_type == CryptoBackendType.SEQUOIA:
        from .sequoia_backend import SequoiaBackend

        backend = SequoiaBackend()
        if not backend.available():
            from ..exceptions import BackendError

            raise BackendError(
                "Sequoia backend unavailable. Build sequoia-sq (pqc) and ensure "
                "`sq` is on PATH or at ~/.cargo/bin/sq (see "
                "memory: sequoia-pqc-backend-build)."
            )
        return backend

    if backend_type == CryptoBackendType.SKPGP:
        from .skpgp_backend import SKPgpBackend

        backend = SKPgpBackend()
        if not backend.available():
            from ..exceptions import BackendError

            raise BackendError(
                "sk_pgp backend unavailable. Install the sk_pgp library "
                "(OpenPGP-PQC) so it imports in this interpreter (see "
                "memory: sk_pgp-library)."
            )
        return backend

    if backend_type == CryptoBackendType.GNUPG:
        from .gnupg_backend import GnuPGBackend

        backend = GnuPGBackend()
        if not backend.available():
            from ..exceptions import BackendError

            raise BackendError(
                "GnuPG backend unavailable. Install: pip install capauth[gnupg] "
                "and ensure gpg2 is on PATH."
            )
        return backend

    # Default: PGPy (pure-Python). Imported lazily so 3.13 (no ``imghdr``)
    # only fails here, on the PGPy path, rather than at package import time.
    try:
        from .pgpy_backend import PGPyBackend
    except ImportError as exc:
        from ..exceptions import BackendError

        raise BackendError(
            "PGPy backend unavailable in this interpreter "
            f"({exc}). On Python 3.13+ PGPy fails because the stdlib "
            "`imghdr` module was removed; use a PQC backend instead "
            "(CryptoBackendType.SKPGP or SEQUOIA)."
        ) from exc

    return PGPyBackend()
