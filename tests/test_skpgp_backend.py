"""Tests for the sk_pgp crypto backend (migration boundary to sk_pgp).

Two layers:
  * Import-guard behavior that does NOT require sk_pgp to be installed
    (simulated-absent via monkeypatch): available() False, factory + ops
    raise a clear BackendError.
  * Live round-trip / delegation tests, skipped when sk_pgp is absent.

The point of the boundary: capauth code selects the backend through
``get_backend(CryptoBackendType.SKPGP)`` and never imports sk_pgp directly.
"""

from __future__ import annotations

import pytest

from capauth.crypto import skpgp_backend as _mod
from capauth.crypto.skpgp_backend import SKPgpBackend
from capauth.exceptions import BackendError
from capauth.models import Algorithm, CryptoBackendType


# ---------------------------------------------------------------------------
# Import-guard layer: runs even when sk_pgp is not installed.
# ---------------------------------------------------------------------------
class TestSKPgpImportGuard:
    """Boundary must degrade cleanly when sk_pgp is unavailable."""

    def test_available_false_when_sk_pgp_absent(self, monkeypatch):
        """available() reflects sk_pgp import state."""
        monkeypatch.setattr(_mod, "_sk_pgp", None)
        assert SKPgpBackend().available() is False

    def test_operations_raise_backend_error_when_absent(self, monkeypatch):
        """Every op raises a clear BackendError, not a raw ImportError/AttributeError."""
        monkeypatch.setattr(_mod, "_sk_pgp", None)
        backend = SKPgpBackend()
        with pytest.raises(BackendError):
            backend.generate_keypair("N", "n@e.io", "pw", Algorithm.ED25519)
        with pytest.raises(BackendError):
            backend.sign(b"x", "not-a-key", "pw")
        with pytest.raises(BackendError):
            backend.fingerprint_from_armor("not-a-key")

    def test_factory_raises_when_absent(self, monkeypatch):
        """get_backend(SKPGP) raises BackendError when sk_pgp cannot import."""
        monkeypatch.setattr(_mod, "_sk_pgp", None)
        # Re-import path in the factory pulls this same module object, so the
        # patched _sk_pgp = None is observed.
        from capauth.crypto import get_backend

        with pytest.raises(BackendError):
            get_backend(CryptoBackendType.SKPGP)

    def test_module_imports_without_sk_pgp(self, monkeypatch):
        """The module itself imports regardless of sk_pgp presence."""
        # Importing skpgp_backend above already proves this; assert the guard
        # sentinel exists so the contract is explicit.
        assert hasattr(_mod, "_sk_pgp")


# ---------------------------------------------------------------------------
# Live layer: requires sk_pgp.
# ---------------------------------------------------------------------------
sk_pgp = pytest.importorskip("sk_pgp", reason="sk_pgp library not installed")


@pytest.fixture
def skpgp():
    """A live sk_pgp backend."""
    return SKPgpBackend()


@pytest.fixture
def ed25519_bundle(skpgp):
    """An Ed25519 keypair generated through the boundary (fast)."""
    return skpgp.generate_keypair("Test User", "test@capauth.local", "pw-2026", Algorithm.ED25519)


class TestSKPgpFactory:
    """Factory returns the sk_pgp adapter when the library is present."""

    def test_factory_returns_skpgp_backend(self):
        from capauth.crypto import get_backend

        backend = get_backend(CryptoBackendType.SKPGP)
        assert isinstance(backend, SKPgpBackend)
        assert backend.available() is True


class TestSKPgpRoundTrip:
    """Generate / sign / verify through the boundary, no direct sk_pgp calls."""

    def test_generate_produces_valid_bundle(self, ed25519_bundle):
        assert "BEGIN PGP PUBLIC KEY BLOCK" in ed25519_bundle.public_armor
        assert "BEGIN PGP PRIVATE KEY BLOCK" in ed25519_bundle.private_armor
        assert ed25519_bundle.algorithm == Algorithm.ED25519
        assert all(c in "0123456789ABCDEFabcdef" for c in ed25519_bundle.fingerprint)

    def test_sign_and_verify_roundtrip(self, skpgp, ed25519_bundle):
        data = b"sovereignty is not negotiable"
        sig = skpgp.sign(data, ed25519_bundle.private_armor, "pw-2026")
        assert isinstance(sig, str) and "BEGIN PGP" in sig
        assert skpgp.verify(data, sig, ed25519_bundle.public_armor) is True

    def test_verify_rejects_tampered_data(self, skpgp, ed25519_bundle):
        data = b"original message"
        sig = skpgp.sign(data, ed25519_bundle.private_armor, "pw-2026")
        assert skpgp.verify(b"tampered", sig, ed25519_bundle.public_armor) is False

    def test_verify_rejects_garbage_signature(self, skpgp, ed25519_bundle):
        # Non-raising contract: malformed signature -> False, not an exception.
        assert skpgp.verify(b"x", "not a signature", ed25519_bundle.public_armor) is False

    def test_fingerprint_from_public_armor(self, skpgp, ed25519_bundle):
        fpr = skpgp.fingerprint_from_armor(ed25519_bundle.public_armor)
        assert fpr == ed25519_bundle.fingerprint

    def test_fingerprint_from_private_armor(self, skpgp, ed25519_bundle):
        fpr = skpgp.fingerprint_from_armor(ed25519_bundle.private_armor)
        assert fpr == ed25519_bundle.fingerprint

    def test_fingerprint_from_bad_armor_raises(self, skpgp):
        with pytest.raises(BackendError):
            skpgp.fingerprint_from_armor("-----BEGIN NONSENSE-----\n\n-----END NONSENSE-----")


class TestSKPgpPostQuantum:
    """sk_pgp is PQC-capable: the boundary can host a post-quantum signing key."""

    def test_pqc_generate_sign_verify(self, skpgp):
        # ML-DSA-65 + Ed25519 composite (L3); fast enough for CI.
        bundle = skpgp.generate_keypair(
            "PQ Root", "pq@capauth.local", "pw-2026", Algorithm.HYBRID_ED25519_MLDSA65
        )
        assert bundle.algorithm == Algorithm.HYBRID_ED25519_MLDSA65
        data = b"post-quantum signing root"
        sig = skpgp.sign(data, bundle.private_armor, "pw-2026")
        assert skpgp.verify(data, sig, bundle.public_armor) is True

    def test_unmapped_algorithm_raises_not_implemented(self, skpgp):
        with pytest.raises(NotImplementedError):
            skpgp.generate_keypair("X", "x@e.io", "pw", Algorithm.SLH_DSA_SHAKE_256)
