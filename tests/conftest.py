"""Shared fixtures for CapAuth tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

TEST_NAME = "Test User"
TEST_EMAIL = "test@capauth.local"
TEST_PASSPHRASE = "test-sovereign-passphrase-2026"

# Reason: PGPy fails on Python 3.13+ due to removed imghdr module;
# guard crypto imports so non-crypto tests can still run.
try:
    from capauth.crypto import get_backend
    from capauth.crypto.base import KeyBundle
    from capauth.models import Algorithm, CryptoBackendType

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

_requires_crypto = pytest.mark.skipif(
    not _HAS_CRYPTO, reason="PGPy unavailable on this Python version"
)


@pytest.fixture
def pgpy_backend():
    """Return a PGPy crypto backend instance."""
    if not _HAS_CRYPTO:
        pytest.skip("PGPy unavailable")
    return get_backend(CryptoBackendType.PGPY)


@pytest.fixture
def rsa_keybundle(pgpy_backend) -> "KeyBundle":
    """Generate an RSA-4096 test keypair (cached per test)."""
    return pgpy_backend.generate_keypair(TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.RSA4096)


@pytest.fixture
def tmp_capauth_home(tmp_path) -> Path:
    """Provide a temporary directory for profile tests."""
    return tmp_path / ".capauth"


# --- Trust domain fixtures (kernel track M1) -------------------------------
# The moved trust-web tests build a full skcapstone agent home. These fixtures
# are ported from skcapstone's conftest so the copied tests run byte-identically.


@pytest.fixture
def tmp_agent_home(tmp_path: Path) -> Path:
    """Provide a temporary agent home directory (~/.skcapstone) for testing."""
    agent_home = tmp_path / ".skcapstone"
    agent_home.mkdir()
    return agent_home


@pytest.fixture(autouse=True)
def _isolate_skcapstone_agent_env(monkeypatch):
    """Keep host SKCAPSTONE_AGENT / SKMEMORY_AGENT out of the trust tests.

    skcapstone's profile-aware runtime routes memory/trust writes to the active
    agent (from the env vars and a live ~/.skcapstone/agents/ scan). On a dev box
    that would send the moved trust tests' writes into a real agent's home. Clear
    both vars and stub the active-agent detector so the pillars use the flat
    ``home/`` layout the tests pass explicitly. No-op when skcapstone is absent
    (capauth standalone CI), so capauth's own tests are unaffected.
    """
    try:
        import skcapstone
    except ImportError:
        return

    monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
    monkeypatch.delenv("SKMEMORY_AGENT", raising=False)
    monkeypatch.setenv("SKAGENT", "")
    monkeypatch.setattr(skcapstone, "SKCAPSTONE_AGENT", "", raising=False)
    if hasattr(skcapstone, "_detect_active_agent"):
        monkeypatch.setattr(skcapstone, "_detect_active_agent", lambda root=None: None)


# --- Token signing stub (PDP signature gate) --------------------------------
# ``capauth.authz.decide`` requires the granting token to carry a signature that
# verifies over its exact payload bytes, made by the key the payload names as
# issuer. That makes real gpg a dependency of any suite that expects an ALLOW.
# The authz / provisioning / capability suites are deliberately hermetic (no
# gpg, no network, no real home) and their subject matter is enrollment modes,
# capability chains, expiry and revocation, not OpenPGP itself, so they stub the
# gpg boundary rather than generating real keys.
#
# The stub is FAITHFUL on purpose: it fakes ONLY the gpg subprocess, leaving the
# real ``signature_verifies`` logic (empty-signature check, unattributable-issuer
# check, canonical payload bytes, issuer pinning) running for real. Its "signature"
# is a digest of the exact bytes signed, so an unsigned token still fails, a
# tampered payload still fails, and a signature lifted from another token still
# fails. A stub that just returned True would have let the very defect this gate
# closes (SEC-CRIT bc56b98b: an unsigned token granting skcode.dispatch) sail
# straight back in.
#
# Real end-to-end OpenPGP signing and verification is covered separately, against
# a real generated key, in ``tests/test_authz_signature_gate.py``.

#: The issuer fingerprint the stub pretends this node's identity key carries.
STUB_ISSUER_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

_STUB_SIG_HEAD = "-----BEGIN PGP SIGNATURE-----"
_STUB_SIG_TAIL = "-----END PGP SIGNATURE-----"


def stub_signature_for(payload_bytes: bytes) -> str:
    """A deterministic stand-in signature bound to the exact bytes signed."""
    digest = hashlib.sha256(payload_bytes).hexdigest()
    return f"{_STUB_SIG_HEAD}\ncapauth-test-stub:{digest}\n{_STUB_SIG_TAIL}\n"


@pytest.fixture
def stub_token_signing(monkeypatch):
    """Fake the gpg boundary so tokens can be signed and verified without gpg.

    Patches exactly three seams:

    * ``tokens._get_issuer_fingerprint`` so issued tokens name a plausible issuer
      instead of the ``"unknown"`` placeholder (which ``signature_verifies``
      correctly refuses as unattributable);
    * ``tokens._pgp_sign_payload`` so ``sign=True`` yields a stand-in signature
      over the payload's canonical bytes;
    * ``tokens.verify_manifest`` so verification accepts exactly that stand-in,
      for exactly those bytes, from exactly that issuer.

    Everything else, including the whole of ``signature_verifies`` and the PDP,
    runs unmodified.
    """
    from capauth import tokens as _tokens

    monkeypatch.setattr(_tokens, "_get_issuer_fingerprint", lambda home: STUB_ISSUER_FPR)
    monkeypatch.setattr(
        _tokens,
        "_pgp_sign_payload",
        lambda payload, home: stub_signature_for(payload.model_dump_json().encode()),
    )

    def _fake_verify_manifest(manifest_bytes, signature, *, expected_signer=None):
        if not signature:
            return False
        if expected_signer and expected_signer.strip().upper() != STUB_ISSUER_FPR:
            return False
        return signature == stub_signature_for(bytes(manifest_bytes))

    monkeypatch.setattr(_tokens, "verify_manifest", _fake_verify_manifest)
    return stub_signature_for
