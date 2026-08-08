"""PQC Q0 — crypto-agility scaffolding tests for capauth.

Covers:
    - Classical Algorithm values still work / default unchanged.
    - PQC stub values are declared, flagged post-quantum, and map to suite ids.
    - KeyInfo round-trips with a PQC algorithm value (declaration only).
    - Backends raise NotImplementedError for PQC stubs (not silently classical).
    - Back-compat: a KeyInfo serialized without algorithm defaults to ed25519.
"""

from __future__ import annotations

import pytest

from capauth.models import Algorithm, KeyInfo


def test_classical_algorithms_unchanged():
    assert Algorithm.ED25519.value == "ed25519"
    assert Algorithm.RSA4096.value == "rsa4096"
    assert not Algorithm.ED25519.is_post_quantum
    assert not Algorithm.RSA4096.is_post_quantum


def test_pqc_stub_values_declared():
    assert Algorithm.ML_KEM_768.value == "ml-kem-768"
    assert Algorithm.ML_DSA_65.value == "ml-dsa-65"
    assert Algorithm.HYBRID_X25519_MLKEM768.value == "hybrid-x25519-mlkem768"
    assert Algorithm.HYBRID_ED25519_MLDSA65.value == "hybrid-ed25519-mldsa65"
    assert Algorithm.SLH_DSA_SHAKE_256.value == "slh-dsa-shake-256"


def test_pqc_stubs_flagged_post_quantum():
    for alg in (
        Algorithm.ML_KEM_768,
        Algorithm.ML_DSA_65,
        Algorithm.HYBRID_X25519_MLKEM768,
        Algorithm.HYBRID_ED25519_MLDSA65,
        Algorithm.SLH_DSA_SHAKE_256,
    ):
        assert alg.is_post_quantum


def test_algorithm_maps_to_suite_id():
    assert Algorithm.ED25519.crypto_suite_id == "ed25519-v1"
    assert Algorithm.RSA4096.crypto_suite_id == "rsa4096-v1"
    assert Algorithm.HYBRID_X25519_MLKEM768.crypto_suite_id == "x25519-mlkem768-v2"
    assert Algorithm.HYBRID_ED25519_MLDSA65.crypto_suite_id == "mldsa65-ed25519-v2"
    assert Algorithm.SLH_DSA_SHAKE_256.crypto_suite_id == "slh-dsa-shake-256-v2"


def test_keyinfo_default_algorithm_is_classical():
    ki = KeyInfo(
        fingerprint="F" * 40,
        public_key_path="/pub.asc",
        private_key_path="/priv.asc",
    )
    assert ki.algorithm == Algorithm.ED25519


def test_keyinfo_backcompat_without_algorithm_field():
    """A KeyInfo serialized before extra algos existed must still load."""
    data = {
        "fingerprint": "A" * 40,
        "public_key_path": "/pub.asc",
        "private_key_path": "/priv.asc",
        # no algorithm key
    }
    ki = KeyInfo.model_validate(data)
    assert ki.algorithm == Algorithm.ED25519


def test_keyinfo_accepts_pqc_stub_declaration():
    ki = KeyInfo(
        fingerprint="B" * 40,
        algorithm=Algorithm.HYBRID_ED25519_MLDSA65,
        public_key_path="/pub.asc",
        private_key_path="/priv.asc",
    )
    loaded = KeyInfo.model_validate_json(ki.model_dump_json())
    assert loaded.algorithm == Algorithm.HYBRID_ED25519_MLDSA65


def test_pgpy_backend_rejects_pqc_stub():
    pgpy_backend = pytest.importorskip("capauth.crypto.pgpy_backend")
    backend = pgpy_backend.PGPyBackend()
    with pytest.raises(NotImplementedError):
        backend.generate_keypair("x", "x@y.z", "pw", algorithm=Algorithm.ML_DSA_65)
