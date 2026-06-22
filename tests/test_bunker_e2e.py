"""Tests for the CapAuth Bunker relay E2E-encryption (capauth-bunker-e2e-v1).

Covers: the shared cross-impl vector (KDF + AEAD bytes), the X25519 ECDH
round-trip, the E2ESession handshake, and tamper detection. The JS suite
(browser-extension/tests/unit/bunker_e2e.test.js) asserts the SAME vector so the
broker-blind channel can never drift between Python and JS.
"""

from __future__ import annotations

import binascii
import json
import pathlib

import pytest

from capauth.service.bunker_e2e import (
    E2ESession,
    derive_key,
    derive_key_from_shared,
    generate_keypair,
    open_msg,
    seal,
)

_VECTOR = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "bunker_e2e_v1_vector.json").read_text()
)


def test_vector_key_derivation_matches():
    shared = binascii.unhexlify(_VECTOR["inputs"]["shared_secret_hex"])
    key = derive_key_from_shared(shared, _VECTOR["inputs"]["pairing_secret"])
    assert key.hex() == _VECTOR["expected"]["aes_key_hex"]


def test_vector_aead_ciphertext_matches():
    shared = binascii.unhexlify(_VECTOR["inputs"]["shared_secret_hex"])
    key = derive_key_from_shared(shared, _VECTOR["inputs"]["pairing_secret"])
    nonce = binascii.unhexlify(_VECTOR["inputs"]["nonce_hex"])
    # seal() takes the object; json.dumps(separators=",":") must reproduce the
    # vector's exact plaintext bytes — this also pins our serialisation.
    obj = json.loads(_VECTOR["inputs"]["plaintext_utf8"])
    wire = seal(key, obj, nonce=nonce)
    got_hex = binascii.hexlify(__import__("base64").b64decode(wire)).decode()
    assert got_hex == _VECTOR["expected"]["ciphertext_wire_hex"]


def test_vector_open_roundtrips():
    shared = binascii.unhexlify(_VECTOR["inputs"]["shared_secret_hex"])
    key = derive_key_from_shared(shared, _VECTOR["inputs"]["pairing_secret"])
    import base64

    wire = base64.b64encode(
        binascii.unhexlify(_VECTOR["expected"]["ciphertext_wire_hex"])
    ).decode()
    assert open_msg(key, wire) == json.loads(_VECTOR["inputs"]["plaintext_utf8"])


def test_vector_with_frag_matches():
    # active-MITM hardening: the QR-only frag is mixed into the HKDF info.
    shared = binascii.unhexlify(_VECTOR["inputs"]["shared_secret_hex"])
    frag = _VECTOR["inputs"]["qr_fragment"]
    key = derive_key_from_shared(shared, _VECTOR["inputs"]["pairing_secret"], frag)
    assert key.hex() == _VECTOR["expected"]["aes_key_with_frag_hex"]
    nonce = binascii.unhexlify(_VECTOR["inputs"]["nonce_hex"])
    obj = json.loads(_VECTOR["inputs"]["plaintext_utf8"])
    wire = seal(key, obj, nonce=nonce)
    import base64

    assert (
        binascii.hexlify(base64.b64decode(wire)).decode()
        == _VECTOR["expected"]["ciphertext_wire_with_frag_hex"]
    )


def test_frag_mismatch_cannot_decrypt():
    # A broker that substitutes kex keys but lacks the QR frag derives a
    # different key and cannot read the channel.
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    wire = seal(derive_key(a_priv, b_pub, "p", "secret-frag"), {"id": "1", "x": 1})
    with pytest.raises(Exception):
        open_msg(derive_key(b_priv, a_pub, "p", ""), wire)  # no frag


def test_x25519_ecdh_both_sides_agree():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    ka = derive_key(a_priv, b_pub, "secret123")
    kb = derive_key(b_priv, a_pub, "secret123")
    assert ka == kb
    # and a different pairing secret yields a different key (salt is bound in)
    kc = derive_key(a_priv, b_pub, "secret999")
    assert kc != ka


def test_e2e_session_handshake_roundtrip():
    client = E2ESession("pair-xyz")
    signer = E2ESession("pair-xyz")
    c_kex = client.start()
    s_kex = signer.start()
    assert c_kex["type"] == "kex" and s_kex["type"] == "kex"
    client.on_kex(s_kex["pub"])
    signer.on_kex(c_kex["pub"])
    assert client.is_secure and signer.is_secure

    req = {"type": "sign_request", "id": "r1", "payload": "CAPAUTH_NONCE_V2\n..."}
    env = client.seal_msg(req)
    assert env["type"] == "enc" and env["id"] == "r1" and "payload" not in env
    assert signer.open(env) == req

    resp = {"type": "sign_response", "id": "r1", "signature": "-----BEGIN..."}
    assert client.open(signer.seal_msg(resp)) == resp


def test_session_requires_kex_before_seal():
    s = E2ESession("p")
    s.start()
    with pytest.raises(RuntimeError):
        s.seal_msg({"id": "x"})


def test_tampered_ciphertext_fails():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    key = derive_key(a_priv, b_pub, "p")
    wire = seal(key, {"id": "1", "secret": "hi"})
    import base64

    blob = bytearray(base64.b64decode(wire))
    blob[-1] ^= 0x01  # flip a tag byte
    tampered = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(Exception):
        open_msg(derive_key(b_priv, a_pub, "p"), tampered)


def test_wrong_pairing_secret_cannot_decrypt():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    wire = seal(derive_key(a_priv, b_pub, "right"), {"id": "1", "x": 1})
    with pytest.raises(Exception):
        open_msg(derive_key(b_priv, a_pub, "wrong"), wire)
