"""Tests for the WebAuthn passkey front-door (oidc/passkey.py).

Drives the FULL registration + authentication ceremony with a simulated
authenticator (soft-webauthn), so the begin/complete logic, persistence, and
challenge binding are all exercised without a browser.
"""

from __future__ import annotations

import base64

import pytest

soft = pytest.importorskip("soft_webauthn")
from soft_webauthn import SoftWebauthnDevice  # noqa: E402

from capauth.service.oidc.passkey import PasskeyStore, rp_origin_and_id  # noqa: E402

FP = "A1B2C3D4E5F6A7B8C9D0A1B2C3D4E5F6A7B8C9D0"


def _u2b(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b2u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _create_input(options: dict) -> dict:
    pk = dict(options)
    pk["challenge"] = _u2b(options["challenge"])
    pk["user"] = dict(options["user"], id=_u2b(options["user"]["id"]))
    if options.get("excludeCredentials"):
        pk["excludeCredentials"] = [dict(c, id=_u2b(c["id"])) for c in options["excludeCredentials"]]
    return {"publicKey": pk}


def _att_json(att: dict) -> dict:
    return {
        "id": _b2u(att["rawId"]),
        "rawId": _b2u(att["rawId"]),
        "type": "public-key",
        "response": {
            "attestationObject": _b2u(att["response"]["attestationObject"]),
            "clientDataJSON": _b2u(att["response"]["clientDataJSON"]),
            "transports": [],
        },
        "clientExtensionResults": {},
    }


def _get_input(options: dict) -> dict:
    pk = dict(options)
    pk["challenge"] = _u2b(options["challenge"])
    if options.get("allowCredentials"):
        pk["allowCredentials"] = [dict(c, id=_u2b(c["id"])) for c in options["allowCredentials"]]
    return {"publicKey": pk}


def _assert_json(asr: dict) -> dict:
    uh = asr["response"].get("userHandle")
    return {
        "id": _b2u(asr["rawId"]),
        "rawId": _b2u(asr["rawId"]),
        "type": "public-key",
        "response": {
            "authenticatorData": _b2u(asr["response"]["authenticatorData"]),
            "clientDataJSON": _b2u(asr["response"]["clientDataJSON"]),
            "signature": _b2u(asr["response"]["signature"]),
            "userHandle": _b2u(uh) if uh else None,
        },
        "clientExtensionResults": {},
    }


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", "https://example.test")


def test_origin_and_rpid(env):
    origin, rpid = rp_origin_and_id()
    assert origin == "https://example.test"
    assert rpid == "example.test"


def test_full_register_then_authenticate(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()

    # --- register (gating PGP proof is verified at the HTTP layer, not here) ---
    ticket, options = store.begin_registration(FP)
    att = device.create(_create_input(options), origin)
    fp, cid = store.complete_registration(ticket, _att_json(att))
    assert fp == FP
    assert cid in store.credentials_for(FP)
    assert store.has_any(FP)

    # persisted across a reload
    assert PasskeyStore(data_dir=str(tmp_path)).has_any(FP)

    # --- authenticate (with a fingerprint hint → allowCredentials) ---
    req_options = store.begin_authentication("req-1", FP)
    asr = device.get(_get_input(req_options), origin)
    got = store.complete_authentication("req-1", _assert_json(asr))
    assert got == FP


def test_authenticate_discoverable_no_hint(env, tmp_path):
    origin, _ = rp_origin_and_id()
    store = PasskeyStore(data_dir=str(tmp_path))
    device = SoftWebauthnDevice()
    ticket, options = store.begin_registration(FP)
    store.complete_registration(ticket, _att_json(device.create(_create_input(options), origin)))

    # no fingerprint hint → empty allowCredentials (resident/discoverable)
    req_options = store.begin_authentication("req-2", "")
    asr = device.get(_get_input(req_options), origin)
    assert store.complete_authentication("req-2", _assert_json(asr)) == FP


def test_unknown_credential_rejected(env, tmp_path):
    store = PasskeyStore(data_dir=str(tmp_path))
    store.begin_authentication("req-3", "")
    with pytest.raises(ValueError):
        store.complete_authentication(
            "req-3",
            {"id": "bogus", "rawId": "bogus", "type": "public-key", "response": {}},
        )


def test_expired_or_unknown_ticket(env, tmp_path):
    store = PasskeyStore(data_dir=str(tmp_path))
    with pytest.raises(ValueError):
        store.complete_registration("nope", {"id": "x"})
