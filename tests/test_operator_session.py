"""Tests for capauth.pairing.operator_session (Unified Consent Plane, Phase 1).

Lifted alongside the module itself from skchat's operator_auth test suite
(test_operator_auth_session.py, test_operator_auth_device.py), plus new
coverage the move requires:

* the missing-``approved``-key fail-open is CLOSED here (opposite of the
  skchat original it was lifted from) -- see ``test_missing_approved_key_...``;
* device-fp revocation and session (jti) revocation are both native capauth
  state now, not delegated to ``skchat.guest``;
* the legacy secret/path env var fallbacks that keep an in-flight cutover
  from invalidating already-live sessions.

Every test injects its own ``tmp_path`` as ``home=`` (or points the device
store env var at ``tmp_path``); nothing here touches a real
``~/.skcapstone/capauth`` directory.
"""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from capauth.pairing import operator_session as oa


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv(oa._SECRET_ENV, "test-secret-at-least-32-bytes-long!!")
    monkeypatch.delenv(oa._SECRET_ENV_LEGACY, raising=False)


# ── mint / verify: the JWT shape itself ──────────────────────────────────────


def test_mint_then_verify_roundtrip(tmp_path):
    token = oa.mint_operator_session(device_fp="abc123", ttl=60)
    oa.approve_device("abc123", approved_by="chef", home=tmp_path)
    sess = oa.verify_operator_session(token, home=tmp_path)
    assert sess.device_fp == "abc123"
    assert sess.exp > int(time.time())


def test_expired_is_rejected(tmp_path):
    token = oa.mint_operator_session(device_fp="abc123", ttl=-1)
    oa.approve_device("abc123", home=tmp_path)
    with pytest.raises(oa.OperatorAuthError):
        oa.verify_operator_session(token, home=tmp_path)


def test_wrong_secret_is_rejected(tmp_path, monkeypatch):
    token = oa.mint_operator_session(device_fp="abc123", ttl=60)
    monkeypatch.setenv(oa._SECRET_ENV, "a-completely-different-secret-value")
    oa.approve_device("abc123", home=tmp_path)
    with pytest.raises(oa.OperatorAuthError):
        oa.verify_operator_session(token, home=tmp_path)


def test_no_secret_set_raises(tmp_path, monkeypatch):
    monkeypatch.delenv(oa._SECRET_ENV, raising=False)
    monkeypatch.delenv(oa._SECRET_ENV_LEGACY, raising=False)
    with pytest.raises(oa.OperatorAuthError):
        oa.mint_operator_session(device_fp="abc123")


def test_legacy_secret_env_var_still_works(tmp_path, monkeypatch):
    """A fleet mid-cutover has the secret under the OLD skchat env var name."""
    monkeypatch.delenv(oa._SECRET_ENV, raising=False)
    monkeypatch.setenv(oa._SECRET_ENV_LEGACY, "legacy-secret-still-32-bytes-ok!")
    token = oa.mint_operator_session(device_fp="abc123", ttl=60)
    oa.approve_device("abc123", home=tmp_path)
    sess = oa.verify_operator_session(token, home=tmp_path)
    assert sess.device_fp == "abc123"


def test_missing_required_claim_rejected(tmp_path):
    """A token missing a required claim (forged, or from an old shape) fails closed."""
    import jwt

    bad = jwt.encode(
        {"tier": "operator-session", "device_fp": "x"}, oa._secret(), algorithm="HS256"
    )
    with pytest.raises(oa.OperatorAuthError):
        oa.verify_operator_session(bad, home=tmp_path)


def test_wrong_tier_rejected(tmp_path):
    import jwt

    now = int(time.time())
    bad = jwt.encode(
        {
            "jti": "j1",
            "tier": "guest-session",
            "device_fp": "abc123",
            "iat": now,
            "exp": now + 60,
        },
        oa._secret(),
        algorithm="HS256",
    )
    oa.approve_device("abc123", home=tmp_path)
    with pytest.raises(oa.OperatorAuthError, match="wrong tier"):
        oa.verify_operator_session(bad, home=tmp_path)


# ── device standing: approval, the fail-open closure (AC4) ─────────────────


def test_unapproved_device_with_no_row_is_rejected(tmp_path):
    """No standing row at all for the device -> rejected."""
    token = oa.mint_operator_session(device_fp="never-enrolled", ttl=60)
    with pytest.raises(oa.OperatorAuthError, match="pending approval"):
        oa.verify_operator_session(token, home=tmp_path)


def test_missing_approved_key_in_an_existing_row_is_rejected(tmp_path):
    """THE fail-open this move closes.

    skchat's original ``device_registry.is_approved()`` read a row with no
    ``approved`` key as approved (a deliberate grandfather for devices
    enrolled before Phase 3 shipped). That default does not carry over here:
    a device with a standing row that simply never got an explicit
    ``approved: true`` (e.g. it only has ``revoked: False`` from some other
    write path, or a hand-edited/partial row) must still fail verification.
    """
    device_fp = "legacy-shaped-row"
    # Write a state row directly, bypassing approve_device(), to simulate a
    # row that exists but was never explicitly approved.
    path = oa._device_state_path(tmp_path)
    oa._write_json(path, {device_fp: {"revoked": False, "label": "no approved key"}})

    token = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    with pytest.raises(oa.OperatorAuthError, match="pending approval"):
        oa.verify_operator_session(token, home=tmp_path)

    # Confirm it is not merely absent from is_device_approved's fast path --
    # the underlying row genuinely lacks the key.
    assert "approved" not in oa._load_json(path)[device_fp]
    assert oa.is_device_approved(device_fp, home=tmp_path) is False


def test_approve_device_flips_verification_to_pass(tmp_path):
    device_fp = "fp-approve-me"
    token = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    assert oa.is_device_approved(device_fp, home=tmp_path) is False
    oa.approve_device(device_fp, approved_by="chef", home=tmp_path)
    assert oa.is_device_approved(device_fp, home=tmp_path) is True
    sess = oa.verify_operator_session(token, home=tmp_path)
    assert sess.device_fp == device_fp


def test_unreadable_device_state_store_reads_as_not_approved(tmp_path):
    """Unlike the skchat original (unreadable registry -> fail OPEN), an
    unreadable operator device-state file here fails CLOSED, consistent with
    "no row" and "row missing the key" both reading as not-approved."""
    path = oa._device_state_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json")
    assert oa.is_device_approved("anything", home=tmp_path) is False


# ── revocation: device-level and session-level (AC3) ────────────────────────


def test_revoked_device_fails_verification(tmp_path):
    device_fp = "fp-revoke-me"
    token = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    oa.approve_device(device_fp, home=tmp_path)
    # sanity: passes before revocation
    oa.verify_operator_session(token, home=tmp_path)

    oa.revoke_device(device_fp, reason="lost phone", home=tmp_path)
    with pytest.raises(oa.OperatorAuthError, match="device revoked"):
        oa.verify_operator_session(token, home=tmp_path)


def test_device_revocation_kills_every_session_for_that_device(tmp_path):
    """One device-level revoke invalidates ALL sessions minted for it, not
    just the one checked -- the whole point of keying revocation on device_fp
    instead of requiring the caller to enumerate jtis."""
    device_fp = "fp-multi-session"
    oa.approve_device(device_fp, home=tmp_path)
    tokens = [oa.mint_operator_session(device_fp=device_fp, ttl=60) for _ in range(3)]
    for t in tokens:
        oa.verify_operator_session(t, home=tmp_path)  # all valid before revoke

    oa.revoke_device(device_fp, home=tmp_path)
    for t in tokens:
        with pytest.raises(oa.OperatorAuthError):
            oa.verify_operator_session(t, home=tmp_path)


def test_unrevoke_device_restores_verification(tmp_path):
    device_fp = "fp-unrevoke-me"
    oa.approve_device(device_fp, home=tmp_path)
    token = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    oa.revoke_device(device_fp, home=tmp_path)
    assert oa.is_device_revoked(device_fp, home=tmp_path) is True

    oa.unrevoke_device(device_fp, home=tmp_path)
    assert oa.is_device_revoked(device_fp, home=tmp_path) is False
    oa.verify_operator_session(token, home=tmp_path)  # no longer raises


def test_revoked_session_fails_even_on_an_approved_non_revoked_device(tmp_path):
    device_fp = "fp-session-revoke"
    oa.approve_device(device_fp, home=tmp_path)
    token = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    sess = oa.verify_operator_session(token, home=tmp_path)

    oa.revoke_session(sess.jti, home=tmp_path)
    with pytest.raises(oa.OperatorAuthError, match="revoked"):
        oa.verify_operator_session(token, home=tmp_path)


def test_revoking_one_session_does_not_affect_a_sibling_session(tmp_path):
    device_fp = "fp-sibling-sessions"
    oa.approve_device(device_fp, home=tmp_path)
    token_a = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    token_b = oa.mint_operator_session(device_fp=device_fp, ttl=60)
    sess_a = oa.verify_operator_session(token_a, home=tmp_path)

    oa.revoke_session(sess_a.jti, home=tmp_path)
    with pytest.raises(oa.OperatorAuthError):
        oa.verify_operator_session(token_a, home=tmp_path)
    oa.verify_operator_session(token_b, home=tmp_path)  # unaffected


def test_revoke_nonexistent_device_and_session_are_harmless(tmp_path):
    oa.revoke_device("", home=tmp_path)
    oa.revoke_device("never-seen", home=tmp_path)
    oa.revoke_session("", home=tmp_path)
    oa.revoke_session("never-minted", home=tmp_path)
    oa.unrevoke_device("never-seen", home=tmp_path)


# ── device-key challenge/response handshake (moved verbatim) ───────────────


def _ec_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, base64.b64encode(pub_der).decode()


def _sign_der_b64(priv, payload: bytes) -> str:
    return base64.b64encode(priv.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()


def _sign_p1363_b64(priv, payload: bytes) -> str:
    der_sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def test_device_fingerprint_is_stable_and_derived_from_pubkey():
    priv, pub_b64 = _ec_keypair()
    fp1 = oa.device_fingerprint(pub_b64)
    fp2 = oa.device_fingerprint(pub_b64)
    assert fp1 == fp2
    assert len(fp1) == 16
    _priv2, other_pub_b64 = _ec_keypair()
    assert oa.device_fingerprint(other_pub_b64) != fp1


def test_verify_device_signature_der_and_p1363_both_accepted():
    priv, pub_b64 = _ec_keypair()
    payload = b'{"nonce":"abc","device_fp":"xyz"}'
    assert oa.verify_device_signature(
        device_pubkey_b64=pub_b64, payload=payload, sig_b64=_sign_der_b64(priv, payload)
    )
    assert oa.verify_device_signature(
        device_pubkey_b64=pub_b64, payload=payload, sig_b64=_sign_p1363_b64(priv, payload)
    )


def test_verify_device_signature_rejects_wrong_key_or_payload():
    priv, pub_b64 = _ec_keypair()
    _other_priv, other_pub_b64 = _ec_keypair()
    payload = b"the-real-payload"
    sig = _sign_der_b64(priv, payload)
    assert not oa.verify_device_signature(
        device_pubkey_b64=other_pub_b64, payload=payload, sig_b64=sig
    )
    assert not oa.verify_device_signature(
        device_pubkey_b64=pub_b64, payload=b"tampered-payload", sig_b64=sig
    )
    assert not oa.verify_device_signature(
        device_pubkey_b64=pub_b64, payload=payload, sig_b64="not-base64!!!"
    )


def test_challenge_issue_consume_is_single_use_and_time_bound():
    nonce, exp = oa.issue_challenge()
    assert exp > int(time.time())
    assert oa.consume_challenge(nonce) is True
    # single-use: a second consume of the same nonce fails
    assert oa.consume_challenge(nonce) is False


def test_consume_unknown_challenge_fails():
    assert oa.consume_challenge("never-issued") is False


# ── DeviceStore (enrolled device pubkeys) ────────────────────────────────────


def test_device_store_enroll_lookup_remove(tmp_path):
    store = oa.DeviceStore(tmp_path / "devices.json")
    _priv, pub_b64 = _ec_keypair()
    fp = store.enroll(pub_b64)
    assert store.is_enrolled(fp)
    assert store.pubkey_for(fp) == pub_b64
    assert fp in store.list_fps()

    assert store.remove(fp) is True
    assert not store.is_enrolled(fp)
    assert store.remove(fp) is False  # already gone


def test_device_store_persists_across_instances(tmp_path):
    path = tmp_path / "devices.json"
    _priv, pub_b64 = _ec_keypair()
    fp = oa.DeviceStore(path).enroll(pub_b64)

    reloaded = oa.DeviceStore(path)
    assert reloaded.pubkey_for(fp) == pub_b64


def test_device_store_clear(tmp_path):
    store = oa.DeviceStore(tmp_path / "devices.json")
    for _ in range(3):
        _priv, pub_b64 = _ec_keypair()
        store.enroll(pub_b64)
    assert store.clear() == 3
    assert store.list_fps() == []


def test_default_device_store_path_prefers_new_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv(oa.OPERATOR_DEVICES_PATH_ENV, str(tmp_path / "new.json"))
    monkeypatch.setenv(oa._OPERATOR_DEVICES_PATH_ENV_LEGACY, str(tmp_path / "legacy.json"))
    assert oa.default_device_store_path() == tmp_path / "new.json"


def test_default_device_store_path_falls_back_to_legacy_env_var(monkeypatch, tmp_path):
    monkeypatch.delenv(oa.OPERATOR_DEVICES_PATH_ENV, raising=False)
    monkeypatch.setenv(oa._OPERATOR_DEVICES_PATH_ENV_LEGACY, str(tmp_path / "legacy.json"))
    assert oa.default_device_store_path() == tmp_path / "legacy.json"
