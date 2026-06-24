"""Tests that the CapAuth service accepts v6 (64-hex) fingerprints.

PQC / RFC 9580 (OpenPGP v6) keys have 64-hex-char fingerprints; classic v4
keys have 40-hex. The ``/capauth/v1/challenge`` length gate must accept BOTH
(additive — 40 must still work exactly as before) so a post-quantum root can
resolve / authenticate.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from capauth.service.app import app

client = TestClient(app)

FP_V4 = "A" * 40  # classic v4 (40 hex)
FP_V6 = "B" * 64  # PQC / v6 (64 hex, RFC 9580)
FP_BAD = "C" * 50  # neither 40 nor 64 — must still be rejected


def _challenge(fingerprint: str):
    return client.post(
        "/capauth/v1/challenge",
        json={
            "capauth_version": "1.0",
            "fingerprint": fingerprint,
            "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        },
    )


def _is_length_gate_rejection(resp) -> bool:
    """True iff the response is the 400 invalid_fingerprint length-gate error."""
    if resp.status_code != 400:
        return False
    try:
        detail = resp.json().get("detail", {})
    except Exception:
        return False
    return isinstance(detail, dict) and detail.get("error") == "invalid_fingerprint"


def test_v6_fingerprint_not_rejected_by_length_gate() -> None:
    """A 64-hex (v6/PQC) fingerprint must NOT hit the 'must be 40' length gate.

    It should proceed past the gate (and either succeed or fail later for a
    DIFFERENT reason — never the invalid_fingerprint length rejection).
    """
    resp = _challenge(FP_V6)
    assert not _is_length_gate_rejection(
        resp
    ), f"64-hex fingerprint was rejected by the length gate: {resp.status_code} {resp.text}"


def test_v4_fingerprint_still_accepted() -> None:
    """A 40-hex (v4) fingerprint must still pass the length gate (additive)."""
    resp = _challenge(FP_V4)
    assert not _is_length_gate_rejection(
        resp
    ), f"40-hex fingerprint regressed at the length gate: {resp.status_code} {resp.text}"
    # The happy path issues a challenge nonce.
    assert resp.status_code == 200, resp.text
    assert resp.json().get("nonce")


def test_v6_fingerprint_issues_challenge() -> None:
    """A 64-hex fingerprint should proceed to a normal challenge issuance."""
    resp = _challenge(FP_V6)
    assert resp.status_code == 200, resp.text
    assert resp.json().get("nonce")


def test_invalid_length_still_rejected() -> None:
    """A non-40/64 length must still be rejected by the length gate (not widened)."""
    resp = _challenge(FP_BAD)
    assert _is_length_gate_rejection(
        resp
    ), f"50-hex fingerprint should be rejected by the length gate: {resp.status_code} {resp.text}"


def test_empty_fingerprint_rejected() -> None:
    """An empty fingerprint must still be rejected by the length gate."""
    resp = _challenge("")
    assert _is_length_gate_rejection(
        resp
    ), f"empty fingerprint should be rejected: {resp.status_code} {resp.text}"
