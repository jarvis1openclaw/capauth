"""Tests for the CapAuth Bunker broker (remote signer relay).

Covers:
  - session create + pairing-secret verification
  - join: unknown session / bad secret / role-taken / invalid role
  - paired event fires to BOTH peers when both join
  - relay round-trip client -> signer and signer -> client (mocked sockets)
  - broker never inspects/sees private-key material (only relays envelopes)
  - unrelayable message types are rejected
  - leave notifies the remaining peer; expiry drops sessions
  - pairing URI build + parse round-trip
"""

from __future__ import annotations

import asyncio

import pytest

from capauth.service.bunker import (
    BunkerBroker,
    ROLE_CLIENT,
    ROLE_SIGNER,
    build_pairing_uri,
    parse_pairing_uri,
)


class FakeWS:
    """Mock async websocket that records everything sent to it."""

    def __init__(self) -> None:
        self.sent: list = []

    async def send_json(self, data) -> None:
        self.sent.append(data)


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# --- session create + secret -------------------------------------------------


def test_create_session_returns_id_and_secret():
    broker = BunkerBroker()
    s = broker.create_session()
    assert s["session_id"]
    assert s["pairing_secret"]
    assert broker.get_session(s["session_id"]) is not None


def test_join_unknown_session():
    broker = BunkerBroker()
    err = run(broker.join("nope", ROLE_CLIENT, "x", FakeWS()))
    assert err == "unknown_session"


def test_join_bad_pairing_secret():
    broker = BunkerBroker()
    s = broker.create_session()
    err = run(broker.join(s["session_id"], ROLE_CLIENT, "wrong", FakeWS()))
    assert err == "bad_pairing_secret"


def test_join_invalid_role():
    broker = BunkerBroker()
    s = broker.create_session()
    err = run(broker.join(s["session_id"], "hacker", s["pairing_secret"], FakeWS()))
    assert err == "invalid_role"


def test_role_taken():
    broker = BunkerBroker()
    s = broker.create_session()
    sec = s["pairing_secret"]
    assert run(broker.join(s["session_id"], ROLE_CLIENT, sec, FakeWS())) is None
    err = run(broker.join(s["session_id"], ROLE_CLIENT, sec, FakeWS()))
    assert err == "role_taken"


# --- pairing event -----------------------------------------------------------


def test_paired_event_fires_to_both():
    broker = BunkerBroker()
    s = broker.create_session()
    sid, sec = s["session_id"], s["pairing_secret"]
    client_ws, signer_ws = FakeWS(), FakeWS()

    assert run(broker.join(sid, ROLE_CLIENT, sec, client_ws)) is None
    # No pair event yet — only one peer.
    assert all(m["type"] != "paired" for m in client_ws.sent)

    assert run(broker.join(sid, ROLE_SIGNER, sec, signer_ws)) is None
    # Now BOTH should have a paired event.
    assert any(m["type"] == "paired" for m in client_ws.sent)
    assert any(m["type"] == "paired" for m in signer_ws.sent)


# --- relay round-trip --------------------------------------------------------


def _paired_broker():
    broker = BunkerBroker()
    s = broker.create_session()
    sid, sec = s["session_id"], s["pairing_secret"]
    client_ws, signer_ws = FakeWS(), FakeWS()
    run(broker.join(sid, ROLE_CLIENT, sec, client_ws))
    run(broker.join(sid, ROLE_SIGNER, sec, signer_ws))
    return broker, sid, client_ws, signer_ws


def test_relay_sign_request_client_to_signer():
    broker, sid, client_ws, signer_ws = _paired_broker()
    req = {
        "type": "sign_request",
        "id": "req-1",
        "payload": "CAPAUTH_NONCE_V2\nnonce=abc",
        "origin": "https://cloud.example.org",
        "fingerprint": "131C966F0281149C5F3E77EA4A673B689D64A164",
    }
    err = run(broker.relay(sid, ROLE_CLIENT, req))
    assert err is None
    # The signer received the EXACT envelope (broker is pass-through).
    assert signer_ws.sent[-1] == req
    # The client did not receive its own request echoed.
    assert all(
        m.get("id") != "req-1" or m["type"] != "sign_request"
        for m in client_ws.sent
        if m.get("type") == "sign_request"
    )


def test_relay_sign_response_signer_to_client():
    broker, sid, client_ws, signer_ws = _paired_broker()
    resp = {
        "type": "sign_response",
        "id": "req-1",
        "signature": "-----BEGIN PGP SIGNATURE-----\nMOCK\n-----END PGP SIGNATURE-----",
        "fingerprint": "131C966F0281149C5F3E77EA4A673B689D64A164",
    }
    err = run(broker.relay(sid, ROLE_SIGNER, resp))
    assert err is None
    assert client_ws.sent[-1] == resp


def test_broker_never_sees_private_key():
    """The broker only ever holds the two sockets — no key fields anywhere."""
    broker, sid, client_ws, signer_ws = _paired_broker()
    session = broker.get_session(sid)
    # The session object carries no key material, only peer sockets + secret.
    assert set(session.peers.keys()) == {ROLE_CLIENT, ROLE_SIGNER}
    # Relay a request whose payload is the canonical bytes (NOT a key); broker
    # forwards verbatim without parsing it.
    req = {"type": "sign_request", "id": "x", "payload": "CAPAUTH_NONCE_V2\n..."}
    run(broker.relay(sid, ROLE_CLIENT, req))
    forwarded = signer_ws.sent[-1]
    assert "private" not in str(forwarded).lower()
    assert forwarded["payload"].startswith("CAPAUTH_NONCE_V2")


def test_relay_rejects_unrelayable_type():
    broker, sid, _, _ = _paired_broker()
    err = run(broker.relay(sid, ROLE_CLIENT, {"type": "hello"}))
    assert err == "unrelayable_type"


def test_relay_peer_absent():
    broker = BunkerBroker()
    s = broker.create_session()
    sid, sec = s["session_id"], s["pairing_secret"]
    run(broker.join(sid, ROLE_CLIENT, sec, FakeWS()))
    # No signer joined.
    err = run(broker.relay(sid, ROLE_CLIENT, {"type": "sign_request", "id": "1"}))
    assert err == "peer_absent"


def test_approve_and_reject_are_relayed():
    broker, sid, client_ws, signer_ws = _paired_broker()
    run(broker.relay(sid, ROLE_SIGNER, {"type": "approve", "id": "1"}))
    run(broker.relay(sid, ROLE_SIGNER, {"type": "reject", "id": "2", "reason": "no"}))
    types = [m["type"] for m in client_ws.sent]
    assert "approve" in types and "reject" in types


def test_kex_and_enc_are_relayed():
    # E2E handshake + sealed envelopes must pass through the broker.
    broker, sid, client_ws, signer_ws = _paired_broker()
    assert run(broker.relay(sid, ROLE_CLIENT, {"type": "kex", "pub": "AAAA"})) is None
    assert run(broker.relay(sid, ROLE_CLIENT, {"type": "enc", "id": "e1", "ct": "zzz"})) is None
    types = [m["type"] for m in signer_ws.sent]
    assert "kex" in types and "enc" in types


def test_replay_duplicate_request_id_rejected():
    # The same client request id may only be relayed once (replay guard).
    broker, sid, _, _ = _paired_broker()
    assert run(broker.relay(sid, ROLE_CLIENT, {"type": "enc", "id": "dup", "ct": "a"})) is None
    err = run(broker.relay(sid, ROLE_CLIENT, {"type": "enc", "id": "dup", "ct": "a"}))
    assert err == "duplicate_request"
    # signer->client direction is not deduped (sign_response can echo the id).
    assert run(broker.relay(sid, ROLE_SIGNER, {"type": "enc", "id": "dup", "ct": "b"})) is None


def test_session_capacity_cap():
    broker = BunkerBroker(max_sessions=2)
    broker.create_session()
    broker.create_session()
    from capauth.service.bunker import BunkerCapacityError

    with pytest.raises(BunkerCapacityError):
        broker.create_session()


# --- leave + expiry ----------------------------------------------------------


def test_leave_notifies_remaining_peer():
    broker, sid, client_ws, signer_ws = _paired_broker()
    run(broker.leave(sid, ROLE_SIGNER))
    assert client_ws.sent[-1] == {"type": "peer_left", "role": ROLE_SIGNER}


def test_session_expires():
    broker = BunkerBroker(ttl_seconds=0)
    s = broker.create_session()
    # ttl=0 → immediately expired on next access.
    assert broker.get_session(s["session_id"]) is None


# --- pairing URI -------------------------------------------------------------


def test_pairing_uri_round_trip():
    uri = build_pairing_uri(
        "capauth-skstack41.skworld.io",
        "sess-123",
        "secret-xyz",
        "wss://capauth-skstack41.skworld.io/bunker/ws",
    )
    assert uri.startswith("capauth-bunker://capauth-skstack41.skworld.io/sess-123?")
    parsed = parse_pairing_uri(uri)
    assert parsed["broker_host"] == "capauth-skstack41.skworld.io"
    assert parsed["session_id"] == "sess-123"
    assert parsed["pairing_secret"] == "secret-xyz"
    assert parsed["relay"] == "wss://capauth-skstack41.skworld.io/bunker/ws"


def test_parse_rejects_non_bunker_uri():
    with pytest.raises(ValueError):
        parse_pairing_uri("https://example.org/foo")


# --- WS endpoint integration (FastAPI TestClient) ---------------------------


def test_ws_endpoint_pairs_and_relays_end_to_end():
    """Full broker path via the real FastAPI WebSocket endpoint.

    Client + signer connect over the actual /bunker/ws route, get paired, and a
    sign_request relays to the signer; a sign_response relays back. Proves the
    canonical bytes survive the relay byte-for-byte.
    """
    from fastapi.testclient import TestClient

    from capauth.service.app import app

    canonical = (
        "CAPAUTH_NONCE_V2\n"
        "nonce=11111111-2222-4333-8444-555555555555\n"
        "client_nonce=Y2xpZW50LW5vbmNlLWZpeGVk\n"
        "origin=https://cloud.example.org\n"
        "timestamp=2026-06-22T12:00:00+00:00\n"
        "service=cloud.example.org\n"
        "expires=2026-06-22T12:02:00+00:00"
    )

    client = TestClient(app)
    sess = client.post("/bunker/session").json()
    sid = sess["session_id"]
    secret = sess["pairing_secret"]
    assert sess["pairing_uri"].startswith("capauth-bunker://")

    with client.websocket_connect(f"/bunker/ws?session={sid}&role=client&key={secret}") as cws:
        with client.websocket_connect(f"/bunker/ws?session={sid}&role=signer&key={secret}") as sws:
            # Both should get a paired event.
            assert cws.receive_json()["type"] == "paired"
            assert sws.receive_json()["type"] == "paired"

            # Client → signer: the canonical bytes.
            cws.send_json(
                {
                    "type": "sign_request",
                    "id": "r1",
                    "payload": canonical,
                    "origin": "https://cloud.example.org",
                }
            )
            got = sws.receive_json()
            assert got["type"] == "sign_request"
            assert got["payload"] == canonical  # byte-identical across the relay

            # Signer → client: the signature.
            sws.send_json(
                {"type": "sign_response", "id": "r1", "signature": "ARMORED", "fingerprint": "FP"}
            )
            back = cws.receive_json()
            assert back["type"] == "sign_response"
            assert back["signature"] == "ARMORED"


def test_ws_endpoint_rejects_bad_secret():
    from fastapi.testclient import TestClient

    from capauth.service.app import app

    client = TestClient(app)
    sess = client.post("/bunker/session").json()
    sid = sess["session_id"]
    with client.websocket_connect(f"/bunker/ws?session={sid}&role=client&key=wrong") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "bad_pairing_secret"


# --- session persistence / restart survivability ----------------------------
#
# Card 3db2c81d: an approved bunker pairing session must survive a service
# restart so clients do not have to re-pair. These prove: a session survives a
# simulated restart (fresh broker over the same store), expired sessions are not
# reloaded, a corrupt/missing store does not crash the broker, the store file is
# mode 0600, and the replay guard (seen_ids) also survives the restart.


def test_session_survives_restart(tmp_path):
    store = tmp_path / "bunker_sessions.json"
    broker1 = BunkerBroker(store_path=store)
    created = broker1.create_session()
    sid, secret = created["session_id"], created["pairing_secret"]

    # Simulate a restart: a brand-new broker pointed at the same store.
    broker2 = BunkerBroker(store_path=store)
    reloaded = broker2.get_session(sid)
    assert reloaded is not None, "session should survive the restart"

    # And it is still USABLE: both peers can (re)pair with the same secret and
    # relay a round-trip through the reloaded session.
    cws, sws = FakeWS(), FakeWS()
    assert run(broker2.join(sid, ROLE_CLIENT, secret, cws)) is None
    assert run(broker2.join(sid, ROLE_SIGNER, secret, sws)) is None
    assert reloaded.is_paired
    err = run(broker2.relay(sid, ROLE_CLIENT, {"type": "sign_request", "id": "r1"}))
    assert err is None
    assert sws.sent[-1]["type"] == "sign_request"


def test_wrong_secret_still_rejected_after_restart(tmp_path):
    store = tmp_path / "bunker_sessions.json"
    b1 = BunkerBroker(store_path=store)
    sid = b1.create_session()["session_id"]
    b2 = BunkerBroker(store_path=store)
    # A reloaded session must keep enforcing its pairing secret.
    assert run(b2.join(sid, ROLE_CLIENT, "not-the-secret", FakeWS())) == "bad_pairing_secret"


def test_expired_sessions_not_reloaded(tmp_path):
    import json
    import time

    store = tmp_path / "bunker_sessions.json"
    now = time.time()
    store.write_text(
        json.dumps(
            {
                "version": 1,
                "sessions": [
                    {  # expired: created long ago, past its TTL
                        "session_id": "old",
                        "pairing_secret": "s1",
                        "ttl_seconds": 300,
                        "created_at": now - 10_000,
                        "seen_ids": [],
                    },
                    {  # fresh: well within TTL
                        "session_id": "new",
                        "pairing_secret": "s2",
                        "ttl_seconds": 300,
                        "created_at": now,
                        "seen_ids": [],
                    },
                ],
            }
        )
    )
    broker = BunkerBroker(store_path=store)
    assert broker.get_session("old") is None
    assert broker.get_session("new") is not None


def test_corrupt_store_does_not_crash(tmp_path):
    store = tmp_path / "bunker_sessions.json"
    store.write_text("{ this is not valid json ]]]")
    broker = BunkerBroker(store_path=store)  # must not raise
    # Starts empty and remains fully functional.
    created = broker.create_session()
    assert broker.get_session(created["session_id"]) is not None


def test_missing_store_does_not_crash(tmp_path):
    store = tmp_path / "does-not-exist" / "bunker_sessions.json"
    broker = BunkerBroker(store_path=store)  # must not raise
    created = broker.create_session()
    assert store.exists()  # created on first save
    assert broker.get_session(created["session_id"]) is not None


def test_store_file_is_mode_0600(tmp_path):
    import stat

    store = tmp_path / "bunker_sessions.json"
    broker = BunkerBroker(store_path=store)
    broker.create_session()
    mode = stat.S_IMODE(store.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_replay_guard_survives_restart(tmp_path):
    store = tmp_path / "bunker_sessions.json"
    b1 = BunkerBroker(store_path=store)
    sid = b1.create_session()["session_id"]
    secret = b1.get_session(sid).pairing_secret
    cws, sws = FakeWS(), FakeWS()
    run(b1.join(sid, ROLE_CLIENT, secret, cws))
    run(b1.join(sid, ROLE_SIGNER, secret, sws))
    # First relay of id "dup" records it in seen_ids (and persists it). The relay
    # ran on an event loop, so the store write is queued; flush before "restart".
    assert run(b1.relay(sid, ROLE_CLIENT, {"type": "sign_request", "id": "dup"})) is None
    b1.flush()

    # Restart: a fresh broker reloads the session AND its seen_ids, so the same
    # request id cannot be replayed against the reloaded session.
    b2 = BunkerBroker(store_path=store)
    err = run(b2.relay(sid, ROLE_CLIENT, {"type": "sign_request", "id": "dup"}))
    assert err == "duplicate_request"


def test_no_store_path_is_pure_in_memory(tmp_path):
    # Default behaviour (no store_path) persists nothing.
    broker = BunkerBroker()
    broker.create_session()
    assert list(tmp_path.iterdir()) == []


def test_secret_persisted_but_no_key_material(tmp_path):
    # The store carries the opaque pairing secret + ids only; assert there is no
    # PGP/private-key material serialized (defense-in-depth on the schema).
    store = tmp_path / "bunker_sessions.json"
    broker = BunkerBroker(store_path=store)
    broker.create_session()
    blob = store.read_text()
    assert "PRIVATE KEY" not in blob
    assert "BEGIN PGP" not in blob
