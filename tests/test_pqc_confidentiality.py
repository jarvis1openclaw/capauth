"""capauth PQC confidentiality capability lookup (PQC cut-over, Phase 1)."""

from __future__ import annotations

import json

from capauth.pqc_confidentiality import (
    confidentiality_suite_for,
    hybrid_prekey_available,
)


def test_no_store_reports_classical(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCHAT_HOME", str(tmp_path))
    assert hybrid_prekey_available("nobody") is False
    assert confidentiality_suite_for("nobody") == "x25519-pgp-wrap-v1"


def test_published_peer_bundle_reports_hybrid(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCHAT_HOME", str(tmp_path))
    peers = tmp_path / "pqc" / "peers"
    peers.mkdir(parents=True)
    (peers / "chef.json").write_text(
        json.dumps({"suite": "x25519-mlkem768", "hybrid_public_hex": "ab" * 1216})
    )
    assert hybrid_prekey_available("capauth:chef@skworld.io") is True
    assert confidentiality_suite_for("chef") == "x25519-mlkem768"


def test_own_keypair_reports_hybrid(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCHAT_HOME", str(tmp_path))
    pqc = tmp_path / "pqc"
    pqc.mkdir(parents=True)
    (pqc / "lumina_hybrid.pub").write_text("cd" * 1216)
    assert hybrid_prekey_available("lumina") is True


def test_agent_identity_accessor(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCHAT_HOME", str(tmp_path))
    from capauth.agent_identity import AgentIdentity

    ident = AgentIdentity(agent="ghost", capauth_uri="capauth:ghost@skworld.io")
    assert ident.hybrid_prekey_available() is False
    assert ident.confidentiality_suite() == "x25519-pgp-wrap-v1"
