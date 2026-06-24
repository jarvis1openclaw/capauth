"""Tests for PQC/v6 (RFC 9580) fingerprint acceptance in the resolver.

capauth historically assumed 40-hex (v4) OpenPGP fingerprints.  PQC roots use
OpenPGP v6 keys (RFC 9580) whose fingerprints are 64 hex chars.  The canonical
resolver (:func:`capauth.agent_identity.resolve_agent_identity`) must surface a
real fingerprint for BOTH widths — never ``None`` for a valid v6 root — while
still accepting v4 exactly as before (additive, non-narrowing).
"""

from __future__ import annotations

import json
from pathlib import Path

from capauth.agent_identity import resolve_agent_identity


def _write_profile(tmp_path: Path, fp: str) -> None:
    profile_dir = tmp_path / "identity"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "profile.json").write_text(json.dumps({"key_info": {"fingerprint": fp}}))


def test_resolver_returns_v6_64hex_fingerprint(tmp_path: Path):
    """A v6 (PQC) profile fingerprint (64 hex) resolves — not None."""
    fp_v6 = "B" * 64
    _write_profile(tmp_path, fp_v6)

    from capauth import agent_identity

    original_fn = agent_identity._agent_capauth_dir
    try:
        agent_identity._agent_capauth_dir = lambda _a: tmp_path
        ident = resolve_agent_identity("pqc-root")
        assert ident.fingerprint == fp_v6
        assert ident.fingerprint is not None
        assert len(ident.fingerprint) == 64
    finally:
        agent_identity._agent_capauth_dir = original_fn


def test_resolver_still_returns_v4_40hex_fingerprint(tmp_path: Path):
    """A classical v4 profile fingerprint (40 hex) still resolves as before."""
    fp_v4 = "A" * 40
    _write_profile(tmp_path, fp_v4)

    from capauth import agent_identity

    original_fn = agent_identity._agent_capauth_dir
    try:
        agent_identity._agent_capauth_dir = lambda _a: tmp_path
        ident = resolve_agent_identity("classical")
        assert ident.fingerprint == fp_v4
        assert len(ident.fingerprint) == 40
    finally:
        agent_identity._agent_capauth_dir = original_fn


def test_resolver_rejects_malformed_fingerprint_width(tmp_path: Path):
    """A wrong-width fingerprint (neither 40 nor 64) is not surfaced."""
    _write_profile(tmp_path, "C" * 50)

    from capauth import agent_identity

    original_fn = agent_identity._agent_capauth_dir
    original_home = agent_identity.SKCAPSTONE_HOME
    try:
        agent_identity._agent_capauth_dir = lambda _a: tmp_path
        # Avoid picking up a real on-disk identity.json fallback.
        agent_identity.SKCAPSTONE_HOME = tmp_path / "no-such-home"
        ident = resolve_agent_identity("bad")
        assert ident.fingerprint is None
    finally:
        agent_identity._agent_capauth_dir = original_fn
        agent_identity.SKCAPSTONE_HOME = original_home
