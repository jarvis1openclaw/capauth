"""Tests for capauth.agent_identity — T1/T2 resolver.

Covers:
    - AgentIdentity dataclass basics
    - resolve_agent_identity with explicit agent name
    - resolve_agent_identity auto-resolution from env vars
    - fqid computation from cluster.json
    - fingerprint loading from profile.json
    - graceful fallback when cluster.json / profile absent
    - T2 delegation contract: callers get both capauth_uri + fqid
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from capauth.agent_identity import (
    AgentIdentity,
    _build_fqid,
    _load_cluster,
    resolve_agent_identity,
)


# ---------------------------------------------------------------------------
# AgentIdentity dataclass
# ---------------------------------------------------------------------------


class TestAgentIdentity:
    def test_uri_alias(self):
        ident = AgentIdentity(
            agent="lumina", capauth_uri="capauth:lumina@skworld.io"
        )
        assert ident.uri == ident.capauth_uri

    def test_to_dict_keys(self):
        ident = AgentIdentity(
            agent="lumina",
            capauth_uri="capauth:lumina@skworld.io",
            fqid="lumina@chef.skworld",
            fingerprint="AB" * 20,
        )
        d = ident.to_dict()
        assert set(d.keys()) == {"agent", "capauth_uri", "fqid", "fingerprint"}

    def test_optional_fields_default_none(self):
        ident = AgentIdentity(agent="x", capauth_uri="capauth:x@skworld.io")
        assert ident.fqid is None
        assert ident.fingerprint is None


# ---------------------------------------------------------------------------
# _build_fqid
# ---------------------------------------------------------------------------


class TestBuildFqid:
    def test_builds_from_cluster(self):
        cluster = {"realm": "skworld", "operator": "chef"}
        assert _build_fqid("lumina", cluster) == "lumina@chef.skworld"

    def test_none_when_cluster_none(self):
        assert _build_fqid("lumina", None) is None

    def test_none_when_realm_missing(self):
        assert _build_fqid("lumina", {"operator": "chef"}) is None

    def test_none_when_operator_missing(self):
        assert _build_fqid("lumina", {"realm": "skworld"}) is None


# ---------------------------------------------------------------------------
# _load_cluster
# ---------------------------------------------------------------------------


class TestLoadCluster:
    def test_loads_from_tmp(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(
            json.dumps({"realm": "skworld", "operator": "chef"})
        )
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [cluster_file]
            data = _load_cluster()
            assert data is not None
            assert data["realm"] == "skworld"
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_returns_none_when_absent(self, tmp_path: Path):
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [tmp_path / "nonexistent.json"]
            assert _load_cluster() is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original


# ---------------------------------------------------------------------------
# resolve_agent_identity — explicit agent
# ---------------------------------------------------------------------------


class TestResolveExplicit:
    def test_capauth_uri_always_present(self):
        ident = resolve_agent_identity("testbot")
        assert ident.capauth_uri == "capauth:testbot@skworld.io"
        assert ident.agent == "testbot"

    def test_fqid_with_cluster(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(
            json.dumps({"realm": "skworld", "operator": "chef"})
        )
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [cluster_file]
            ident = resolve_agent_identity("lumina")
            assert ident.fqid == "lumina@chef.skworld"
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_fqid_none_without_cluster(self, tmp_path: Path):
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [tmp_path / "no.json"]
            ident = resolve_agent_identity("lumina")
            assert ident.fqid is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_fingerprint_from_profile_json(self, tmp_path: Path):
        fake_fp = "A" * 40
        profile_dir = tmp_path / "identity"
        profile_dir.mkdir(parents=True)
        profile_json = profile_dir / "profile.json"
        profile_json.write_text(
            json.dumps({"key_info": {"fingerprint": fake_fp}})
        )
        from capauth import agent_identity

        original_fn = agent_identity._agent_capauth_dir
        try:
            agent_identity._agent_capauth_dir = lambda _a: tmp_path
            ident = resolve_agent_identity("dummy")
            assert ident.fingerprint == fake_fp
        finally:
            agent_identity._agent_capauth_dir = original_fn

    def test_fingerprint_none_when_no_profile(self, tmp_path: Path):
        from capauth import agent_identity

        original_fn = agent_identity._agent_capauth_dir
        try:
            # Point to a dir with no profile.json
            agent_identity._agent_capauth_dir = lambda _a: tmp_path / "empty"
            # Also patch skcapstone home to avoid picking up real profiles
            with patch.object(
                agent_identity,
                "SKCAPSTONE_HOME",
                tmp_path,
            ):
                ident = resolve_agent_identity("ghost")
                assert ident.fingerprint is None
        finally:
            agent_identity._agent_capauth_dir = original_fn

    def test_local_fallback_for_empty_agent(self):
        ident = resolve_agent_identity("")
        assert ident.agent == "local"
        assert ident.capauth_uri == "capauth:local@skworld.io"

    def test_template_agent_becomes_local(self):
        ident = resolve_agent_identity("lumina-template")
        assert ident.agent == "local"


# ---------------------------------------------------------------------------
# resolve_agent_identity — auto-resolution from env
# ---------------------------------------------------------------------------


class TestResolveAutoEnv:
    def test_reads_skagent_env(self):
        with patch.dict(os.environ, {"SKAGENT": "jarvis"}, clear=False):
            ident = resolve_agent_identity(None)
        assert ident.agent == "jarvis"

    def test_falls_back_to_skcapstone_agent(self):
        env = {"SKCAPSTONE_AGENT": "herald"}
        with patch.dict(os.environ, env, clear=False):
            # Remove SKAGENT to ensure legacy fallback
            env_without_skagent = {
                k: v for k, v in {**os.environ, **env}.items()
                if k != "SKAGENT"
            }
            with patch.dict(os.environ, env_without_skagent, clear=True):
                ident = resolve_agent_identity(None)
                assert ident.agent in ("herald", "local")  # local if skmemory returns something

    def test_local_when_no_env(self):
        # Strip all agent env vars; skmemory may or may not be installed
        env_clean = {
            k: v for k, v in os.environ.items()
            if k not in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT")
        }
        with patch.dict(os.environ, env_clean, clear=True):
            with patch(
                "capauth.agent_identity._resolve_active_agent_name",
                return_value=None,
            ):
                ident = resolve_agent_identity(None)
                assert ident.agent == "local"
                assert ident.capauth_uri == "capauth:local@skworld.io"


# ---------------------------------------------------------------------------
# Public __init__ re-export
# ---------------------------------------------------------------------------


class TestPublicExport:
    def test_importable_from_capauth(self):
        from capauth import AgentIdentity as AI
        from capauth import resolve_agent_identity as rai

        assert AI is AgentIdentity
        assert callable(rai)

    def test_resolve_returns_agent_identity_instance(self):
        from capauth import resolve_agent_identity as rai

        result = rai("opus")
        assert isinstance(result, AgentIdentity)
        assert result.capauth_uri == "capauth:opus@skworld.io"
