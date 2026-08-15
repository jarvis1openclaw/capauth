"""provision_subject enrolls + tokenizes so authz.decide allows the subject."""

from __future__ import annotations

import pytest

from capauth import provision_subject
from capauth.authz import decide

# ``decide`` requires the granting token to carry a verifying signature, so
# tokens here are issued SIGNED against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing")


def test_provision_makes_decide_allow_all_skchat_caps(tmp_path):
    base = tmp_path / "home"
    out = provision_subject("lumina@chef.skworld.io", mode="verified", sign=True, base_dir=base)
    assert out["subject"] == "lumina@chef.skworld.io"
    assert out["mode"] == "verified"
    for cap in ("skchat.send", "skchat.inbox", "skchat.prekey"):
        d = decide("lumina@chef.skworld.io", cap, base_dir=base)
        assert d.allow is True, (cap, d.reason)


def test_provision_normalizes_a_legacy_missing_tld_subject(tmp_path):
    # "lumina@chef.skworld" is the missing-TLD legacy shape agent_identity has
    # shipped as its fqid field (IDENTITY_NAMING_STANDARD.md sec 2.5). provision_subject
    # (via enroll_device, card N3) normalizes it, and issues the token under the
    # SAME canonical spelling, so decide() can still correlate device + token.
    base = tmp_path / "home"
    out = provision_subject("lumina@chef.skworld", mode="verified", sign=True, base_dir=base)
    assert out["subject"] == "lumina@chef.skworld.io"
    d = decide("lumina@chef.skworld.io", "skchat.send", base_dir=base)
    assert d.allow is True, d.reason


def test_unprovisioned_subject_is_denied(tmp_path):
    base = tmp_path / "home"
    d = decide("stranger@chef.skworld.io", "skchat.send", base_dir=base)
    assert d.allow is False
    assert "unknown subject" in d.reason


def test_tofu_mode_provisioning_allows_only_inbox(tmp_path):
    # A tofu device satisfies inbox (min tofu) but not send (min verified).
    base = tmp_path / "home"
    provision_subject("guest@chef.skworld.io", mode="tofu", sign=True, base_dir=base)
    assert decide("guest@chef.skworld.io", "skchat.inbox", base_dir=base).allow is True
    send = decide("guest@chef.skworld.io", "skchat.send", base_dir=base)
    assert send.allow is False
    assert "enrollment mode" in send.reason


def test_provision_returns_ids(tmp_path):
    out = provision_subject("op@chef.skworld.io", sign=True, base_dir=tmp_path)
    assert out["device_id"] and out["token_id"]
    assert out["scopes"] == ["skchat.send", "skchat.inbox", "skchat.prekey"]
