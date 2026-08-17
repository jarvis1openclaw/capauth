"""``$SKCAPSTONE_HOME`` overrides ``default_base_dir()``; unset changes nothing.

Why the override exists: a node may legitimately hold a per-agent key while its
flat ``~/.skcapstone/identity/identity.json`` declares a DIFFERENT key whose
secret it does not have (measured on .41: it holds the opus and jarvis secrets,
the identity file names Chef's root). Before this there was no supported way to
point capauth at a home it can actually sign from, which is what blocked giving
that node signing failover.

Why it is dangerous: :func:`capauth.pairing.store.default_base_dir` also locates
the PAIRING STORE and the token store, so redirecting it moves where devices are
enrolled, not just where an identity is read. ``test_env_override_moves_the_pairing_store``
below pins that as OBSERVED behaviour rather than leaving it as a docstring
claim, because a warning nobody tested is a warning nobody can rely on.
"""

from __future__ import annotations

import os
from pathlib import Path

from capauth.pairing import EnrollmentMode, approve, build_verified_proof, enroll_device
from capauth.pairing.store import SKCAPSTONE_HOME_ENV, PairingStore, default_base_dir

from .conftest import TEST_EMAIL, TEST_NAME, TEST_PASSPHRASE

SUBJECT = "nia@chef.skworld.io"


def test_unset_resolves_exactly_as_before(monkeypatch):
    """The no-change guarantee: unset behaviour is byte-identical to the old body."""
    monkeypatch.delenv(SKCAPSTONE_HOME_ENV, raising=False)
    assert default_base_dir() == Path.home() / ".skcapstone"


def test_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(tmp_path / "agent-home"))
    assert default_base_dir() == tmp_path / "agent-home"


def test_the_env_var_is_the_name_the_rest_of_the_fleet_already_uses():
    """Not a capauth-private spelling: the same var capauth.manifest already reads."""
    assert SKCAPSTONE_HOME_ENV == "SKCAPSTONE_HOME"

    from capauth.manifest import shell_home

    saved = os.environ.get(SKCAPSTONE_HOME_ENV)
    try:
        os.environ[SKCAPSTONE_HOME_ENV] = "/tmp/capauth-env-agreement-probe"
        assert default_base_dir() == shell_home()
    finally:
        if saved is None:
            os.environ.pop(SKCAPSTONE_HOME_ENV, None)
        else:
            os.environ[SKCAPSTONE_HOME_ENV] = saved


def test_a_tilde_is_expanded(monkeypatch):
    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, "~/some-agent-home")
    assert default_base_dir() == Path.home() / "some-agent-home"


def test_an_EMPTY_value_falls_back_to_the_default_not_the_cwd(monkeypatch, tmp_path):
    """A unit file exporting the var unset must not reroot every store into cwd."""
    monkeypatch.chdir(tmp_path)
    for empty in ("", "   ", "\t\n"):
        monkeypatch.setenv(SKCAPSTONE_HOME_ENV, empty)
        resolved = default_base_dir()
        assert resolved == Path.home() / ".skcapstone"
        assert resolved != Path.cwd()


def test_an_explicit_base_dir_still_outranks_the_env(monkeypatch, tmp_path):
    """Tests inject ``base_dir=``; that must keep winning over an operator's env."""
    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(tmp_path / "env-home"))
    store = PairingStore(tmp_path / "explicit")
    assert store.base_dir == tmp_path / "explicit"


def test_the_store_follows_the_env_when_no_base_dir_is_given(monkeypatch, tmp_path):
    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(tmp_path / "env-home"))
    assert PairingStore().base_dir == tmp_path / "env-home"


def test_env_override_moves_the_pairing_store(monkeypatch, tmp_path):
    """THE HAZARD, observed: a node pointed at a new home has NO enrolled devices.

    Enroll + approve a device under home A, then repoint the env at home B and
    list. The device is gone, not because it was revoked but because the store
    moved with the root. Nothing migrates or merges; that is a separate
    decision, deliberately not made here.
    """
    from capauth.crypto import get_backend
    from capauth.models import Algorithm
    from capauth.pairing import list_devices

    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"

    bundle = get_backend().generate_keypair(
        TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.ED25519
    )
    proof = build_verified_proof(
        bundle.public_armor,
        private_key=bundle.private_armor,
        passphrase=TEST_PASSPHRASE,
        subject=SUBJECT,
    )

    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(home_a))
    enrollment = enroll_device(
        bundle.public_armor, ["skchat.send"], mode="verified", subject=SUBJECT, **proof
    )
    assert enrollment.mode is EnrollmentMode.VERIFIED
    approve(enrollment.enrollment_id, "operator")
    assert len(list_devices(SUBJECT)) == 1

    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(home_b))
    assert list_devices(SUBJECT) == []  # the hazard: an empty store, not a denial to debug

    monkeypatch.setenv(SKCAPSTONE_HOME_ENV, str(home_a))
    assert len(list_devices(SUBJECT)) == 1  # and nothing was lost, just relocated
