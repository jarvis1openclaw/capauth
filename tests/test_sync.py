"""Secret-custody boundary tests for Syncthing setup."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from capauth.sync import (
    REQUIRED_SECRET_IGNORE_RULES,
    ensure_secret_material_ignored,
    setup_syncthing_sync,
)


def test_ignore_policy_preserves_existing_rules_and_is_idempotent(tmp_path: Path) -> None:
    ignore = tmp_path / ".stignore"
    ignore.write_text("# operator rule\ncustom-cache/\n", encoding="utf-8")

    ensure_secret_material_ignored(tmp_path)
    first = ignore.read_text(encoding="utf-8")
    ensure_secret_material_ignored(tmp_path)
    second = ignore.read_text(encoding="utf-8")

    assert first == second
    assert "custom-cache/" in first
    assert all(rule in first.splitlines() for rule in REQUIRED_SECRET_IGNORE_RULES)
    assert ignore.stat().st_mode & 0o077 == 0


def test_setup_enforces_ignores_before_registering_folder(tmp_path: Path) -> None:
    with (
        patch("capauth.sync._get_api_info", return_value=("http://sync", "key")),
        patch("capauth.sync._setup_via_api", return_value=True) as setup_api,
    ):
        assert setup_syncthing_sync(tmp_path, device_ids=["device"]) is True

    setup_api.assert_called_once()
    ignore = (tmp_path / ".stignore").read_text(encoding="utf-8")
    assert "**/private.*" in ignore
    assert "**/root-revocation.asc" in ignore


def test_setup_fails_closed_when_ignore_policy_cannot_be_written(tmp_path: Path) -> None:
    with patch(
        "capauth.sync.ensure_secret_material_ignored",
        side_effect=PermissionError("read-only"),
    ):
        assert setup_syncthing_sync(tmp_path) is False
