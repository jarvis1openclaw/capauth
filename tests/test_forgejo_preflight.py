"""Tests for the CapAuth + Forgejo compose secret preflight guard.

The guard (`deploy/forgejo-capauth/preflight.sh`) must hard-fail (exit non-zero)
when a required secret is unset, empty, or still the committed placeholder
default, and must pass (exit 0) only when strong real secrets are set. This
proves the default-secret security hole cannot be deployed silently.
"""

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = REPO_ROOT / "deploy" / "forgejo-capauth" / "preflight.sh"

# A strong, non-default value used for the passing cases.
GOOD_SECRET = "a" * 40

DEFAULT_ADMIN = "change-me-admin-token"
DEFAULT_JWT = "change-me-jwt-secret-at-least-32-chars"


def run_preflight(env_overrides: dict) -> subprocess.CompletedProcess:
    """Invoke preflight.sh with a clean env plus the given secret vars.

    Runs from a temp cwd with no .env so only the passed env is seen.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        # Ensure no ambient values leak in.
        "CAPAUTH_ADMIN_TOKEN": "",
        "CAPAUTH_JWT_SECRET": "",
    }
    # Remove empties so "unset" cases are truly unset.
    env = {k: v for k, v in env.items() if v != "" or k == "PATH"}
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(PREFLIGHT)],
        env=env,
        capture_output=True,
        text=True,
    )


def test_preflight_script_exists_and_executable():
    assert PREFLIGHT.is_file(), f"missing guard script: {PREFLIGHT}"
    assert os.access(PREFLIGHT, os.X_OK), "preflight.sh must be executable"


def test_fails_when_both_unset():
    result = run_preflight({})
    assert result.returncode != 0
    assert "CAPAUTH_ADMIN_TOKEN" in result.stderr
    assert "CAPAUTH_JWT_SECRET" in result.stderr


def test_fails_when_admin_token_is_default():
    result = run_preflight(
        {"CAPAUTH_ADMIN_TOKEN": DEFAULT_ADMIN, "CAPAUTH_JWT_SECRET": GOOD_SECRET}
    )
    assert result.returncode != 0
    assert "CAPAUTH_ADMIN_TOKEN" in result.stderr


def test_fails_when_jwt_secret_is_default():
    result = run_preflight({"CAPAUTH_ADMIN_TOKEN": GOOD_SECRET, "CAPAUTH_JWT_SECRET": DEFAULT_JWT})
    assert result.returncode != 0
    assert "CAPAUTH_JWT_SECRET" in result.stderr


def test_fails_when_secret_empty():
    result = run_preflight({"CAPAUTH_ADMIN_TOKEN": "", "CAPAUTH_JWT_SECRET": GOOD_SECRET})
    assert result.returncode != 0
    assert "CAPAUTH_ADMIN_TOKEN" in result.stderr


def test_fails_when_secret_too_short():
    result = run_preflight({"CAPAUTH_ADMIN_TOKEN": "short", "CAPAUTH_JWT_SECRET": GOOD_SECRET})
    assert result.returncode != 0
    assert "CAPAUTH_ADMIN_TOKEN" in result.stderr


@pytest.mark.parametrize(
    "value",
    ["change-me-anything", "changeme", "CHANGE_ME_now", "change_me_token_value_here"],
)
def test_fails_on_change_me_variants(value):
    result = run_preflight({"CAPAUTH_ADMIN_TOKEN": value, "CAPAUTH_JWT_SECRET": GOOD_SECRET})
    assert result.returncode != 0
    assert "CAPAUTH_ADMIN_TOKEN" in result.stderr


def test_passes_when_both_strong():
    result = run_preflight(
        {
            "CAPAUTH_ADMIN_TOKEN": GOOD_SECRET,
            "CAPAUTH_JWT_SECRET": "b" * 48,
        }
    )
    assert result.returncode == 0, result.stderr
    assert "passed" in result.stdout.lower()
