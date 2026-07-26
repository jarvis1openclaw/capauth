"""Tests for capauth-service deploy secret provisioning + gitignore.

Card dd7f35eb: the CapAuth verification service deploy generates
CAPAUTH_ADMIN_TOKEN / CAPAUTH_JWT_SECRET into a local `.env`. That `.env` is the
only on-disk copy of the service secrets, so it MUST:

  1. be gitignored (never committed), and
  2. be provisioned idempotently - re-running the deploy REUSES the existing
     secrets rather than rotating them on every restart.

These tests exercise `deploy/capauth-service/deploy.sh --provision`, a mode that
performs only the secret provisioning (no docker), so the security-relevant
behaviour is testable without a running container.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DIR = REPO_ROOT / "deploy" / "capauth-service"
DEPLOY_SH = DEPLOY_DIR / "deploy.sh"
ENV_EXAMPLE = DEPLOY_DIR / ".env.example"

DEFAULT_ADMIN = "change-me-admin-token-min-32-chars"
DEFAULT_JWT = "change-me-jwt-secret-at-least-32-chars"


def _has_git() -> bool:
    return shutil.which("git") is not None


def _parse_env(path: Path) -> dict:
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip()
    return values


def _make_deploy_copy(tmp_path: Path) -> Path:
    """Copy deploy.sh + .env.example into a temp dir so SCRIPT_DIR is isolated.

    deploy.sh derives SCRIPT_DIR from its own location, so a copy provisions its
    own local .env without touching the real checkout.
    """
    d = tmp_path / "capauth-service"
    d.mkdir()
    shutil.copy2(DEPLOY_SH, d / "deploy.sh")
    shutil.copy2(ENV_EXAMPLE, d / ".env.example")
    return d


def _run_provision(deploy_copy: Path, extra_env: dict | None = None):
    env = dict(os.environ)
    # Never let ambient secrets leak into the "generate random" default path.
    env.pop("CAPAUTH_ADMIN_TOKEN", None)
    env.pop("CAPAUTH_JWT_SECRET", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(deploy_copy / "deploy.sh"), "--provision"],
        env=env,
        capture_output=True,
        text=True,
    )


# ── gitignore: the generated .env must never be committable ───────────────────


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_generated_env_is_gitignored():
    """`git check-ignore` must match the deploy .env path (fail-before/pass-after)."""
    result = subprocess.run(
        ["git", "check-ignore", "deploy/capauth-service/.env"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "deploy/capauth-service/.env is NOT gitignored - service secrets could "
        "be committed. Add `.env` to .gitignore."
    )


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_forgejo_env_is_also_gitignored():
    result = subprocess.run(
        ["git", "check-ignore", "deploy/forgejo-capauth/.env"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_env_example_templates_are_not_ignored():
    """Committed .example templates must stay tracked (not caught by the rule)."""
    for tracked in (
        "deploy/capauth-service/.env.example",
        "deploy/forgejo-capauth/.env.example",
    ):
        result = subprocess.run(
            ["git", "check-ignore", tracked],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, f"{tracked} must not be gitignored"


@pytest.mark.skipif(not _has_git(), reason="git not available")
def test_no_real_env_secret_file_is_tracked():
    """No populated .env (only .example) may be tracked in the repo."""
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    offenders = [
        p
        for p in tracked
        if Path(p).name == ".env" or p.endswith("/.env")
    ]
    assert not offenders, f"secret .env files are tracked: {offenders}"


# ── provisioning: generate once, then reuse (no rotation) ─────────────────────


def test_provision_generates_strong_secrets(tmp_path):
    d = _make_deploy_copy(tmp_path)
    result = _run_provision(d)
    assert result.returncode == 0, result.stderr

    env_path = d / ".env"
    assert env_path.exists(), "provision must create .env"
    vals = _parse_env(env_path)

    assert vals["CAPAUTH_ADMIN_TOKEN"] != DEFAULT_ADMIN
    assert vals["CAPAUTH_JWT_SECRET"] != DEFAULT_JWT
    assert len(vals["CAPAUTH_ADMIN_TOKEN"]) >= 32
    assert len(vals["CAPAUTH_JWT_SECRET"]) >= 32
    # token_hex(24)=48 hex chars, token_hex(32)=64 hex chars.
    assert all(c in "0123456789abcdef" for c in vals["CAPAUTH_ADMIN_TOKEN"])
    assert all(c in "0123456789abcdef" for c in vals["CAPAUTH_JWT_SECRET"])


def test_provision_is_idempotent_and_does_not_rotate(tmp_path):
    """Second --provision run must NOT change the existing secrets."""
    d = _make_deploy_copy(tmp_path)

    first = _run_provision(d)
    assert first.returncode == 0, first.stderr
    before = _parse_env(d / ".env")

    second = _run_provision(d)
    assert second.returncode == 0, second.stderr
    after = _parse_env(d / ".env")

    assert before["CAPAUTH_ADMIN_TOKEN"] == after["CAPAUTH_ADMIN_TOKEN"], (
        "restart rotated CAPAUTH_ADMIN_TOKEN - must reuse existing secret"
    )
    assert before["CAPAUTH_JWT_SECRET"] == after["CAPAUTH_JWT_SECRET"], (
        "restart rotated CAPAUTH_JWT_SECRET - must reuse existing secret"
    )
    assert "Reusing existing" in (second.stdout + second.stderr)


def test_two_fresh_provisions_differ(tmp_path):
    """Independent first-runs mint different random secrets (real randomness)."""
    # Build two isolated copies explicitly.
    da = tmp_path / "da" / "capauth-service"
    db = tmp_path / "db" / "capauth-service"
    for dd in (da, db):
        dd.mkdir(parents=True)
        shutil.copy2(DEPLOY_SH, dd / "deploy.sh")
        shutil.copy2(ENV_EXAMPLE, dd / ".env.example")
    assert _run_provision(da).returncode == 0
    assert _run_provision(db).returncode == 0
    va = _parse_env(da / ".env")
    vb = _parse_env(db / ".env")
    assert va["CAPAUTH_ADMIN_TOKEN"] != vb["CAPAUTH_ADMIN_TOKEN"]
    assert va["CAPAUTH_JWT_SECRET"] != vb["CAPAUTH_JWT_SECRET"]


def test_provision_adopts_vault_provided_secrets(tmp_path):
    """A strong secret exported in the env (e.g. from skvault) is adopted verbatim."""
    d = _make_deploy_copy(tmp_path)
    vault_admin = "vault/admin+token=" + "Z" * 40  # exercises sed-hostile chars
    vault_jwt = "vault|jwt&secret " + "Q" * 40
    result = _run_provision(
        d,
        {"CAPAUTH_ADMIN_TOKEN": vault_admin, "CAPAUTH_JWT_SECRET": vault_jwt},
    )
    assert result.returncode == 0, result.stderr
    vals = _parse_env(d / ".env")
    assert vals["CAPAUTH_ADMIN_TOKEN"] == vault_admin
    assert vals["CAPAUTH_JWT_SECRET"] == vault_jwt


def test_provision_env_is_chmod_600(tmp_path):
    d = _make_deploy_copy(tmp_path)
    assert _run_provision(d).returncode == 0
    mode = (d / ".env").stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
