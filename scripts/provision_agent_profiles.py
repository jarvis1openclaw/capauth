#!/usr/bin/env python3
"""T4: Provision real per-agent capauth PGP profiles + canonical identity.json.

Coord task 8350c9e7.

For each active agent:
1. If a real CapAuth profile (``capauth/identity/profile.json``) already
   exists: reads fingerprint from it.
2. If not: generates a fresh Ed25519 keypair via ``capauth.profile.init_profile``
   and writes it to ``~/.skcapstone/agents/<agent>/capauth/``.
3. Writes / updates ``identity.json`` with the canonical dual-URI fields:
   ``capauth_uri``, ``fqid``, ``fingerprint``.

Usage::

    python scripts/provision_agent_profiles.py [--dry-run] [--agent AGENT ...]

Dry-run prints what *would* change without writing anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SKCAPSTONE_HOME = Path.home() / ".skcapstone"
AGENTS_DIR = SKCAPSTONE_HOME / "agents"

# Known active agents.  Extend as the registry grows.
DEFAULT_AGENTS = [
    "lumina",
    "opus",
    "jarvis",
    "ava",
    "artisan",
    "herald",
    "sentinel",
    "architect",
    "scholar",
    "steward",
    "coder",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_cluster() -> dict:
    """Return cluster.json contents or a safe default."""
    for p in [Path("/etc/skcapstone/cluster.json"), SKCAPSTONE_HOME / "cluster.json"]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"realm": "skworld", "operator": "chef"}


def _build_fqid(agent: str, cluster: dict) -> str:
    realm = cluster.get("realm", "skworld")
    operator = cluster.get("operator", "chef")
    return f"{agent}@{operator}.{realm}"


def _load_existing_fingerprint(capauth_dir: Path) -> str | None:
    """Read fingerprint from an existing profile.json."""
    profile_path = capauth_dir / "identity" / "profile.json"
    if not profile_path.exists():
        return None
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        fp = data.get("key_info", {}).get("fingerprint")
        if isinstance(fp, str) and len(fp) in (40, 64):
            return fp
    except Exception:
        pass
    return None


def _generate_profile(agent: str, capauth_dir: Path) -> str | None:
    """Generate a new CapAuth profile for *agent* into *capauth_dir*.

    Returns the fingerprint string, or None on failure.
    """
    try:
        from capauth.models import EntityType
        from capauth.profile import init_profile

        profile = init_profile(
            name=agent.capitalize(),
            email=f"{agent}@skworld.io",
            passphrase="",
            entity_type=EntityType.AI,
            base_dir=capauth_dir,
        )
        return profile.key_info.fingerprint
    except Exception as exc:
        print(f"  [WARN] Could not generate profile for {agent}: {exc}", file=sys.stderr)
        return None


def _update_identity_json(
    identity_path: Path,
    agent: str,
    capauth_uri: str,
    fqid: str,
    fingerprint: str | None,
    dry_run: bool,
) -> None:
    """Write or merge dual-URI fields into identity.json."""
    existing: dict = {}
    if identity_path.exists():
        try:
            existing = json.loads(identity_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    updated = dict(existing)
    # Always set these canonical fields
    updated["capauth_uri"] = capauth_uri
    updated["fqid"] = fqid
    if fingerprint:
        updated["fingerprint"] = fingerprint
    # Ensure core fields are present
    if "name" not in updated:
        updated["name"] = agent.capitalize()
    if "email" not in updated:
        updated["email"] = f"{agent}@skworld.io"
    if "capauth_managed" not in updated:
        updated["capauth_managed"] = bool(fingerprint)
    if "created_at" not in updated:
        updated["created_at"] = datetime.now(timezone.utc).isoformat()

    changed = updated != existing

    if dry_run:
        status = "CHANGE" if changed else "no-op"
        print(f"  [{status}] {identity_path}")
        if changed:
            for k in ("capauth_uri", "fqid", "fingerprint"):
                old = existing.get(k, "<missing>")
                new = updated.get(k)
                if old != new:
                    print(f"         {k}: {old!r} → {new!r}")
        return

    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
    action = "updated" if changed else "unchanged"
    print(f"  [{action}] {identity_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing.")
    parser.add_argument(
        "--agent",
        nargs="*",
        default=DEFAULT_AGENTS,
        help="Agents to provision (default: all known agents).",
    )
    args = parser.parse_args()

    cluster = _load_cluster()
    agents = args.agent
    dry_run = args.dry_run

    if dry_run:
        print("DRY RUN — no files will be written.\n")

    for agent in agents:
        agent_dir = AGENTS_DIR / agent
        if not agent_dir.exists():
            print(f"[SKIP] {agent} — agent directory not found")
            continue

        capauth_dir = agent_dir / "capauth"
        identity_path = agent_dir / "identity" / "identity.json"
        capauth_uri = f"capauth:{agent}@skworld.io"
        fqid = _build_fqid(agent, cluster)

        print(f"\n[{agent}]")
        print(f"  capauth_uri : {capauth_uri}")
        print(f"  fqid        : {fqid}")

        # Step 1: Try to load existing fingerprint
        fingerprint = _load_existing_fingerprint(capauth_dir)

        # Step 2: Generate new profile if missing
        if fingerprint is None:
            print(f"  No profile found at {capauth_dir} — generating...")
            if not dry_run:
                fingerprint = _generate_profile(agent, capauth_dir)
                if fingerprint:
                    print(f"  Generated fingerprint: {fingerprint}")
                else:
                    print(
                        f"  [WARN] Could not generate profile; identity.json will lack fingerprint"
                    )
            else:
                print(f"  [dry-run] Would generate new Ed25519 keypair")
                fingerprint = None
        else:
            print(f"  fingerprint : {fingerprint}")

        # Step 3: Update identity.json
        _update_identity_json(
            identity_path=identity_path,
            agent=agent,
            capauth_uri=capauth_uri,
            fqid=fqid,
            fingerprint=fingerprint,
            dry_run=dry_run,
        )

    print("\nDone." if not dry_run else "\nDone (dry-run).")


if __name__ == "__main__":
    main()
