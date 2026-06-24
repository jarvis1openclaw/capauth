"""Agent-aware identity resolution — the capauth source of truth.

Coord tasks:
    T1 (a532771e) — AgentIdentity dataclass + resolve_agent_identity (dual URI)
    T2 (1fec05a8) — consumers delegate here instead of reimplementing

Overview
--------
Every SK package used to have its own identity-resolution code.  This module
is the **single canonical resolver** that all consumers (skchat, skmemory,
skcomms, skcapstone) must delegate to.

A resolved identity carries **two complementary URIs**:

``capauth_uri``
    ``capauth:<agent>@skworld.io`` — the wire identity used by the existing
    peer registry, bridge scripts, skchat transport, and delivery routing.
    Always present (derived from the agent name when no profile exists).

``fqid``
    ``<agent>@<operator>.<realm>`` — the skcomms three-tier FQID
    (agent @ operator . realm, e.g. ``lumina@chef.skworld``).  Derived from
    ``~/.skcapstone/cluster.json`` for operator/realm; ``None`` when
    cluster.json is absent or malformed.

``fingerprint``
    40 (v4) or 64 (v6) hex PGP fingerprint from the agent's CapAuth profile.
    ``None`` when no real profile exists (placeholder identities are not
    surfaced here).

Public API
----------
::

    from capauth.agent_identity import resolve_agent_identity, AgentIdentity

    ident = resolve_agent_identity("lumina")
    # AgentIdentity(
    #   agent       = "lumina",
    #   capauth_uri = "capauth:lumina@skworld.io",
    #   fqid        = "lumina@chef.skworld",
    #   fingerprint = "02BC0EB3CAD31DB691A753C70C5629AB893F9746",
    # )

For convenience ``capauth.resolve_agent_identity`` is also exported from the
package ``__init__``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("capauth.agent_identity")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SKWORLD_DOMAIN = "skworld.io"
"""Default CapAuth wire domain for all SK agents."""

SKCAPSTONE_HOME = Path.home() / ".skcapstone"
_CLUSTER_LOOKUP = [
    Path("/etc/skcapstone/cluster.json"),
    SKCAPSTONE_HOME / "cluster.json",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AgentIdentity:
    """Resolved identity for a single SK agent.

    Attributes:
        agent:        Short agent name (e.g. ``"lumina"``).
        capauth_uri:  Wire identity — ``capauth:<agent>@skworld.io``.
        fqid:         Three-tier label — ``<agent>@<operator>.<realm>``
                      (e.g. ``"lumina@chef.skworld"``).  ``None`` when
                      cluster.json is not available.
        fingerprint:  40 (v4) or 64 (v6) hex PGP fingerprint from the agent's
                      CapAuth profile.  ``None`` when no real profile exists.
    """

    agent: str
    capauth_uri: str
    fqid: Optional[str] = field(default=None)
    fingerprint: Optional[str] = field(default=None)

    # Convenience shim: make the object truthy in a boolean check and let
    # callers do ``ident.uri`` as an alias for ``ident.capauth_uri``.
    @property
    def uri(self) -> str:
        """Alias for ``capauth_uri`` — the primary wire identity."""
        return self.capauth_uri

    def to_dict(self) -> dict:
        """Serialise to a plain dict (suitable for identity.json)."""
        return {
            "agent": self.agent,
            "capauth_uri": self.capauth_uri,
            "fqid": self.fqid,
            "fingerprint": self.fingerprint,
        }

    def hybrid_prekey_available(self) -> bool:
        """Whether this agent advertises a hybrid PQ confidentiality prekey.

        Honest capability lookup for the PQC cut-over (see
        :mod:`capauth.pqc_confidentiality`): ``True`` only when a real
        X25519+ML-KEM-768 prekey exists for this agent; ``False`` (classical /
        negotiated downgrade) otherwise. CapAuth does not generate these keys
        (Phase 2) — it reports them.
        """
        from .pqc_confidentiality import hybrid_prekey_available

        return hybrid_prekey_available(self.agent)

    def confidentiality_suite(self) -> str:
        """The confidentiality suite a peer negotiates TO this agent today."""
        from .pqc_confidentiality import confidentiality_suite_for

        return confidentiality_suite_for(self.agent)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_cluster() -> Optional[dict]:
    """Load cluster.json from the standard search path.

    Returns:
        The parsed JSON dict, or ``None`` if no cluster.json exists.
    """
    for path in _CLUSTER_LOOKUP:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("cluster.json load failed at %s: %s", path, exc)
    return None


def _build_fqid(agent: str, cluster: Optional[dict]) -> Optional[str]:
    """Build ``<agent>@<operator>.<realm>`` from cluster data.

    Args:
        agent:   Short agent name.
        cluster: Parsed cluster.json dict, or None.

    Returns:
        FQID string, or None when cluster data is unavailable/incomplete.
    """
    if cluster is None:
        return None
    realm = cluster.get("realm")
    operator = cluster.get("operator")
    if not realm or not operator:
        return None
    return f"{agent}@{operator}.{realm}"


def _agent_capauth_dir(agent: str) -> Path:
    """Return the agent-local CapAuth home.

    Two layouts are supported:
    1. ``~/.skcapstone/agents/<agent>/capauth/`` — per-agent (canonical).
    2. ``~/.skcapstone/capauth/`` — single-agent legacy layout.
    """
    per_agent = SKCAPSTONE_HOME / "agents" / agent / "capauth"
    if per_agent.exists():
        return per_agent
    return SKCAPSTONE_HOME / "capauth"


def _load_fingerprint(agent: str) -> Optional[str]:
    """Read the fingerprint from the agent's CapAuth profile.

    Tries ``profile.json`` first; falls back to ``identity/identity.json``
    under the agent home (which skcapstone writes during ``init``).

    Args:
        agent: Short agent name.

    Returns:
        40 (v4) or 64 (v6) hex fingerprint string, or None.
    """
    # 1. CapAuth profile.json (source of truth for real PGP profiles)
    capauth_dir = _agent_capauth_dir(agent)
    profile_path = capauth_dir / "identity" / "profile.json"
    if profile_path.exists():
        try:
            data = json.loads(profile_path.read_text(encoding="utf-8"))
            fp = data.get("key_info", {}).get("fingerprint")
            if isinstance(fp, str) and len(fp) in (40, 64):
                return fp
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("profile.json parse failed for %s: %s", agent, exc)

    # 2. Try via capauth.profile Python API (graceful import)
    try:
        from capauth.profile import load_profile  # type: ignore[import-untyped]

        profile = load_profile(base_dir=capauth_dir)
        fp = profile.key_info.fingerprint
        if isinstance(fp, str) and len(fp) in (40, 64):
            return fp
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("capauth.profile load failed for %s: %s", agent, exc)

    # 3. identity/identity.json under the agent home (written by skcapstone)
    identity_path = SKCAPSTONE_HOME / "agents" / agent / "identity" / "identity.json"
    if identity_path.exists():
        try:
            data = json.loads(identity_path.read_text(encoding="utf-8"))
            fp = data.get("fingerprint")
            # Only return if it looks like a real fingerprint (not placeholder)
            if isinstance(fp, str) and len(fp) in (40, 64):
                # Reject placeholder fingerprints (all caps hex, but generated
                # from SHA256 of "skcapstone:<name>")
                if data.get("capauth_managed", False):
                    return fp
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("identity.json parse failed for %s: %s", agent, exc)

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_agent_identity(
    agent: Optional[str] = None,
) -> AgentIdentity:
    """Resolve the full identity for an SK agent.

    This is the **single canonical resolver**.  All SK packages must call
    this instead of reimplementing identity logic.

    Resolution order:
        1. ``agent`` arg — explicit name.
        2. ``SKAGENT`` env var.
        3. ``SKCAPSTONE_AGENT`` / ``SKMEMORY_AGENT`` env vars (legacy).
        4. ``skmemory.agents.get_active_agent()`` — checks disk if no env.
        5. Fallback: ``"local"`` (absolute floor; ``fqid`` will be None).

    The ``capauth_uri`` is always ``capauth:<name>@skworld.io`` — conventional
    even without a real PGP profile.  The ``fqid`` requires ``cluster.json``.
    The ``fingerprint`` requires a real CapAuth profile on disk.

    Args:
        agent: Short agent name (e.g. ``"lumina"``).  ``None`` triggers
               automatic resolution via env / skmemory.

    Returns:
        :class:`AgentIdentity` with ``capauth_uri`` always populated.

    Examples:
        >>> ident = resolve_agent_identity("lumina")
        >>> ident.capauth_uri
        'capauth:lumina@skworld.io'
        >>> ident.fqid   # only if cluster.json present
        'lumina@chef.skworld'
    """
    if agent is None:
        agent = _resolve_active_agent_name()

    # Guarantee a non-empty name
    if not agent or agent.endswith("-template"):
        agent = "local"

    capauth_uri = f"capauth:{agent}@{SKWORLD_DOMAIN}"
    cluster = _load_cluster()
    fqid = _build_fqid(agent, cluster)
    fingerprint = _load_fingerprint(agent)

    return AgentIdentity(
        agent=agent,
        capauth_uri=capauth_uri,
        fqid=fqid,
        fingerprint=fingerprint,
    )


def _resolve_active_agent_name() -> Optional[str]:
    """Resolve the active agent name from env vars or skmemory.

    Returns:
        Agent name string, or None.
    """
    # 1. Env vars (primary → legacy)
    for var in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT"):
        val = os.environ.get(var)
        if val and not val.endswith("-template"):
            return val

    # 2. skmemory (optional dependency — works without it)
    try:
        from skmemory.agents import get_active_agent  # type: ignore[import-untyped]

        name = get_active_agent()
        if name and not name.endswith("-template"):
            return name
    except Exception as exc:
        logger.debug("skmemory agent resolution failed: %s", exc)

    return None
