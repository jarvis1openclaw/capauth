"""PQC confidentiality capability lookup (PQC-MIGRATION cut-over, Phase 1).

CapAuth's identity layer is the source of truth for *who* an agent is. For the
confidentiality cut-over it also answers an honest capability question: **does
this agent advertise a hybrid X25519+ML-KEM-768 confidentiality prekey?**

CapAuth itself does NOT yet generate PQC keys (that is Phase 2 — the Sequoia/
liboqs identity migration; see ``models.Algorithm`` PQC stubs and
``docs/CRYPTO_SPEC.md``). The hybrid *confidentiality* prekeys are produced by
``skchat.pq_prekeys`` and live in the shared ``~/.skchat/pqc/`` store. This
module reads that store so identity consumers can honestly report which peers
are hybrid-capable — never asserting hybrid for an agent that has no key.

Returns conservative answers: absent store / unreadable key → ``False`` (the
agent is treated as classical, a negotiated downgrade — never an overclaim).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

HYBRID_SUITE = "x25519-mlkem768"


def _pqc_dir() -> Path:
    home = Path(os.environ.get("SKCHAT_HOME", str(Path.home() / ".skchat")))
    return home / "pqc"


def _short(identity: str) -> str:
    s = identity[len("capauth:") :] if identity.startswith("capauth:") else identity
    return s.split("@")[0]


def _current_agent() -> str:
    return (
        os.environ.get("SKAGENT")
        or os.environ.get("SKCAPSTONE_AGENT")
        or os.environ.get("SKMEMORY_AGENT")
        or "lumina"
    ).split("@")[0]


def hybrid_prekey_available(agent: Optional[str] = None) -> bool:
    """True iff ``agent`` advertises a usable hybrid confidentiality prekey.

    Checks, in order:
      1. The agent's OWN keypair (``<agent>_hybrid.pub`` or the legacy
         ``lumina_hybrid.pub``) — present when the daemon published one on
         startup.
      2. A published peer bundle (``peers/<agent>.json``) with the hybrid suite.
    """
    short = _short(agent or _current_agent())
    d = _pqc_dir()
    for pub in (d / f"{short}_hybrid.pub", d / "lumina_hybrid.pub" if short == "lumina" else d / f"{short}_hybrid.pub"):
        if pub.exists():
            try:
                if len(bytes.fromhex(pub.read_text().strip())) == 1216:
                    return True
            except Exception:
                pass
    bundle = d / "peers" / f"{short}.json"
    if bundle.exists():
        try:
            data = json.loads(bundle.read_text())
            return data.get("suite") == HYBRID_SUITE and bool(data.get("hybrid_public_hex"))
        except Exception:
            return False
    return False


def confidentiality_suite_for(agent: Optional[str] = None) -> str:
    """The confidentiality suite a peer will negotiate TO ``agent`` today.

    ``x25519-mlkem768`` when the agent advertises a hybrid prekey, else the
    classical wrap. This is the honest, evidence-backed answer for the
    self-report — never a default assertion.
    """
    return HYBRID_SUITE if hybrid_prekey_available(agent) else "x25519-pgp-wrap-v1"
