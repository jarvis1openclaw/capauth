"""CapAuth Bunker — NIP-46-style remote signer broker (SPIKE).

The *bunker* lets a PHONE hold the PGP private key and sign login requests
relayed from any device (a desktop browser / extension). The private key
NEVER touches the desktop; the broker only relays opaque messages between
two peers joined to the same session.

Roles
-----
* **client** — the desktop browser / extension. It builds the *exact*
  ``CAPAUTH_NONCE_V2`` canonical payload and asks the phone to sign it.
* **signer** ("bunker") — the phone PWA holding the key. It shows an approval
  prompt (origin + fingerprint + payload), signs with OpenPGP.js, and returns
  the armored detached signature.
* **broker** — this module. A WebSocket relay that pairs ``client`` <-> ``signer``
  by a ``session_id`` and forwards messages. It is intentionally *dumb*: it
  validates the message envelope, never inspects the signing payload's meaning,
  and **never sees the private key**.

Pairing
-------
The client creates a session (``create_session``) and renders a QR encoding a
``capauth-bunker://`` URI (analog of ``nostrconnect://``). The phone scans it,
opens ``/bunker/ws?session=<id>&role=signer&key=<pairing_secret>``, and both
sides receive a ``paired`` event.

Pairing URI format::

    capauth-bunker://<broker-host>/<session-id>?key=<pairing-secret>&relay=<wss-url>

Message protocol (JSON over the WS, both directions)
----------------------------------------------------
Control (broker <-> peer):

    {"type": "hello",  "role": "client"|"signer", "session": "<id>"}   (peer->broker, sent as query too)
    {"type": "paired", "role": "client"|"signer"}                       (broker->peer, when both present)
    {"type": "peer_left", "role": "..."}                               (broker->peer)
    {"type": "error", "code": "...", "message": "..."}                  (broker->peer)

Relayed (client <-> signer, broker is pass-through):

    client -> signer:
      {"type": "sign_request", "id": "<req-id>", "payload": "<canonical bytes>",
       "origin": "<rp origin>", "fingerprint": "<expected fp>",
       "version": "CAPAUTH_NONCE_V2"}

    signer -> client:
      {"type": "approve",  "id": "<req-id>"}                            (optional UX ping)
      {"type": "reject",   "id": "<req-id>", "reason": "..."}
      {"type": "sign_response", "id": "<req-id>", "signature": "<armored>",
       "fingerprint": "<fp that signed>"}

SPIKE scope / hardening follow-ups (documented, NOT done here):
* The relay is plaintext app-layer (TLS terminates at the funnel/ingress). The
  hardening step is to **E2E-encrypt** the relayed ``payload``/``signature`` so
  the broker process cannot read them (X25519 ECDH from the pairing secret).
* No replay/nonce protection on the bunker protocol itself (the CapAuth nonce
  TTL is the only guard today).
* No broker auth / rate-limit beyond the pairing secret + session expiry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

logger = logging.getLogger("capauth.bunker")

# Session lifetime: a pairing must complete + a sign must occur inside this.
SESSION_TTL_SECONDS = 300  # 5 minutes
ROLE_CLIENT = "client"
ROLE_SIGNER = "signer"
_ROLES = (ROLE_CLIENT, ROLE_SIGNER)


class WSLike(Protocol):
    """Minimal async websocket surface (subset of Starlette's WebSocket).

    Kept as a Protocol so the relay logic is testable with a mock socket that
    only implements ``send_json``.
    """

    async def send_json(self, data: Any) -> None:  # pragma: no cover - protocol
        ...


@dataclass
class _Session:
    """In-memory pairing session. Holds the two peer sockets, no key material."""

    session_id: str
    pairing_secret: str
    ttl_seconds: int = SESSION_TTL_SECONDS
    created_at: float = field(default_factory=time.time)
    peers: dict[str, WSLike] = field(default_factory=dict)

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self.created_at) >= self.ttl_seconds

    @property
    def is_paired(self) -> bool:
        return ROLE_CLIENT in self.peers and ROLE_SIGNER in self.peers


class BunkerBroker:
    """Stateless-ish in-memory broker that pairs and relays.

    One instance is created per service process. Sessions live only in memory
    and expire; nothing is persisted. Safe for the single-worker spike service.
    """

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._sessions: dict[str, _Session] = {}
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    # -- pairing ----------------------------------------------------------

    def create_session(self) -> dict[str, str]:
        """Create a new pairing session and return its id + pairing secret.

        Returns:
            dict with ``session_id`` and ``pairing_secret`` (both opaque).
        """
        self._gc()
        session_id = secrets.token_urlsafe(12)
        pairing_secret = secrets.token_urlsafe(24)
        self._sessions[session_id] = _Session(
            session_id, pairing_secret, ttl_seconds=self._ttl
        )
        logger.info("bunker: session created %s", session_id)
        return {"session_id": session_id, "pairing_secret": pairing_secret}

    def get_session(self, session_id: str) -> Optional[_Session]:
        s = self._sessions.get(session_id)
        if s and s.is_expired():
            self._sessions.pop(session_id, None)
            return None
        return s

    def _gc(self) -> None:
        """Drop expired sessions (called opportunistically on create)."""
        now = time.time()
        dead = [sid for sid, s in self._sessions.items() if s.is_expired(now)]
        for sid in dead:
            self._sessions.pop(sid, None)
        if dead:
            logger.debug("bunker: gc dropped %d expired sessions", len(dead))

    # -- connection lifecycle --------------------------------------------

    async def join(
        self, session_id: str, role: str, pairing_secret: str, ws: WSLike
    ) -> Optional[str]:
        """Attach a peer socket to a session.

        Returns:
            ``None`` on success, otherwise an error code string. On success the
            caller's socket is registered; if both peers are now present, a
            ``paired`` event is sent to BOTH.
        """
        if role not in _ROLES:
            return "invalid_role"
        async with self._lock:
            session = self.get_session(session_id)
            if session is None:
                return "unknown_session"
            if not secrets.compare_digest(pairing_secret, session.pairing_secret):
                return "bad_pairing_secret"
            if role in session.peers:
                return "role_taken"
            session.peers[role] = ws
            paired = session.is_paired
        if paired:
            await self._broadcast_paired(session)
        logger.info("bunker: %s joined session %s (paired=%s)", role, session_id, paired)
        return None

    async def leave(self, session_id: str, role: str) -> None:
        """Detach a peer; notify the remaining peer that its partner left."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session.peers.pop(role, None)
            remaining = dict(session.peers)
            if not session.peers:
                self._sessions.pop(session_id, None)
        for other_role, sock in remaining.items():
            await self._safe_send(sock, {"type": "peer_left", "role": role})
        logger.info("bunker: %s left session %s", role, session_id)

    # -- relay ------------------------------------------------------------

    async def relay(self, session_id: str, from_role: str, message: dict) -> Optional[str]:
        """Forward a message from one peer to the other.

        The broker validates the envelope ``type`` is a known relayed type but
        does NOT interpret the signing payload. Returns ``None`` on success or
        an error code.
        """
        mtype = message.get("type")
        if mtype not in _RELAYED_TYPES:
            return "unrelayable_type"
        async with self._lock:
            session = self.get_session(session_id)
            if session is None:
                return "unknown_session"
            target_role = ROLE_SIGNER if from_role == ROLE_CLIENT else ROLE_CLIENT
            target = session.peers.get(target_role)
        if target is None:
            return "peer_absent"
        await self._safe_send(target, message)
        return None

    # -- helpers ----------------------------------------------------------

    async def _broadcast_paired(self, session: _Session) -> None:
        for role, sock in list(session.peers.items()):
            await self._safe_send(sock, {"type": "paired", "role": role})

    @staticmethod
    async def _safe_send(sock: WSLike, data: dict) -> None:
        try:
            await sock.send_json(data)
        except Exception as exc:  # pragma: no cover - transport error path
            logger.warning("bunker: send failed: %s", exc)


# Messages the broker will relay client<->signer (pass-through, opaque payload).
_RELAYED_TYPES = frozenset(
    {"sign_request", "sign_response", "approve", "reject"}
)


def build_pairing_uri(
    broker_host: str, session_id: str, pairing_secret: str, relay_ws_url: str = ""
) -> str:
    """Build the ``capauth-bunker://`` pairing URI encoded into the QR.

    Args:
        broker_host: Host (and optional port) of the broker, e.g.
            ``capauth-skstack41.skworld.io`` or a Tailscale Funnel host.
        session_id: The session id from :meth:`BunkerBroker.create_session`.
        pairing_secret: The pairing secret (becomes the ``key`` query param).
        relay_ws_url: Optional explicit ``wss://.../bunker/ws`` URL the phone
            should connect to (overrides deriving it from ``broker_host``).

    Returns:
        ``capauth-bunker://<host>/<session>?key=<secret>[&relay=<wss-url>]``
    """
    from urllib.parse import quote, urlencode

    qs = {"key": pairing_secret}
    if relay_ws_url:
        qs["relay"] = relay_ws_url
    return (
        f"capauth-bunker://{broker_host}/{quote(session_id, safe='')}"
        f"?{urlencode(qs)}"
    )


def parse_pairing_uri(uri: str) -> dict[str, str]:
    """Parse a ``capauth-bunker://`` URI back into its parts (phone side helper).

    Returns:
        dict with ``broker_host``, ``session_id``, ``pairing_secret``,
        ``relay`` (may be "").

    Raises:
        ValueError: if the URI is not a capauth-bunker URI.
    """
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(uri)
    if parsed.scheme != "capauth-bunker":
        raise ValueError("not a capauth-bunker URI")
    broker_host = parsed.netloc
    session_id = parsed.path.lstrip("/")
    q = parse_qs(parsed.query)
    return {
        "broker_host": broker_host,
        "session_id": session_id,
        "pairing_secret": (q.get("key") or [""])[0],
        "relay": (q.get("relay") or [""])[0],
    }
