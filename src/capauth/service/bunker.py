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

E2E-encryption (DONE — see bunker_e2e.py): the client + signer perform an
ephemeral X25519 ``kex`` over the relay and AES-256-GCM ``enc`` every sensitive
message, so the broker only relays ``kex`` + ``enc`` and CANNOT read the
``sign_request`` payload or the returned signature. Defeats a passive /
honest-but-curious broker (and log/memory/3rd-party-relay leakage); see the
honest threat-model note in bunker_e2e.py for the active-MITM caveat.

SPIKE scope / hardening follow-ups (documented, NOT done here):
* Active-MITM resistance vs the broker itself (a secret the broker never sees,
  e.g. a client key fragment carried only in the QR).
* No replay/nonce protection on the bunker protocol itself (the CapAuth nonce
  TTL is the only guard today).
* No broker auth / rate-limit beyond the pairing secret + session expiry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol, Union

logger = logging.getLogger("capauth.bunker")

# Session lifetime: a pairing must complete + a sign must occur inside this.
SESSION_TTL_SECONDS = 300  # 5 minutes
# Backstop on concurrent in-memory sessions (DoS guard). Override via the
# BunkerBroker(max_sessions=) ctor / CAPAUTH_BUNKER_MAX_SESSIONS env.
MAX_ACTIVE_SESSIONS = 500
ROLE_CLIENT = "client"
ROLE_SIGNER = "signer"
_ROLES = (ROLE_CLIENT, ROLE_SIGNER)


class BunkerCapacityError(Exception):
    """Raised when the broker is at its concurrent-session cap."""


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
    # Request ids already relayed in this session — replay guard. A relayed
    # sign_request/enc whose ``id`` was already seen is rejected, so a malicious
    # or replaying peer cannot re-submit a prior (approved) request.
    seen_ids: set[str] = field(default_factory=set)

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self.created_at) >= self.ttl_seconds

    @property
    def is_paired(self) -> bool:
        return ROLE_CLIENT in self.peers and ROLE_SIGNER in self.peers

    def to_record(self) -> dict[str, Any]:
        """Serialize the durable part of the session (no live sockets, no keys).

        Only the pairing identity + approval state is written: the ``session_id``,
        the ``pairing_secret`` (an opaque join token, NOT key material), the TTL /
        creation time, and the replay-guard ``seen_ids``. The live ``peers``
        sockets are deliberately excluded (they cannot survive a process restart
        and are re-established when peers reconnect).
        """
        return {
            "session_id": self.session_id,
            "pairing_secret": self.pairing_secret,
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at,
            "seen_ids": sorted(self.seen_ids),
        }

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> "_Session":
        """Rebuild a session from a persisted record (peers start empty)."""
        s = cls(
            session_id=str(rec["session_id"]),
            pairing_secret=str(rec["pairing_secret"]),
            ttl_seconds=int(rec.get("ttl_seconds", SESSION_TTL_SECONDS)),
            created_at=float(rec["created_at"]),
        )
        s.seen_ids = set(rec.get("seen_ids") or [])
        return s


class BunkerBroker:
    """In-memory broker that pairs and relays, with optional restart survival.

    One instance is created per service process. The live peer sockets always
    live only in memory (they cannot outlast the process). When ``store_path``
    is given, the *durable* part of each session (session id, pairing secret,
    TTL/creation time, and the replay-guard ``seen_ids``) is persisted to a JSON
    file so that an approved pairing survives a service restart: a client and
    signer that reconnect with the same ``session_id`` + ``pairing_secret`` are
    rejoined to the same session instead of getting ``unknown_session`` and
    having to re-pair from scratch. No private-key material is ever persisted
    (the broker never holds any).

    On construction, non-expired persisted sessions are reloaded; expired ones
    are dropped. A missing or corrupt store is tolerated (start empty), never
    fatal. When ``store_path`` is ``None`` the broker is purely in-memory
    (previous behaviour).
    """

    def __init__(
        self,
        ttl_seconds: int = SESSION_TTL_SECONDS,
        max_sessions: int = MAX_ACTIVE_SESSIONS,
        store_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self._sessions: dict[str, _Session] = {}
        self._ttl = ttl_seconds
        self._max_sessions = max_sessions
        self._lock = asyncio.Lock()
        self._store_path: Optional[Path] = Path(store_path) if store_path else None
        # Serializes the actual disk writes (the background writer thread is the
        # only writer, but the io lock also guards inline synchronous writes).
        self._io_lock = threading.Lock()
        # Persistence from the async (event-loop) hot path must never touch the
        # loop with blocking IO. Callers running on a loop hand a pre-serialized
        # snapshot to this queue; a dedicated daemon thread does the disk write.
        # This decouples persistence from the loop entirely (blocking IO or
        # ``run_in_executor`` on the relay path both wedge Starlette's test
        # WebSocket portal). Synchronous callers write inline for immediate
        # durability. ``flush()`` drains the queue for tests / graceful shutdown.
        self._write_q: "queue.Queue[Optional[str]]" = queue.Queue()
        self._writer: Optional[threading.Thread] = None
        if self._store_path is not None:
            self._load_store()
            self._start_writer()

    # -- persistence ------------------------------------------------------

    def _start_writer(self) -> None:
        """Start the background store-writer daemon thread (idempotent)."""
        if self._writer is not None:
            return
        t = threading.Thread(target=self._writer_loop, name="bunker-store-writer", daemon=True)
        t.start()
        self._writer = t

    def _writer_loop(self) -> None:
        """Drain queued snapshots and write them to disk, in order."""
        while True:
            data = self._write_q.get()
            try:
                if data is not None:
                    self._write_store(data)
            finally:
                self._write_q.task_done()

    def flush(self) -> None:
        """Block until all queued persistence writes have hit disk.

        For tests and graceful shutdown; a no-op when persistence is disabled.
        """
        if self._store_path is None:
            return
        self._write_q.join()

    def _load_store(self) -> None:
        """Reload persisted, non-expired sessions. Missing/corrupt = start empty.

        Never raises: a broker must always come up, even if the store is absent
        or malformed. Expired records are silently dropped on load.
        """
        path = self._store_path
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text())
        except Exception as exc:
            logger.warning("bunker: session store unreadable (%s); starting empty", exc)
            return
        records = raw.get("sessions", []) if isinstance(raw, dict) else raw
        now = time.time()
        loaded = 0
        for rec in records or []:
            try:
                session = _Session.from_record(rec)
            except Exception:
                logger.warning("bunker: skipping malformed session record")
                continue
            if session.is_expired(now):
                continue
            self._sessions[session.session_id] = session
            loaded += 1
        if loaded:
            logger.info("bunker: reloaded %d persisted session(s)", loaded)
        # Rewrite so any dropped-expired / malformed records are pruned on disk.
        # Construction is synchronous (no running loop), so write inline.
        self._write_store(self._serialize())

    def _serialize(self) -> str:
        """Snapshot the durable session state as a JSON string.

        Called on the caller's thread so the ``self._sessions`` read is
        consistent with the surrounding (locked) mutation, before any write is
        potentially off-loaded to another thread.
        """
        records = [s.to_record() for s in self._sessions.values()]
        return json.dumps({"version": 1, "sessions": records})

    def _write_store(self, data: str) -> None:
        """Atomically write ``data`` to the store file (mode 0600). Never raises.

        Only serialized :meth:`_Session.to_record` output is written (session id
        + pairing secret + TTL + replay ids), never live sockets, never key
        material.
        """
        path = self._store_path
        if path is None:
            return
        try:
            with self._io_lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_name(path.name + ".tmp")
                # Create the temp file 0600 before writing any secret material.
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.write(fd, data.encode("utf-8"))
                finally:
                    os.close(fd)
                os.replace(tmp, path)
        except Exception as exc:  # pragma: no cover - disk error path
            logger.warning("bunker: could not persist session store: %s", exc)

    def _persist(self) -> None:
        """Persist the current sessions durably.

        The snapshot (:meth:`_serialize`) is always taken synchronously on the
        caller's thread so it is consistent with the mutation that triggered it
        (no ``await`` interleaves). When called on a running event loop (the POST
        handler / the websocket relay), the disk write is handed to the
        background writer thread so the loop never blocks; in a plain synchronous
        context (construction, direct unit-test calls) it writes inline for
        immediate durability. No-op when persistence is disabled.
        """
        if self._store_path is None:
            return
        data = self._serialize()
        try:
            asyncio.get_running_loop()
            on_loop = True
        except RuntimeError:
            on_loop = False
        if on_loop:
            self._write_q.put(data)  # off the loop; writer thread persists it
        else:
            self._write_store(data)  # sync context: durable immediately

    # -- pairing ----------------------------------------------------------

    def create_session(self) -> dict[str, str]:
        """Create a new pairing session and return its id + pairing secret.

        Returns:
            dict with ``session_id`` and ``pairing_secret`` (both opaque).

        Raises:
            BunkerCapacityError: if too many sessions are already active (after
                a GC sweep) — a DoS backstop.
        """
        self._gc()
        if len(self._sessions) >= self._max_sessions:
            raise BunkerCapacityError("too many active bunker sessions")
        session_id = secrets.token_urlsafe(12)
        pairing_secret = secrets.token_urlsafe(24)
        self._sessions[session_id] = _Session(session_id, pairing_secret, ttl_seconds=self._ttl)
        self._persist()
        logger.info("bunker: session created %s", session_id)
        return {"session_id": session_id, "pairing_secret": pairing_secret}

    def get_session(self, session_id: str) -> Optional[_Session]:
        s = self._sessions.get(session_id)
        if s and s.is_expired():
            self._sessions.pop(session_id, None)
            self._persist()
            return None
        return s

    def _gc(self) -> None:
        """Drop expired sessions (called opportunistically on create)."""
        now = time.time()
        dead = [sid for sid, s in self._sessions.items() if s.is_expired(now)]
        for sid in dead:
            self._sessions.pop(sid, None)
        if dead:
            self._persist()
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
            removed = False
            if not session.peers:
                self._sessions.pop(session_id, None)
                removed = True
        if removed:
            self._persist()
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
            # Replay guard: a request-bearing message (the client's sign_request,
            # or its sealed `enc` wrapper) may only be relayed once per session.
            newly_seen = False
            if mtype in ("sign_request", "enc") and from_role == ROLE_CLIENT:
                rid = message.get("id")
                if rid:
                    if rid in session.seen_ids:
                        return "duplicate_request"
                    session.seen_ids.add(rid)
                    newly_seen = True
            target_role = ROLE_SIGNER if from_role == ROLE_CLIENT else ROLE_CLIENT
            target = session.peers.get(target_role)
        # Persist the grown replay-guard so a request approved just before a
        # restart cannot be replayed against the reloaded session afterwards.
        if newly_seen:
            self._persist()
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
# ``kex`` carries an ephemeral X25519 public key; ``enc`` carries an AES-GCM
# sealed envelope (see bunker_e2e.py). With E2E on, the broker only ever sees
# kex + enc — the sign_request payload and the signature are unreadable to it.
# The plaintext sign_* types remain relayable for the legacy / non-E2E path and
# the test harness.
_RELAYED_TYPES = frozenset({"sign_request", "sign_response", "approve", "reject", "kex", "enc"})


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
    return f"capauth-bunker://{broker_host}/{quote(session_id, safe='')}?{urlencode(qs)}"


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
