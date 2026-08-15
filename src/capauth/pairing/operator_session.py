"""Operator session identity primitive (Unified Consent Plane, Phase 1).

Lifted from skchat's ``operator_auth.py`` (spec
``2026-08-13-unified-consent-plane-arch.md`` section 3: "one operator
identity ... lift skchat's operator_auth.py into capauth, which already owns
device pairing"). This was, verbatim, "the strongest identity primitive in
the fleet, and used by no consent surface" (section 2.1, row 10): an HS256
JWT bound to an approved, individually revocable device fingerprint. Moving
it here means the dashboard, the CLI, and any future messaging door present
the same session instead of skchat owning a private copy that nothing else
can reach.

Two independent pieces of state back :func:`verify_operator_session`, both
new here (they lived in ``skchat.guest``, not in ``operator_auth.py`` itself,
so they were never a single module to "move" -- they are re-created as
capauth-native state, closing one legacy gap on the way, see below):

* **Device standing** (:func:`is_device_approved` / :func:`is_device_revoked`
  / :func:`approve_device` / :func:`revoke_device`): whether a device
  fingerprint may currently hold a session at all.
* **Session revocation** (:func:`is_session_revoked` / :func:`revoke_session`):
  killing one already-minted token by its ``jti`` without waiting for it to
  expire.

Both are plain JSON under ``resolve_capauth_home() / "operator"``, following
the same injectable-``home`` / atomic-write shape as ``capauth.tokens``
(``revoked-tokens.json`` under ``<home>/security/``).

**Fail-open closed on the move.** skchat's ``device_registry.is_approved()``
read a device row with a *missing* ``approved`` key as approved, by design,
to avoid locking out devices enrolled before the approval-to-link feature
shipped. That default does not travel with the primitive: here, a device
fingerprint with **no** standing row, or a row with no explicit
``approved: true``, is **not** approved. There is no legacy population to
protect in a brand-new store, and defaulting an unknown device closed is the
correct posture for the thing every consent surface in the fleet is about to
lean on. A caller migrating an existing, already-trusted device population
(skchat's linked devices) must explicitly call :func:`approve_device` for
each one; this module intentionally provides no implicit grandfathering.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..exceptions import OperatorAuthError

logger = logging.getLogger("capauth.pairing.operator_session")

_TIER = "operator-session"
_DEFAULT_TTL = 12 * 3600
_MAX_TTL = 24 * 3600

#: Primary secret env var. Falls back to skchat's original name so a fleet
#: mid-cutover (secret already provisioned for the skchat-owned primitive)
#: does not invalidate every live operator session the moment this module
#: starts being consulted instead.
_SECRET_ENV = "CAPAUTH_OPERATOR_SESSION_SECRET"
_SECRET_ENV_LEGACY = "SKCHAT_OPERATOR_TOKEN_SECRET"


@dataclass
class OperatorSession:
    jti: str
    device_fp: str
    exp: int


def _secret() -> str:
    s = os.environ.get(_SECRET_ENV, "") or os.environ.get(_SECRET_ENV_LEGACY, "")
    if not s:
        raise OperatorAuthError(f"{_SECRET_ENV} not set")
    return s


def mint_operator_session(*, device_fp: str, ttl: int | None = None) -> str:
    """Mint an HS256 operator-session JWT bound to ``device_fp``.

    Minting does not itself check standing (approval/revocation): a session
    minted for a device that is not (yet, or no longer) approved is a valid
    JWT that will fail :func:`verify_operator_session`. Callers that mint and
    then hand the token straight back to a caller (the enroll-and-session HTTP
    flow) should self-verify before responding, exactly as skchat's
    ``operator_auth_routes.session`` route does.
    """
    import jwt  # PyJWT; lazy import matches capauth's existing lazy-jwt convention

    now = int(time.time())
    ttl = _DEFAULT_TTL if ttl is None else min(ttl, _MAX_TTL)
    claims = {
        "jti": uuid.uuid4().hex,
        "tier": _TIER,
        "device_fp": device_fp,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(claims, _secret(), algorithm="HS256")


def verify_operator_session(token: str, *, home: Optional[Path] = None) -> OperatorSession:
    """Verify an operator-session JWT and its device's live standing.

    Raises :class:`~capauth.exceptions.OperatorAuthError` on any of: a
    malformed/expired/wrong-secret token, the wrong ``tier``, a revoked
    session (jti), a revoked device, or a device with no approved standing.
    Order matters only for the error message; every one of these is a hard
    reject.
    """
    import jwt  # PyJWT; lazy import matches capauth's existing lazy-jwt convention

    try:
        claims = jwt.decode(
            token,
            _secret(),
            algorithms=["HS256"],
            options={"require": ["jti", "tier", "device_fp", "iat", "exp"]},
        )
    except jwt.PyJWTError as e:
        raise OperatorAuthError(f"invalid operator session: {e}") from e
    if claims.get("tier") != _TIER:
        raise OperatorAuthError("wrong tier")
    if is_session_revoked(claims["jti"], home=home):
        raise OperatorAuthError("revoked")
    # Device-level kill: unlinking a device revokes its fingerprint once, which
    # invalidates every session it holds without needing to know their jtis.
    if is_device_revoked(claims["device_fp"], home=home):
        raise OperatorAuthError("device revoked")
    # Approval-to-link: a device that is not approved cannot hold a verified
    # session, so it cannot authenticate for anything. Unlike the skchat
    # primitive this was lifted from, a missing standing row (or a row with no
    # explicit ``approved: true``) reads as NOT approved -- see the module
    # docstring for why that default does not carry over.
    if not is_device_approved(claims["device_fp"], home=home):
        raise OperatorAuthError("device pending approval")
    return OperatorSession(jti=claims["jti"], device_fp=claims["device_fp"], exp=claims["exp"])


# ── Storage plumbing (JSON under <home>/operator/, atomic write) ────────────

_state_lock = threading.Lock()


def _operator_dir(home: Optional[Path] = None) -> Path:
    if home is not None:
        return home / "operator"
    # Lazy import: capauth.__init__ imports capauth.pairing at module load
    # time, so a module-level "from .. import resolve_capauth_home" here would
    # be a circular import against the partially-initialized capauth package.
    from .. import resolve_capauth_home

    return resolve_capauth_home() / "operator"


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (ValueError, OSError):
        logger.warning("operator state file unreadable, treating as empty: %s", path)
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ── Device standing: approval + revocation, keyed by device_fp ──────────────


def _device_state_path(home: Optional[Path] = None) -> Path:
    return _operator_dir(home) / "device_state.json"


def approve_device(device_fp: str, *, approved_by: str = "", home: Optional[Path] = None) -> None:
    """Mark ``device_fp`` approved to hold an operator session. Idempotent."""
    if not device_fp:
        return
    path = _device_state_path(home)
    with _state_lock:
        data = _load_json(path)
        row = data.get(device_fp) or {}
        row["approved"] = True
        row["approved_by"] = approved_by
        row["approved_at"] = time.time()
        data[device_fp] = row
        _write_json(path, data)


def is_device_approved(device_fp: str, *, home: Optional[Path] = None) -> bool:
    """True iff ``device_fp`` has an explicit ``approved: true`` standing row.

    No row, an unreadable store, or a row with no ``approved`` key are all
    treated as NOT approved. See the module docstring: this is the fail-open
    closure, not a preserved legacy default.
    """
    if not device_fp:
        return False
    data = _load_json(_device_state_path(home))
    row = data.get(device_fp)
    if not isinstance(row, dict):
        return False
    return row.get("approved") is True


def revoke_device(device_fp: str, *, reason: str = "", home: Optional[Path] = None) -> None:
    """Revoke every session ``device_fp`` holds or will ever mint. Idempotent."""
    if not device_fp:
        return
    path = _device_state_path(home)
    with _state_lock:
        data = _load_json(path)
        row = data.get(device_fp) or {}
        row["revoked"] = True
        row["revoked_reason"] = reason
        row["revoked_at"] = time.time()
        data[device_fp] = row
        _write_json(path, data)


def unrevoke_device(device_fp: str, *, home: Optional[Path] = None) -> None:
    """Clear a device revocation (re-linking a previously unlinked device)."""
    if not device_fp:
        return
    path = _device_state_path(home)
    with _state_lock:
        data = _load_json(path)
        row = data.get(device_fp)
        if row is None:
            return
        row["revoked"] = False
        row.pop("revoked_reason", None)
        row.pop("revoked_at", None)
        data[device_fp] = row
        _write_json(path, data)


def is_device_revoked(device_fp: str, *, home: Optional[Path] = None) -> bool:
    if not device_fp:
        return False
    data = _load_json(_device_state_path(home))
    row = data.get(device_fp)
    if not isinstance(row, dict):
        return False
    return bool(row.get("revoked", False))


# ── Session revocation, keyed by jti ─────────────────────────────────────────


def _revoked_sessions_path(home: Optional[Path] = None) -> Path:
    return _operator_dir(home) / "revoked_sessions.json"


def revoke_session(jti: str, *, home: Optional[Path] = None) -> None:
    """Revoke one already-minted session by its ``jti``. Idempotent."""
    if not jti:
        return
    path = _revoked_sessions_path(home)
    with _state_lock:
        data = _load_json(path)
        data[jti] = {"revoked_at": time.time()}
        _write_json(path, data)


def is_session_revoked(jti: str, *, home: Optional[Path] = None) -> bool:
    if not jti:
        return False
    data = _load_json(_revoked_sessions_path(home))
    return jti in data


# ── Device-key enrollment handshake (challenge-response) ────────────────────
#
# Distinct from device STANDING above: this is the "prove you hold the private
# key for a fingerprint" handshake used when a new device enrolls, moved
# verbatim from skchat.operator_auth. A device must still separately be
# approved (see above) before a session minted for it will verify.

_CHALLENGE_TTL = 120
_challenges: dict[str, int] = {}
_challenge_lock = threading.Lock()


def device_fingerprint(device_pubkey_b64: str) -> str:
    return hashlib.sha256(device_pubkey_b64.encode()).hexdigest()[:16]


def issue_challenge() -> tuple[str, int]:
    nonce = secrets.token_urlsafe(24)
    exp = int(time.time()) + _CHALLENGE_TTL
    with _challenge_lock:
        # opportunistic sweep of expired nonces
        now = int(time.time())
        for k in [k for k, v in _challenges.items() if v < now]:
            _challenges.pop(k, None)
        _challenges[nonce] = exp
    return nonce, exp


def consume_challenge(nonce: str) -> bool:
    with _challenge_lock:
        exp = _challenges.pop(nonce, None)
    return exp is not None and exp >= int(time.time())


def verify_device_signature(*, device_pubkey_b64: str, payload: bytes, sig_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        spki = base64.b64decode(device_pubkey_b64)
        pub = serialization.load_der_public_key(spki)
        raw = base64.b64decode(sig_b64)
        if len(raw) == 64:  # WebCrypto P1363 r||s
            r = int.from_bytes(raw[:32], "big")
            s = int.from_bytes(raw[32:], "big")
            der = encode_dss_signature(r, s)
        else:  # already DER
            der = raw
        pub.verify(der, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


#: Override the enrolled-device store location (tests point this at tmp_path;
#: an operator can also override it). Named for backward-compat with the
#: skchat env var this replaces.
OPERATOR_DEVICES_PATH_ENV = "CAPAUTH_OPERATOR_DEVICES"
_OPERATOR_DEVICES_PATH_ENV_LEGACY = "SKCHAT_OPERATOR_DEVICES"


def default_device_store_path() -> Path:
    """Resolve the enrolled-device (pubkey) store path.

    Reads :data:`OPERATOR_DEVICES_PATH_ENV` first so tests and operators can
    relocate the store, falling back to the legacy skchat env var so an
    in-flight cutover keeps reading the same file, then to
    ``resolve_capauth_home()``.
    """
    raw = (
        os.getenv(OPERATOR_DEVICES_PATH_ENV, "").strip()
        or os.getenv(_OPERATOR_DEVICES_PATH_ENV_LEGACY, "").strip()
    )
    if raw:
        return Path(raw).expanduser()
    from .. import resolve_capauth_home  # lazy: see _operator_dir for why

    return resolve_capauth_home() / "operator" / "devices.json"


class DeviceStore:
    """Enrolled device public keys, keyed by fingerprint.

    Moved verbatim from ``skchat.operator_auth.DeviceStore``: an atomic-write
    JSON map with a reload-before-mutate step so two instances sharing one
    process never resurrect a device the other already removed. See
    :meth:`_reload_locked` for the cross-process caveat this does NOT close.
    """

    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        if self._path.exists():
            self._data = json.loads(self._path.read_text() or "{}")

    def _write(self) -> None:
        """Atomic write of the current map (caller holds ``self._lock``)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(self._data))
        os.replace(tmp, self._path)

    def _reload_locked(self) -> None:
        """Re-read the file from disk (caller holds ``self._lock``).

        Two ``DeviceStore`` instances over the same path each cache ``_data``
        from their own construction time. Without a reload before every
        mutation, a later instance's write is a full-map overwrite from that
        instance's OWN stale snapshot, silently resurrecting a device another
        instance already removed WITHIN THIS PROCESS. This does not close a
        cross-process race: reload-then-mutate-then-write is still an
        unlocked read-modify-write once two OS processes are involved.

        A read or parse failure degrades rather than raises, keeping the
        current in-memory ``self._data`` instead of clobbering it with ``{}``.
        """
        if not self._path.exists():
            self._data = {}
            return
        try:
            self._data = json.loads(self._path.read_text() or "{}")
        except (ValueError, OSError):
            logger.warning(
                "operator device store unreadable, keeping in-memory state: %s", self._path
            )

    def enroll(self, device_pubkey_b64: str) -> str:
        fp = device_fingerprint(device_pubkey_b64)
        with self._lock:
            self._reload_locked()
            self._data[fp] = device_pubkey_b64
            self._write()
        return fp

    def is_enrolled(self, device_fp: str) -> bool:
        return device_fp in self._data

    def pubkey_for(self, device_fp: str) -> str | None:
        return self._data.get(device_fp)

    def list_fps(self) -> list[str]:
        """Every enrolled device fingerprint."""
        with self._lock:
            return list(self._data.keys())

    def remove(self, device_fp: str) -> bool:
        """Drop a device so no NEW session can be minted for it."""
        with self._lock:
            self._reload_locked()
            if device_fp not in self._data:
                return False
            del self._data[device_fp]
            self._write()
            return True

    def clear(self) -> int:
        """Remove every enrolled device. Returns the count."""
        with self._lock:
            self._reload_locked()
            count = len(self._data)
            self._data = {}
            self._write()
            return count


__all__ = [
    "OperatorAuthError",
    "OperatorSession",
    "mint_operator_session",
    "verify_operator_session",
    "approve_device",
    "is_device_approved",
    "revoke_device",
    "unrevoke_device",
    "is_device_revoked",
    "revoke_session",
    "is_session_revoked",
    "device_fingerprint",
    "issue_challenge",
    "consume_challenge",
    "verify_device_signature",
    "DeviceStore",
    "default_device_store_path",
    "OPERATOR_DEVICES_PATH_ENV",
]
