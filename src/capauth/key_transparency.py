"""Append-only, hash-chained key transparency log for CapAuth.

A Certificate-Transparency-style log of key lifecycle events (key published,
rotated, revoked, subkey added) so that a key's history is tamper-evident.

Each entry embeds the SHA-256 hash of the previous entry (a hash chain), so any
retroactive edit or deletion of a past entry breaks the linkage and is detected
by :meth:`KeyTransparencyLog.verify_chain`. Peers can therefore audit that a
key was not silently swapped out from under them.

Security invariants enforced by structure:
  - The log is append-only. :meth:`~KeyTransparencyLog.append` never mutates or
    rewrites a prior entry; it only computes ``prev_hash`` from the current tail
    and writes one new line.
  - Only public, non-secret material is logged: fingerprints, event types, and
    caller-supplied payload metadata. **Private key material is never logged.**
  - The on-disk format is newline-delimited JSON (one entry per line), which
    makes append the only cheap write operation.

Entry hash definition::

    entry_hash = sha256(
        canonical(seq, ts, event_type, key_fingerprint, payload, prev_hash)
    )

where ``canonical`` is a stable, sorted-key JSON serialization (no whitespace,
UTF-8). The genesis entry uses ``prev_hash = "0" * 64``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger("capauth.key_transparency")

# SHA-256 hex digest length; the genesis entry links to this all-zero hash.
_HASH_HEX_LEN = 64
GENESIS_PREV_HASH = "0" * _HASH_HEX_LEN

# Default log location under the CapAuth home directory.
_DEFAULT_LOG_NAME = "key_transparency.log"


class KeyEventType(str, Enum):
    """Type of key lifecycle event recorded in the transparency log."""

    PUBLISHED = "published"  # A new key / DID document was published.
    ROTATED = "rotated"  # A key was rotated to a new keypair.
    REVOKED = "revoked"  # A key was revoked.
    SUBKEY_ADDED = "subkey_added"  # A subkey was added to an existing key.


@dataclass(frozen=True)
class LogEntry:
    """A single append-only, hash-chained key transparency log entry.

    Attributes:
        seq: Zero-based monotonic sequence number.
        ts: RFC 3339 / ISO 8601 UTC timestamp of when the entry was appended.
        event_type: The :class:`KeyEventType` value (as a string).
        key_fingerprint: PGP/CapAuth fingerprint the event concerns.
        payload: Arbitrary JSON-serializable public metadata for the event.
            Must never contain private key material.
        prev_hash: ``entry_hash`` of the previous entry, or
            :data:`GENESIS_PREV_HASH` for the first entry.
        entry_hash: SHA-256 over the canonical serialization of all fields
            above (excluding ``entry_hash`` itself).
    """

    seq: int
    ts: str
    event_type: str
    key_fingerprint: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_json(self) -> str:
        """Serialize the full entry (including ``entry_hash``) to one JSON line.

        Returns:
            A compact, sorted-key JSON string with no embedded newlines.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> "LogEntry":
        """Parse a single stored JSON line back into a :class:`LogEntry`.

        Args:
            line: One line of the on-disk log (a JSON object).

        Returns:
            The reconstructed entry.

        Raises:
            KeyTransparencyError: If the line is missing required fields.
        """
        try:
            raw = json.loads(line)
            return cls(
                seq=int(raw["seq"]),
                ts=str(raw["ts"]),
                event_type=str(raw["event_type"]),
                key_fingerprint=str(raw["key_fingerprint"]),
                payload=dict(raw["payload"]),
                prev_hash=str(raw["prev_hash"]),
                entry_hash=str(raw["entry_hash"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise KeyTransparencyError(f"Malformed log entry: {exc}") from exc


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking and verifying a hash-chained log.

    Attributes:
        ok: ``True`` if the whole chain verifies, ``False`` otherwise.
        entries_checked: Number of entries walked before stopping.
        broken_seq: Sequence number of the first invalid entry, or ``None``
            when ``ok`` is ``True``.
        reason: Human-readable description of the first break, or ``None``.
    """

    ok: bool
    entries_checked: int
    broken_seq: Optional[int] = None
    reason: Optional[str] = None


class KeyTransparencyError(Exception):
    """Raised on malformed entries or append-integrity violations."""


def _canonical_hash(
    *,
    seq: int,
    ts: str,
    event_type: str,
    key_fingerprint: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute the SHA-256 ``entry_hash`` over the canonical field set.

    The serialization binds every field except ``entry_hash`` itself using a
    stable sorted-key, whitespace-free JSON encoding, so the digest is stable
    across processes and Python versions.

    Args:
        seq: Sequence number.
        ts: ISO 8601 UTC timestamp.
        event_type: Event type string.
        key_fingerprint: Fingerprint the event concerns.
        payload: Public event metadata.
        prev_hash: Hash of the previous entry (chain linkage).

    Returns:
        The 64-character lowercase hex SHA-256 digest.
    """
    canonical = json.dumps(
        {
            "seq": seq,
            "ts": ts,
            "event_type": event_type,
            "key_fingerprint": key_fingerprint,
            "payload": payload,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class KeyTransparencyLog:
    """Append-only, hash-chained log of key lifecycle events.

    The log is persisted as newline-delimited JSON at ``path``. Each
    :meth:`append` reads the current tail to derive ``prev_hash``, computes the
    new ``entry_hash``, and writes exactly one new line. Prior lines are never
    rewritten, which is what makes tampering detectable by :meth:`verify_chain`.

    Example:
        >>> log = KeyTransparencyLog(path)
        >>> log.append(KeyEventType.PUBLISHED, "ABCD...", {"tier": "key"})
        >>> log.verify_chain().ok
        True
    """

    def __init__(self, path: Path) -> None:
        """Initialize the log at a specific file path.

        Args:
            path: Absolute path to the log file. Parent directories are created
                on first append; the file itself is created lazily with ``0600``
                permissions.
        """
        self.path = Path(path)

    @classmethod
    def default(cls, base_dir: Optional[Path] = None) -> "KeyTransparencyLog":
        """Construct a log rooted at the resolved CapAuth home directory.

        Args:
            base_dir: Explicit CapAuth home override. When ``None`` the standard
                :func:`capauth.resolve_capauth_home` resolution is used.

        Returns:
            A log instance at ``<capauth_home>/key_transparency.log``.
        """
        from capauth import resolve_capauth_home

        home = resolve_capauth_home(base_dir)
        return cls(home / _DEFAULT_LOG_NAME)

    # -- reads -------------------------------------------------------------

    def entries(self) -> list[LogEntry]:
        """Load and return all entries in sequence order.

        Returns:
            The full list of entries (empty if the log does not exist yet).

        Raises:
            KeyTransparencyError: If any stored line is malformed.
        """
        return list(self._iter_entries())

    def _iter_entries(self) -> Iterator[LogEntry]:
        """Yield each stored entry, skipping blank trailing lines."""
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                yield LogEntry.from_json(line)

    def _last_entry(self) -> Optional[LogEntry]:
        """Return the tail entry, or ``None`` when the log is empty."""
        last: Optional[LogEntry] = None
        for entry in self._iter_entries():
            last = entry
        return last

    # -- writes ------------------------------------------------------------

    def append(
        self,
        event_type: KeyEventType | str,
        key_fingerprint: str,
        payload: Optional[dict[str, Any]] = None,
        *,
        ts: Optional[str] = None,
    ) -> LogEntry:
        """Append one key event, linking it to the current chain tail.

        This is the only write path. It derives ``prev_hash`` from the existing
        tail (or :data:`GENESIS_PREV_HASH` for the first entry), computes the new
        ``entry_hash``, and appends a single line. Existing lines are untouched.

        Args:
            event_type: The kind of key event (:class:`KeyEventType` or its
                string value).
            key_fingerprint: Fingerprint the event concerns.
            payload: Public, JSON-serializable event metadata. **Never pass
                private key material.** Defaults to an empty dict.
            ts: Optional explicit ISO 8601 timestamp (mainly for tests);
                defaults to the current UTC time.

        Returns:
            The newly created, hash-linked :class:`LogEntry`.

        Raises:
            KeyTransparencyError: If the payload is not JSON-serializable.
        """
        event_value = event_type.value if isinstance(event_type, KeyEventType) else str(event_type)
        payload = payload or {}
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as exc:
            raise KeyTransparencyError(f"payload is not JSON-serializable: {exc}") from exc

        last = self._last_entry()
        seq = 0 if last is None else last.seq + 1
        prev_hash = GENESIS_PREV_HASH if last is None else last.entry_hash
        timestamp = ts or _utc_now_iso()

        entry_hash = _canonical_hash(
            seq=seq,
            ts=timestamp,
            event_type=event_value,
            key_fingerprint=key_fingerprint,
            payload=payload,
            prev_hash=prev_hash,
        )
        entry = LogEntry(
            seq=seq,
            ts=timestamp,
            event_type=event_value,
            key_fingerprint=key_fingerprint,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._write_line(entry)
        logger.info(
            "key transparency: appended seq=%d event=%s fp=%s",
            seq,
            event_value,
            key_fingerprint,
        )
        return entry

    def record_key_event(
        self,
        event_type: KeyEventType | str,
        key_fingerprint: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> LogEntry:
        """Record a key lifecycle event (convenience alias for :meth:`append`).

        This is the seam callers (DID publish, key rotate, PMA revoke, subkey
        add) should hook into. See module docs and ``docs`` for wiring points.

        Args:
            event_type: The kind of key event.
            key_fingerprint: Fingerprint the event concerns.
            payload: Public event metadata (no private key material).

        Returns:
            The newly appended entry.
        """
        return self.append(event_type, key_fingerprint, payload)

    def _write_line(self, entry: LogEntry) -> None:
        """Append one serialized entry line, creating the file ``0600``.

        Args:
            entry: The entry to persist.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        newly_created = not self.path.exists()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(entry.to_json() + "\n")
        if newly_created:
            try:
                os.chmod(self.path, 0o600)
            except OSError as exc:  # pragma: no cover - platform dependent
                logger.warning("could not chmod key transparency log: %s", exc)

    # -- verification ------------------------------------------------------

    def verify_chain(self) -> ChainVerification:
        """Walk the log and verify hash linkage and per-entry integrity.

        For each entry the method recomputes ``entry_hash`` from its fields and
        checks that ``prev_hash`` matches the previous entry's ``entry_hash``
        (the genesis entry must link to :data:`GENESIS_PREV_HASH`). Sequence
        numbers must be contiguous from zero. The first failure short-circuits
        and is reported.

        Returns:
            A :class:`ChainVerification` describing OK, or the first break
            (sequence number and reason).
        """
        expected_prev = GENESIS_PREV_HASH
        expected_seq = 0
        checked = 0

        for entry in self._iter_entries():
            if entry.seq != expected_seq:
                return ChainVerification(
                    ok=False,
                    entries_checked=checked,
                    broken_seq=entry.seq,
                    reason=(f"non-contiguous seq: expected {expected_seq}, got {entry.seq}"),
                )
            if entry.prev_hash != expected_prev:
                return ChainVerification(
                    ok=False,
                    entries_checked=checked,
                    broken_seq=entry.seq,
                    reason=(
                        f"prev_hash mismatch at seq {entry.seq}: chain linkage "
                        "broken (an earlier entry was altered or removed)"
                    ),
                )
            recomputed = _canonical_hash(
                seq=entry.seq,
                ts=entry.ts,
                event_type=entry.event_type,
                key_fingerprint=entry.key_fingerprint,
                payload=entry.payload,
                prev_hash=entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                return ChainVerification(
                    ok=False,
                    entries_checked=checked,
                    broken_seq=entry.seq,
                    reason=(
                        f"entry_hash mismatch at seq {entry.seq}: entry contents "
                        "were tampered with"
                    ),
                )
            expected_prev = entry.entry_hash
            expected_seq += 1
            checked += 1

        return ChainVerification(ok=True, entries_checked=checked)
