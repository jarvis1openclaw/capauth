"""Tests for the append-only, hash-chained key transparency log.

Covers coord card 0d918433. Exercises the CT-style invariants:
  - appending grows the chain with correct prev_hash linkage,
  - verify_chain passes on a valid log,
  - tampering with (or deleting) a middle entry is DETECTED,
  - append never mutates prior entries,
  - no private key material is written by the log itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capauth.key_transparency import (
    GENESIS_PREV_HASH,
    ChainVerification,
    KeyEventType,
    KeyTransparencyError,
    KeyTransparencyLog,
    LogEntry,
)


@pytest.fixture()
def log(tmp_path: Path) -> KeyTransparencyLog:
    """A fresh log rooted in a temp directory."""
    return KeyTransparencyLog(tmp_path / "key_transparency.log")


def _seed(log: KeyTransparencyLog) -> list[LogEntry]:
    """Append three linked events and return them."""
    return [
        log.append(KeyEventType.PUBLISHED, "FP-A", {"tier": "key"}),
        log.append(KeyEventType.SUBKEY_ADDED, "FP-A", {"subkey": "kem"}),
        log.append(KeyEventType.ROTATED, "FP-B", {"from": "FP-A"}),
    ]


# -- append / linkage ------------------------------------------------------


def test_append_grows_chain_with_prev_hash_linkage(log: KeyTransparencyLog) -> None:
    """Each appended entry links to the previous entry_hash; genesis is zeros."""
    e0, e1, e2 = _seed(log)

    assert [e.seq for e in (e0, e1, e2)] == [0, 1, 2]
    assert e0.prev_hash == GENESIS_PREV_HASH
    assert e1.prev_hash == e0.entry_hash
    assert e2.prev_hash == e1.entry_hash
    # Distinct content yields distinct hashes.
    assert len({e0.entry_hash, e1.entry_hash, e2.entry_hash}) == 3


def test_entries_persist_and_reload(log: KeyTransparencyLog) -> None:
    """Entries survive a fresh reader over the same file."""
    _seed(log)
    reloaded = KeyTransparencyLog(log.path).entries()
    assert [e.seq for e in reloaded] == [0, 1, 2]
    assert reloaded[2].event_type == KeyEventType.ROTATED.value


def test_record_key_event_alias(log: KeyTransparencyLog) -> None:
    """record_key_event is a thin alias over append."""
    entry = log.record_key_event(KeyEventType.REVOKED, "FP-A", {"reason": "compromised"})
    assert entry.event_type == KeyEventType.REVOKED.value
    assert entry.seq == 0


def test_payload_must_be_serializable(log: KeyTransparencyLog) -> None:
    """A non-JSON payload is rejected before anything is written."""
    with pytest.raises(KeyTransparencyError):
        log.append(KeyEventType.PUBLISHED, "FP-A", {"bad": object()})
    assert not log.path.exists() or log.entries() == []


# -- verify_chain: happy path ---------------------------------------------


def test_verify_chain_ok_on_valid_log(log: KeyTransparencyLog) -> None:
    """A well-formed chain verifies and reports all entries checked."""
    _seed(log)
    result = log.verify_chain()
    assert isinstance(result, ChainVerification)
    assert result.ok is True
    assert result.entries_checked == 3
    assert result.broken_seq is None


def test_verify_chain_ok_on_empty_log(log: KeyTransparencyLog) -> None:
    """An empty / nonexistent log trivially verifies."""
    result = log.verify_chain()
    assert result.ok is True
    assert result.entries_checked == 0


# -- verify_chain: tamper detection ---------------------------------------


def _rewrite_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(l if l.endswith("\n") else l + "\n" for l in lines))


def test_tampering_with_middle_entry_is_detected(log: KeyTransparencyLog) -> None:
    """Mutating a middle entry's payload breaks its entry_hash and is caught."""
    _seed(log)
    assert log.verify_chain().ok is True  # fail-before-would-be-false guard

    raw = log.path.read_text().splitlines()
    mutated = json.loads(raw[1])
    mutated["payload"] = {"subkey": "TAMPERED"}  # entry_hash left stale
    raw[1] = json.dumps(mutated)
    _rewrite_lines(log.path, raw)

    result = log.verify_chain()
    assert result.ok is False
    assert result.broken_seq == 1
    assert "tampered" in (result.reason or "").lower()


def test_deleting_middle_entry_is_detected(log: KeyTransparencyLog) -> None:
    """Removing a middle entry breaks seq contiguity / prev_hash linkage."""
    _seed(log)
    raw = log.path.read_text().splitlines()
    del raw[1]  # drop seq=1
    _rewrite_lines(log.path, raw)

    result = log.verify_chain()
    assert result.ok is False
    assert result.broken_seq == 2  # first surviving entry that no longer links


def test_tampering_with_prev_hash_is_detected(log: KeyTransparencyLog) -> None:
    """Rewriting a prev_hash to forge linkage is caught."""
    _seed(log)
    raw = log.path.read_text().splitlines()
    mutated = json.loads(raw[2])
    mutated["prev_hash"] = "f" * 64
    raw[2] = json.dumps(mutated)
    _rewrite_lines(log.path, raw)

    result = log.verify_chain()
    assert result.ok is False
    assert result.broken_seq == 2


# -- append immutability ---------------------------------------------------


def test_append_never_mutates_prior_entries(log: KeyTransparencyLog) -> None:
    """A later append leaves all earlier stored lines byte-for-byte unchanged."""
    _seed(log)
    before = log.path.read_text().splitlines()

    log.append(KeyEventType.REVOKED, "FP-B", {"reason": "rotation complete"})
    after = log.path.read_text().splitlines()

    assert after[: len(before)] == before  # prefix is identical, only appended
    assert len(after) == len(before) + 1
    assert log.verify_chain().ok is True


def test_no_private_key_material_logged(log: KeyTransparencyLog) -> None:
    """The log writes only what callers pass; nothing pulls in secret material."""
    log.append(KeyEventType.PUBLISHED, "FP-A", {"public_key_tier": "did:key"})
    contents = log.path.read_text()
    assert "PRIVATE KEY BLOCK" not in contents
    assert "private" not in contents.lower()
