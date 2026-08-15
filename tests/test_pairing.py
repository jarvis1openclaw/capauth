"""Tests for the CapAuth pairing kernel (spine M2, capauth.pairing).

Covers, all with an injected ``tmp_path`` storage root (never the real
``~/.skcapstone`` registry):

* each mode's enroll + approve happy path (verified / attested / tofu);
* ``enroll_device`` canonicalizes a translatable legacy subject shape and
  refuses a subject that still does not conform (card N3);
* the operator window (open, nonce check, expiry, max_accepts, rate limit);
* revoke as a state transition;
* list_devices filtering by subject + include_revoked;
* mode_satisfies ordering (verified > attested > tofu);
* the sidecar storage round-trip proving an existing v1 peer record shape is
  preserved byte-for-byte, with only the ``pairing`` sidecar added.
"""

from __future__ import annotations

import copy
import itertools
import json

import pytest

from capauth.exceptions import SubjectNamingError
from capauth.pairing import (
    SIDECAR_KEY,
    SIDECAR_VERSION,
    DeviceRecord,
    EnrollmentMode,
    PairingError,
    PairingStore,
    approve,
    attested_challenge,
    enroll_device,
    fingerprint_for,
    list_devices,
    mode_satisfies,
    open_window,
    revoke,
    verified_challenge,
)

from .conftest import enrolled_attested_credentials, enrolled_verified_credentials

# A representative v1 peer record, exactly as the shipped registry writes it
# (fields copied from ~/.skcapstone/peers/architect.json). Used to prove the
# sidecar round-trip preserves the existing shape verbatim.
V1_PEER = {
    "name": "The Strategic Architect",
    "identity": "capauth:architect@skworld.io",
    "fingerprint": "9F6A6710121925B6AD6E53C9A25BB1BC978C28F5",
    "public_key": "",
    "entity_type": "ai-agent",
    "handle": "architect@skworld.io",
    "email": "architect@skworld.io",
    "capabilities": ["capauth:identity", "skchat:p2p-chat"],
    "contact_uris": ["capauth:architect@skworld.io", "mailto:architect@skworld.io"],
    "trust_level": "verified",
    "added_at": "2026-04-28T01:34:48.902219+00:00",
    "last_seen": None,
    "source": "auto-generated:generate-peers-from-agents",
    "agent_type": "ai",
    "notes": "Brutally direct diagnostic coach.",
    "transport_addresses": {"file": "file:///home/cbrd21/.skcomm/inbox"},
    "capauth_uri": "capauth:architect@skworld.io",
    "fqid": "architect@chef.skworld",
}


class _Clock:
    """Deterministic monotonic-ish clock the window can inject."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# --------------------------------------------------------------------------
# mode ordering
# --------------------------------------------------------------------------


def test_mode_satisfies_ordering():
    # verified (3) > attested (2) > tofu (1)
    assert mode_satisfies("verified", "verified")
    assert mode_satisfies("verified", "attested")
    assert mode_satisfies("verified", "tofu")
    assert mode_satisfies("attested", "tofu")
    assert mode_satisfies("attested", "attested")
    # weaker never satisfies stronger
    assert not mode_satisfies("tofu", "attested")
    assert not mode_satisfies("tofu", "verified")
    assert not mode_satisfies("attested", "verified")
    # enum and string are interchangeable
    assert mode_satisfies(EnrollmentMode.VERIFIED, EnrollmentMode.TOFU)


def test_mode_satisfies_rejects_unknown():
    with pytest.raises(ValueError):
        mode_satisfies("bogus", "tofu")


def test_device_record_satisfies_honors_revocation():
    dev = DeviceRecord(
        device_id="d1",
        subject="phone",
        pubkey="k",
        mode=EnrollmentMode.VERIFIED,
        approved_by="op",
    )
    assert dev.satisfies("attested")
    dev.revoked = True
    # a revoked device satisfies nothing, even at its own mode
    assert not dev.satisfies("tofu")


# --------------------------------------------------------------------------
# per-mode enroll + approve happy paths
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    [EnrollmentMode.VERIFIED, EnrollmentMode.ATTESTED, EnrollmentMode.TOFU],
)
def test_enroll_and_approve_happy_path(tmp_path, mode):
    # "phone@chef.skworld" is the missing-TLD legacy shape agent_identity has
    # shipped as its fqid field (IDENTITY_NAMING_STANDARD.md sec 2.5); enroll_device
    # normalizes it to the canonical "phone@chef.skworld.io" (card N3), it is
    # not refused. Proof (card N10) is bound to that CANONICAL form, since
    # that is what enroll_device actually verifies against.
    canonical_subject = "phone@chef.skworld.io"
    pubkey = "device-pubkey-material"
    extra: dict = {}
    if mode is EnrollmentMode.VERIFIED:
        pubkey, proof = enrolled_verified_credentials(canonical_subject)
        extra = {"proof": proof}
    elif mode is EnrollmentMode.ATTESTED:
        operator_pubkey, attestation = enrolled_attested_credentials(pubkey, canonical_subject)
        extra = {
            "operator_id": "chef@skworld.io",
            "operator_pubkey": operator_pubkey,
            "attestation": attestation,
        }

    enr = enroll_device(
        pubkey,
        ["skchat.send", "skchat.inbox"],
        mode=mode,
        base_dir=tmp_path,
        subject="phone@chef.skworld",
        **extra,
    )
    assert enr.mode == mode
    assert enr.requested_scopes == ["skchat.send", "skchat.inbox"]
    assert enr.fingerprint  # derived
    assert enr.subject == "phone@chef.skworld.io"
    # mode-specific evidence rode onto the record
    for key, val in extra.items():
        assert getattr(enr, key) == val

    dev = approve(enr.enrollment_id, "chef@skworld.io", base_dir=tmp_path)
    assert isinstance(dev, DeviceRecord)
    assert dev.mode == mode
    assert dev.scopes == ["skchat.send", "skchat.inbox"]
    assert dev.approved_by == "chef@skworld.io"
    assert dev.subject == "phone@chef.skworld.io"
    assert not dev.revoked

    # it now shows up in the registry, and the pending enrollment is consumed
    devices = list_devices(base_dir=tmp_path)
    assert [d.device_id for d in devices] == [dev.device_id]
    assert PairingStore(tmp_path).load_enrollment(enr.enrollment_id) is None


def test_approve_unknown_enrollment_raises(tmp_path):
    with pytest.raises(PairingError):
        approve("does-not-exist", "chef", base_dir=tmp_path)


def test_enroll_defaults_subject_to_fingerprint(tmp_path):
    # No subject given: defaults to the bare fingerprint, then canonicalizes to
    # the one legal prefixed subject class for a fingerprint-only seat (card N3).
    # canonical_subject lowercases (case is not an identity dimension), while
    # ``fingerprint`` itself rides the record unmodified, so the two differ in
    # case here.
    enr = enroll_device("some-key", ["s"], mode="tofu", base_dir=tmp_path)
    assert enr.fingerprint == fingerprint_for("some-key")
    assert enr.subject == f"device:{enr.fingerprint.lower()}"


# --------------------------------------------------------------------------
# subject canonicalization (card N3, bab1cca6): enroll_device refuses what
# does not conform to IDENTITY_NAMING_STANDARD.md, normalizing a translatable
# legacy shape rather than rejecting it outright.
# --------------------------------------------------------------------------


def test_enroll_device_refuses_a_non_conforming_subject(tmp_path):
    # Not ASCII/dot-clean/grammar-matching, and no alias translates it: this is
    # exactly the naming defect that used to surface later, at decide() time, as
    # an opaque "unknown subject" deny. It is refused HERE instead, at the one
    # entry point that writes a subject into the store.
    with pytest.raises(SubjectNamingError):
        enroll_device(
            "k", ["s"], mode="tofu", base_dir=tmp_path, subject="not-a-conforming-subject"
        )
    # nothing was persisted
    assert list_devices(base_dir=tmp_path) == []


def test_enroll_device_refuses_trailing_dot():
    with pytest.raises(SubjectNamingError):
        enroll_device("k", ["s"], mode="tofu", subject="alice@chef.skworld.io.")


def test_enroll_device_refuses_non_ascii_subject():
    with pytest.raises(SubjectNamingError):
        enroll_device("k", ["s"], mode="tofu", subject="lümina@chef.skworld.io")


@pytest.mark.parametrize(
    "legacy,canonical",
    [
        ("capauth:lumina@skworld.io", "lumina@chef.skworld.io"),
        ("lumina@skworld.io", "lumina@chef.skworld.io"),
        ("architect@chef.skworld", "architect@chef.skworld.io"),
        ("architect@skcapstone.local", "architect@chef.skworld.io"),
        (
            "operator:0a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d",
            "device:0a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d",
        ),
        ("CAPAUTH:Lumina@Skworld.io", "lumina@chef.skworld.io"),
    ],
)
def test_enroll_device_normalizes_every_documented_legacy_shape(tmp_path, legacy, canonical):
    # The six shapes subject.py's own docstring documents finding live in the
    # pairing store: enroll_device translates every one, it does not refuse
    # them (a translatable legacy shape is not the naming defect this card
    # closes; an UNtranslatable one is).
    enr = enroll_device(f"key-{legacy}", ["s"], mode="tofu", base_dir=tmp_path, subject=legacy)
    assert enr.subject == canonical


def test_enroll_device_normalizes_a_bare_device_fingerprint():
    # skchat.pairing_mirror.mirror_admission presents a bare peer fingerprint
    # (no "device:" prefix) as ``subject``: the ONE legal prefixed subject
    # class is "device:<fingerprint>", so this is normalized rather than
    # refused, not a new alias invented ad hoc.
    bare_fp = "0a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d"
    enr = enroll_device("some-device-key", ["s"], mode="tofu", subject=bare_fp)
    assert enr.subject == f"device:{bare_fp}"


def test_list_devices_finds_a_bare_fingerprint_enrollment_by_the_same_bare_query(tmp_path):
    # A caller that enrolled under a bare fingerprint (normalized to
    # "device:<fp>" at write time) must still be able to look the device up by
    # that SAME bare fingerprint at read time (skchat.pairing_mirror.mirror_revocation
    # does exactly this), or normalizing at enroll_device silently breaks
    # revocation for every TOFU-admitted peer.
    bare_fp = "0a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d"
    enr = enroll_device("some-device-key", ["s"], mode="tofu", base_dir=tmp_path, subject=bare_fp)
    approve(enr.enrollment_id, "skchat", base_dir=tmp_path)

    found = list_devices(bare_fp, base_dir=tmp_path)
    assert len(found) == 1
    assert found[0].subject == f"device:{bare_fp}"


def test_list_devices_still_finds_a_pre_n3_non_canonical_record(tmp_path):
    # A device enrolled before this card, under a subject canonical_subject
    # cannot translate, must remain findable by that exact raw string: this
    # card canonicalizes going forward, it is not a data migration.
    peers = tmp_path / "peers"
    peers.mkdir(parents=True)
    (peers / "legacyhandle.json").write_text(
        json.dumps(
            {
                "name": "legacyhandle",
                "identity": "legacyhandle",
                "fingerprint": "AA",
                "pairing": {
                    "version": SIDECAR_VERSION,
                    "devices": [
                        {
                            "device_id": "pre-n3-device",
                            "subject": "legacyhandle",
                            "pubkey": "k",
                            "fingerprint": "AA",
                            "mode": "tofu",
                            "scopes": [],
                            "approved_by": "chef",
                            "approved_at": "2026-01-01T00:00:00+00:00",
                            "revoked": False,
                        }
                    ],
                },
            }
        )
    )
    found = list_devices("legacyhandle", base_dir=tmp_path)
    assert [d.device_id for d in found] == ["pre-n3-device"]


# --------------------------------------------------------------------------
# operator pairing window (promoted PairingGate semantics)
# --------------------------------------------------------------------------


def test_window_open_and_nonce_check(tmp_path):
    clock = _Clock()
    win = open_window(now=clock)
    assert win.is_open()
    assert win.nonce
    # good nonce enrolls; consumes one accept
    enr = enroll_device(
        "k1", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce=win.nonce
    )
    assert enr.window_id == win.window_id
    assert win.accepts == 1


def test_window_bad_nonce_refused(tmp_path):
    win = open_window()
    with pytest.raises(PairingError, match="nonce"):
        enroll_device("k", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce="wrong")
    # nothing persisted
    assert list_devices(base_dir=tmp_path) == []


def test_window_expiry_refuses(tmp_path):
    clock = _Clock()
    win = open_window(window_ttl=300.0, now=clock)
    nonce = win.nonce
    clock.advance(301.0)
    assert not win.is_open()
    with pytest.raises(PairingError, match="not open"):
        enroll_device("k", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce=nonce)


def test_window_max_accepts_auto_closes(tmp_path):
    clock = _Clock()
    win = open_window(max_accepts=2, now=clock)
    nonce = win.nonce
    e1 = enroll_device("k1", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce=nonce)
    e2 = enroll_device("k2", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce=nonce)
    # cap hit -> window auto-closed
    assert not win.is_open()
    with pytest.raises(PairingError, match="not open"):
        enroll_device("k3", ["s"], mode="tofu", base_dir=tmp_path, window=win, window_nonce=nonce)
    # the two that got through the window approve into two devices
    approve(e1.enrollment_id, "chef", base_dir=tmp_path)
    approve(e2.enrollment_id, "chef", base_dir=tmp_path)
    assert len(list_devices(base_dir=tmp_path)) == 2


def test_window_rate_limit(tmp_path):
    clock = _Clock()
    # allow only 3 attempts per rolling 60s; keep accept cap high so throttle is
    # the thing under test.
    win = open_window(
        max_accepts=100, throttle_window=60.0, max_attempts_per_throttle=3, now=clock
    )
    ok_nonce = win.nonce
    # 3 attempts allowed
    for _ in range(3):
        ok, _reason = win.check(ok_nonce)
        assert ok
    # 4th within the window is throttled
    ok, reason = win.check(ok_nonce)
    assert not ok
    assert "rate limited" in reason
    # after the throttle window slides, attempts are allowed again
    clock.advance(61.0)
    ok, _reason = win.check(ok_nonce)
    assert ok


# --------------------------------------------------------------------------
# revoke
# --------------------------------------------------------------------------


def test_revoke_is_a_state_transition(tmp_path):
    pubkey, proof = enrolled_verified_credentials("laptop@chef.skworld.io")
    enr = enroll_device(
        pubkey,
        ["skchat.send"],
        mode="verified",
        base_dir=tmp_path,
        subject="laptop@chef.skworld.io",
        proof=proof,
    )
    dev = approve(enr.enrollment_id, "chef", base_dir=tmp_path)
    assert not dev.revoked

    revoked = revoke(dev.device_id, "stolen laptop", base_dir=tmp_path)
    assert revoked.revoked
    assert revoked.revoked_reason == "stolen laptop"
    assert revoked.revoked_at is not None

    # persisted: reloading shows it revoked, and it no longer satisfies its mode
    again = list_devices("laptop@chef.skworld.io", base_dir=tmp_path)[0]
    assert again.revoked
    assert not again.satisfies("verified")

    # filtered listing can drop it
    assert list_devices(base_dir=tmp_path, include_revoked=False) == []


def test_revoke_unknown_device_raises(tmp_path):
    with pytest.raises(PairingError):
        revoke("nope", "reason", base_dir=tmp_path)


# --------------------------------------------------------------------------
# list_devices filtering
# --------------------------------------------------------------------------


def test_list_devices_filters_by_subject(tmp_path):
    e1 = enroll_device(
        "ka", ["s"], mode="tofu", base_dir=tmp_path, subject="alice@chef.skworld.io"
    )
    e2 = enroll_device("kb", ["s"], mode="tofu", base_dir=tmp_path, subject="bob@chef.skworld.io")
    kc_operator_pubkey, kc_attestation = enrolled_attested_credentials("kc", "alice@chef.skworld.io")
    e3 = enroll_device(
        "kc",
        ["s"],
        mode="attested",
        base_dir=tmp_path,
        subject="alice@chef.skworld.io",
        operator_pubkey=kc_operator_pubkey,
        attestation=kc_attestation,
    )
    for e in (e1, e2, e3):
        approve(e.enrollment_id, "chef", base_dir=tmp_path)

    alice = list_devices("alice@chef.skworld.io", base_dir=tmp_path)
    assert {d.subject for d in alice} == {"alice@chef.skworld.io"}
    assert len(alice) == 2
    bob = list_devices("bob@chef.skworld.io", base_dir=tmp_path)
    assert len(bob) == 1
    assert len(list_devices(base_dir=tmp_path)) == 3
    # case-insensitive
    assert len(list_devices("ALICE@CHEF.SKWORLD.IO", base_dir=tmp_path)) == 2


# --------------------------------------------------------------------------
# sidecar storage round-trip: v1 peer shape preserved verbatim
# --------------------------------------------------------------------------


def test_sidecar_preserves_existing_v1_peer_shape(tmp_path):
    peers = tmp_path / "peers"
    peers.mkdir(parents=True)
    peer_file = peers / "architect.json"
    original = copy.deepcopy(V1_PEER)
    peer_file.write_text(json.dumps(original, indent=2), encoding="utf-8")

    # enroll + approve a device for this existing subject (matched by identity).
    # "capauth:architect@skworld.io" canonicalizes to "architect@skworld.io"
    # (the capauth: prefix is stripped; "architect" is not in the two-name
    # domain alias table, unlike lumina/opus); the attestation must be bound
    # to THAT canonical form.
    operator_pubkey, attestation = enrolled_attested_credentials(
        "architect-device-key", "architect@skworld.io"
    )
    enr = enroll_device(
        "architect-device-key",
        ["skchat.send"],
        mode="attested",
        base_dir=tmp_path,
        subject="capauth:architect@skworld.io",
        operator_pubkey=operator_pubkey,
        attestation=attestation,
    )
    dev = approve(enr.enrollment_id, "chef@skworld.io", base_dir=tmp_path)

    # the SAME file was updated in place (matched by identity), not a new file
    assert sorted(p.name for p in peers.glob("*.json")) == ["architect.json"]

    reloaded = json.loads(peer_file.read_text(encoding="utf-8"))
    # every original v1 key is byte-identical
    for key, val in original.items():
        assert reloaded[key] == val, f"v1 field {key} was mutated"
    # only ONE new key was added: the versioned sidecar
    assert set(reloaded) - set(original) == {SIDECAR_KEY}

    sidecar = reloaded[SIDECAR_KEY]
    assert sidecar["version"] == SIDECAR_VERSION
    assert len(sidecar["devices"]) == 1
    entry = sidecar["devices"][0]
    assert entry["device_id"] == dev.device_id
    assert entry["mode"] == "attested"
    assert entry["scopes"] == ["skchat.send"]
    assert entry["approved_by"] == "chef@skworld.io"
    assert entry["revoked"] is False
    # the device's OWN key rides the entry, never the peer identity fingerprint
    assert entry["fingerprint"] == dev.fingerprint
    assert reloaded["fingerprint"] == V1_PEER["fingerprint"]


def test_new_device_creates_v1_shaped_record(tmp_path):
    enr = enroll_device(
        "k", ["skchat.send"], mode="tofu", base_dir=tmp_path, subject="newphone@chef.skworld.io"
    )
    approve(enr.enrollment_id, "chef", base_dir=tmp_path)

    peer_files = list((tmp_path / "peers").glob("*.json"))
    assert len(peer_files) == 1
    rec = json.loads(peer_files[0].read_text(encoding="utf-8"))
    # carries the v1 field vocabulary plus the sidecar
    for field in (
        "name",
        "identity",
        "fingerprint",
        "public_key",
        "entity_type",
        "trust_level",
        "added_at",
        "capauth_uri",
    ):
        assert field in rec
    assert rec[SIDECAR_KEY]["devices"][0]["mode"] == "tofu"


def test_sidecar_revocation_round_trips_on_existing_peer(tmp_path):
    peers = tmp_path / "peers"
    peers.mkdir(parents=True)
    (peers / "architect.json").write_text(json.dumps(V1_PEER, indent=2), encoding="utf-8")

    pubkey, proof = enrolled_verified_credentials("architect@skworld.io")
    enr = enroll_device(
        pubkey,
        ["s"],
        mode="verified",
        base_dir=tmp_path,
        subject="capauth:architect@skworld.io",
        proof=proof,
    )
    dev = approve(enr.enrollment_id, "chef", base_dir=tmp_path)
    revoke(dev.device_id, "compromised", base_dir=tmp_path)

    reloaded = json.loads((peers / "architect.json").read_text(encoding="utf-8"))
    # v1 fields STILL preserved after a second write (revoke)
    for key, val in V1_PEER.items():
        assert reloaded[key] == val
    entry = reloaded[SIDECAR_KEY]["devices"][0]
    assert entry["revoked"] is True
    assert entry["revoked_reason"] == "compromised"


def test_multiple_devices_per_subject_coexist(tmp_path):
    # a subject pairs two distinct device keys; both persist under one peer file
    phone_pubkey, phone_proof = enrolled_verified_credentials("alice@chef.skworld.io")
    e1 = enroll_device(
        phone_pubkey,
        ["s"],
        mode="verified",
        base_dir=tmp_path,
        subject="alice@chef.skworld.io",
        proof=phone_proof,
    )
    e2 = enroll_device(
        "laptop-key", ["s"], mode="tofu", base_dir=tmp_path, subject="alice@chef.skworld.io"
    )
    d1 = approve(e1.enrollment_id, "chef", base_dir=tmp_path)
    d2 = approve(e2.enrollment_id, "chef", base_dir=tmp_path)

    peer_files = list((tmp_path / "peers").glob("*.json"))
    assert len(peer_files) == 1  # one subject, one file
    alice = list_devices("alice@chef.skworld.io", base_dir=tmp_path)
    assert {d.device_id for d in alice} == {d1.device_id, d2.device_id}
    # revoking one leaves the other intact
    revoke(d1.device_id, "lost", base_dir=tmp_path)
    live = list_devices("alice@chef.skworld.io", base_dir=tmp_path, include_revoked=False)
    assert [d.device_id for d in live] == [d2.device_id]


def test_store_root_is_injectable_and_isolated(tmp_path):
    # two independent roots do not see each other's devices
    a = tmp_path / "a"
    b = tmp_path / "b"
    e = enroll_device("k", ["s"], mode="tofu", base_dir=a, subject="x@chef.skworld.io")
    approve(e.enrollment_id, "chef", base_dir=a)
    assert len(list_devices(base_dir=a)) == 1
    assert list_devices(base_dir=b) == []


def test_unique_device_ids_across_enrollments(tmp_path):
    ids = set()
    for i in range(5):
        e = enroll_device(
            f"k{i}", ["s"], mode="tofu", base_dir=tmp_path, subject=f"s{i}@chef.skworld.io"
        )
        d = approve(e.enrollment_id, "chef", base_dir=tmp_path)
        ids.add(d.device_id)
    assert len(ids) == 5
    # sanity: itertools import used (round-trip stability across a re-list)
    listed = list(
        itertools.chain.from_iterable([[d.device_id] for d in list_devices(base_dir=tmp_path)])
    )
    assert set(listed) == ids


def test_device_findable_when_peer_file_identity_differs(tmp_path):
    # Regression: a device enrolled under subject X landing in a pre-existing peer
    # file whose identity is Y must still be found by list_devices(X).
    import json

    from capauth.pairing import approve, enroll_device, list_devices

    base = tmp_path / "home"
    peers = base / "peers"
    peers.mkdir(parents=True)
    # A pre-existing v1 peer record keyed by the same slug but a DIFFERENT identity.
    (peers / "lumina.json").write_text(
        json.dumps({"name": "Lumina", "identity": "lumina@chef.skworld", "fingerprint": "AA"})
    )
    pubkey, proof = enrolled_verified_credentials("lumina@chef.skworld.io")
    enr = enroll_device(
        pubkey,
        ["skchat.send"],
        mode="verified",
        subject="lumina@chef.skworld.io",
        proof=proof,
        base_dir=base,
    )
    approve(enr.enrollment_id, "operator", base_dir=base)
    found = list_devices("lumina@chef.skworld.io", base_dir=base)
    assert len(found) == 1
    assert found[0].subject == "lumina@chef.skworld.io"
    # The pre-existing v1 identity field is left untouched.
    assert json.loads((peers / "lumina.json").read_text())["identity"] == "lumina@chef.skworld"
