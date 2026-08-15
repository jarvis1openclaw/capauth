"""The pairing kernel public API (spec 3.4 part 1, M0-frozen surface).

One pairing kernel, two front doors (skchat and skcode-hostd delegate here; that
delegation, the call-site conversion, is a deliberate later step behind the
``SKCHAT_PAIRING_KERNEL`` shadow flag and is NOT part of this package).

Frozen API:

* ``enroll_device(pubkey, requested_scopes, *, mode) -> Enrollment``
* ``approve(enrollment_id, approver_ident) -> DeviceRecord``
* ``revoke(device_id, reason)``
* ``list_devices(subject=None) -> list[DeviceRecord]``
* ``open_window(...)`` (re-exported from :mod:`capauth.pairing.window`)

Every function takes an additive keyword-only ``base_dir`` so tests inject a
``tmp_path`` root and never touch the real ``~/.skcapstone`` registry. The frozen
positional/keyword parameters above are untouched.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capauth.exceptions import CapAuthError, SubjectNamingError
from capauth.subject import canonical_subject

from .records import DeviceRecord, Enrollment, EnrollmentMode
from .store import PairingStore, fingerprint_for
from .window import PairingWindow


class PairingError(CapAuthError):
    """Raised when a pairing operation is refused (bad window, unknown id, ...)."""


#: Domain-separated challenge prefixes for the two proof-bearing modes (card
#: N10, 09a6d6f3). Distinct prefixes so a signature made for one mode/purpose
#: can never be replayed as proof for the other (an attested attestation
#: cannot double as a verified self-proof, and vice versa).
_VERIFIED_CHALLENGE_DOMAIN = "capauth-pairing-enrollment-verified-v1"
_ATTESTED_CHALLENGE_DOMAIN = "capauth-pairing-enrollment-attested-v1"


def verified_challenge(fingerprint: str, subject: str) -> bytes:
    """The exact bytes a ``verified`` enrollment's ``proof`` must be a signature over.

    Binds the claim to BOTH the presented device fingerprint and the resolved
    subject, so a self-signature proves possession of the device's own private
    key over precisely the identity this enrollment claims -- not merely "a
    signature exists somewhere." Callers building a real ``proof`` (this
    package's own :func:`enroll_device`, or a future front door) sign exactly
    this over the device's private key.
    """
    return f"{_VERIFIED_CHALLENGE_DOMAIN}:{fingerprint}:{subject}".encode("utf-8")


def attested_challenge(fingerprint: str, subject: str) -> bytes:
    """The exact bytes an ``attested`` enrollment's ``attestation`` must sign.

    Same binding as :func:`verified_challenge` (fingerprint + subject), signed
    instead by the VOUCHING OPERATOR's key (``operator_pubkey``), proving the
    operator, not the device, attests to this specific device/identity pair.
    """
    return f"{_ATTESTED_CHALLENGE_DOMAIN}:{fingerprint}:{subject}".encode("utf-8")


def _proof_verifies(
    pubkey_armor: Optional[str], signature_armor: Optional[str], challenge: bytes
) -> bool:
    """Fail-closed signature check: True only for a real, matching signature.

    Any failure mode -- missing key, missing signature, unparseable armor, a
    signature over different bytes, a signature from a different key, a crypto
    backend that is unavailable in this interpreter -- returns False rather
    than raising, so a caller who cannot produce a real proof is refused with
    the same "invalid proof" reason as a caller who forged one, never with an
    unrelated crash.
    """
    if not pubkey_armor or not signature_armor:
        return False
    try:
        from capauth.crypto import get_backend

        return bool(get_backend().verify(challenge, signature_armor, pubkey_armor))
    except Exception:  # noqa: BLE001 -- any backend/parse failure means "not proven"
        return False


#: A bare device fingerprint (no ``device:`` prefix, no ``@``): the exact shape
#: :func:`fingerprint_for` returns and the one this function itself used to
#: store verbatim as the default subject. It is also what
#: ``skchat.pairing_mirror.mirror_admission`` presents as ``subject=peer_fp``
#: (a real, live caller, not a hypothetical). Under
#: ``IDENTITY_NAMING_STANDARD.md`` sec 1, ``device:<fingerprint>`` is the ONE
#: legal prefixed subject class, so a string that is already exactly hex of
#: legal fingerprint length, missing only that prefix, has exactly one sane
#: reading: a caller that meant the device-seat form and omitted the prefix.
#: Deliberately narrow (anchored, hex-only, the same 16-64 length canonical_subject's
#: own grammar allows) so it can never reinterpret a genuine ``local@domain``
#: or already-prefixed subject.
_BARE_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16,64}$")


def _coerce_mode(mode: EnrollmentMode | str) -> EnrollmentMode:
    if isinstance(mode, EnrollmentMode):
        return mode
    try:
        return EnrollmentMode(mode)
    except ValueError as exc:
        raise PairingError(f"unknown enrollment mode: {mode!r}") from exc


def _with_bare_fingerprint_shorthand(candidate: str) -> str:
    """Prefix a bare device fingerprint with ``device:``, else pass through.

    Shared by the write path (:func:`_resolve_subject`, below) and the read
    path (:func:`list_devices`'s subject filter), so a query for the same bare
    fingerprint an enrollment was made under still finds the now-canonical
    ``device:<fingerprint>`` record. See :func:`_resolve_subject` for the full
    rationale.
    """
    if _BARE_FINGERPRINT_RE.match(candidate.lower()):
        return f"device:{candidate}"
    return candidate


def _try_canonicalize(raw: str) -> Optional[str]:
    """Best-effort :func:`canonical_subject`, returning None instead of raising.

    For read paths (``list_devices``): a query subject that does not
    canonicalize is not a defect to refuse, just a shape :func:`_resolve_subject`
    would have refused had it been an enroll. The caller falls back to a
    raw-string comparison so an already-stored legacy-shaped record (enrolled
    before this card, or filtered on the same legacy string a live caller
    still passes) is still found.
    """
    try:
        return canonical_subject(_with_bare_fingerprint_shorthand(raw.strip()))
    except SubjectNamingError:
        return None


def _resolve_subject(subject: Optional[str], fingerprint: str) -> Optional[str]:
    """Resolve and canonicalize the subject an enrollment is recorded under.

    Card N3 (``bab1cca6``): this is capauth's live proof that mismatched
    subject shapes fail closed as an opaque "unknown subject" deny rather than
    the naming defect they actually are. Routes the resolved subject through
    :func:`canonical_subject` and lets a refusal propagate, so the shape can
    never regress past this one entry point.

    Normalizes rather than rejects on a translatable legacy shape (a
    ``capauth:`` prefix, a missing-TLD ``@chef.skworld``, ``operator:<fp>``,
    ...): the real callers of ``enroll_device`` today
    (``capauth.provisioning``, ``skchat.operator_grants``,
    ``skcomms.pairing_mirror``) all present one of those translatable
    legacy shapes, not the bare canonical form, because the identity code that
    builds their subject strings predates the standard. Rejecting those
    outright would immediately break every one of them; :func:`canonical_subject`
    already encodes exactly which shapes are safe to translate versus which
    are a genuine defect, so enroll_device defers to it rather than
    second-guessing it with a stricter equality check.

    One caller-facing shape needs a second pass first: a BARE device
    fingerprint (no ``device:`` prefix), which is both this function's own
    fallback (``subject`` not given -> the fingerprint) and what
    ``skchat.pairing_mirror.mirror_admission`` presents as ``subject=peer_fp``.
    That shape is not in ``canonical_subject``'s alias table (by design: the
    table only lists shapes the standard's own audit found actually enrolled
    under a wrong spelling of a human/agent identity, not the ONE case where a
    subject is a device-fingerprint-only seat and only its prefix went
    missing). It is unambiguous under the grammar, so it is resolved here,
    once, before the general normalizer runs.

    Args:
        subject: The caller-presented subject, or None to derive from
            ``fingerprint``.
        fingerprint: This enrollment's device fingerprint (may be "").

    Returns:
        The canonical fqid, or None when neither a subject nor a usable
        fingerprint was presented (nothing to canonicalize; the record keeps
        capauth's existing "None = derive later" contract for that case).

    Raises:
        SubjectNamingError: ``subject`` (or the derived fingerprint) does not
            conform to the canonical fqid grammar even after alias
            translation.
    """
    raw = subject if subject is not None else (fingerprint or None)
    if not raw:
        return None

    candidate = _with_bare_fingerprint_shorthand(raw.strip())
    try:
        return canonical_subject(candidate)
    except SubjectNamingError as exc:
        raise SubjectNamingError(
            f"enroll_device refuses non-canonical subject {raw!r}: {exc}"
        ) from exc


def enroll_device(
    pubkey: str,
    requested_scopes: list[str],
    *,
    mode: EnrollmentMode | str,
    base_dir: Optional[Path] = None,
    subject: Optional[str] = None,
    window: Optional[PairingWindow] = None,
    window_nonce: Optional[str] = None,
    operator_id: Optional[str] = None,
    operator_pubkey: Optional[str] = None,
    attestation: Optional[str] = None,
    proof: Optional[str] = None,
) -> Enrollment:
    """Register a pending device enrollment (M0-frozen entry point).

    Promotes the skchat accept path: when an operator pairing ``window`` is
    supplied, the enroll is gated by the PairingGate semantics (rate limit ->
    window open -> nonce match -> accept cap) exactly as ``/pair/accept`` is,
    and a successful enroll consumes one window accept. Without a window the
    enroll is ungated (the tailnet-local path, unchanged behavior).

    Mode-specific evidence rides the optional kwargs, and is now (card N10,
    09a6d6f3) ACTUALLY CHECKED rather than merely stored:

    * ``verified`` requires ``proof``: an ASCII-armored PGP signature, made by
      the device's own ``pubkey``, over :func:`verified_challenge`'s bytes for
      this enrollment's fingerprint + resolved subject. Proves the caller
      possesses the device's private key, not merely that it asserts one.
    * ``attested`` requires ``operator_pubkey`` + ``attestation``: a signature
      made by ``operator_pubkey`` over :func:`attested_challenge`'s bytes for
      the same fingerprint + subject. Proves a vouching operator, not the
      device itself, attests to this specific device/identity pair.
    * ``tofu`` needs neither; pin-on-first-use requires no upfront proof by
      design.

    Missing or invalid evidence for ``verified``/``attested`` raises
    :class:`PairingError` -- the enrollment is never persisted, so a caller
    cannot land a claimed mode it did not actually prove. This is enforced
    only at THIS call (new enrollments); it does not and cannot retroactively
    touch a :class:`DeviceRecord` an earlier :func:`approve` already
    persisted, since ``decide()`` reads only the stored ``mode`` field off
    those, never re-checking proof after approval.

    Args:
        pubkey: The device's presented public key (ASCII-armored).
        requested_scopes: Scopes the device asks for.
        mode: ``verified`` | ``attested`` | ``tofu`` (or the enum).
        base_dir: Injectable storage root (defaults to ``~/.skcapstone``).
        subject: Who the device belongs to; defaults to its fingerprint.
            Canonicalized via :func:`capauth.subject.canonical_subject` (card
            N3): a translatable legacy shape (``capauth:`` prefix,
            missing-TLD, ``operator:<fp>``, a bare device fingerprint, ...)
            is normalized to its one canonical fqid; a subject that still
            does not conform after translation is refused.
        window: An open :class:`PairingWindow` to gate this enroll.
        window_nonce: The nonce presented against ``window``.
        operator_id: Vouching operator id (attested).
        operator_pubkey: Vouching operator public key (attested).
        attestation: Operator signature over the device key (attested).
        proof: Self-signed assertion / challenge proof (verified).

    Returns:
        Enrollment: The persisted pending enrollment.

    Raises:
        PairingError: If the window gate refuses the attempt, or if
            ``mode="verified"``/``"attested"`` is claimed without the proof
            that mode requires actually checking out (card N10, 09a6d6f3: the
            mode used to be accepted on the caller's say-so alone).
        SubjectNamingError: If ``subject`` (or the fingerprint it defaults
            to) does not conform to the canonical fqid grammar even after
            alias translation.
    """
    resolved_mode = _coerce_mode(mode)
    store = PairingStore(base_dir)

    window_id: Optional[str] = None
    nonce: Optional[str] = window_nonce
    if window is not None:
        ok, reason = window.check(window_nonce)
        if not ok:
            raise PairingError(f"pairing window refused enrollment: {reason}")
        window.consume()
        window_id = window.window_id
        nonce = window_nonce

    fingerprint = fingerprint_for(pubkey)
    canonical = _resolve_subject(subject, fingerprint)
    identity_for_proof = canonical or fingerprint or ""

    # Card N10 (09a6d6f3): mode was caller-asserted and its proof was never
    # validated, so decide() gated agentrun.execute / change.deploy /
    # skcode.dispatch (VERIFIED-only, "arbitrary command execution AS the
    # subject") on a claim nobody checked. Enforced HERE, at the one entry
    # point that creates a new Enrollment, so it cannot retroactively touch a
    # DeviceRecord an earlier approve() already persisted (those are read by
    # stored mode only, never re-proven).
    if resolved_mode is EnrollmentMode.VERIFIED:
        if not _proof_verifies(pubkey, proof, verified_challenge(fingerprint, identity_for_proof)):
            raise PairingError(
                "verified enrollment requires 'proof': a signature by the device's "
                "own pubkey over the fingerprint+subject challenge, proving key "
                "possession (card N10); none was presented or it did not verify"
            )
    elif resolved_mode is EnrollmentMode.ATTESTED:
        challenge = attested_challenge(fingerprint, identity_for_proof)
        if not _proof_verifies(operator_pubkey, attestation, challenge):
            raise PairingError(
                "attested enrollment requires 'operator_pubkey' + 'attestation': a "
                "signature by the vouching operator's key over the fingerprint+"
                "subject challenge (card N10); none was presented or it did not verify"
            )

    enrollment = Enrollment(
        pubkey=pubkey,
        fingerprint=fingerprint,
        requested_scopes=list(requested_scopes or []),
        mode=resolved_mode,
        subject=canonical,
        window_id=window_id,
        nonce=nonce,
        operator_id=operator_id,
        operator_pubkey=operator_pubkey,
        attestation=attestation,
        proof=proof,
    )
    store.save_enrollment(enrollment)
    return enrollment


def approve(
    enrollment_id: str,
    approver_ident: str,
    *,
    base_dir: Optional[Path] = None,
) -> DeviceRecord:
    """Approve a pending enrollment into a durable :class:`DeviceRecord`.

    The device record is persisted into the peer registry as a versioned
    sidecar on the subject's v1 peer record (existing fields untouched). The
    pending enrollment is consumed (single-use).

    Args:
        enrollment_id: The pending enrollment to approve.
        approver_ident: The operator/agent approving (recorded as ``approved_by``).
        base_dir: Injectable storage root.

    Returns:
        DeviceRecord: The approved, persisted device.

    Raises:
        PairingError: If no such pending enrollment exists.
    """
    store = PairingStore(base_dir)
    enrollment = store.load_enrollment(enrollment_id)
    if enrollment is None:
        raise PairingError(f"no pending enrollment: {enrollment_id}")

    subject = enrollment.subject or enrollment.fingerprint or enrollment.enrollment_id
    device = DeviceRecord(
        device_id=enrollment.enrollment_id,
        subject=subject,
        pubkey=enrollment.pubkey,
        fingerprint=enrollment.fingerprint,
        mode=enrollment.mode,
        scopes=list(enrollment.requested_scopes),
        approved_by=approver_ident,
        enrollment_id=enrollment.enrollment_id,
    )
    store.upsert_device(device)
    store.delete_enrollment(enrollment_id)
    return device


def revoke(
    device_id: str,
    reason: str,
    *,
    base_dir: Optional[Path] = None,
) -> DeviceRecord:
    """Revoke an approved device (a state transition, never a delete).

    Sets ``revoked`` on the sidecar with the reason and a timestamp; the v1 peer
    fields are left untouched. A revoked device satisfies no minimum mode.

    Args:
        device_id: The device to revoke.
        reason: Why it is being revoked.
        base_dir: Injectable storage root.

    Returns:
        DeviceRecord: The updated, revoked device.

    Raises:
        PairingError: If no device with that id exists.
    """
    store = PairingStore(base_dir)
    found = store.find_device(device_id)
    if found is None:
        raise PairingError(f"no such device: {device_id}")
    _path, _record, device = found
    device.revoked = True
    device.revoked_reason = reason
    device.revoked_at = datetime.now(timezone.utc)
    store.upsert_device(device)
    return device


def list_devices(
    subject: Optional[str] = None,
    *,
    base_dir: Optional[Path] = None,
    include_revoked: bool = True,
) -> list[DeviceRecord]:
    """List approved devices, optionally filtered to a single ``subject``.

    The filter matches on the raw (lowercased) ``subject`` as given AND, when
    it canonicalizes, on its canonical fqid (card N3): since
    :func:`enroll_device` now stores subjects canonically, a caller filtering
    on the same legacy-shaped string it enrolled with (e.g. a bare device
    fingerprint) still finds the record. A ``subject`` that does not
    canonicalize is not refused here, only matched by its raw form, so
    records enrolled before this card (under a non-canonical subject) remain
    findable.

    Args:
        subject: If given, only devices belonging to this subject.
        base_dir: Injectable storage root.
        include_revoked: When False, drop revoked devices.

    Returns:
        list[DeviceRecord]: Matching devices (newest approval first).
    """
    store = PairingStore(base_dir)
    devices = [d for _path, d in store.iter_devices()]
    if subject is not None:
        wanted = {subject.strip().lower()}
        canonical = _try_canonicalize(subject)
        if canonical is not None:
            wanted.add(canonical)
        devices = [d for d in devices if (d.subject or "").strip().lower() in wanted]
    if not include_revoked:
        devices = [d for d in devices if not d.revoked]
    devices.sort(key=lambda d: d.approved_at, reverse=True)
    return devices


__all__ = [
    "PairingError",
    "enroll_device",
    "approve",
    "revoke",
    "list_devices",
    "verified_challenge",
    "attested_challenge",
]
