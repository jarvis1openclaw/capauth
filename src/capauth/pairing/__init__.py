"""CapAuth pairing kernel (spine M2): device enrollment, modes, and windows.

The one pairing kernel for the SKWorld platform. It promotes skchat's shipped
trust-bootstrap code into a clean L0 domain package, preserving real semantics
rather than inventing new behavior:

* the operator pairing window (time-boxed nonce + accept cap + rate limit) from
  ``skchat.pairing_gate.PairingGate`` -> :class:`PairingWindow` / :func:`open_window`;
* three first-class enrollment MODES (ratified by Chef, 2026-07-30):
  ``verified`` (capauth challenge-response / self-signed FQID assertion,
  ``join_routes``), ``attested`` (operator signature over the key,
  ``guest_accept`` Mode B), ``tofu`` (pin-on-first-use, ``guest_accept`` Mode C);
* a device standing model (:class:`DeviceRecord`) that carries its mode so
  downstream authz can require a minimum via :func:`mode_satisfies`.

Storage keeps the ``~/.skcapstone/peers/`` v1 record shape VERBATIM; mode /
enrollment metadata rides a versioned ``pairing`` sidecar. The storage root is
injectable (``base_dir=``) so tests never touch the real registry.

This package is additive and standalone: skchat / skcomms / skcode call-site
conversion (delegating to this kernel behind the ``SKCHAT_PAIRING_KERNEL`` shadow
flag) is a deliberate later step and lives in those repos, not here.
"""

from __future__ import annotations

# OperatorAuthError lives in capauth.exceptions (the shared exception
# hierarchy) but is re-exported here too, so `from capauth.pairing import
# OperatorAuthError` works next to the mint/verify functions it belongs with.
from ..exceptions import OperatorAuthError
from .canonicalize import (
    DeviceRewrite,
    RewritePlan,
    RewriteReport,
    TokenRewrite,
    TokenSkip,
    apply_canonical_rewrite,
    format_rewrite_plan,
    scan_canonical_rewrite,
)
from .kernel import PairingError, approve, enroll_device, list_devices, revoke
from .operator_session import (
    OPERATOR_DEVICES_PATH_ENV,
    DeviceStore,
    OperatorSession,
    approve_device,
    consume_challenge,
    default_device_store_path,
    device_fingerprint,
    is_device_approved,
    is_device_revoked,
    is_session_revoked,
    issue_challenge,
    mint_operator_session,
    revoke_device,
    revoke_session,
    unrevoke_device,
    verify_device_signature,
    verify_operator_session,
)
from .records import (
    MODE_SEVERITY,
    DeviceRecord,
    Enrollment,
    EnrollmentMode,
    mode_satisfies,
    mode_severity,
)
from .store import (
    SIDECAR_KEY,
    SIDECAR_VERSION,
    PairingStore,
    default_base_dir,
    fingerprint_for,
)
from .window import PairingWindow, open_window

__all__ = [
    # kernel API (M0-frozen)
    "enroll_device",
    "approve",
    "revoke",
    "list_devices",
    "open_window",
    "PairingError",
    # records + modes
    "EnrollmentMode",
    "Enrollment",
    "DeviceRecord",
    "MODE_SEVERITY",
    "mode_severity",
    "mode_satisfies",
    # window
    "PairingWindow",
    # storage
    "PairingStore",
    "SIDECAR_KEY",
    "SIDECAR_VERSION",
    "default_base_dir",
    "fingerprint_for",
    # canonical-subject rewrite (card N5)
    "DeviceRewrite",
    "TokenRewrite",
    "TokenSkip",
    "RewritePlan",
    "RewriteReport",
    "scan_canonical_rewrite",
    "format_rewrite_plan",
    "apply_canonical_rewrite",
    # operator session (Unified Consent Plane Phase 1: one operator identity)
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
