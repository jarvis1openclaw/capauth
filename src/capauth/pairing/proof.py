"""Build the enrollment proof :func:`capauth.pairing.enroll_device` demands.

    THIS IS A CONSTRUCTOR, NOT A BYPASS.

Card N10 (``83c1fa2``) made ``proof`` mandatory for ``verified`` enrollment and
``operator_pubkey`` + ``attestation`` mandatory for ``attested``. That was the
right change, and this module does not soften one line of it: the verifier
(``capauth.pairing.kernel._proof_verifies``) is untouched and is in fact called
here, on this module's own output, before that output is handed back.

What shipped with N10 was the requirement without a supported way to satisfy it.
A downstream that wanted to enroll a verified device had to reconstruct the
challenge by reading capauth's source -- derive the fingerprint with
:func:`capauth.pairing.store.fingerprint_for` (capauth's 40-char uppercase form,
not any caller-local fingerprint), canonicalize the subject with
:func:`capauth.subject.canonical_subject` (so an ``operator:<fp>`` becomes the
``device:<fp>`` actually recorded), then assemble
:func:`capauth.pairing.verified_challenge` over exactly those two -- and get all
three right, or produce a signature that fails identically to a forged one.
skchat did that work by hand and left a comment saying so: "capauth has no
public helper for this today; if it grows one, delete this and call it."
This is that helper.

Why this cannot become a way in
-------------------------------
The signature IS the proof. Every function here signs the challenge with a
private key the CALLER supplies, using the same crypto backends the verifier
uses. There is no code path that produces an acceptable proof for a key whose
private half you do not hold, because there is nothing to produce: forging one
is exactly as hard as it was before this module existed, which is the whole
point of an asymmetric signature. Presenting a proof for someone else's key is
impossible by construction, not by a check this module performs.

Two further properties keep it honest:

* **It never returns an unsigned or empty proof.** If the backend produces no
  signature, or produces one the real verifier rejects, the call RAISES
  :class:`ProofSigningError` and returns nothing, in the same spirit as
  :class:`capauth.tokens.TokenSigningError` (issuance fails rather than
  degrading to an artifact that looks issued and authorizes nothing).
* **It self-checks against the real verifier.** Before returning, the built
  proof is run through ``_proof_verifies`` with the same challenge bytes
  ``enroll_device`` will independently re-derive. So the round trip is a
  structural property of the helper, not a hope: if capauth ever changes either
  derivation, this raises at build time instead of silently reverting a caller
  to a lower tier.

Key shapes
----------
The signing branch is chosen from the DEVICE PUBLIC KEY alone, using the same
``"BEGIN PGP" in key`` discriminator ``_proof_verifies`` and ``fingerprint_for``
use, never a caller-supplied "which algorithm" flag:

* an ASCII-armored PGP public key -> signed by an ASCII-armored PGP private key
  through :func:`capauth.crypto.get_backend`;
* anything else -> treated as a base64 DER SPKI WebCrypto ECDSA P-256 device key
  (skchat/skcode's device-linking shape) and signed by a ``cryptography`` EC
  private key (an object, or a PEM blob this loads).

For the common web case the device's private key lives in the browser as a
non-extractable WebCrypto key and cannot be handed to Python at all. That caller
wants :func:`enrollment_challenge`, which derives the exact bytes to sign from
the PUBLIC key alone -- no secret, no round trip -- and hands them to the client
to sign.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, Optional

from ..subject import canonical_subject
from .kernel import PairingError, _proof_verifies, attested_challenge, verified_challenge
from .records import EnrollmentMode
from .store import fingerprint_for

__all__ = [
    "EnrollmentProof",
    "ProofSigningError",
    "build_attested_proof",
    "build_verified_proof",
    "enrollment_challenge",
]


class ProofSigningError(PairingError):
    """Signing an enrollment proof failed, so no proof was produced.

    Raised by :func:`build_verified_proof` / :func:`build_attested_proof` when
    the private key cannot sign (wrong/locked key, bad passphrase, unavailable
    backend, unparseable key material) or when the resulting signature does not
    satisfy capauth's own verifier.

    Fails loudly and returns nothing, deliberately mirroring
    :class:`capauth.tokens.TokenSigningError`. An empty or non-verifying proof
    handed to :func:`capauth.pairing.enroll_device` is refused there anyway, and
    the historical shape of that failure -- an exception swallowed by a
    best-effort caller, an enrollment that quietly became a no-op, and a
    ``decide()`` denial for "no enrolled device" pointing at nothing -- is
    exactly what this class exists to make impossible to miss.

    Subclasses :class:`capauth.pairing.PairingError`.
    """


@dataclass(frozen=True)
class EnrollmentProof:
    """A built, self-verified proof plus the facts it is bound to.

    Splats straight into :func:`capauth.pairing.enroll_device` -- it implements
    the mapping protocol, and yields exactly the evidence kwargs the claimed
    mode requires and no others::

        proof = build_verified_proof(pubkey, private_key=priv, subject=subj)
        enroll_device(pubkey, scopes, mode="verified", subject=subj, **proof)

    ``subject`` is the CANONICAL subject the enrollment will be recorded under,
    which may differ from the string the caller passed in (a translatable legacy
    shape is normalized). Pass THAT value as ``enroll_device``'s ``subject``, or
    pass the original: both canonicalize to the same string, which is the one
    the challenge is bound to.

    Attributes:
        mode: The enrollment mode this proof establishes.
        pubkey: The DEVICE public key the enrollment presents.
        fingerprint: capauth's fingerprint for ``pubkey``.
        subject: The canonical subject the proof is bound to.
        challenge: The exact bytes that were signed.
        proof: The device's self-signature (``verified`` only, else None).
        operator_pubkey: The vouching operator's key (``attested`` only).
        attestation: The operator's signature (``attested`` only).
    """

    mode: EnrollmentMode
    pubkey: str
    fingerprint: str
    subject: str
    challenge: bytes
    proof: Optional[str] = None
    operator_pubkey: Optional[str] = None
    attestation: Optional[str] = None

    def keys(self) -> Iterator[str]:
        """The ``enroll_device`` kwarg names this proof supplies (mapping protocol)."""
        return iter(self.enroll_kwargs)

    def __getitem__(self, key: str) -> str:
        """Look up one ``enroll_device`` kwarg (mapping protocol)."""
        return self.enroll_kwargs[key]

    @property
    def enroll_kwargs(self) -> dict[str, str]:
        """The evidence kwargs to pass to :func:`capauth.pairing.enroll_device`.

        Only the ones this mode actually requires: ``{"proof": ...}`` for
        ``verified``, ``{"operator_pubkey": ..., "attestation": ...}`` for
        ``attested``. Never both, so a proof built for one mode cannot be
        splatted into an enroll claiming the other and accidentally satisfy it
        (the two challenges are domain-separated anyway, so it would fail; this
        just means it fails as a missing-evidence refusal rather than looking
        like a near miss).
        """
        if self.mode is EnrollmentMode.ATTESTED:
            return {
                "operator_pubkey": self.operator_pubkey or "",
                "attestation": self.attestation or "",
            }
        return {"proof": self.proof or ""}


def _is_pgp(key: Optional[str]) -> bool:
    """Whether ``key`` is ASCII-armored PGP, by the verifier's own discriminator."""
    return "BEGIN PGP" in (key or "")


def _resolve_subject(pubkey: str, subject: Optional[str]) -> tuple[str, str]:
    """Derive ``(fingerprint, canonical_subject)`` exactly as ``enroll_device`` will.

    Mirrors :func:`capauth.pairing.kernel._resolve_subject`'s two steps for the
    shapes a proof-building caller presents: a bare device fingerprint gains its
    ``device:`` prefix, and everything then goes through
    :func:`capauth.subject.canonical_subject`. Must match byte for byte or
    ``enroll_device`` re-derives a different challenge than the one signed here
    and rejects a perfectly legitimate proof.
    """
    from .kernel import _with_bare_fingerprint_shorthand

    fingerprint = fingerprint_for(pubkey)
    raw = subject if subject is not None else (fingerprint or None)
    if not raw:
        raise ProofSigningError(
            "cannot build an enrollment proof with no subject and no derivable "
            "fingerprint: the challenge binds to both, so there is nothing to sign"
        )
    return fingerprint, canonical_subject(_with_bare_fingerprint_shorthand(raw.strip()))


def _coerce_mode(mode: EnrollmentMode | str) -> EnrollmentMode:
    """Match ``enroll_device``'s own mode coercion, including its error wording."""
    if isinstance(mode, EnrollmentMode):
        return mode
    try:
        return EnrollmentMode(mode)
    except ValueError as exc:
        raise PairingError(f"unknown enrollment mode: {mode!r}") from exc


def enrollment_challenge(
    pubkey: str,
    *,
    subject: Optional[str] = None,
    mode: EnrollmentMode | str = EnrollmentMode.VERIFIED,
) -> bytes:
    """The exact bytes an enrollment's proof must sign, from the PUBLIC key alone.

    A pure function of public inputs: no secret is involved and none is
    disclosed, so a server can compute these and hand them to a client whose
    private key it must never see (the WebCrypto non-extractable device key
    case). It performs the two derivations that are easy to get wrong and that
    silently invalidate an otherwise correct signature:

    * the fingerprint is capauth's (:func:`capauth.pairing.store.fingerprint_for`,
      40-char uppercase for a PGP key), not any caller-local fingerprint;
    * the subject is the CANONICAL one the enrollment will be recorded under, so
      an ``operator:<fp>`` is challenged as the ``device:<fp>`` it becomes.

    Args:
        pubkey: The DEVICE public key being enrolled (armored PGP, or base64
            DER SPKI for an ECDSA P-256 device key).
        subject: Who the device belongs to. Defaults to the device fingerprint,
            matching ``enroll_device``'s own default.
        mode: ``verified`` (the device signs) or ``attested`` (the operator
            signs). The two domains are separate, so bytes for one are never
            valid proof for the other.

    Returns:
        bytes: The challenge to sign.

    Raises:
        ProofSigningError: If no subject and no derivable fingerprint were
            given, or if ``mode`` is one that carries no challenge (``tofu``).
        capauth.exceptions.SubjectNamingError: If ``subject`` does not conform
            to the canonical fqid grammar even after alias translation -- the
            same refusal ``enroll_device`` would raise for it.
        PairingError: If ``mode`` is not a known enrollment mode.
    """
    resolved = _coerce_mode(mode)
    fingerprint, canonical = _resolve_subject(pubkey, subject)
    if resolved is EnrollmentMode.ATTESTED:
        return attested_challenge(fingerprint, canonical)
    if resolved is EnrollmentMode.VERIFIED:
        return verified_challenge(fingerprint, canonical)
    raise ProofSigningError(
        f"mode {resolved.value!r} carries no proof challenge; only 'verified' and "
        f"'attested' require evidence (tofu is pin-on-first-use by design)"
    )


def _sign(challenge: bytes, private_key: Any, passphrase: str, *, pgp: bool) -> str:
    """Sign ``challenge`` with the caller's own key. Raises rather than returning junk.

    Two branches, chosen by the caller's public key shape (never by a flag on
    this call), each using the same machinery the corresponding verifier uses.
    """
    if pgp:
        if not isinstance(private_key, str) or not _is_pgp(private_key):
            raise ProofSigningError(
                "the device key is ASCII-armored PGP, so the signing key must be an "
                "ASCII-armored PGP PRIVATE key block; got "
                f"{type(private_key).__name__}"
            )
        try:
            from ..crypto import get_backend

            signature = get_backend().sign(challenge, private_key, passphrase)
        except Exception as exc:  # noqa: BLE001 -- normalized below, never swallowed
            raise ProofSigningError(
                f"PGP signing of the enrollment challenge failed: {exc}"
            ) from exc
        if not signature:
            raise ProofSigningError(
                "the PGP backend produced no signature for the enrollment challenge; "
                "refusing to return an unsigned proof (check that the secret key is "
                "present and the passphrase is correct)"
            )
        return signature

    import base64

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = private_key
        if isinstance(key, (str, bytes)):
            pem = key.encode("utf-8") if isinstance(key, str) else key
            key = serialization.load_pem_private_key(
                pem, password=passphrase.encode("utf-8") if passphrase else None
            )
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                "expected an elliptic-curve private key (or a PEM blob holding one), "
                f"got {type(key).__name__}"
            )
        der_sig = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:  # noqa: BLE001 -- normalized below, never swallowed
        raise ProofSigningError(
            f"ECDSA signing of the enrollment challenge failed: {exc}"
        ) from exc
    signature = base64.b64encode(der_sig).decode("ascii")
    if not signature:
        raise ProofSigningError(
            "ECDSA signing produced an empty signature; refusing to return an unsigned proof"
        )
    return signature


def _self_check(verifying_pubkey: str, signature: str, challenge: bytes, *, what: str) -> None:
    """Run the built proof through capauth's REAL verifier before returning it.

    Not a second, weaker check: it is literally
    ``capauth.pairing.kernel._proof_verifies``, the same function
    ``enroll_device`` calls, over the same bytes it will independently
    re-derive. This is what makes the round trip a property of the helper
    rather than a hope, and what turns a future drift in either derivation into
    a loud failure at build time instead of a caller silently sliding back to
    the tofu floor.
    """
    if not _proof_verifies(verifying_pubkey, signature, challenge):
        raise ProofSigningError(
            f"the {what} this helper built does not satisfy capauth's own verifier, "
            f"so enroll_device would reject it. The signing key almost certainly does "
            f"not match the public key presented for enrollment (the signature IS the "
            f"proof: a proof for a key you do not hold cannot be constructed). "
            f"Refusing to return a proof that would enroll nothing."
        )


def build_verified_proof(
    pubkey: str,
    *,
    private_key: Any,
    passphrase: str = "",
    subject: Optional[str] = None,
) -> EnrollmentProof:
    """Sign the ``verified`` enrollment challenge with the device's OWN key.

    The supported way to satisfy ``enroll_device(mode="verified")``. What it
    proves is possession of ``pubkey``'s private half, over precisely the
    fingerprint + subject this enrollment claims. What it does NOT do is lower,
    widen, or skip any check: the proof it returns is verified against
    capauth's real verifier before it is handed back, and ``enroll_device``
    verifies it again independently.

    Presenting a proof for a key you do not control is impossible by
    construction. The signature is the proof; there is no argument to this
    function that substitutes for holding the private key.

    Args:
        pubkey: The device's PUBLIC key, exactly as it will be presented to
            ``enroll_device`` (armored PGP, or base64 DER SPKI for an ECDSA
            P-256 device key). This also chooses the signing branch.
        private_key: The matching PRIVATE key the caller already holds: an
            ASCII-armored PGP private key block for a PGP device key, or a
            ``cryptography`` EC private key (or a PEM blob holding one) for a
            device key.
        passphrase: Passphrase unlocking ``private_key``, if any.
        subject: Who the device belongs to; defaults to its fingerprint, the
            same default ``enroll_device`` applies. Canonicalized here exactly
            as ``enroll_device`` will canonicalize it.

    Returns:
        EnrollmentProof: Splat it into ``enroll_device`` (``**proof``).

    Raises:
        ProofSigningError: If signing fails, produces nothing, or produces a
            signature capauth's own verifier rejects. Never returns an
            unsigned or empty proof.
        capauth.exceptions.SubjectNamingError: If ``subject`` does not conform
            to the canonical fqid grammar even after alias translation.
    """
    fingerprint, canonical = _resolve_subject(pubkey, subject)
    challenge = verified_challenge(fingerprint, canonical)
    signature = _sign(challenge, private_key, passphrase, pgp=_is_pgp(pubkey))
    _self_check(pubkey, signature, challenge, what="verified proof")
    return EnrollmentProof(
        mode=EnrollmentMode.VERIFIED,
        pubkey=pubkey,
        fingerprint=fingerprint,
        subject=canonical,
        challenge=challenge,
        proof=signature,
    )


def build_attested_proof(
    pubkey: str,
    *,
    operator_pubkey: str,
    operator_private_key: Any,
    passphrase: str = "",
    subject: Optional[str] = None,
) -> EnrollmentProof:
    """Sign the ``attested`` challenge with a VOUCHING OPERATOR's key.

    The attested counterpart of :func:`build_verified_proof`, for the case
    where the operator, not the device, is the one attesting: the operator signs
    over the DEVICE's fingerprint plus the subject, so the resulting evidence
    says "I, this operator, vouch that this device belongs to this identity."
    The device's private key is not involved and is never needed.

    Same guarantees as :func:`build_verified_proof`, and the same limit: the
    attestation is only as good as the operator key it is signed with, and that
    key must genuinely be held by the caller. Vouching with a key you do not
    control is impossible by construction.

    Note the domain separation is real: an attestation can never be replayed as
    a device self-proof, nor a self-proof as an attestation, because the two
    challenges carry different prefixes (see
    :func:`capauth.pairing.attested_challenge`).

    Args:
        pubkey: The DEVICE's public key being vouched for (its fingerprint is
            what gets attested; the operator's key shape chooses the signing
            branch).
        operator_pubkey: The vouching operator's PUBLIC key, exactly as it will
            be presented to ``enroll_device``.
        operator_private_key: The operator's matching PRIVATE key.
        passphrase: Passphrase unlocking ``operator_private_key``, if any.
        subject: Who the device belongs to; defaults to the DEVICE's
            fingerprint, matching ``enroll_device``.

    Returns:
        EnrollmentProof: Splat it into ``enroll_device`` (``**proof``), which
        supplies both ``operator_pubkey`` and ``attestation``.

    Raises:
        ProofSigningError: If signing fails, produces nothing, or produces a
            signature capauth's own verifier rejects.
        capauth.exceptions.SubjectNamingError: If ``subject`` does not conform
            to the canonical fqid grammar even after alias translation.
    """
    fingerprint, canonical = _resolve_subject(pubkey, subject)
    challenge = attested_challenge(fingerprint, canonical)
    signature = _sign(challenge, operator_private_key, passphrase, pgp=_is_pgp(operator_pubkey))
    _self_check(operator_pubkey, signature, challenge, what="attestation")
    return EnrollmentProof(
        mode=EnrollmentMode.ATTESTED,
        pubkey=pubkey,
        fingerprint=fingerprint,
        subject=canonical,
        challenge=challenge,
        operator_pubkey=operator_pubkey,
        attestation=signature,
    )
