"""Identity verification via PGP challenge-response.

Replaces "Login with Google" — the user's PGP key IS their identity.
No redirect, no token exchange, no corporate middleman.

Flow:
  1. Verifier generates a random challenge
  2. Prover signs the challenge with their private key
  3. Verifier checks the signature against the prover's public key
  4. Valid signature = authenticated. Done.

Replay contract (READ THIS before using verify_challenge directly):
  * verify_challenge enforces a max challenge age by default
    (DEFAULT_MAX_CHALLENGE_AGE_SECONDS, 5 minutes). Older challenges raise
    ChallengeExpiredError. Pass max_age_seconds=None ONLY if your layer
    enforces TTL elsewhere.
  * Within that TTL the primitive is REPLAYABLE: the same signed response
    verifies again and again unless YOU track seen challenge ids. Pass a
    replay_guard (see InMemoryReplayGuard for a single-process default) or
    use a durable nonce store for anything multi-process/multi-node. The
    reference durable implementation is
    capauth.authentik.nonce_store.NonceStore, which is what the service
    layer uses.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Optional

from .crypto import get_backend
from .exceptions import ChallengeExpiredError, ChallengeReplayError, VerificationError
from .models import ChallengeRequest, ChallengeResponse, CryptoBackendType

CHALLENGE_BYTES = 32

#: Default max age of a challenge accepted by verify_challenge (seconds).
#: Minutes, not hours: a challenge is meant to be signed and returned
#: immediately, and a short window shrinks the replay surface.
DEFAULT_MAX_CHALLENGE_AGE_SECONDS = 300

#: How far in the future a challenge's created timestamp may sit before it
#: is rejected as suspicious (tolerates small clock skew between peers).
CLOCK_SKEW_TOLERANCE_SECONDS = 30

#: A replay guard is any callable (challenge_id, expires_at) -> bool that
#: returns True the first time an id is seen (and records it until
#: expires_at) and False on any repeat within that window.
ReplayGuard = Callable[[str, datetime], bool]


def _as_utc(ts: datetime) -> datetime:
    """Normalize a timestamp to aware UTC (naive values are read as UTC)."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


class InMemoryReplayGuard:
    """Reference in-memory seen-nonce guard for verify_challenge.

    Single-process, non-durable: state is lost on restart and NOT shared
    across processes or nodes. Good enough for a single-verifier peer mesh
    or tests. For anything durable or multi-node use a real nonce store
    (see capauth.authentik.nonce_store.NonceStore).

    Expired entries are pruned lazily on each call, so memory stays
    bounded by the number of challenges seen within one TTL window.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, datetime] = {}

    def __call__(self, challenge_id: str, expires_at: datetime) -> bool:
        """Record challenge_id; True if fresh, False if already seen."""
        now = datetime.now(timezone.utc)
        expires_at = _as_utc(expires_at)
        self._prune(now)
        if challenge_id in self._seen:
            return False
        self._seen[challenge_id] = expires_at
        return True

    def _prune(self, now: datetime) -> None:
        expired = [cid for cid, exp in self._seen.items() if exp <= now]
        for cid in expired:
            del self._seen[cid]


def create_challenge(
    from_fingerprint: str,
    to_fingerprint: str,
) -> ChallengeRequest:
    """Generate a fresh identity verification challenge.

    Args:
        from_fingerprint: PGP fingerprint of the entity issuing the challenge.
        to_fingerprint: PGP fingerprint of the entity being challenged.

    Returns:
        ChallengeRequest: The challenge to send to the prover.
    """
    challenge_hex = secrets.token_hex(CHALLENGE_BYTES)
    return ChallengeRequest(
        challenge_hex=challenge_hex,
        from_fingerprint=from_fingerprint,
        to_fingerprint=to_fingerprint,
    )


def respond_to_challenge(
    challenge: ChallengeRequest,
    private_key_armor: str,
    passphrase: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
) -> ChallengeResponse:
    """Sign a challenge to prove identity.

    The prover signs the challenge bytes with their private key,
    producing a ChallengeResponse that can be verified by anyone
    who has the prover's public key.

    Args:
        challenge: The challenge to respond to.
        private_key_armor: ASCII-armored private key of the prover.
        passphrase: Passphrase to unlock the private key.
        backend_type: Crypto backend to use.

    Returns:
        ChallengeResponse: Signed response.

    Raises:
        VerificationError: If signing fails.
    """
    backend = get_backend(backend_type)

    try:
        data = challenge.challenge_hex.encode("utf-8")
        signature = backend.sign(data, private_key_armor, passphrase)
        fingerprint = backend.fingerprint_from_armor(private_key_armor)

        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            challenge_hex=challenge.challenge_hex,
            signature=signature,
            responder_fingerprint=fingerprint,
        )
    except Exception as exc:
        raise VerificationError(f"Failed to sign challenge: {exc}") from exc


def verify_challenge(
    challenge: ChallengeRequest,
    response: ChallengeResponse,
    public_key_armor: str,
    backend_type: CryptoBackendType = CryptoBackendType.PGPY,
    *,
    max_age_seconds: Optional[float] = DEFAULT_MAX_CHALLENGE_AGE_SECONDS,
    replay_guard: Optional[ReplayGuard] = None,
    _now: Optional[datetime] = None,
) -> bool:
    """Verify a signed challenge response.

    Checks that:
    1. The response matches the original challenge
    2. The challenge is not older than max_age_seconds (TTL, default 5 min)
    3. The PGP signature is valid
    4. The responder fingerprint matches the challenged entity
    5. Optionally, that the challenge has not been used before
       (only if a replay_guard is supplied)

    REPLAY WARNING: without a replay_guard this primitive verifies the
    same signed response any number of times within the TTL window.
    Single-use semantics require a seen-nonce store. Pass
    InMemoryReplayGuard() for a single-process guard, or wire a durable
    store (reference: capauth.authentik.nonce_store.NonceStore, which is
    how the service layer enforces single-use).

    Args:
        challenge: The original challenge that was issued.
        response: The signed response from the prover.
        public_key_armor: ASCII-armored public key of the prover.
        backend_type: Crypto backend to use.
        max_age_seconds: Maximum accepted challenge age. Defaults to
            DEFAULT_MAX_CHALLENGE_AGE_SECONDS (300 s). Pass None to opt
            out ONLY when the calling layer enforces TTL itself.
        replay_guard: Optional callable (challenge_id, expires_at) -> bool
            returning False when the id was already seen. Called only
            after the signature verifies, so failed attempts do not
            consume the nonce.
        _now: Test hook to inject the verification time; leave unset in
            production code.

    Returns:
        bool: True if the identity is verified.

    Raises:
        ChallengeExpiredError: If the challenge is past max_age_seconds
            or dated in the future beyond clock-skew tolerance.
        ChallengeReplayError: If replay_guard reports the challenge id
            was already used.
        VerificationError: If the challenge IDs don't match or the
            fingerprint doesn't match the challenged entity.
    """
    if challenge.challenge_id != response.challenge_id:
        raise VerificationError(
            f"Challenge ID mismatch: expected {challenge.challenge_id}, "
            f"got {response.challenge_id}"
        )

    if challenge.challenge_hex != response.challenge_hex:
        raise VerificationError("Challenge content was tampered with")

    if response.responder_fingerprint != challenge.to_fingerprint:
        raise VerificationError(
            f"Fingerprint mismatch: challenge was for {challenge.to_fingerprint}, "
            f"but response came from {response.responder_fingerprint}"
        )

    now = _as_utc(_now) if _now is not None else datetime.now(timezone.utc)
    created = _as_utc(challenge.created)

    if max_age_seconds is not None:
        age = (now - created).total_seconds()
        if age > max_age_seconds:
            raise ChallengeExpiredError(
                f"Challenge {challenge.challenge_id} expired: "
                f"age {age:.0f}s exceeds max {max_age_seconds:.0f}s"
            )
        if age < -CLOCK_SKEW_TOLERANCE_SECONDS:
            raise ChallengeExpiredError(
                f"Challenge {challenge.challenge_id} is dated "
                f"{-age:.0f}s in the future (skew tolerance "
                f"{CLOCK_SKEW_TOLERANCE_SECONDS}s); refusing to verify"
            )

    backend = get_backend(backend_type)
    data = challenge.challenge_hex.encode("utf-8")

    verified = backend.verify(data, response.signature, public_key_armor)

    if verified and replay_guard is not None:
        retention = (
            max_age_seconds
            if max_age_seconds is not None
            else DEFAULT_MAX_CHALLENGE_AGE_SECONDS
        )
        expires_at = created + timedelta(seconds=retention)
        if not replay_guard(challenge.challenge_id, expires_at):
            raise ChallengeReplayError(
                f"Challenge {challenge.challenge_id} was already used: "
                "replay detected"
            )

    return verified
