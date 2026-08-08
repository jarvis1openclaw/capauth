"""Tests for challenge TTL enforcement and the replay-guard hook.

Covers (card 8e33ec88):
  - Expired-challenge rejection at the default max age
  - Boundary behavior (exactly at the limit vs just past it)
  - Custom max_age_seconds
  - Explicit opt-out (max_age_seconds=None)
  - Future-dated challenge rejection beyond clock-skew tolerance
  - Naive (tz-less) created timestamps treated as UTC
  - InMemoryReplayGuard single-use semantics + TTL pruning
  - verify_challenge replay_guard hook (in-memory default impl and a
    plain-callable custom hook)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from capauth.crypto import get_backend
from capauth.exceptions import (
    ChallengeExpiredError,
    ChallengeReplayError,
    VerificationError,
)
from capauth.identity import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    DEFAULT_MAX_CHALLENGE_AGE_SECONDS,
    InMemoryReplayGuard,
    create_challenge,
    respond_to_challenge,
    verify_challenge,
)
from capauth.models import Algorithm

PASSPHRASE = "ttl-test-2026"


@pytest.fixture(scope="module")
def keys():
    """One fast Ed25519 keypair shared by every test in this module."""
    backend = get_backend()
    return backend.generate_keypair(
        "TTL Tester", "ttl@capauth.local", PASSPHRASE, Algorithm.ED25519
    )


@pytest.fixture(scope="module")
def signed_pair(keys):
    """A (challenge, response) pair signed once; tests shift time via _now."""
    challenge = create_challenge("A" * 40, keys.fingerprint)
    response = respond_to_challenge(challenge, keys.private_armor, PASSPHRASE)
    return challenge, response


def _at(challenge, offset_seconds: float) -> datetime:
    """A fake 'now' that is offset_seconds after the challenge was created."""
    return challenge.created + timedelta(seconds=offset_seconds)


class TestChallengeTTL:
    """Max-age enforcement in verify_challenge."""

    def test_fresh_challenge_verifies(self, keys, signed_pair):
        challenge, response = signed_pair
        assert verify_challenge(challenge, response, keys.public_armor) is True

    def test_expired_challenge_rejected_by_default(self, keys, signed_pair):
        challenge, response = signed_pair
        now = _at(challenge, DEFAULT_MAX_CHALLENGE_AGE_SECONDS + 60)
        with pytest.raises(ChallengeExpiredError, match="expired"):
            verify_challenge(challenge, response, keys.public_armor, _now=now)

    def test_expired_error_is_a_verification_error(self, keys, signed_pair):
        """Back-compat: callers catching VerificationError still catch expiry."""
        challenge, response = signed_pair
        now = _at(challenge, DEFAULT_MAX_CHALLENGE_AGE_SECONDS + 60)
        with pytest.raises(VerificationError):
            verify_challenge(challenge, response, keys.public_armor, _now=now)

    def test_boundary_exactly_at_max_age_accepted(self, keys, signed_pair):
        """age == max_age is still valid; rejection starts strictly past it."""
        challenge, response = signed_pair
        now = _at(challenge, DEFAULT_MAX_CHALLENGE_AGE_SECONDS)
        assert verify_challenge(challenge, response, keys.public_armor, _now=now) is True

    def test_boundary_just_past_max_age_rejected(self, keys, signed_pair):
        challenge, response = signed_pair
        now = _at(challenge, DEFAULT_MAX_CHALLENGE_AGE_SECONDS + 1)
        with pytest.raises(ChallengeExpiredError):
            verify_challenge(challenge, response, keys.public_armor, _now=now)

    def test_custom_max_age(self, keys, signed_pair):
        challenge, response = signed_pair
        ok_now = _at(challenge, 5)
        bad_now = _at(challenge, 11)
        assert (
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                max_age_seconds=10,
                _now=ok_now,
            )
            is True
        )
        with pytest.raises(ChallengeExpiredError):
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                max_age_seconds=10,
                _now=bad_now,
            )

    def test_opt_out_accepts_old_challenge(self, keys, signed_pair):
        """max_age_seconds=None disables TTL for callers that TTL elsewhere."""
        challenge, response = signed_pair
        now = _at(challenge, 10 * 24 * 3600)  # ten days later
        assert (
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                max_age_seconds=None,
                _now=now,
            )
            is True
        )

    def test_future_dated_challenge_rejected(self, keys, signed_pair):
        """A created timestamp far in the future is suspicious, reject it."""
        challenge, response = signed_pair
        now = _at(challenge, -(CLOCK_SKEW_TOLERANCE_SECONDS + 30))
        with pytest.raises(ChallengeExpiredError, match="future"):
            verify_challenge(challenge, response, keys.public_armor, _now=now)

    def test_small_clock_skew_tolerated(self, keys, signed_pair):
        """created slightly ahead of the verifier clock is allowed."""
        challenge, response = signed_pair
        now = _at(challenge, -(CLOCK_SKEW_TOLERANCE_SECONDS - 5))
        assert verify_challenge(challenge, response, keys.public_armor, _now=now) is True

    def test_naive_created_treated_as_utc(self, keys, signed_pair):
        """A tz-less created timestamp must not crash and is read as UTC."""
        challenge, response = signed_pair
        naive = challenge.model_copy(update={"created": challenge.created.replace(tzinfo=None)})
        now = challenge.created + timedelta(seconds=30)
        assert verify_challenge(naive, response, keys.public_armor, _now=now) is True
        late = challenge.created + timedelta(seconds=DEFAULT_MAX_CHALLENGE_AGE_SECONDS + 60)
        with pytest.raises(ChallengeExpiredError):
            verify_challenge(naive, response, keys.public_armor, _now=late)

    def test_ttl_checked_before_signature(self, keys, signed_pair):
        """Expired challenges are rejected without touching the crypto backend."""
        challenge, response = signed_pair
        now = _at(challenge, DEFAULT_MAX_CHALLENGE_AGE_SECONDS + 60)
        with pytest.raises(ChallengeExpiredError):
            verify_challenge(challenge, response, "NOT A VALID PUBLIC KEY", _now=now)


class TestInMemoryReplayGuard:
    """The reference in-memory seen-nonce implementation."""

    def test_first_use_is_fresh_second_is_replay(self):
        guard = InMemoryReplayGuard()
        exp = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert guard("nonce-1", exp) is True
        assert guard("nonce-1", exp) is False

    def test_distinct_ids_independent(self):
        guard = InMemoryReplayGuard()
        exp = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert guard("nonce-a", exp) is True
        assert guard("nonce-b", exp) is True

    def test_expired_entries_are_pruned(self):
        guard = InMemoryReplayGuard()
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert guard("stale", past) is True
        # Entry expired; a later call prunes it and the id is fresh again.
        # (Safe: the TTL check in verify_challenge already rejects the
        # challenge itself past its max age.)
        future = datetime.now(timezone.utc) + timedelta(minutes=5)
        assert guard("other", future) is True
        assert "stale" not in guard._seen

    def test_naive_expiry_treated_as_utc(self):
        guard = InMemoryReplayGuard()
        naive_exp = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5)
        assert guard("naive-1", naive_exp) is True
        assert guard("naive-1", naive_exp) is False


class TestVerifyChallengeReplayGuard:
    """The pluggable replay_guard hook on verify_challenge."""

    def test_replay_rejected_with_guard(self, keys, signed_pair):
        challenge, response = signed_pair
        guard = InMemoryReplayGuard()
        now = _at(challenge, 1)
        assert (
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                replay_guard=guard,
                _now=now,
            )
            is True
        )
        with pytest.raises(ChallengeReplayError, match="replay"):
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                replay_guard=guard,
                _now=now,
            )

    def test_replay_error_is_a_verification_error(self, keys, signed_pair):
        challenge, response = signed_pair
        guard = InMemoryReplayGuard()
        now = _at(challenge, 1)
        verify_challenge(challenge, response, keys.public_armor, replay_guard=guard, _now=now)
        with pytest.raises(VerificationError):
            verify_challenge(challenge, response, keys.public_armor, replay_guard=guard, _now=now)

    def test_failed_verification_does_not_consume_nonce(self, keys, signed_pair):
        """Only a successful verification records the challenge as seen."""
        challenge, response = signed_pair
        guard = InMemoryReplayGuard()
        now = _at(challenge, 1)
        tampered = response.model_copy(update={"responder_fingerprint": "B" * 40})
        with pytest.raises(VerificationError, match="Fingerprint mismatch"):
            verify_challenge(
                challenge,
                tampered,
                keys.public_armor,
                replay_guard=guard,
                _now=now,
            )
        # The genuine response still works: the failed attempt burned nothing.
        assert (
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                replay_guard=guard,
                _now=now,
            )
            is True
        )

    def test_custom_callable_guard(self, keys, signed_pair):
        """Any (challenge_id, expires_at) -> bool callable can be plugged in."""
        challenge, response = signed_pair
        seen: dict[str, datetime] = {}

        def my_guard(challenge_id: str, expires_at: datetime) -> bool:
            if challenge_id in seen:
                return False
            seen[challenge_id] = expires_at
            return True

        now = _at(challenge, 1)
        assert (
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                replay_guard=my_guard,
                _now=now,
            )
            is True
        )
        assert challenge.challenge_id in seen
        with pytest.raises(ChallengeReplayError):
            verify_challenge(
                challenge,
                response,
                keys.public_armor,
                replay_guard=my_guard,
                _now=now,
            )

    def test_guard_with_ttl_opt_out_still_gets_expiry(self, keys, signed_pair):
        """With max_age_seconds=None the guard still receives a finite
        expires_at (default retention) so it can prune."""
        challenge, response = signed_pair
        captured: list[datetime] = []

        def capturing_guard(challenge_id: str, expires_at: datetime) -> bool:
            captured.append(expires_at)
            return True

        now = _at(challenge, 1)
        verify_challenge(
            challenge,
            response,
            keys.public_armor,
            max_age_seconds=None,
            replay_guard=capturing_guard,
            _now=now,
        )
        assert len(captured) == 1
        expected = challenge.created + timedelta(seconds=DEFAULT_MAX_CHALLENGE_AGE_SECONDS)
        assert captured[0] == expected
