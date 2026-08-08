"""In-memory authorization-request + code store for the CapAuth OIDC IdP.

Two short-lived record types:

* ``LoginRequest`` — created when a client hits ``/oidc/authorize``. Holds the
  validated OAuth params (client, redirect_uri, scope, state, PKCE challenge,
  OIDC ``nonce``) until the user finishes PGP login. Keyed by an opaque
  ``request_id`` carried through the PGP login page.

* ``AuthCode`` — minted after a successful PGP verify. Binds the authorization
  code to the verified fingerprint + claims + PKCE challenge + client. Consumed
  exactly once at ``/oidc/token``.

SPIKE: this is process-local and not persisted. Swap for Redis/DB for HA and to
survive restarts (see TODO in docs/CAPAUTH_OIDC_IDP.md).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LoginRequest:
    """A pending authorization request awaiting PGP login completion."""

    request_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    nonce: str  # OIDC nonce (echoed into the ID token), NOT the PGP nonce
    issued_at: float
    expires_at: float


@dataclass
class AuthCode:
    """A minted authorization code bound to a verified identity."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    nonce: str
    code_challenge: str
    code_challenge_method: str
    fingerprint: str
    claims: dict[str, Any]
    issued_at: float
    expires_at: float


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify a PKCE ``code_verifier`` against a stored ``code_challenge``.

    Args:
        code_verifier: Plain-text verifier presented at the token endpoint.
        code_challenge: Challenge captured at the authorization endpoint.
        method: ``"S256"`` or ``"plain"``.

    Returns:
        bool: True when verification passes. If no challenge was registered the
        check passes (PKCE was not requested by that client).
    """
    if not code_challenge:
        return True
    if not code_verifier:
        return False
    if method == "plain":
        return hmac.compare_digest(code_verifier, code_challenge)
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(computed, code_challenge)
    return False


class AuthCodeStore:
    """Process-local store for login requests and authorization codes.

    Args:
        request_ttl: Seconds a pending login request stays valid (default 600).
        code_ttl: Seconds an authorization code stays valid (default 120).
    """

    def __init__(self, request_ttl: int = 600, code_ttl: int = 120) -> None:
        self.request_ttl = request_ttl
        self.code_ttl = code_ttl
        self._requests: dict[str, LoginRequest] = {}
        self._codes: dict[str, AuthCode] = {}

    # ------------------------------------------------------------------
    # Login requests
    # ------------------------------------------------------------------

    def create_login_request(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        nonce: str = "",
    ) -> LoginRequest:
        """Create and store a pending login request, returning it."""
        self._evict_expired()
        now = time.time()
        req = LoginRequest(
            request_id=secrets.token_urlsafe(24),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "S256",
            nonce=nonce,
            issued_at=now,
            expires_at=now + self.request_ttl,
        )
        self._requests[req.request_id] = req
        return req

    def get_login_request(self, request_id: str) -> Optional[LoginRequest]:
        """Return a live login request, or None if missing/expired."""
        req = self._requests.get(request_id)
        if req is None:
            return None
        if time.time() > req.expires_at:
            self._requests.pop(request_id, None)
            return None
        return req

    def pop_login_request(self, request_id: str) -> Optional[LoginRequest]:
        """Remove and return a login request (call when minting the code)."""
        req = self.get_login_request(request_id)
        if req is not None:
            self._requests.pop(request_id, None)
        return req

    # ------------------------------------------------------------------
    # Authorization codes
    # ------------------------------------------------------------------

    def issue_code(
        self,
        request: LoginRequest,
        fingerprint: str,
        claims: dict[str, Any],
    ) -> AuthCode:
        """Mint an authorization code from a completed login request."""
        self._evict_expired()
        now = time.time()
        code = AuthCode(
            code=secrets.token_urlsafe(32),
            client_id=request.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            fingerprint=fingerprint,
            claims=claims,
            issued_at=now,
            expires_at=now + self.code_ttl,
        )
        self._codes[code.code] = code
        return code

    def consume_code(self, code: str) -> Optional[AuthCode]:
        """Single-use consumption of an authorization code.

        Returns the record on success (removing it), or None if the code is
        unknown, already used, or expired.
        """
        record = self._codes.pop(code, None)
        if record is None:
            return None
        if time.time() > record.expires_at:
            return None
        return record

    # ------------------------------------------------------------------
    # Maintenance / diagnostics
    # ------------------------------------------------------------------

    def _evict_expired(self) -> None:
        now = time.time()
        for rid in [k for k, v in self._requests.items() if v.expires_at < now]:
            self._requests.pop(rid, None)
        for code in [k for k, v in self._codes.items() if v.expires_at < now]:
            self._codes.pop(code, None)

    @property
    def pending_requests(self) -> int:
        """Number of login requests awaiting completion."""
        return len(self._requests)

    @property
    def pending_codes(self) -> int:
        """Number of authorization codes awaiting exchange."""
        return len(self._codes)
