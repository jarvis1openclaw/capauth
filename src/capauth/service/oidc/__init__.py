"""CapAuth OIDC/OAuth2 Identity Provider (Track-2 spike).

Turns the standalone CapAuth FastAPI service into a real OIDC Authorization
Code + PKCE provider so it can be registered as an external OAuth/OIDC
**Source** in *stock* Authentik (or any OIDC client) — with NO Authentik
bundle patching.

The PGP login UI lives on CapAuth's own ``/oidc/authorize`` page (fully ours).
On successful PGP verification (reusing ``capauth.authentik.verifier`` /
``capauth.authentik.stage``), the provider issues an authorization code bound to
the PKCE challenge + the verified fingerprint, then exchanges it for an RS256
**ID token** signed by the IdP's RSA key (published at ``/oidc/jwks.json``).

See ``docs/CAPAUTH_OIDC_IDP.md`` for endpoints, client config, and the exact
steps to register CapAuth as an OAuth/OIDC Source in stock Authentik.
"""

from __future__ import annotations

from .clients import ClientRegistry, OIDCClient
from .passkey import PasskeyStore
from .provider import build_oidc_router
from .signing_key import SigningKey
from .store import AuthCodeStore

__all__ = [
    "AuthCodeStore",
    "ClientRegistry",
    "OIDCClient",
    "PasskeyStore",
    "SigningKey",
    "build_oidc_router",
]
