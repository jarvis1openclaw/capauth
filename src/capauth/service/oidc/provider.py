"""CapAuth OIDC/OAuth2 Identity Provider — FastAPI router (Track-2 spike).

Mount into the main CapAuth service::

    from capauth.service.oidc import build_oidc_router
    app.include_router(build_oidc_router(), prefix="/oidc")

Endpoints (under the mount prefix, default ``/oidc``)::

    GET  /oidc/.well-known/openid-configuration   discovery document
    GET  /oidc/jwks.json                           JWKS (RSA public signing key)
    GET  /oidc/authorize                           validate params + render PGP login page
    POST /oidc/complete                            (called by the login page) verify PGP -> code
    POST /oidc/token                               code + PKCE -> RS256 ID token + access token
    GET  /oidc/userinfo                            Bearer access token -> claims

A copy of the discovery document is ALSO served at the service root
(``/.well-known/openid-configuration``) by the main app so generic clients that
only know the issuer can autodiscover; that wiring lives in ``service/app.py``.

The login page reuses the canonical ``CAPAUTH_NONCE_V1`` payload contract and
the existing ``/capauth/v1/challenge`` + ``/capauth/v1/verify`` endpoints, so any
existing CapAuth signing client (CLI, browser extension, Nextcloud app) works
unchanged.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional
from urllib.parse import urlencode

import jwt as pyjwt
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ...authentik.claims_mapper import preferred_username_fallback
from .clients import ClientRegistry
from .signing_key import SigningKey
from .store import AuthCodeStore, verify_pkce

logger = logging.getLogger("capauth.service.oidc")

SUPPORTED_SCOPES = ["openid", "profile", "email", "groups"]
ID_TOKEN_TTL = int(os.environ.get("CAPAUTH_OIDC_ID_TOKEN_TTL", "3600"))
ACCESS_TOKEN_TTL = int(os.environ.get("CAPAUTH_OIDC_ACCESS_TOKEN_TTL", "3600"))


def issuer_url() -> str:
    """Resolve the IdP issuer URL (``CAPAUTH_OIDC_ISSUER`` or base URL)."""
    explicit = os.environ.get("CAPAUTH_OIDC_ISSUER")
    if explicit:
        return explicit.rstrip("/")
    service_id = os.environ.get("CAPAUTH_SERVICE_ID", "capauth.local")
    base = os.environ.get("CAPAUTH_BASE_URL", f"https://{service_id}")
    return base.rstrip("/")


def discovery_document(issuer: Optional[str] = None) -> dict[str, Any]:
    """Build the OpenID Connect discovery document for the IdP.

    Args:
        issuer: Override issuer URL. Defaults to :func:`issuer_url`.

    Returns:
        dict: The ``.well-known/openid-configuration`` payload.
    """
    iss = (issuer or issuer_url()).rstrip("/")
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oidc/authorize",
        "token_endpoint": f"{iss}/oidc/token",
        "userinfo_endpoint": f"{iss}/oidc/userinfo",
        "jwks_uri": f"{iss}/oidc/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "iat",
            "exp",
            "nonce",
            "amr",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "groups",
            "picture",
            "locale",
            "capauth_fingerprint",
            "agent_type",
        ],
    }


# ---------------------------------------------------------------------------
# PGP login page (server-rendered; reuses /capauth/v1/challenge + /verify)
# ---------------------------------------------------------------------------

_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CapAuth — Sign in with PGP</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f0f1a;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
    .card{{background:#1a1a35;border:1px solid rgba(124,58,237,.25);border-radius:14px;
           padding:2rem;max-width:520px;width:100%}}
    h1{{font-size:1.35rem;color:#a78bfa;margin-bottom:.4rem}}
    p.sub{{color:#94a3b8;font-size:.88rem;margin-bottom:1.3rem;line-height:1.5}}
    .step{{color:#64748b;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
    label{{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.3rem}}
    input,textarea{{width:100%;background:#0f0f1a;border:1px solid #334155;border-radius:8px;
                    color:#e2e8f0;padding:.6rem .8rem;font-size:.88rem;margin-bottom:1rem;
                    font-family:monospace}}
    textarea{{min-height:130px;resize:vertical}}
    button{{width:100%;background:#7C3AED;color:#fff;border:none;border-radius:8px;
            padding:.8rem;font-size:1rem;cursor:pointer;font-weight:600}}
    button:hover{{background:#6d28d9}}
    .nonce-box{{background:#0f0f1a;border:1px solid #334155;border-radius:8px;padding:.7rem;
                margin-bottom:1rem;font-family:monospace;font-size:.78rem;color:#00e5ff;word-break:break-all}}
    .err{{color:#f87171;font-size:.85rem;margin-top:.6rem;display:none}}
    code{{color:#a78bfa}}
  </style>
</head>
<body>
<div class="card">
  <h1>Sign in with CapAuth</h1>
  <p class="sub">Authenticate to <strong>{client_name}</strong> with your PGP key.
     No password — sign the challenge to prove key possession.</p>

  <div class="step">1 — Your PGP fingerprint</div>
  <label for="fp">Fingerprint (40 hex chars)</label>
  <input id="fp" type="text" maxlength="50" placeholder="ABCDEF0123..." autocomplete="off"/>

  <div class="step">2 — Challenge nonce</div>
  <div class="nonce-box" id="nonce">Enter your fingerprint to load a challenge…</div>

  <div class="step">3 — Paste your PGP signature over the challenge</div>
  <label for="sig">Signed message / signature (ASCII armor)</label>
  <textarea id="sig" placeholder="-----BEGIN PGP MESSAGE-----&#10;...&#10;-----END PGP MESSAGE-----"></textarea>

  <label for="pub" style="font-size:.72rem;color:#475569">First time? Paste your public key (armored) to enroll</label>
  <textarea id="pub" style="min-height:80px" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK----- (optional after first login)"></textarea>

  <button onclick="submitSig()">Verify &amp; Continue</button>
  <div class="err" id="err"></div>

  <p style="margin-top:1rem;font-size:.74rem;color:#475569">
    CLI: <code>capauth sign --nonce &lt;nonce&gt;</code> &nbsp;·&nbsp; the browser extension fills the signature automatically.
  </p>
</div>

<script>
const BASE = "{base_url}";
const REQUEST_ID = "{request_id}";
let currentNonce = null, currentEcho = null;

function setErr(m){{ const e=document.getElementById("err"); e.textContent=m; e.style.display="block"; }}

async function loadChallenge(fp){{
  const r = await fetch(BASE + "/capauth/v1/challenge", {{
    method:"POST", headers:{{"Content-Type":"application/json"}},
    body: JSON.stringify({{capauth_version:"1.0", fingerprint:fp,
      client_nonce: btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16))))}})
  }});
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}}

document.getElementById("fp").addEventListener("blur", async function(){{
  const fp=this.value.trim().toUpperCase().replace(/\\s/g,"");
  if(fp.length!==40){{ return; }}
  try{{
    const ch=await loadChallenge(fp);
    currentNonce=ch.nonce; currentEcho=ch.client_nonce_echo;
    document.getElementById("nonce").textContent=ch.nonce;
    // window.capauth provider: auto-sign with Tier B origin-binding. The
    // extension injects origin=window.location.origin and signs in-extension —
    // the private key never reaches this page. Falls back to manual paste.
    if(window.capauth && window.capauth.isCapAuth){{
      try{{
        const res=await window.capauth.signChallenge(ch);
        document.getElementById("sig").value=res.signature;
        submitSig();
      }}catch(e){{ /* denied/locked — leave the paste flow available */ }}
    }}
  }}catch(e){{ document.getElementById("nonce").textContent="Error: "+e.message; }}
}});

async function submitSig(){{
  document.getElementById("err").style.display="none";
  const fp=document.getElementById("fp").value.trim().toUpperCase().replace(/\\s/g,"");
  const sig=document.getElementById("sig").value.trim();
  const pub=document.getElementById("pub").value.trim();
  if(fp.length!==40) return setErr("Fingerprint must be 40 hex characters.");
  if(!currentNonce) return setErr("No challenge loaded — tab out of the fingerprint field first.");
  if(!sig) return setErr("Paste your PGP signature.");

  const body={{request_id:REQUEST_ID, fingerprint:fp, nonce:currentNonce,
               nonce_signature:sig}};
  if(pub) body.public_key=pub;

  const r=await fetch(BASE + "/oidc/complete", {{
    method:"POST", headers:{{"Content-Type":"application/json"}}, body: JSON.stringify(body)
  }});
  if(!r.ok){{ const b=await r.json().catch(()=>({{}})); return setErr(b.detail || b.error || "Login failed."); }}
  const d=await r.json();
  window.location.href=d.redirect_to;
}}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_oidc_router(
    *,
    signing_key: Optional[SigningKey] = None,
    clients: Optional[ClientRegistry] = None,
    store: Optional[AuthCodeStore] = None,
) -> APIRouter:
    """Build the OIDC IdP router.

    Args:
        signing_key: RSA token-signing key. Defaults to a persisted
            :class:`SigningKey`.
        clients: Static :class:`ClientRegistry`. Defaults to env-loaded.
        store: :class:`AuthCodeStore`. Defaults to a fresh in-memory store.

    Returns:
        APIRouter: Mount at prefix ``/oidc``.
    """
    signing_key = signing_key or SigningKey()
    clients = clients if clients is not None else ClientRegistry()
    store = store or AuthCodeStore()

    router = APIRouter(tags=["oidc-idp"])
    # Expose internals for the main app / tests.
    router.signing_key = signing_key  # type: ignore[attr-defined]
    router.clients = clients  # type: ignore[attr-defined]
    router.store = store  # type: ignore[attr-defined]

    def _verify_pgp(
        fingerprint: str,
        nonce: str,
        nonce_signature: str,
        public_key: str,
        claims: dict[str, Any],
        claims_signature: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Reuse the service's PGP verify path (challenge/nonce/verify/claims).

        Returns ``(ok, error_code, oidc_claims)``.  Implemented lazily so the
        OIDC module imports cleanly without the FastAPI app side-effects.
        """
        from ...authentik.nonce_store import peek
        from ...authentik.stage import verify_auth_response
        from ...authentik.verifier import fingerprint_from_armor
        from ..app import SERVICE_ID, get_keystore

        ks = get_keystore()
        existing = ks.get(fingerprint)
        armor = public_key or (existing.public_key_armor if existing else "")
        if not armor:
            return False, "unknown_fingerprint", {}

        derived = fingerprint_from_armor(armor)
        if derived and derived.upper() != fingerprint.upper():
            return False, "invalid_fingerprint", {}

        # Enroll-on-first-use (mirrors /capauth/v1/verify; spike: auto-approve).
        if existing is None:
            ks.enroll(fingerprint, armor, approved=True)

        nonce_record = peek(nonce)
        if nonce_record is None:
            return False, "invalid_nonce", {}
        challenge_ctx = {
            "nonce": nonce_record["nonce"],
            "client_nonce_echo": nonce_record.get("client_nonce_echo", ""),
            "timestamp": nonce_record["issued_at"],
            "service": SERVICE_ID,
            "expires": nonce_record["expires_at"],
        }
        ok, err, oidc_claims = verify_auth_response(
            fingerprint=fingerprint,
            nonce_id=nonce,
            nonce_signature_armor=nonce_signature,
            claims=claims,
            claims_signature_armor=claims_signature,
            public_key_armor=armor,
            challenge_context=challenge_ctx,
        )
        if ok:
            ks.update_last_auth(fingerprint)
        return ok, err, oidc_claims

    # ------------------------------------------------------------------
    # Discovery + JWKS
    # ------------------------------------------------------------------

    @router.get("/.well-known/openid-configuration", summary="OIDC discovery")
    async def discovery() -> dict[str, Any]:
        return discovery_document()

    @router.get("/jwks.json", summary="JSON Web Key Set (RSA signing key)")
    async def jwks() -> dict[str, Any]:
        return signing_key.jwks()

    # ------------------------------------------------------------------
    # Authorization endpoint — renders the PGP login page
    # ------------------------------------------------------------------

    @router.get("/authorize", summary="Authorization endpoint (renders PGP login)")
    async def authorize(
        response_type: str = "code",
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "openid",
        state: str = "",
        nonce: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
    ) -> Any:
        if response_type != "code":
            raise HTTPException(status_code=400, detail="unsupported_response_type")

        client = clients.get(client_id)
        if client is None:
            raise HTTPException(status_code=400, detail="unknown client_id")
        if not redirect_uri or not client.redirect_uri_allowed(redirect_uri):
            # Per OAuth2: do NOT redirect on an invalid redirect_uri.
            raise HTTPException(status_code=400, detail="invalid redirect_uri")
        if code_challenge_method not in ("S256", "plain"):
            raise HTTPException(status_code=400, detail="unsupported code_challenge_method")

        req = store.create_login_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope or "openid",
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )

        base_url = issuer_url()
        html = _LOGIN_PAGE.format(
            base_url=base_url,
            request_id=req.request_id,
            client_name=client.name or client.client_id,
        )
        return HTMLResponse(content=html)

    # ------------------------------------------------------------------
    # Completion endpoint — called by the login page after the user signs
    # ------------------------------------------------------------------

    @router.post("/complete", summary="Complete PGP login and mint an auth code")
    async def complete(request: Request) -> dict[str, Any]:
        body = await request.json()
        request_id = (body.get("request_id") or "").strip()
        fingerprint = (body.get("fingerprint") or "").strip().upper()
        nonce_sig = (body.get("nonce_signature") or "").strip()
        nonce_id = (body.get("nonce") or "").strip()
        public_key = (body.get("public_key") or "").strip()
        claims = body.get("claims") or {}
        claims_sig = (body.get("claims_signature") or "").strip()

        login_req = store.get_login_request(request_id)
        if login_req is None:
            raise HTTPException(status_code=400, detail="expired or unknown request")
        if len(fingerprint) != 40 or not nonce_sig or not nonce_id:
            raise HTTPException(status_code=400, detail="fingerprint, nonce, nonce_signature required")

        ok, err, oidc_claims = _verify_pgp(
            fingerprint=fingerprint,
            nonce=nonce_id,
            nonce_signature=nonce_sig,
            public_key=public_key,
            claims=claims,
            claims_signature=claims_sig,
        )
        if not ok:
            raise HTTPException(status_code=401, detail=err or "pgp_verification_failed")

        # Consume the login request and mint a code bound to the verified id.
        login_req = store.pop_login_request(request_id)
        code_record = store.issue_code(login_req, fingerprint, oidc_claims)

        params = {"code": code_record.code}
        if login_req.state:
            params["state"] = login_req.state
        redirect_to = f"{login_req.redirect_uri}?{urlencode(params)}"
        logger.info("OIDC code issued for fp=%s client=%s", fingerprint[:8], login_req.client_id)
        return {"redirect_to": redirect_to, "code": code_record.code}

    # ------------------------------------------------------------------
    # Token endpoint
    # ------------------------------------------------------------------

    @router.post("/token", summary="Token endpoint (authorization_code + PKCE)")
    async def token(
        request: Request,
        grant_type: str = Form(default="authorization_code"),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
    ) -> dict[str, Any]:
        if grant_type != "authorization_code":
            raise HTTPException(status_code=400, detail="unsupported_grant_type")

        # Support HTTP Basic client auth (client_secret_basic) as well.
        if not client_id:
            import base64 as _b64

            auth = request.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                try:
                    decoded = _b64.b64decode(auth[6:]).decode("utf-8")
                    client_id, _, client_secret = decoded.partition(":")
                except Exception:
                    raise HTTPException(status_code=401, detail="invalid_client")

        client = clients.get(client_id)
        if client is None or not client.secret_matches(client_secret):
            raise HTTPException(status_code=401, detail="invalid_client")

        record = store.consume_code(code)
        if record is None:
            raise HTTPException(status_code=400, detail="invalid_grant")
        if record.client_id != client_id:
            raise HTTPException(status_code=400, detail="invalid_grant: client mismatch")
        if redirect_uri and redirect_uri != record.redirect_uri:
            raise HTTPException(status_code=400, detail="invalid_grant: redirect_uri mismatch")
        if not verify_pkce(code_verifier, record.code_challenge, record.code_challenge_method):
            raise HTTPException(status_code=400, detail="invalid_grant: PKCE verification failed")

        iss = issuer_url()
        now = int(time.time())
        sub = record.fingerprint

        id_claims: dict[str, Any] = {
            "iss": iss,
            "sub": sub,
            "aud": client_id,
            "iat": now,
            "exp": now + ID_TOKEN_TTL,
            "amr": ["pgp"],
            "capauth_fingerprint": sub,
        }
        if record.nonce:
            id_claims["nonce"] = record.nonce
        # Fold in verified profile claims (name/email/groups/etc.) from mapper.
        for key in (
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "groups",
            "picture",
            "locale",
            "agent_type",
        ):
            if key in record.claims:
                id_claims[key] = record.claims[key]
        id_claims.setdefault(
            "preferred_username", preferred_username_fallback(sub)
        )

        headers = {"kid": signing_key.kid}
        id_token = pyjwt.encode(
            id_claims, signing_key.private_pem, algorithm=signing_key.ALGORITHM, headers=headers
        )

        # Access token: a JWT carrying claims so /userinfo is self-contained.
        access_claims = dict(id_claims)
        access_claims["exp"] = now + ACCESS_TOKEN_TTL
        access_claims["token_use"] = "access"
        access_token = pyjwt.encode(
            access_claims, signing_key.private_pem, algorithm=signing_key.ALGORITHM, headers=headers
        )

        logger.info("OIDC token issued for fp=%s client=%s", sub[:8], client_id)
        return {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "scope": record.scope,
        }

    # ------------------------------------------------------------------
    # UserInfo endpoint
    # ------------------------------------------------------------------

    @router.get("/userinfo", summary="UserInfo (Bearer access token -> claims)")
    async def userinfo(request: Request) -> dict[str, Any]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token_str = auth[len("Bearer ") :]
        try:
            payload = pyjwt.decode(
                token_str,
                signing_key.public_pem,
                algorithms=[signing_key.ALGORITHM],
                audience=None,
                options={"verify_aud": False, "require": ["sub", "iss", "exp"]},
            )
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token_expired")
        except pyjwt.InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid_token: {exc}")

        drop = {"iat", "exp", "iss", "aud", "token_use", "nonce"}
        return {k: v for k, v in payload.items() if k not in drop}

    return router
