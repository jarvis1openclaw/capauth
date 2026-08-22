# Strict delegated capabilities

`capauth.delegated` is a reusable verification contract for short-lived,
one-use capability chains. It is a library boundary, not an authorization
server. An application still owns its policy, current principal registry,
issuer policy, revocation store, durable replay reservation, and audit sink.

The contract verifies all authority presented for one protected invocation:

- a versioned transport contains the leaf and the complete ordered ancestor chain;
- every token uses the existing issuer-pinned CapAuth signed-token format;
- every root, ancestor, leaf, and authenticated request principal must match a
  current active principal-policy snapshot;
- every issuer must be currently trusted for the exact capability, audience,
  and principal kind it signed;
- every child names the exact parent credential digest, stays within the signed
  depth bound, keeps all exact scope fields, and can only add constraints or
  narrow an unbound resource identifier;
- revocation is checked for the leaf and every ancestor;
- the leaf is atomically reserved before allow, making it one-use;
- expiry is checked before and after signature work, after replay reservation,
  and after durable audit immediately before returning allow;
- issuer, principal, and revocation state is refreshed both before and after
  audit; any otherwise-valid policy revision change during audit denies and
  requires a fresh invocation;
- allow and deny results contain exact scope and policy revisions, but never raw
  credentials, signatures, token metadata, or exception causes.

## Wire contract

A direct root token may be presented as its exact `skcapstone_token` JSON.
Delegated authority uses this envelope:

```json
{
  "capauth_presented_capability": "1.0",
  "chain": {
    "ancestors": ["<root token>", "<optional parent token>"],
    "leaf": "<leaf token>"
  }
}
```

`parse_authorization_bearer()` rejects unknown fields, wrong versions,
over-depth or repeated credentials, oversized values, ambiguous shapes, and
duplicate JSON object members at every parsed depth. `PresentedCapability`
redacts `str()` and `repr()` and refuses serialization so bearer bytes remain
request-local.

An audit sink must preserve append order for a `decision_id`. Most attempts
produce one record with `attempt_sequence=1`. If expiry, revocation, or policy
state changes while the first allow record is being durably written, CapAuth
appends a compensating denial with `attempt_sequence=2` and never returns the
allow. Audit consumers treat the highest sequence as the terminal disposition.

## Application composition

```python
from capauth.delegated import (
    AuthorizationRequest,
    CapabilityAuthorizer,
    CapabilityScope,
    Principal,
    parse_authorization_bearer,
)

request = AuthorizationRequest(
    principal=Principal(
        principal_id="current-session-id",
        subject="agent@example.test",
        kind="agent",
    ),
    scope=CapabilityScope(
        audience="records-api",
        target="record.read",
        capability="records.read",
        operation="read",
        resource_type="record",
        resource_id="record-7",
        constraints=frozenset({"tenant:blue"}),
    ),
    correlation_id="request-123",
)

presented = parse_authorization_bearer(bearer_value)
decision = authorizer.authorize(presented, request)
```

Construct `CapabilityAuthorizer` with production implementations of
`TrustedIssuerBackend`, `PrincipalPolicyBackend`, `RevocationBackend`,
`ReplayBackend`, and `AuditSink`. The included in-memory implementations are
only for tests and isolated local development. They do not coordinate across
processes or hosts.

By default, signature checks use the existing
`CapAuthSignatureVerifier`, which pins the detached OpenPGP signature to the
issuer named by the signed payload. Tests may inject a `SignatureVerifier`
without changing any other policy boundary.

## Operational requirements

Production callers should:

1. derive `AuthorizationRequest.principal` from authentication, never request JSON;
2. derive the complete `CapabilityScope` from trusted route and resource data;
3. use authoritative, fail-closed current-state backends;
4. implement replay reservation as one atomic durable operation shared by every worker;
5. persist only `AuthorizationDecision`, never a bearer or parsed token;
6. discard `PresentedCapability` after the request finishes.

The signer interface accepts payload bytes and returns a detached signature.
Private key custody remains with the configured OpenPGP backend, hardware token,
or signing sidecar. This module never accepts, serializes, or stores a private key.
