"""W3C capability verification relationships in generated DID documents.

The agency axis of sovereign identity — the ability to invoke and delegate
capabilities — is implemented in skcapstone's capability-token system but must
also be *visible* to any W3C-conformant DID resolver. That means the two
capability verification relationships defined by the DID Core spec:

  - ``capabilityInvocation``  — the key that may invoke a capability
  - ``capabilityDelegation``  — the key that may delegate a capability onward

See https://www.w3.org/TR/did-core/#verification-relationships
"""

from __future__ import annotations

import pytest

from capauth.did import DIDContext, DIDDocumentGenerator, DIDTier

CAPABILITY_RELATIONSHIPS = ("capabilityInvocation", "capabilityDelegation")


@pytest.fixture
def ctx() -> DIDContext:
    """A minimal DIDContext that needs no profile on disk and no PGP parsing."""
    return DIDContext(
        fingerprint="02BC0EB3CAD31DB691A753C70C5629AB893F9746",
        name="Lumina",
        entity_type="ai",
        email="lumina@skworld.io",
        public_key_armor="-----BEGIN PGP PUBLIC KEY BLOCK-----\nstub\n-----END PGP PUBLIC KEY BLOCK-----",
        jwk={"kty": "RSA", "use": "sig", "n": "stub-n", "e": "AQAB"},
        did_key_id="did:key:zSTUBKEYIDENTIFIER",
        capabilities=["memory:read", "memory:write"],
    )


def _generate(ctx: DIDContext, tier: DIDTier) -> dict:
    return DIDDocumentGenerator(ctx).generate(
        tier,
        tailnet_hostname="lumina-node",
        tailnet_name="tailnet-xyz.ts.net",
        org_domain="skworld.io",
        agent_slug="lumina",
    )


@pytest.mark.parametrize("tier", [DIDTier.KEY, DIDTier.WEB_MESH, DIDTier.WEB_PUBLIC])
@pytest.mark.parametrize("relationship", CAPABILITY_RELATIONSHIPS)
def test_tier_declares_capability_relationship(
    ctx: DIDContext, tier: DIDTier, relationship: str
) -> None:
    """Every tier declares both capability verification relationships."""
    doc = _generate(ctx, tier)

    assert relationship in doc, f"{tier.value} DID doc is missing {relationship}"
    assert doc[relationship], f"{tier.value} DID doc has an empty {relationship}"


@pytest.mark.parametrize("tier", [DIDTier.KEY, DIDTier.WEB_MESH, DIDTier.WEB_PUBLIC])
@pytest.mark.parametrize("relationship", CAPABILITY_RELATIONSHIPS)
def test_capability_relationship_references_a_declared_verification_method(
    ctx: DIDContext, tier: DIDTier, relationship: str
) -> None:
    """Referenced key IDs must resolve to a verificationMethod in the same document.

    A dangling reference is worse than an absent relationship: a resolver would
    accept the claim and then fail to find a key to verify it against.
    """
    doc = _generate(ctx, tier)
    declared = {vm["id"] for vm in doc["verificationMethod"]}

    for ref in doc[relationship]:
        assert ref in declared, f"{tier.value}: {relationship} references unknown key {ref}"


def test_mesh_tier_without_tailnet_still_declares_capability_relationships(
    ctx: DIDContext,
) -> None:
    """The did:key fallback path must not silently drop the agency axis."""
    doc = DIDDocumentGenerator(ctx).generate(DIDTier.WEB_MESH, tailnet_hostname="")

    for relationship in CAPABILITY_RELATIONSHIPS:
        assert relationship in doc, f"did:key fallback dropped {relationship}"


def test_opted_out_public_did_declares_no_capability_relationships(ctx: DIDContext) -> None:
    """Opting out of public publishing must not leak an agency claim."""
    ctx.publish_to_skworld = False
    doc = DIDDocumentGenerator(ctx).generate(DIDTier.WEB_PUBLIC)

    assert doc.get("opted_out") is True
    for relationship in CAPABILITY_RELATIONSHIPS:
        assert relationship not in doc
