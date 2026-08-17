"""TEST SEAM: stands in for the gpg subprocess so tests can sign without a key.

    THIS IS NOT A PRODUCTION BYPASS.

If you have found this module in a repo's import list and are wondering whether
someone has switched off CapAuth's authorization checks, the answer is no, and
here is the short version before the detail.

**What it stubs:** the gpg *subprocess* boundary, and nothing else. Three
attributes of :mod:`capauth.tokens` are replaced with in-process stand-ins:
``_get_issuer_fingerprint``, ``_pgp_sign_payload``, and the ``verify_manifest``
that module imported. That is the whole surface. It exists because a CI runner
has no secret key and no unlocked agent, so without it every token mint raises
and every gated route 403s.

**What it does NOT weaken, at all, while active:**

* :func:`capauth.authz.decide`'s signature gate. An unsigned token is still
  denied, including for RCE-tier capabilities like ``skcode.dispatch``. A token
  whose payload was tampered with after signing is still denied. A token
  declaring one issuer while signed by another is still denied. The stand-in
  signature is a digest of the exact payload bytes, checked against the exact
  declared issuer, so all three of those keep failing exactly as they do
  against real gpg.
* The verified-tier enrollment floor. Enrollment mode, its proof requirement
  (:func:`capauth.pairing.enroll_device` validating ``proof`` / ``attestation``
  against real signatures), and the minimum-mode requirement each capability
  rule declares are untouched. The stub replaces no part of
  :mod:`capauth.pairing`.
* The raise-on-signing-failure behaviour of :func:`capauth.tokens.issue_token`
  and :func:`capauth.tokens.mint_audience_token`. With the stub inactive,
  signing failure still raises :class:`capauth.tokens.TokenSigningError` and
  still writes nothing to the token store. The stub does not soften that path;
  it simply makes signing succeed, so the path is not reached.
* The server-derived-subject property. The stub never touches how a PEP derives
  the subject it passes to ``decide``; a caller still cannot assert its own
  identity through it.
* :func:`capauth.tokens.signature_verifies` itself, which runs unmodified:
  empty-signature check, unattributable-issuer check, canonical payload bytes,
  issuer pinning.

In short, it removes gpg as a dependency of a test, not a check from the PDP.
The negative controls in ``tests/test_testing_helper.py`` pin every claim in the
list above, and one of them runs in a fresh subprocess specifically so it cannot
be fooled by this module having been imported.

**Where it cannot reach:** a deployed process, structurally. See "Why this
cannot be switched on by accident in a deployed process" at the end of this
docstring.

Why this module is shipped rather than kept in ``tests/conftest.py``
--------------------------------------------------------------------
:func:`capauth.authz.decide` requires the granting token to carry a signature
that verifies over its exact payload bytes, made by the key the payload names as
issuer, and :func:`capauth.tokens.issue_token` now RAISES rather than storing an
unsigned token when signing fails. Both are correct: an unsigned token used to
be issued anyway and used to grant RCE capabilities.

The consequence is that real gpg (a secret key present, an agent unlocked)
became a hard dependency of any suite that expects an ALLOW. A GitHub Actions
runner has neither, so every downstream repo that mints a capability token in
its tests started failing at the mint, or 403ing at the gate. CapAuth's own
suite never had that problem because it carried this stub privately in
``tests/conftest.py``, where no downstream repo could reach it. This module is
that same stub, promoted into importable, shipped code.

What the stub fakes, and what it deliberately does not
------------------------------------------------------
It fakes ONLY the gpg subprocess, at exactly three seams in
:mod:`capauth.tokens`:

* ``_get_issuer_fingerprint`` so issued tokens name a plausible issuer instead
  of the ``"unknown"`` placeholder (which ``signature_verifies`` correctly
  refuses as unattributable);
* ``_pgp_sign_payload`` so ``sign=True`` yields a stand-in signature over the
  payload's canonical bytes;
* ``verify_manifest`` so verification accepts exactly that stand-in, for exactly
  those bytes, from exactly that issuer.

Everything else runs unmodified, including the whole of
:func:`capauth.tokens.signature_verifies` (empty-signature check,
unattributable-issuer check, canonical payload bytes, issuer pinning) and the
whole PDP. The stand-in "signature" is a digest of the exact bytes signed, so
with the stub active:

* an UNSIGNED token is still denied;
* a token whose payload was tampered with after signing is still denied;
* a signature lifted from another token is still denied;
* a token declaring a different issuer than the one that signed is still denied.

A stub that just returned ``True`` would restore the very defect the signature
gate closes (SEC-CRIT ``bc56b98b``: an unsigned token granting
``skcode.dispatch``) while turning every downstream suite green, which is
strictly worse than a red suite. Those properties are pinned by
``tests/test_testing_helper.py``.

This is a substitute for gpg in a hermetic test, NOT a substitute for OpenPGP.
Real end-to-end signing and verification against a real generated key is covered
separately in ``tests/test_authz_signature_gate.py``, which must keep running
WITHOUT this stub.

Adopting it downstream
----------------------
**Prefer the scoped form.** Apply it to the specific modules that fail without
it, and read that list out of the CI log rather than guessing::

    from capauth.testing import stub_token_signing  # noqa: F401

    pytestmark = pytest.mark.usefixtures("stub_token_signing")

Outside pytest entirely, :func:`signing_stub` is a plain context manager.

There is also a directory-wide autouse form, one line in the consuming repo's
``tests/conftest.py``::

    from capauth.testing import capauth_signing_stub  # noqa: F401

.. warning::

   The directory-wide form silently converts real-gpg coverage into stub
   coverage. If any test under that directory generates a real key and signs end
   to end, the stub takes over the boundary it exists to exercise. That test
   keeps passing while no longer testing the thing it was written for, and
   nobody re-reads a green test.

   This is not hypothetical. It was caught in review during skchat's adoption on
   2026-08-16: a directory-wide conftest import would have reached
   ``test_dataplane_audience_token.py`` and ``test_audience_mint_endpoint.py``,
   both of which generate a real ephemeral key and sign for real. They were
   scoped per module instead, and both real-gpg files were then verified to
   contain zero references to this module.

   Note the asymmetry that makes this worth a warning rather than a footnote.
   The failure this module fixes is LOUD: signing raises, CI shows errors, and
   someone investigates. Over-applying it fails QUIETLY: the suite stays green
   and the loss shows up only when the real signing path breaks in production
   with nothing red to warn you.

   So before using the directory-wide form, grep the tree for tests that touch
   real gpg (a generated keyring, ``GNUPGHOME``, a real ``issue_token`` without
   this stub) and confirm none sit under it. CapAuth's own suite deliberately
   does NOT use the autouse form in ``tests/conftest.py`` for exactly this
   reason: ``tests/test_authz_signature_gate.py`` must keep running against real
   gpg.

Why this cannot be switched on by accident in a deployed process
----------------------------------------------------------------
1. Nothing in CapAuth's runtime imports it. ``import capauth`` does not pull it
   in, and no module under ``capauth/`` references it. A test asserts that.
2. Importing it requires ``pytest``, which is a dev-extra only, absent from
   ``capauth``'s runtime dependencies and from the ``service`` extra. In a
   deployed process ``import capauth.testing`` raises ``ModuleNotFoundError``
   before any seam could be touched.
3. It registers no ``pytest11`` entry point, so pytest never auto-loads it. A
   consuming repo has to name it in its own test code.
4. Importing it patches nothing. Every activation path is an explicit call whose
   effect is lexically scoped and reverted on exit (``monkeypatch`` teardown, or
   the context manager's ``__exit__``).
5. There is no env var, config key, or global flag that enables it. There is
   deliberately no ``CAPAUTH_ALLOW_UNSIGNED``-style switch anywhere: a flag
   production config could set is exactly how a test helper ends up live.
"""

from __future__ import annotations

import hashlib
from contextlib import ExitStack, contextmanager
from typing import Callable, Iterator, Optional
from unittest import mock

import pytest

__all__ = [
    "STUB_ISSUER_FPR",
    "capauth_signing_stub",
    "install_signing_stub",
    "signing_stub",
    "stub_signature_for",
    "stub_token_signing",
]

#: The issuer fingerprint the stub pretends this node's identity key carries.
STUB_ISSUER_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

_STUB_SIG_HEAD = "-----BEGIN PGP SIGNATURE-----"
_STUB_SIG_TAIL = "-----END PGP SIGNATURE-----"


def stub_signature_for(payload_bytes: bytes) -> str:
    """A deterministic stand-in signature bound to the exact bytes signed.

    Bound to the bytes on purpose: this is what makes a tampered payload, or a
    signature copied off a different token, still fail while the stub is active.

    Args:
        payload_bytes: The canonical payload bytes being signed.

    Returns:
        str: An armored-looking stand-in signature over those exact bytes.
    """
    digest = hashlib.sha256(payload_bytes).hexdigest()
    return f"{_STUB_SIG_HEAD}\ncapauth-test-stub:{digest}\n{_STUB_SIG_TAIL}\n"


def _stub_verify_manifest(
    manifest_bytes: bytes,
    signature: str,
    *,
    expected_signer: Optional[str] = None,
) -> bool:
    """Accept exactly the stand-in signature, for exactly these bytes, from that issuer.

    Stands in for :func:`capauth.manifest.verify_manifest` as imported into
    :mod:`capauth.tokens`. Deliberately narrow: it is the only place the stub
    could be widened into a hole, so it grants nothing beyond the one signature
    :func:`stub_signature_for` would have produced for this exact input.
    """
    if not signature:
        return False
    if expected_signer and expected_signer.strip().upper() != STUB_ISSUER_FPR:
        return False
    return signature == stub_signature_for(bytes(manifest_bytes))


def _stub_seams() -> tuple[object, dict[str, Callable]]:
    """The three ``capauth.tokens`` attributes the stub replaces, and their stand-ins.

    Resolved lazily so importing this module has no import-time side effect on
    :mod:`capauth.tokens` beyond loading it.
    """
    from capauth import tokens

    return tokens, {
        "_get_issuer_fingerprint": lambda home: STUB_ISSUER_FPR,
        "_pgp_sign_payload": lambda payload, home: stub_signature_for(
            payload.model_dump_json().encode()
        ),
        "verify_manifest": _stub_verify_manifest,
    }


def install_signing_stub(monkeypatch: pytest.MonkeyPatch) -> Callable[[bytes], str]:
    """Apply the signing stub for the lifetime of ``monkeypatch``.

    The building block behind both shipped fixtures. Use it directly when a test
    needs the stub applied at a point of its own choosing (e.g. after asserting
    the un-stubbed behaviour first).

    Args:
        monkeypatch: A pytest ``monkeypatch`` fixture. Its teardown is what
            reverts the seams, so the stub cannot outlive the test that asked
            for it.

    Returns:
        Callable[[bytes], str]: :func:`stub_signature_for`, so a caller can
        construct the signature the stub will accept for given bytes (and, more
        usefully, one it will NOT accept).
    """
    tokens, seams = _stub_seams()
    for name, stand_in in seams.items():
        monkeypatch.setattr(tokens, name, stand_in)
    return stub_signature_for


@contextmanager
def signing_stub() -> Iterator[Callable[[bytes], str]]:
    """Apply the signing stub for the duration of the ``with`` block.

    The pytest-free form of :func:`install_signing_stub`, for code that is not
    inside a test function. The seams are restored on exit, including on an
    exception, so the stub is scoped to the block and nothing else.

    Yields:
        Callable[[bytes], str]: :func:`stub_signature_for`.
    """
    tokens, seams = _stub_seams()
    with ExitStack() as stack:
        for name, stand_in in seams.items():
            stack.enter_context(mock.patch.object(tokens, name, stand_in))
        yield stub_signature_for


@pytest.fixture
def stub_token_signing(monkeypatch: pytest.MonkeyPatch) -> Callable[[bytes], str]:
    """Sign and verify capability tokens without gpg, for tests that request it.

    Opt-in per test, per class, or per module (via
    ``pytest.mark.usefixtures("stub_token_signing")``). Import it into a
    ``conftest.py`` to make it available to that directory::

        from capauth.testing import stub_token_signing  # noqa: F401

    Use :data:`capauth_signing_stub` instead to turn it on for a whole suite.
    """
    return install_signing_stub(monkeypatch)


@pytest.fixture(autouse=True)
def capauth_signing_stub(monkeypatch: pytest.MonkeyPatch) -> Callable[[bytes], str]:
    """Directory-wide autouse form of :data:`stub_token_signing`.

    Autouse takes effect only where this name is imported, so a consuming repo
    turns it on for its whole suite with one line in ``tests/conftest.py``::

        from capauth.testing import capauth_signing_stub  # noqa: F401

    That is the intended shape for a repo whose tests mint CapAuth tokens
    throughout and are not themselves about OpenPGP.

    .. warning::

       Check before reaching for this. A repo with even one test that asserts
       real signing behaviour must import :data:`stub_token_signing` instead and
       request it per module, so the stub is never active where the real gpg
       path is what is under test.

       Over-applying this fixture fails silently: the affected tests keep
       passing while quietly exercising the stub instead of gpg. Contrast the
       problem it solves, which fails loudly with visible errors. Green is not
       evidence here, so grep for real-gpg tests under the target directory
       first. skchat's adoption caught exactly this in review; see the module
       docstring.
    """
    return install_signing_stub(monkeypatch)
