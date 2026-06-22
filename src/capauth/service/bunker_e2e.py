"""CapAuth Bunker — relay E2E-encryption (``capauth-bunker-e2e-v1``).

The bunker broker relays opaque messages between a desktop ``client`` and a
phone ``signer``. Without this layer the relayed ``sign_request`` payload and
the returned ``signature`` are readable by the broker process (and anything
with access to its memory, logs, or a third-party relay such as a Funnel/CDN).

This module adds an **end-to-end channel the broker cannot read**:

1. Each peer generates an *ephemeral* X25519 keypair and sends its public key
   over the relay (a ``kex`` message). The broker forwards the public keys but
   cannot compute the shared secret (X25519 hardness).
2. ``shared = X25519(my_priv, peer_pub)``.
3. ``key = HKDF-SHA256(ikm=shared, salt=pairing_secret, info=b"capauth-bunker-e2e-v1", 32)``.
   The pairing secret is mixed in as the salt to bind the key to this pairing.
4. Sensitive messages are sealed with **AES-256-GCM**; the wire ciphertext is
   ``base64(nonce[12] || ciphertext || tag)`` and travels inside an ``enc``
   envelope. The broker only ever sees ``kex`` and ``enc``.

This is the Python counterpart of ``phone-signer/lib/bunker-e2e.js`` /
``browser-extension/lib/bunker-e2e.js``; a shared cross-impl vector
(``tests/fixtures/bunker_e2e_v1_vector.json``) pins the KDF + AEAD bytes across
implementations. It is used by the test/integration harness (which simulates a
client and a signer in Python) — the live broker itself stays a dumb relay.

Threat model (be honest):
  * Defeats a PASSIVE / honest-but-curious broker, and protects the relayed
    payload + signature from broker memory/log leakage and from an untrusted
    intermediary relay. This is the realistic threat for a self-hosted broker.
  * Does NOT defeat an ACTIVE man-in-the-middle by the broker itself: the broker
    knows the pairing secret (it issued it) and relays the ``kex`` public keys,
    so it could substitute its own keys. Closing that requires a secret the
    broker never sees (e.g. a client-generated key fragment carried only in the
    QR). Noted as a follow-up. (And since the same origin serves the PWA, an
    actively-malicious broker is already game-over — so relay-layer MITM
    resistance has limited marginal value while it ships the client code.)
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

E2E_SCHEME = "capauth-bunker-e2e-v1"
_NONCE_LEN = 12  # AES-GCM standard nonce length
_KEY_LEN = 32  # AES-256


def _info(frag: str = "") -> bytes:
    """HKDF info. A non-empty ``frag`` (the QR-only key fragment, active-MITM
    hardening — never seen by the broker) is mixed in so the broker cannot derive
    the channel key even by substituting the relayed kex public keys."""
    base = E2E_SCHEME
    return (base if not frag else f"{base}\nfrag={frag}").encode("utf-8")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def generate_keypair() -> tuple[X25519PrivateKey, str]:
    """Generate an ephemeral X25519 keypair.

    Returns:
        ``(private_key, public_key_b64)`` — the base64 of the raw 32-byte public
        key is what goes on the wire in the ``kex`` message.
    """
    priv = X25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    return priv, _b64e(pub_raw)


def derive_key_from_shared(shared: bytes, pairing_secret: str, frag: str = "") -> bytes:
    """HKDF-SHA256 the raw ECDH shared secret into a 32-byte AES key.

    Split out so the cross-impl vector can pin the KDF+AEAD layer with a known
    shared secret (independent of the X25519 step). ``frag`` is the optional
    QR-only key fragment (active-MITM hardening).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=pairing_secret.encode("utf-8"),
        info=_info(frag),
    ).derive(shared)


def derive_key(
    my_priv: X25519PrivateKey, peer_pub_b64: str, pairing_secret: str, frag: str = ""
) -> bytes:
    """Compute the shared AES key from our private key + the peer's public key."""
    peer_pub = X25519PublicKey.from_public_bytes(_b64d(peer_pub_b64))
    shared = my_priv.exchange(peer_pub)
    return derive_key_from_shared(shared, pairing_secret, frag)


def seal(key: bytes, obj: Any, *, nonce: Optional[bytes] = None) -> str:
    """AES-256-GCM seal a JSON-serialisable object → wire ciphertext (base64).

    Wire = base64(nonce[12] || ciphertext || tag). ``nonce`` is injectable for
    the deterministic vector test; production callers MUST let it default to a
    fresh random nonce.
    """
    if nonce is None:
        nonce = os.urandom(_NONCE_LEN)
    pt = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, pt, None)
    return _b64e(nonce + ct)


def open_msg(key: bytes, wire_b64: str) -> Any:
    """Inverse of :func:`seal` — returns the decrypted JSON object."""
    blob = _b64d(wire_b64)
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))


class E2ESession:
    """Stateful helper mirroring the JS ``E2ESession``.

    Lifecycle: :meth:`start` (→ send the returned kex), :meth:`on_kex` when the
    peer's kex arrives (derives the key), then :meth:`seal_msg` / :meth:`open`.
    """

    def __init__(self, pairing_secret: str, frag: str = "") -> None:
        self._pairing_secret = pairing_secret
        self._frag = frag or ""
        self._priv: Optional[X25519PrivateKey] = None
        self._key: Optional[bytes] = None

    def start(self) -> dict[str, str]:
        """Generate our ephemeral keypair; return the ``kex`` message to send."""
        self._priv, pub_b64 = generate_keypair()
        return {"type": "kex", "pub": pub_b64}

    def on_kex(self, peer_pub_b64: str) -> None:
        """Derive the shared AES key from the peer's kex public key."""
        if self._priv is None:
            raise RuntimeError("E2ESession.start() must be called before on_kex()")
        self._key = derive_key(self._priv, peer_pub_b64, self._pairing_secret, self._frag)

    @property
    def is_secure(self) -> bool:
        return self._key is not None

    def seal_msg(self, obj: Any) -> dict[str, str]:
        """Wrap ``obj`` in an ``enc`` envelope (id mirrored in cleartext)."""
        if self._key is None:
            raise RuntimeError("channel not secured (no peer kex yet)")
        env: dict[str, str] = {"type": "enc", "ct": seal(self._key, obj)}
        if isinstance(obj, dict) and "id" in obj:
            env["id"] = obj["id"]
        return env

    def open(self, enc_msg: dict) -> Any:
        """Decrypt an ``enc`` envelope → the inner message object."""
        if self._key is None:
            raise RuntimeError("channel not secured (no peer kex yet)")
        return open_msg(self._key, enc_msg["ct"])
