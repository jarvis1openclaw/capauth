#!/usr/bin/env python3
"""CapAuth native-messaging signer host.

Bridges the CapAuth browser extension to the OS `gpg` / gpg-agent so the
private key NEVER enters the browser. Supports smartcard / YubiKey because all
signing is done by gpg-agent.

Protocol (Chrome Native Messaging — stdio, little-endian uint32 length prefix +
UTF-8 JSON body):

    -> {"op": "get_fingerprint"}                 <- {"fingerprint": "<40 or 64 hex>"}
    -> {"op": "sign", "payload": "<bytes>",      <- {"signature": "<armored>"}
        "fingerprint": "<optional 40 or 64 hex>"}
    (any error)                                   <- {"error": "<message>"}

Signing command:

    gpg --batch --yes --armor --detach-sign \
        --pinentry-mode loopback \
        --local-user <fingerprint> -

The canonical payload bytes are written to gpg's stdin VERBATIM (no added
newline) so the produced detached signature verifies against the exact same
CAPAUTH_NONCE_V2 string the server rebuilds.

Security notes:
  * The private key never leaves gpg-agent; this host only shuttles bytes.
  * Inputs are validated; the armored signature is the ONLY key-derived value
    ever returned. The key material itself is never read, logged, or echoed.
  * `allowed_origins` in the manifest restricts which extension may connect.

macOS / Windows: see install.sh for manifest locations. The host script itself
is OS-agnostic as long as `gpg` is on PATH (set CAPAUTH_GPG_BIN to override).
"""

import json
import os
import re
import struct
import subprocess
import sys

GPG_BIN = os.environ.get("CAPAUTH_GPG_BIN", "gpg")
FINGERPRINT_RE = re.compile(r"^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
MAX_PAYLOAD_BYTES = 64 * 1024  # canonical payloads are tiny; cap defensively.


# --------------------------------------------------------------------------- #
# Native-messaging framing
# --------------------------------------------------------------------------- #
def read_message():
    """Read one length-prefixed JSON message from stdin. None on EOF."""
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) < 4:
        return None
    (msg_len,) = struct.unpack("<I", raw_len)
    if msg_len <= 0 or msg_len > (MAX_PAYLOAD_BYTES + 4096):
        raise ValueError("message length out of bounds")
    data = sys.stdin.buffer.read(msg_len)
    if len(data) < msg_len:
        return None
    return json.loads(data.decode("utf-8"))


def write_message(obj):
    """Write one length-prefixed JSON message to stdout."""
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


# --------------------------------------------------------------------------- #
# gpg operations
# --------------------------------------------------------------------------- #
def gpg_default_fingerprint():
    """Return the fingerprint of the first available secret key, or ''."""
    try:
        out = subprocess.run(
            [GPG_BIN, "--batch", "--with-colons", "--list-secret-keys"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        # `fpr` record: fpr:::::::::<FINGERPRINT>:
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) >= 10 and FINGERPRINT_RE.match(parts[9]):
                return parts[9].upper()
    return ""


def gpg_sign(payload: str, fingerprint: str) -> str:
    """Detach-sign `payload` with the given key; return the armored signature."""
    cmd = [
        GPG_BIN,
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--pinentry-mode",
        "loopback",
    ]
    if fingerprint:
        cmd += ["--local-user", fingerprint]
    cmd += ["-"]

    proc = subprocess.run(
        cmd,
        input=payload.encode("utf-8"),
        capture_output=True,
        timeout=120,  # allow time for a smartcard PIN / touch
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(err or "gpg signing failed")
    sig = proc.stdout.decode("utf-8", "replace")
    if "BEGIN PGP SIGNATURE" not in sig:
        raise RuntimeError("gpg produced no armored signature")
    return sig


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
def handle(msg: dict) -> dict:
    if not isinstance(msg, dict):
        return {"error": "malformed request"}

    op = msg.get("op")

    if op == "get_fingerprint":
        fp = gpg_default_fingerprint()
        if not fp:
            return {"error": "no secret key available in gpg"}
        return {"fingerprint": fp}

    if op == "sign":
        payload = msg.get("payload")
        if not isinstance(payload, str) or not payload:
            return {"error": "missing or invalid payload"}
        if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return {"error": "payload too large"}

        fingerprint = msg.get("fingerprint", "") or ""
        if fingerprint and not FINGERPRINT_RE.match(fingerprint):
            return {"error": "invalid fingerprint"}

        try:
            signature = gpg_sign(payload, fingerprint.upper() if fingerprint else "")
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)}
        return {"signature": signature}

    return {"error": f"unknown op: {op!r}"}


def main():
    while True:
        try:
            msg = read_message()
        except (ValueError, json.JSONDecodeError) as exc:
            write_message({"error": f"bad message: {exc}"})
            continue
        if msg is None:
            break  # stdin closed → browser disconnected
        try:
            write_message(handle(msg))
        except Exception as exc:  # noqa: BLE001 — never let the host die mid-stream
            write_message({"error": f"host exception: {exc}"})


if __name__ == "__main__":
    main()
