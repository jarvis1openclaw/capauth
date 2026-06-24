"""Sequoia (`sq`) crypto backend — post-quantum OpenPGP signing identities.

This backend issues and operates on **post-quantum OpenPGP keys** by shelling
out to the `sq` CLI (sequoia-sq 1.4.0-pqc, built against the crypto-openssl
backend with OpenSSL 3.6+). It is the *only* `CryptoBackend` that can host a PQC
**signing** root: GnuPG's post-quantum support is encryption-only (ML-KEM), and
PGPy has no PQC at all.

Algorithm mapping (capauth ``Algorithm`` → `sq` ``--cipher-suite``):

============================  ==================  ====================
Algorithm                     sq cipher-suite     primary signing key
============================  ==================  ====================
HYBRID_ED448_MLDSA87          mldsa87-ed448       ML-DSA-87 + Ed448  (FIPS 204, L5)
HYBRID_ED25519_MLDSA65        mldsa65-ed25519     ML-DSA-65 + Ed25519 (FIPS 204, L3)
ED25519                       cv25519             Ed25519 (classical)
RSA4096                       rsa4k               RSA-4096 (classical)
============================  ==================  ====================

PQC keys are issued under ``--profile rfc9580`` (OpenPGP v6), which is the
profile that carries the composite PQC algorithms. The ML-DSA signing primary is
a *composite* (lattice ML-DSA + classical EdDSA): it is unforgeable while either
leg holds. The encryption subkey `sq` adds is ML-KEM-1024 + X448 (FIPS 203, L5).

The `sq` binary is discovered via ``CAPAUTH_SQ_BIN``, then ``~/.cargo/bin/sq``,
then ``$PATH``. The built binary embeds an rpath to its OpenSSL, so no
``LD_LIBRARY_PATH`` is required; we still export the brew OpenSSL lib dir
defensively when present.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import Algorithm
from .base import CryptoBackend, KeyBundle

#: capauth Algorithm → sq --cipher-suite name.
_CIPHER_SUITES: dict[Algorithm, str] = {
    Algorithm.HYBRID_ED448_MLDSA87: "mldsa87-ed448",
    Algorithm.HYBRID_ED25519_MLDSA65: "mldsa65-ed25519",
    Algorithm.ED25519: "cv25519",
    Algorithm.RSA4096: "rsa4k",
}

#: A brew OpenSSL lib dir to expose defensively (the binary also has an rpath).
_OPENSSL_LIB = "/home/linuxbrew/.linuxbrew/opt/openssl@3/lib"

_FPR_RE = re.compile(r"Fingerprint:\s*([0-9A-Fa-f]{40,64})")
_ALGO_RE = re.compile(r"Public-key algo:\s*(.+)")


class SequoiaError(Exception):
    """A `sq` invocation failed."""


class SequoiaBackend(CryptoBackend):
    """``CryptoBackend`` backed by the Sequoia ``sq`` CLI (PQC-capable)."""

    def __init__(self, sq_bin: str | None = None) -> None:
        self._sq = sq_bin or self._discover_sq()

    # ------------------------------------------------------------------
    # discovery / availability
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_sq() -> str | None:
        env = os.environ.get("CAPAUTH_SQ_BIN")
        if env and Path(env).is_file():
            return env
        cargo = Path.home() / ".cargo" / "bin" / "sq"
        if cargo.is_file():
            return str(cargo)
        return shutil.which("sq")

    def available(self) -> bool:
        """True iff a runnable `sq` binary was found."""
        if not self._sq:
            return False
        try:
            self._run(["version"])
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # subprocess helper
    # ------------------------------------------------------------------

    def _run(self, args: list[str], *, input_bytes: bytes | None = None) -> str:
        env = dict(os.environ)
        if Path(_OPENSSL_LIB).is_dir():
            env["LD_LIBRARY_PATH"] = _OPENSSL_LIB + ":" + env.get("LD_LIBRARY_PATH", "")
        proc = subprocess.run(
            [self._sq, *args],
            input=input_bytes,
            capture_output=True,
            env=env,
        )
        if proc.returncode != 0:
            raise SequoiaError(
                f"sq {' '.join(args)} failed (exit {proc.returncode}): "
                f"{proc.stderr.decode('utf-8', 'replace')[:500]}"
            )
        return proc.stdout.decode("utf-8", "replace")

    # ------------------------------------------------------------------
    # CryptoBackend API
    # ------------------------------------------------------------------

    def generate_keypair(
        self,
        name: str,
        email: str,
        passphrase: str,
        algorithm: Algorithm = Algorithm.HYBRID_ED448_MLDSA87,
    ) -> KeyBundle:
        """Generate an OpenPGP keypair (PQC by default) via `sq key generate`."""
        cipher = _CIPHER_SUITES.get(algorithm)
        if cipher is None:
            raise SequoiaError(f"SequoiaBackend cannot generate algorithm {algorithm}")

        with tempfile.TemporaryDirectory(prefix="capauth-sq-") as td:
            keyf = Path(td) / "key.pgp"
            revf = Path(td) / "key.rev"
            args = [
                "key",
                "generate",
                "--own-key",
                "--name",
                name,
                "--email",
                email,
                "--cipher-suite",
                cipher,
                "--profile",
                "rfc9580",
                "--output",
                str(keyf),
                "--rev-cert",
                str(revf),
            ]
            if passphrase:
                pwf = Path(td) / "pw"
                pwf.write_text(passphrase)
                args += ["--new-password-file", str(pwf)]
            else:
                args.append("--without-password")
            self._run(args)

            private_armor = keyf.read_text()
            certf = Path(td) / "cert.pgp"
            self._run(["key", "delete", "--cert-file", str(keyf), "--output", str(certf)])
            public_armor = certf.read_text()
            fingerprint = self._fingerprint_of_file(keyf)

        return KeyBundle(
            fingerprint=fingerprint,
            public_armor=public_armor,
            private_armor=private_armor,
            algorithm=algorithm,
        )

    def sign(self, data: bytes, private_key_armor: str, passphrase: str) -> str:
        """Create an armored detached signature over ``data`` (PQC composite)."""
        with tempfile.TemporaryDirectory(prefix="capauth-sq-") as td:
            keyf = Path(td) / "key.pgp"
            keyf.write_text(private_key_armor)
            dataf = Path(td) / "data"
            dataf.write_bytes(data)
            sigf = Path(td) / "data.sig"
            args = [
                "sign",
                "--signer-file",
                str(keyf),
                "--signature-file",
                str(sigf),
                str(dataf),
            ]
            if passphrase:
                # `sq sign` has no password-file flag; a protected signer key
                # needs the keystore path (handled in a later cycle).
                raise NotImplementedError(
                    "signing with a passphrase-protected key is not yet supported"
                )
            self._run(args)
            return sigf.read_text()

    def verify(self, data: bytes, signature_armor: str, public_key_armor: str) -> bool:
        """Verify an armored detached signature. False on any verification failure."""
        with tempfile.TemporaryDirectory(prefix="capauth-sq-") as td:
            certf = Path(td) / "cert.pgp"
            certf.write_text(public_key_armor)
            dataf = Path(td) / "data"
            dataf.write_bytes(data)
            sigf = Path(td) / "data.sig"
            sigf.write_text(signature_armor)
            try:
                self._run(
                    [
                        "verify",
                        "--signer-file",
                        str(certf),
                        "--signature-file",
                        str(sigf),
                        str(dataf),
                    ]
                )
                return True
            except SequoiaError:
                return False

    def fingerprint_from_armor(self, key_armor: str) -> str:
        """Extract the primary key fingerprint from armored key material."""
        with tempfile.NamedTemporaryFile("w", suffix=".pgp", delete=True) as f:
            f.write(key_armor)
            f.flush()
            return self._fingerprint_of_file(Path(f.name))

    # ------------------------------------------------------------------
    # inspection helpers
    # ------------------------------------------------------------------

    def _fingerprint_of_file(self, path: Path) -> str:
        out = self._run(["inspect", str(path)])
        m = _FPR_RE.search(out)
        if not m:
            raise SequoiaError("could not parse fingerprint from sq inspect")
        return m.group(1).upper()

    def _primary_algo(self, key_armor: str) -> str:
        """Return the primary key's public-key algorithm (e.g. 'ML-DSA-87+Ed448')."""
        with tempfile.NamedTemporaryFile("w", suffix=".pgp", delete=True) as f:
            f.write(key_armor)
            f.flush()
            out = self._run(["inspect", f.name])
        m = _ALGO_RE.search(out)
        if not m:
            raise SequoiaError("could not parse public-key algo from sq inspect")
        return m.group(1).strip()
