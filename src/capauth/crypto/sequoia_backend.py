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

Two additive capabilities beyond the core ABC:

* **Protected-key signing** — ``sign()`` unlocks a passphrase-protected signer
  non-interactively. ``sq sign`` has no ``--password`` flag, so we seed `sq`'s
  password cache via the *global* ``--password-file`` and pair it with
  ``--batch`` (fail-fast on a wrong/absent passphrase instead of prompting). No
  unprotected copy of the key is ever written.
* **Additive PQC subkeys** — ``add_pqc_subkeys()`` attaches an ML-DSA-87+Ed448
  signing subkey (FIPS 204) and an ML-KEM-1024+X448 encryption subkey
  (FIPS 203) to an existing classical key via ``sq key subkey add``, **without
  removing anything** (fully reversible). The classical primary fingerprint is
  preserved. Requires a v6/RFC 9580 input key (`sq` rejects PQC algorithms on v4
  keys). This is backend capability against the pre-RFC
  draft-ietf-openpgp-pqc-17 (code points 31 / 36); it migrates no live identity.
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
        """Create an armored detached signature over ``data`` (PQC composite).

        Protected-key signing: ``sq sign`` has no ``--password`` flag, but the
        *global* ``--password-file`` seeds `sq`'s password cache, and ``sq sign
        --signer-file`` draws on that cache to decrypt protected secret-key
        material non-interactively. We pair it with the global ``--batch`` flag
        so a wrong/absent passphrase fails fast (``SequoiaError``) instead of
        prompting. No unprotected copy of the key ever touches disk — the key
        file written to the isolated tmpdir stays passphrase-encrypted and is
        removed when the tmpdir is torn down.

        Args:
            data: Raw bytes to sign.
            private_key_armor: ASCII-armored private key (may be protected).
            passphrase: Passphrase that unlocks the key; empty string for an
                unprotected key.

        Returns:
            str: ASCII-armored detached signature.

        Raises:
            SequoiaError: If signing fails (e.g. wrong passphrase under --batch).
        """
        with tempfile.TemporaryDirectory(prefix="capauth-sq-") as td:
            keyf = Path(td) / "key.pgp"
            keyf.write_text(private_key_armor)
            dataf = Path(td) / "data"
            dataf.write_bytes(data)
            sigf = Path(td) / "data.sig"
            global_args: list[str] = []
            if passphrase:
                # Whole file = the password (sq treats it verbatim), so write
                # exactly the passphrase with no trailing newline.
                pwf = Path(td) / "pw"
                pwf.write_text(passphrase)
                global_args += ["--password-file", str(pwf), "--batch"]
            self._run(
                [
                    *global_args,
                    "sign",
                    "--signer-file",
                    str(keyf),
                    "--signature-file",
                    str(sigf),
                    str(dataf),
                ]
            )
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
    # additive PQC subkeys (PQC-MIGRATION #3 — reversible)
    # ------------------------------------------------------------------

    def add_pqc_subkeys(
        self,
        private_key_armor: str,
        passphrase: str,
        cipher_suite: str = "mldsa87-ed448",
    ) -> KeyBundle:
        """Attach post-quantum subkeys to an existing key, **additively**.

        Takes an existing OpenPGP key (typically classical, e.g. Ed25519/
        cv25519) and *adds* the strongest PQC subkeys `sq` supports without
        removing anything — the classical primary and all its existing subkeys
        stay intact, so the operation is fully reversible (drop the new subkeys
        to return to the original cert). Two subkeys are attached via
        ``sq key subkey add``:

        * an **ML-DSA-87 + Ed448** signing subkey (``--can-sign``,
          FIPS 204, NIST L5 — a composite, unforgeable while either leg holds);
        * an **ML-KEM-1024 + X448** encryption subkey (``--can-encrypt
          universal``, FIPS 203, NIST L5).

        Both are issued under the same cipher-suite (the encryption flag selects
        the ML-KEM half of the composite). The key MUST already be an OpenPGP v6
        / RFC 9580 key: `sq` refuses PQC algorithms on v4 keys ("can't use
        algorithms for v4 keys"). The new subkeys are protected with the same
        passphrase as the input key.

        Honesty: this is a *backend capability* on a draft standard
        (draft-ietf-openpgp-pqc-17, code points 31 / 36 — Standards Track, not
        yet an RFC). It does not migrate any live identity; the capauth root
        remains classical until the gated rotation ceremony.

        Args:
            private_key_armor: ASCII-armored private key to augment (v6/RFC9580).
            passphrase: Passphrase unlocking the primary and protecting the new
                subkeys; empty string for an unprotected key.
            cipher_suite: PQC composite suite for the subkeys
                (``mldsa87-ed448`` default = L5; ``mldsa65-ed25519`` = L3).

        Returns:
            KeyBundle: The augmented key. ``fingerprint`` is unchanged from the
            input (same primary), ``algorithm`` reflects the original primary's
            classical algorithm where known, else the input is preserved.

        Raises:
            SequoiaError: If `sq` rejects the operation (e.g. a v4 key, or the
                wrong passphrase under ``--batch``).
        """
        with tempfile.TemporaryDirectory(prefix="capauth-sq-") as td:
            in_key = Path(td) / "in.pgp"
            in_key.write_text(private_key_armor)
            orig_fpr = self._fingerprint_of_file(in_key)

            global_args: list[str] = []
            pwf = Path(td) / "pw"
            if passphrase:
                pwf.write_text(passphrase)
                global_args += ["--password-file", str(pwf), "--batch"]

            # Step 1: add the ML-DSA signing subkey.
            sign_key = Path(td) / "with_sign.pgp"
            sign_args = [
                *global_args,
                "key",
                "subkey",
                "add",
                "--cert-file",
                str(in_key),
                "--can-sign",
                "--cipher-suite",
                cipher_suite,
                "--output",
                str(sign_key),
            ]
            sign_args += (
                ["--new-password-file", str(pwf)] if passphrase else ["--without-password"]
            )
            self._run(sign_args)

            # Step 2: add the ML-KEM (universal) encryption subkey on top.
            both_key = Path(td) / "with_both.pgp"
            kem_args = [
                *global_args,
                "key",
                "subkey",
                "add",
                "--cert-file",
                str(sign_key),
                "--can-encrypt",
                "universal",
                "--cipher-suite",
                cipher_suite,
                "--output",
                str(both_key),
            ]
            kem_args += ["--new-password-file", str(pwf)] if passphrase else ["--without-password"]
            self._run(kem_args)

            private_armor = both_key.read_text()
            certf = Path(td) / "cert.pgp"
            self._run(["key", "delete", "--cert-file", str(both_key), "--output", str(certf)])
            public_armor = certf.read_text()
            new_fpr = self._fingerprint_of_file(both_key)

        # Additive invariant: the primary (hence its fingerprint) is unchanged.
        if new_fpr != orig_fpr:
            raise SequoiaError(
                "add_pqc_subkeys changed the primary fingerprint "
                f"({orig_fpr} -> {new_fpr}); refusing to return a non-additive key"
            )

        return KeyBundle(
            fingerprint=new_fpr,
            public_armor=public_armor,
            private_armor=private_armor,
            algorithm=self._algorithm_of_armor(private_key_armor),
        )

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

    def _subkey_algos(self, key_armor: str) -> list[str]:
        """Return every public-key algorithm in the cert (primary + subkeys).

        Order follows ``sq inspect`` output. Useful for asserting that PQC
        subkeys were attached while the classical components remain present.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".pgp", delete=True) as f:
            f.write(key_armor)
            f.flush()
            out = self._run(["inspect", f.name])
        return [m.group(1).strip() for m in _ALGO_RE.finditer(out)]

    def _algorithm_of_armor(self, key_armor: str) -> Algorithm:
        """Best-effort map the primary's `sq` algo string to a capauth Algorithm.

        Falls back to ``Algorithm.ED25519`` for an unrecognized classical
        primary (the augmented bundle's PQC capability lives in the subkeys, so
        the primary's enum is informational only).
        """
        algo = self._primary_algo(key_armor)
        if "ML-DSA-87" in algo:
            return Algorithm.HYBRID_ED448_MLDSA87
        if "ML-DSA-65" in algo:
            return Algorithm.HYBRID_ED25519_MLDSA65
        if "RSA" in algo:
            return Algorithm.RSA4096
        return Algorithm.ED25519
