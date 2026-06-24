#!/usr/bin/env python3
"""PQC root-rotation ceremony DRY-RUN harness.

Validates — against THROWAWAY keys in an isolated tempdir — the exact ``sq``
operations the ceremony runbook (``capauth/docs/ROOT_ROTATION_CEREMONY.md``)
depends on:

  1. Generate an OLD classical v6 root (cv25519 / rfc9580) → 64-hex fpr.
  2. Generate a NEW PQC root (mldsa87-ed448 / rfc9580) → ML-DSA-87+Ed448
     primary + ML-KEM-1024+X448 encryption subkey.
  3. CROSS-SIGN for continuity (``sq pki vouch add``): OLD certifies NEW *and*
     NEW certifies OLD, then cryptographically authenticate each direction via
     ``sq pki authenticate`` with the certifier pinned as trust-root.
  4. Detached signature by the NEW PQC root verifies; the OLD root still
     verifies (continuity); a tampered payload is rejected.
  5. Additive path: add an ML-DSA-87+Ed448 signing subkey to the classical v6
     key (``sq key subkey add``) and confirm the primary fingerprint is
     UNCHANGED, and the additive key can still sign/verify.

SAFETY: touches NO real key. Everything happens in a fresh ``tempfile.mkdtemp``
(override with ``--workdir``). An isolated ``SEQUOIA_HOME`` is created inside the
workdir so the real ``~/.local/share/sequoia`` cert/key store is never used.

Run:   python scripts/pqc_ceremony_dryrun.py
Import: from pqc_ceremony_dryrun import run_ceremony

Exits non-zero if ANY step fails.

Verified against: sq 1.4.0-pqc.1 (sequoia-openpgp 2.2.0-pqc.1).
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SQ = os.path.expanduser("~/.cargo/bin/sq")
FPR_RE = re.compile(r"Fingerprint:\s*([0-9A-Fa-f]{40,64})")
ALGO_RE = re.compile(r"Public-key algo:\s*(.+)")


@dataclass
class StepResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Ceremony:
    sq: str
    workdir: Path
    sq_home: Path = field(init=False)
    results: list[StepResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sq_home = self.workdir / "sqhome"
        self.sq_home.mkdir(parents=True, exist_ok=True)

    # -- subprocess helpers -------------------------------------------------
    def _run(self, args: list[str], *, check: bool = True,
             isolated: bool = False) -> subprocess.CompletedProcess:
        """Run sq. ``isolated=True`` adds the scratch SEQUOIA_HOME (only the
        WoT/cert-store commands need it; keygen/sign/verify are file-based)."""
        cmd = [self.sq]
        if isolated:
            cmd += ["--home", str(self.sq_home)]
        cmd += args
        return subprocess.run(
            cmd, cwd=self.workdir, check=check,
            capture_output=True, text=True,
        )

    def _path(self, name: str) -> str:
        return str(self.workdir / name)

    @staticmethod
    def _primary_fpr(inspect_out: str) -> str | None:
        m = FPR_RE.search(inspect_out)
        return m.group(1).upper() if m else None

    @staticmethod
    def _primary_algo(inspect_out: str) -> str | None:
        m = ALGO_RE.search(inspect_out)
        return m.group(1).strip() if m else None

    def _record(self, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append(StepResult(name, passed, detail))
        return passed

    # -- steps --------------------------------------------------------------
    def step1_old_classical(self) -> str | None:
        """OLD classical v6 root. Returns primary fpr (64-hex) or None."""
        try:
            self._run([
                "key", "generate", "--own-key", "--email", "old@test.invalid",
                "--cipher-suite", "cv25519", "--profile", "rfc9580",
                "--without-password",
                "--output", self._path("old.pgp"),
                "--rev-cert", self._path("old.rev"),
            ])
            ins = self._run(["inspect", self._path("old.pgp")]).stdout
        except subprocess.CalledProcessError as e:
            self._record("1. OLD classical v6 root", False, e.stderr.strip())
            return None
        fpr = self._primary_fpr(ins)
        algo = self._primary_algo(ins)
        ok = bool(fpr) and len(fpr) == 64 and algo == "Ed25519"
        self._record(
            "1. OLD classical v6 root", ok,
            f"primary={algo} fpr={fpr} ({len(fpr) if fpr else 0}-hex)",
        )
        return fpr if ok else None

    def step2_new_pqc(self) -> str | None:
        """NEW PQC root. Returns primary fpr or None."""
        try:
            self._run([
                "key", "generate", "--own-key", "--email", "new@test.invalid",
                "--cipher-suite", "mldsa87-ed448", "--profile", "rfc9580",
                "--without-password",
                "--output", self._path("new.pgp"),
                "--rev-cert", self._path("new.rev"),
            ])
            ins = self._run(["inspect", self._path("new.pgp")]).stdout
        except subprocess.CalledProcessError as e:
            self._record("2. NEW PQC root", False, e.stderr.strip())
            return None
        fpr = self._primary_fpr(ins)
        algo = self._primary_algo(ins)
        has_mlkem = "ML-KEM-1024+X448" in ins
        ok = (bool(fpr) and len(fpr) == 64
              and algo == "ML-DSA-87+Ed448" and has_mlkem)
        self._record(
            "2. NEW PQC root", ok,
            f"primary={algo} fpr={fpr} mlkem_enc_subkey={has_mlkem}",
        )
        return fpr if ok else None

    def _derive_cert(self, key_file: str, cert_file: str) -> None:
        self._run([
            "key", "delete", "--cert-file", self._path(key_file),
            "--output", self._path(cert_file),
        ])

    def _vouch(self, certifier_key: str, cert_file: str, email: str,
               output: str) -> None:
        self._run([
            "pki", "vouch", "add",
            "--certifier-file", self._path(certifier_key),
            "--cert-file", self._path(cert_file),
            "--email", email,
            "--output", self._path(output),
        ])

    def _authenticate(self, certifier_cert: str, certified_obj: str,
                      trust_root_fpr: str, target_fpr: str,
                      email: str) -> bool:
        """Cryptographically verify a certification via the WoT engine."""
        out = self._run([
            "--keyring", self._path(certifier_cert),
            "--keyring", self._path(certified_obj),
            "--trust-root", trust_root_fpr,
            "pki", "authenticate", "--cert", target_fpr, "--email", email,
        ], check=False, isolated=True)
        # A fully-authenticated binding prints the green check mark.
        return out.returncode == 0 and "[    ✓    ]" in out.stdout

    def step3_cross_sign(self, old_fpr: str, new_fpr: str) -> bool:
        """OLD certifies NEW and NEW certifies OLD; verify both directions."""
        try:
            self._derive_cert("old.pgp", "old.cert")
            self._derive_cert("new.pgp", "new.cert")
            # OLD certifies NEW (load-bearing continuity link)
            self._vouch("old.pgp", "new.cert", "new@test.invalid",
                        "new.cert.by-old")
            # NEW (PQC) certifies OLD
            self._vouch("new.pgp", "old.cert", "old@test.invalid",
                        "old.cert.by-new")
        except subprocess.CalledProcessError as e:
            return self._record("3. Cross-sign old<->new", False,
                                 e.stderr.strip())

        old_certifies_new = self._authenticate(
            "old.cert", "new.cert.by-old", old_fpr, new_fpr, "new@test.invalid")
        new_certifies_old = self._authenticate(
            "new.cert", "old.cert.by-new", new_fpr, old_fpr, "old@test.invalid")
        ok = old_certifies_new and new_certifies_old
        return self._record(
            "3. Cross-sign old<->new", ok,
            f"old->new authenticated={old_certifies_new} "
            f"new->old authenticated={new_certifies_old}",
        )

    def _sign_verify(self, key_file: str, cert_file: str, label: str,
                     payload: str = "continuity payload\n") -> bool:
        data = self._path(f"{label}.txt")
        Path(data).write_text(payload)
        sig = self._path(f"{label}.sig")
        try:
            self._run(["sign", "--signer-file", self._path(key_file),
                       "--signature-file", sig, data])
            self._run(["verify", "--signer-file", self._path(cert_file),
                       "--signature-file", sig, data])
        except subprocess.CalledProcessError:
            return False
        return True

    def step4_sign_verify_continuity(self) -> bool:
        new_ok = self._sign_verify("new.pgp", "new.cert", "msg_new")
        old_ok = self._sign_verify("old.pgp", "old.cert", "msg_old")
        # tamper check: NEW's signature must reject a mutated payload
        tampered = self._path("msg_new.txt")
        Path(tampered).write_text("continuity payload TAMPERED\n")
        tamper = self._run(
            ["verify", "--signer-file", self._path("new.cert"),
             "--signature-file", self._path("msg_new.sig"), tampered],
            check=False)
        tamper_rejected = tamper.returncode != 0
        ok = new_ok and old_ok and tamper_rejected
        return self._record(
            "4. Sign/verify + continuity + tamper", ok,
            f"new_verifies={new_ok} old_verifies={old_ok} "
            f"tamper_rejected={tamper_rejected}",
        )

    def step5_additive_subkey(self, old_fpr: str) -> bool:
        """Add ML-DSA-87+Ed448 signing subkey to classical v6 key; primary
        fingerprint must be unchanged; additive key must still sign."""
        try:
            self._run([
                "key", "subkey", "add", "--cert-file", self._path("old.pgp"),
                "--can-sign", "--cipher-suite", "mldsa87-ed448",
                "--without-password",
                "--output", self._path("old.pqc-added.pgp"),
            ])
            ins = self._run(["inspect", self._path("old.pqc-added.pgp")]).stdout
        except subprocess.CalledProcessError as e:
            return self._record("5. Additive PQC subkey (classical v6)", False,
                                 e.stderr.strip())
        primary_after = self._primary_fpr(ins)
        unchanged = primary_after == old_fpr
        has_pqc_subkey = "ML-DSA-87+Ed448" in ins
        # additive key still signs/verifies
        self._derive_cert("old.pqc-added.pgp", "old.pqc-added.cert")
        sign_ok = self._sign_verify("old.pqc-added.pgp", "old.pqc-added.cert",
                                    "additive")
        ok = unchanged and has_pqc_subkey and sign_ok
        return self._record(
            "5. Additive PQC subkey (classical v6)", ok,
            f"primary_unchanged={unchanged} pqc_subkey_added={has_pqc_subkey} "
            f"sign_verify={sign_ok}",
        )

    # -- driver -------------------------------------------------------------
    def run(self) -> bool:
        old_fpr = self.step1_old_classical()
        new_fpr = self.step2_new_pqc()
        if old_fpr and new_fpr:
            self.step3_cross_sign(old_fpr, new_fpr)
        else:
            self._record("3. Cross-sign old<->new", False,
                         "skipped: step 1 or 2 failed")
        self.step4_sign_verify_continuity()
        if old_fpr:
            self.step5_additive_subkey(old_fpr)
        else:
            self._record("5. Additive PQC subkey (classical v6)", False,
                         "skipped: step 1 failed")
        return all(r.passed for r in self.results)


def _check_sq(sq: str) -> str:
    """Return the version string, or raise SystemExit if sq is unusable."""
    if not Path(sq).exists():
        raise SystemExit(f"sq binary not found: {sq}")
    out = subprocess.run([sq, "version"], capture_output=True, text=True)
    ver = (out.stdout or out.stderr).strip().splitlines()[0] if (
        out.stdout or out.stderr) else ""
    if "pqc" not in ver:
        raise SystemExit(
            f"sq build is not PQC-enabled (got: {ver!r}). "
            "Expected sq 1.4.0-pqc.1.")
    return ver


def run_ceremony(workdir: str | None = None, sq: str = DEFAULT_SQ) -> bool:
    """Importable entrypoint. Returns True iff every step passes."""
    ver = _check_sq(sq)
    wd = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="pqc_dryrun."))
    wd.mkdir(parents=True, exist_ok=True)
    print(f"sq: {ver}")
    print(f"workdir (throwaway): {wd}")
    print("=" * 60)
    cer = Ceremony(sq=sq, workdir=wd)
    ok = cer.run()
    print("=" * 60)
    for r in cer.results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name}")
        if r.detail:
            print(f"        {r.detail}")
    print("=" * 60)
    print("RESULT:", "ALL PASS" if ok else "FAILURE")
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workdir", default=None,
                   help="scratch dir (default: fresh tempfile.mkdtemp). "
                        "NEVER point at a real key store.")
    p.add_argument("--sq", default=DEFAULT_SQ, help="path to sq binary")
    p.add_argument("--keep", action="store_true",
                   help="keep the workdir after running (default keeps it; "
                        "throwaway keys only)")
    args = p.parse_args(argv)
    ok = run_ceremony(workdir=args.workdir, sq=args.sq)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
