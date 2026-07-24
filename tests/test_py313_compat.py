"""Python 3.13 forward-compatibility regression tests.

Two concrete 3.13 hazards fixed by card 4cbda842:

1. ``capauth.crypto`` used to eagerly import PGPy at package-import time. PGPy
   imports the ``imghdr`` stdlib module, which was **removed in Python 3.13**,
   so ``import capauth.crypto`` (and the sk_pgp migration path with it) blew up
   on 3.13. The import is now lazy: importing the package must NOT pull PGPy.

2. ``forgejo.cli._run`` used ``asyncio.get_event_loop().run_until_complete``,
   which raises a ``DeprecationWarning`` ("There is no current event loop") when
   no loop is running (deprecated since 3.12, hard error on the 3.14 track). It
   now uses ``asyncio.run``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import warnings


def test_importing_capauth_crypto_does_not_import_pgpy():
    """Regression: ``import capauth.crypto`` must not eagerly import pgpy.

    Run in a fresh interpreter so the assertion is not polluted by other tests
    that legitimately load pgpy. On the pre-fix code pgpy is in sys.modules
    right after importing the package; on the fixed code it is not (imported
    lazily only when the PGPy backend is actually requested).
    """
    code = (
        "import sys\n"
        "import capauth.crypto\n"
        "assert 'capauth.crypto' in sys.modules\n"
        "assert 'pgpy' not in sys.modules, 'pgpy was eagerly imported'\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, (
        f"subprocess failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "OK" in result.stdout


def test_crypto_package_imports_and_exposes_factory():
    """The package imports cleanly and still exposes the factory + sk_pgp path."""
    from capauth.crypto import get_backend  # noqa: F401
    from capauth.models import CryptoBackendType

    assert hasattr(CryptoBackendType, "SKPGP")


def test_forgejo_run_uses_no_deprecated_event_loop():
    """``_run`` must drive a coroutine without a DeprecationWarning.

    Under ``warnings -> error`` the old ``asyncio.get_event_loop()`` path would
    raise ("There is no current event loop"); ``asyncio.run`` does not.
    """
    from capauth.integrations.forgejo.cli import _run

    async def _coro():
        return 4880

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        result = _run(_coro())

    assert result == 4880
