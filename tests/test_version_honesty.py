"""`capauth.__version__` must never disagree with what pip actually installed.

Background, so this file is not mistaken for style policing. capauth declares
`dynamic = ["version"]` and lets setuptools_scm derive the version from the git
tag, so a hardcoded `__version__` literal in `__init__.py` feeds nothing. It
merely shadows the real value, and it drifts the moment a tag is cut.

It sat at "0.2.15" while releases went out through 0.3.0. On 2026-08-16 a fleet
audit read that attribute across three nodes, reported 0.2.15 everywhere, and
concluded a signature gate had not reached production. Every node had 0.3.0
installed. The wrong reading inverted the risk assessment for a node that could
not sign and was therefore one restart away from failing closed.

The lesson is not "keep the literal updated". It is that a version a human has
to remember to update is a version that lies.
"""

from __future__ import annotations

import ast
from importlib.metadata import version as dist_version
from pathlib import Path

import capauth


def test_version_agrees_with_the_installed_distribution() -> None:
    """The attribute reports what pip resolved, not what someone last typed."""
    assert capauth.__version__ == dist_version("capauth")


def test_version_is_not_a_hardcoded_literal() -> None:
    """Guard the mechanism, not just today's value.

    The runtime check above passes for a hardcoded literal too, on any machine
    where the literal happens to match. That is exactly how this drifted
    unnoticed for several releases: it was correct at 0.2.15, then simply stayed
    there while the tags moved on. So assert the *source* never re-introduces a
    bare string assignment, which is the only form that can go stale.
    """
    src = Path(capauth.__file__)
    tree = ast.parse(src.read_text(encoding="utf-8"))

    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and target.id == "__version__"
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and node.value.value != "0.0.0.dev0"  # the no-install fallback is fine
    ]

    assert not offenders, (
        f"{src.name} assigns __version__ a hardcoded string at line(s) "
        f"{offenders}. The git tag is the version (setuptools_scm); a literal "
        f"here cannot feed packaging and will drift. Derive it from "
        f"importlib.metadata instead."
    )
