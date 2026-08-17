"""Failure visibility for the coordination-board projection read.

Context (coord card 49e9b427, audited 2026-08-16): `_add_coord_agents` reads
`~/.skcapstone/coordination/agents/*.json`, a REBUILT PROJECTION of the
coordination board, and turns `len(completed_tasks)` into a trust edge weight.
The read continued past `json.JSONDecodeError` and `OSError` per file, and the
one downstream renderer that matters (skdashboard) collapses every exception
into an empty graph. So a projection that was entirely unreadable produced the
exact same picture as an agent with no collaborators: zero coord edges, no
warning, no difference in any output format.

These tests pin the distinction. They are deliberately written against the
three things a caller can actually observe (the graph object, the JSON wire
shape, and the human-facing text/DOT renderings), because a fix that only
changed an internal counter would leave the two states indistinguishable
exactly where the confusion happens.

Nothing here asserts anything about trust SEMANTICS. The weight formula is
unchanged and is discussed in docs/TRUST_GRAPH_COORD_PROJECTION.md.

These tests do not need skcapstone: they write the projection files directly,
which is also the point, since the shapes below are what the reader actually
has to survive.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capauth.trust.graph import (
    build_trust_graph,
    format_dot,
    format_json,
    format_table,
)


def _agents_dir(home: Path) -> Path:
    d = home / "coordination" / "agents"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_agent(home: Path, name: str, completed: int = 0) -> Path:
    path = _agents_dir(home) / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "agent": name,
                "state": "idle",
                "completed_tasks": [f"task-{i}" for i in range(completed)],
            }
        ),
        encoding="utf-8",
    )
    return path


def _coord_source(graph) -> object:
    """The recorded health of the coord projection read, or None."""
    return graph.source(  # type: ignore[attr-defined]
        "coord"
    )


class TestGenuineEmptyIsNotDegraded:
    """A real absence of collaborators reports as a real absence."""

    def test_no_coordination_dir_reports_absent_not_ok(self, tmp_agent_home: Path):
        """No projection on disk is 'absent', which is not the same as 'ok, none'."""
        graph = build_trust_graph(tmp_agent_home)

        health = _coord_source(graph)
        assert health is not None, "the coord read must report its own status"
        assert health.status == "absent"
        assert health.files_seen == 0
        assert health.files_failed == 0

    def test_empty_dir_is_ok_with_zero_collaborators(self, tmp_agent_home: Path):
        """A readable, genuinely empty projection is 'ok' and carries no warning."""
        _agents_dir(tmp_agent_home)

        graph = build_trust_graph(tmp_agent_home)

        health = _coord_source(graph)
        assert health is not None
        assert health.status == "ok"
        assert health.files_failed == 0
        assert graph.warnings() == []

    def test_readable_agents_are_ok(self, tmp_agent_home: Path):
        """Files that all parse report 'ok' and still produce coord edges."""
        _write_agent(tmp_agent_home, "jarvis", completed=3)
        _write_agent(tmp_agent_home, "ava", completed=1)

        graph = build_trust_graph(tmp_agent_home)

        health = _coord_source(graph)
        assert health.status == "ok"
        assert health.files_seen == 2
        assert health.files_failed == 0
        assert len([e for e in graph.edges if e.edge_type == "coord"]) == 2
        assert graph.warnings() == []


class TestUnreadableProjectionIsVisible:
    """The failure mode this card exists for: unreadable must not look empty."""

    def test_all_files_unparseable_reports_unreadable(self, tmp_agent_home: Path):
        """Every file failing to parse is 'unreadable', never a silent zero."""
        d = _agents_dir(tmp_agent_home)
        (d / "jarvis.json").write_text("{ truncated", encoding="utf-8")
        (d / "ava.json").write_text("\x00\x00 not json", encoding="utf-8")

        graph = build_trust_graph(tmp_agent_home)

        health = _coord_source(graph)
        assert health is not None
        assert health.status == "unreadable"
        assert health.files_seen == 2
        assert health.files_failed == 2
        assert [e for e in graph.edges if e.edge_type == "coord"] == []
        assert graph.warnings(), "an unreadable projection must raise a warning"

    def test_partial_failure_reports_degraded(self, tmp_agent_home: Path):
        """Some files failing is 'degraded': the edges shown are an undercount."""
        _write_agent(tmp_agent_home, "jarvis", completed=4)
        (_agents_dir(tmp_agent_home) / "broken.json").write_text("{", encoding="utf-8")

        graph = build_trust_graph(tmp_agent_home)

        health = _coord_source(graph)
        assert health.status == "degraded"
        assert health.files_seen == 2
        assert health.files_failed == 1
        assert len([e for e in graph.edges if e.edge_type == "coord"]) == 1
        assert graph.warnings(), "a partial read must warn that edges are missing"

    def test_unreadable_and_empty_render_differently(self, tmp_agent_home: Path, tmp_path: Path):
        """The whole point: the two states must not produce the same picture.

        Same assertion in all three renderings, because the reader of a DOT
        file, a JSON payload and a terminal table are three different humans
        (or, for JSON, skdashboard) and all three were previously lied to.
        """
        empty_home = tmp_path / "empty-home"
        (empty_home / "coordination" / "agents").mkdir(parents=True)
        empty_graph = build_trust_graph(empty_home)

        d = _agents_dir(tmp_agent_home)
        (d / "jarvis.json").write_text("{ truncated", encoding="utf-8")
        broken_graph = build_trust_graph(tmp_agent_home)

        assert [e for e in empty_graph.edges if e.edge_type == "coord"] == []
        assert [e for e in broken_graph.edges if e.edge_type == "coord"] == []

        assert format_json(empty_graph) != format_json(broken_graph)
        assert format_table(empty_graph) != format_table(broken_graph)
        assert format_dot(empty_graph) != format_dot(broken_graph)

    def test_json_payload_carries_source_health(self, tmp_agent_home: Path):
        """skdashboard consumes format_json, so the status has to be on the wire."""
        (_agents_dir(tmp_agent_home) / "jarvis.json").write_text("{", encoding="utf-8")

        payload = json.loads(format_json(build_trust_graph(tmp_agent_home)))

        assert "sources" in payload, "the JSON wire shape must report source health"
        coord = [s for s in payload["sources"] if s["source"] == "coord"]
        assert coord and coord[0]["status"] == "unreadable"
        assert payload.get("warnings"), "a degraded read must surface as a warning"

    def test_table_names_the_failure(self, tmp_agent_home: Path):
        """A human reading the terminal output sees the word, not a blank section."""
        (_agents_dir(tmp_agent_home) / "jarvis.json").write_text("{", encoding="utf-8")

        table = format_table(build_trust_graph(tmp_agent_home))

        assert "unreadable" in table.lower()
        assert "coord" in table.lower()

    def test_dot_renders_a_warning_node(self, tmp_agent_home: Path):
        """The rendered graph image shows the gap instead of omitting it."""
        (_agents_dir(tmp_agent_home) / "jarvis.json").write_text("{", encoding="utf-8")

        dot = format_dot(build_trust_graph(tmp_agent_home))

        assert "source:coord" in dot
        assert "unreadable" in dot.lower()


class TestUnreadableDirectoryItself:
    """A permissions failure on the directory is a read failure, not an absence."""

    def test_unreadable_dir_is_not_reported_as_ok(self, tmp_agent_home: Path):
        d = _agents_dir(tmp_agent_home)
        _write_agent(tmp_agent_home, "jarvis", completed=2)
        d.chmod(0o000)
        try:
            graph = build_trust_graph(tmp_agent_home)
        finally:
            d.chmod(0o755)

        health = _coord_source(graph)
        assert health is not None
        if health.status == "ok":
            pytest.skip("directory mode not enforced here (running as root?)")
        assert health.status in {"unreadable", "degraded"}
        assert graph.warnings()


class TestNegativeControl:
    """Prove the audit fails on corrupt input rather than passing on anything.

    Each case below is a projection state the audit MUST NOT call healthy. If
    the health reporting ever degrades back into 'always ok', every assertion
    here fails, which is the property the card asked to be demonstrated: the
    check discriminates, it does not just describe.
    """

    CORRUPT_CASES = [
        ("truncated json", '{ "agent": "jarvis"'),
        ("not json at all", "<html>502 Bad Gateway</html>"),
        ("empty file", ""),
        ("json but not an object", "[1, 2, 3]"),
        ("null", "null"),
    ]

    @pytest.mark.parametrize("desc,content", CORRUPT_CASES, ids=[c[0] for c in CORRUPT_CASES])
    def test_corrupt_projection_never_reports_healthy(
        self, tmp_agent_home: Path, desc: str, content: str
    ):
        (_agents_dir(tmp_agent_home) / "jarvis.json").write_text(content, encoding="utf-8")

        graph = build_trust_graph(tmp_agent_home)
        health = _coord_source(graph)

        assert health is not None, f"{desc}: no health recorded"
        assert health.status != "ok", f"{desc}: a corrupt projection was reported healthy"
        assert health.files_failed == 1, f"{desc}: the failed file was not counted"
        assert graph.warnings(), f"{desc}: no warning surfaced"
        assert "unreadable" in format_table(graph).lower()

    def test_positive_control_healthy_input_stays_healthy(self, tmp_agent_home: Path):
        """The mirror of the above: a good projection must NOT trip the audit.

        Without this, a check that reported 'degraded' unconditionally would
        satisfy every corrupt case above and still be useless.
        """
        _write_agent(tmp_agent_home, "jarvis", completed=2)

        graph = build_trust_graph(tmp_agent_home)
        health = _coord_source(graph)

        assert health.status == "ok"
        assert health.files_failed == 0
        assert graph.warnings() == []


class TestEdgesDeclareTheirProvenance:
    """A coord edge says where its weight came from, without changing the weight."""

    def test_edge_metadata_marks_the_count_uncorroborated(self, tmp_agent_home: Path):
        _write_agent(tmp_agent_home, "jarvis", completed=3)

        graph = build_trust_graph(tmp_agent_home)
        edge = next(e for e in graph.edges if e.edge_type == "coord")

        assert edge.metadata.get("source") == "coord-agent-projection"
        assert edge.metadata.get("corroborated") is False
        assert edge.metadata.get("tasks_claimed") == 3

    def test_weight_formula_is_unchanged(self, tmp_agent_home: Path):
        """Pin the existing formula so a later semantics change is deliberate.

        0.3 + 0.05n, saturating at n = 14. This test is a lock, not an
        endorsement. See docs/TRUST_GRAPH_COORD_PROJECTION.md.
        """
        _write_agent(tmp_agent_home, "a", completed=0)
        _write_agent(tmp_agent_home, "b", completed=3)
        _write_agent(tmp_agent_home, "c", completed=14)
        _write_agent(tmp_agent_home, "d", completed=200)

        graph = build_trust_graph(tmp_agent_home)
        by_target = {e.target: e.strength for e in graph.edges if e.edge_type == "coord"}

        assert by_target["a"] == pytest.approx(0.3)
        assert by_target["b"] == pytest.approx(0.45)
        assert by_target["c"] == pytest.approx(1.0)
        assert by_target["d"] == pytest.approx(1.0)
