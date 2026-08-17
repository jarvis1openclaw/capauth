# The coordination projection as a trust input

**Status:** audit landed, failure visibility fixed, weighting change PROPOSED and
NOT applied.
**Audited:** 2026-08-16, against the live fleet coordination store.
**Owner decision required:** yes. See "Recommendation to the repo owner" below.
**Refs:** coord card `49e9b427`, upstream `ebc927c3` (A5.1), `7dd497bc`.

## 1. What this document is for

`capauth.trust.graph` builds the trust web that `skcapstone trust graph`, the
skcapstone shell, the `trust_graph` MCP tool and skdashboard's trust panel all
render. One of its five input sources is the coordination board, and it reads
that board through a REBUILDABLE PROJECTION rather than through the board's
store of record.

That read was never audited, because the read lives in capauth and the store
lives in skcapstone. This document records the audit, states plainly what was
fixed, and puts the part that changes trust semantics in front of the repo
owner instead of quietly changing it.

## 2. The read, as it stands

`src/capauth/trust/graph.py::_add_coord_agents` opens every
`~/.skcapstone/coordination/agents/*.json`, takes `data["agent"]` as the
collaborator name, and computes:

```
completed = len(data.get("completed_tasks", []))
strength  = min(1.0, 0.3 + completed * 0.05)
```

So a claimed completion count is a direct multiplier on a trust edge weight.
Fourteen claimed completions saturate the edge at 1.0, and every collaborator
at or above fourteen is thereafter indistinguishable from every other.

## 3. The audit: four independent ways the count is wrong

All four were measured on the live store on 2026-08-16, not estimated.

1. **1,683 completions are claimed across the agent projections, and 188 of
   them are backed by no store at all.** Not the coordination event log, not
   the archive manifest. Each uncorroborated claim inflates a trust edge by
   0.05.
2. **The identity fields describe the rebuilder, not the agent.** 106 of about
   120 agent files share a two-second-wide `last_seen`, and 100 carry the
   rebuilder's hostname, because `export_to_legacy -> save_agent` restamps
   `last_seen` and `AgentFile.host` defaults to `socket.gethostname()`. Any
   freshness or provenance signal on these nodes is an artifact of whoever last
   ran a rebuild.
3. **Conflict resolution loses completions in one consistent direction.** All 6
   Syncthing conflict copies claimed completions that the surviving live file
   had lost (autopilot 4 versus 0; opus-swarm 5, 11, 22, 5, 11 versus 0), and
   never the reverse. The live counts are therefore systematically low, and
   nothing about the surviving file reveals that.
4. **The projection cannot represent the board's `review` column at all.** 32
   cards currently disagree between store and projection for structural
   reasons that no rebuild can fix. A projection that cannot express a state of
   the thing it projects is not a faithful view of it.

None of this is evidence of an attack. It is evidence that a trust weight is
computed from a number that is wrong in at least four unrelated ways, and that
nobody noticed because the reader and the writer live in different repos.

## 4. The aggravating factor, and the thing that was actually fixed

The whole consumer chain was built to hide this. `_add_coord_agents` continued
past `json.JSONDecodeError` and `OSError` per file, and
`skdashboard/src/skdashboard/dashboard.py` collapses every exception out of
`build_trust_graph` into an empty graph so the panel never 500s. The net
effect: a totally unreadable projection rendered as a graph with zero coord
edges, which is exactly what a healthy agent with no collaborators renders as.
Healthy and broken were the same picture, in all three output formats.

That is fixed. `TrustGraph` now carries a `SourceHealth` record per
instrumented source with four states:

| status       | meaning                                                        |
| ------------ | -------------------------------------------------------------- |
| `ok`         | read succeeded. Zero edges means zero relationships.            |
| `absent`     | the source does not exist on this home.                         |
| `degraded`   | some records read, some failed. The graph UNDERCOUNTS.          |
| `unreadable` | nothing could be read. Absence of edges means nothing at all.   |

`TrustGraph.warnings()` is empty only when every instrumented source was read
in full. The three renderers surface it: `format_json` gains `sources`,
`warnings` and `complete` (this is the dict skdashboard renders), `format_table`
gains a Sources section and an explicit incomplete-graph warning, and
`format_dot` draws a red node for a degraded source so the gap is visible in a
rendered image rather than expressed as a smaller graph.

Two smaller correctness fixes came with it, both cases where "unreadable" was
being silently converted into "empty":

- A JSON payload that parses but is not an object (an error page, an array, a
  bare `null`) is now counted as a failed file. Previously `[1,2,3]` raised an
  uncaught `AttributeError` out of `build_trust_graph`, which skdashboard then
  turned into an empty graph.
- The directory listing uses `iterdir` rather than `glob`, because `glob`
  swallows a `PermissionError` on the directory and returns nothing, reporting
  an unreadable store as an empty one.

Per-file tolerance is deliberately KEPT. One corrupt agent file should not
blank the whole trust web. The change is that tolerated failures are now
counted and reported instead of being invisible.

## 5. Why the projection is still read at all (the PROJECTION-OK marker)

The marker above `_add_coord_agents` justifies the read for a trust weight
specifically, and it rests on exactly one property, which was verified rather
than assumed:

> `TrustEdge.strength` is a DISPLAY quantity and nothing else.

Its only consumers fleet-wide are renderers: DOT `penwidth` in `format_dot`,
the ASCII bar in `format_table`, and skdashboard's `static/trust.html` stroke
width and label. No authorization, capability issuance, token gate or policy
decision in capauth or in any consumer reads it. Nothing under
`src/capauth/authz.py`, `src/capauth/tokens.py` or `src/capauth/service/`
imports the trust graph at all. An inflated coord edge draws a thicker line. It
does not grant anything.

That justification is CONDITIONAL, and the condition is the entire basis of the
marker. The moment any code path makes an access decision from a coord edge
weight, this read stops being acceptable and must move to the corroborated
source. Every coord edge therefore ships with `corroborated: False` in its
metadata so a future consumer cannot claim it was not told.

## 6. Recommendation to the repo owner

Two of the card's four questions change what trust MEANS, so they are proposed
here rather than applied. Both are yours.

### (a) Should trust weight derive from a completion count at all?

**Recommendation: no.** Reasoning, in order of weight:

1. **A count measures volume, not trustworthiness.** Fourteen trivial
   completions produce the same maximal 1.0 edge as years of high-stakes work.
   The formula rewards task churn, and the fleet's own agents are the ones
   generating the churn.
2. **The channel is monotonic and one-directional.** Nothing decays and nothing
   subtracts. An agent that failed two hundred cards and completed fourteen is
   rendered as maximally trusted. A trust signal with no way to go down is not
   measuring trust.
3. **It is precisely the quantity the store cannot corroborate.** 188 of 1,683
   claims are backed by nothing (section 3.1). If a count is kept, it must read
   the union of the coordination event log and the archive manifest, never
   `agents/*.json`; per card `7dd497bc` an events-only read under-reports by 93
   percent, so the union is not optional.
4. **The projection is structurally incomplete** (section 3.4) and its identity
   fields are rebuild artifacts (section 3.2). It cannot be made faithful by
   rebuilding it more often.

**Preferred replacement: make the coord edge a PRESENCE edge with a fixed
strength (0.3), and keep the count as a label and metadata only.** What the
projection can genuinely support is "these two agents appear on the same
coordination board". That is a real fact about collaboration, it survives all
four corruption modes above, and it is all the projection is entitled to
assert. The human reader still sees "collaborator (7 tasks)" in the label; the
number simply stops moving a weight. This is also the smallest possible change:
one constant, no new data source, and the saturation cliff disappears because
the ramp disappears.

**Second option, if a ramp is wanted:** source it from the corroborated union
(event log plus archive manifest), make it logarithmic rather than linear so
volume has diminishing returns, and add recency decay. Note that recency decay
needs a corroborated timestamp, because `last_seen` on these files is the
rebuilder's clock (section 3.2). This is real work and it still measures
volume, so I would only do it if the trust graph is going to become an input to
something that decides.

**Third option:** keep the status quo plus the marker, which is what this
change ships as an interim. Acceptable only while section 5 stays true.

### (d) Record or replace `0.3 + 0.05n`

Recorded, not silently kept. The constants are now named in `graph.py` as
`COORD_BASE_STRENGTH`, `COORD_STRENGTH_PER_TASK` and `COORD_SATURATION_TASKS`
(14), the saturation point is stated in the code rather than left to be
discovered, and `tests/test_trust_graph_coord_audit.py` locks the exact curve at
n = 0, 3, 14 and 200 so that any future change to it is a deliberate, reviewed
edit rather than a drift.

That test is a lock, not an endorsement. If (a) is accepted, the lock changes in
the same commit as the formula and the reasoning goes here.

## 7. Follow-ups this change does NOT do

- **skdashboard still collapses every exception into an empty graph** with a
  `note` field. It now has `sources` and `complete` available in the payload it
  already parses, and its trust panel should surface both, but that is another
  repo and another card.
- **The other file-scanning readers in `graph.py`** (`_add_token_edges`,
  `_add_feb_edges`, `_add_sync_edges`) still swallow per-file failures without
  counting them. `SourceHealth` is deliberately general so they can be
  instrumented the same way. Coord was done first because it is the one whose
  source is known to be corrupt.
- **Nothing in this change touches the coordination store or its rebuilder.**
  The four corruption modes in section 3 are still live. This change makes
  capauth stop presenting them as fact; it does not fix them.
