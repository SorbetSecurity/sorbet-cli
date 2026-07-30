"""Per-emitter capability tables + the generic loss report.

Each emitter declares which graph fact kinds it can express; ``--loss-report``
is computed generically by diffing the facts actually present in a store
against that table — never hand-maintained per conversion pair.
"""

from __future__ import annotations

from sorb.graph.store import GraphStore

#: fact kinds the graph can hold
ALL_FACTS = (
    "components",
    "dependency-graph",
    "contains-hierarchy",
    "evidence-records",
    "occurrence-locations",
    "confidence-scores",
    "annotations",
    "hashes",
    "licenses",
    "layer-attribution",
    "file-transitions",
    "supersedes-chains",
    "provenance-projects",
)

CAPABILITIES: dict[str, frozenset[str]] = {
    "sorb": frozenset(ALL_FACTS),
    "cyclonedx-json": frozenset(
        {
            "components",
            "dependency-graph",
            "evidence-records",  # components[].evidence identity+occurrences
            "occurrence-locations",
            "confidence-scores",  # sorb:confidence properties
            "annotations",  # sorb:annotation:* properties
            "hashes",
            "licenses",
            "layer-attribution",  # sorb:layer* properties
        }
    ),
    "spdx-json": frozenset(
        {
            "components",
            "dependency-graph",
            "contains-hierarchy",
            "hashes",
            "licenses",
        }
    ),
}


def graph_facts(store: GraphStore) -> dict[str, int]:
    """Count the facts actually present in a store (only present facts can be lost)."""
    comps = [c for c in store.components() if not c.attrs.get("excluded")]
    edges = store.edges()
    conn = store._conn
    n_evidence = int(conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])
    n_occurrence = int(
        conn.execute("SELECT COUNT(*) FROM evidence WHERE location LIKE '%span%'").fetchone()[0]
    )
    n_states = int(conn.execute("SELECT COUNT(*) FROM file_states").fetchone()[0])
    facts = {
        "components": len(comps),
        "dependency-graph": sum(1 for e in edges if e["kind"] == "DEPENDS_ON"),
        "contains-hierarchy": sum(1 for e in edges if e["kind"] == "CONTAINS"),
        "evidence-records": n_evidence,
        "occurrence-locations": n_occurrence,
        "confidence-scores": len(comps),
        "annotations": len(store.all_annotations()),
        "hashes": sum(1 for c in comps if c.hashes),
        "licenses": sum(1 for c in comps if c.attrs.get("licenses_declared")),
        "layer-attribution": sum(1 for c in comps if c.attrs.get("layer") is not None),
        "file-transitions": n_states,
        "supersedes-chains": sum(1 for e in edges if e["kind"] == "SUPERSEDES"),
        "provenance-projects": len(store.projects()),
    }
    return {k: v for k, v in facts.items() if v}


def loss_report(store: GraphStore, target_format: str) -> list[str]:
    """Facts present in the graph that `target_format` cannot express."""
    capable = CAPABILITIES.get(target_format)
    if capable is None:
        raise ValueError(f"no capability table for format {target_format!r}")
    lines: list[str] = []
    for fact, count in sorted(graph_facts(store).items()):
        if fact not in capable:
            lines.append(f"{fact}: {count} fact(s) cannot be represented in {target_format}")
    return lines
