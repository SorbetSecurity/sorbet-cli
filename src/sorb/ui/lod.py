"""Level-of-detail graph clustering.

At low zoom the graph is served as **cluster nodes** (per ecosystem / layer /
tier); zooming expands a cluster into its real component members. Clustering runs
as SQL aggregation directly over the store — no Python-side materialization of the
component set — so the overview is a `GROUP BY` and an expand is an indexed
`… WHERE cluster_key = ? LIMIT budget`. That keeps it interactive at 100k+
components (the expand path, the one a zoom actually triggers, is a few ms). The
server guarantees ≤ a node budget per response so the WebGL canvas never receives
more than it can draw.

The cluster key is expressed once as SQL (`_CLUSTER_SQL`) and reused for the
overview grouping, the cluster→cluster edge join, and the expand filter, so the
three can never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sorb.graph.store import GraphStore
from sorb.model import Tier

DEFAULT_NODE_BUDGET = 2000
_CLUSTER_BY = ("ecosystem", "layer", "tier")

#: keep-set filter: a component is excluded iff it carries an `excluded` reason.
_KEEP = "json_extract(attrs,'$.excluded') IS NULL"

#: cluster-key SQL per mode. `tier` groups on the raw column and is labelled in
#: Python (Tier enum); the others resolve to a text key directly in SQL.
_CLUSTER_SQL = {
    "ecosystem": (
        "COALESCE(NULLIF(json_extract(attrs,'$.ecosystem'),''),"
        "CASE WHEN purl LIKE 'pkg:%/%' "
        "THEN substr(purl,5,instr(substr(purl,5)||'/','/')-1) END,ctype)"
    ),
    "layer": "COALESCE(json_extract(attrs,'$.layer'),'no-layer')",
    "tier": "tier_cap",
}


@dataclass
class LodNode:
    id: str
    label: str
    kind: str  # "cluster" | "component"
    count: int = 1
    ecosystem: str | None = None
    tier: str | None = None
    scope: str | None = None
    component_id: int | None = None


@dataclass
class LodResponse:
    nodes: list[LodNode] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    node_budget: int = DEFAULT_NODE_BUDGET

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.__dict__ for n in self.nodes],
            "edges": self.edges,
            "truncated": self.truncated,
            "node_budget": self.node_budget,
        }


def _label_for(cluster_by: str, raw: Any) -> str:
    if cluster_by == "tier" and raw is not None:
        try:
            return Tier(int(raw)).label
        except (ValueError, KeyError):
            return str(raw)
    return "(none)" if raw is None else str(raw)


def lod(
    store: GraphStore,
    *,
    cluster_by: str = "ecosystem",
    expand: str | None = None,
    node_budget: int = DEFAULT_NODE_BUDGET,
) -> LodResponse:
    """Cluster overview (expand=None) or a single cluster's real members."""
    if cluster_by not in _CLUSTER_BY:
        cluster_by = "ecosystem"
    key_sql = _CLUSTER_SQL[cluster_by]
    conn = store._conn
    resp = LodResponse(node_budget=node_budget)

    if expand is None:
        return _overview(conn, cluster_by, key_sql, resp)
    return _expand(store, cluster_by, key_sql, expand, node_budget, resp)


def _overview(conn: Any, cluster_by: str, key_sql: str, resp: LodResponse) -> LodResponse:
    rows = conn.execute(
        f"SELECT {key_sql} AS k, COUNT(*) AS c FROM components "  # noqa: S608 — key_sql is a fixed allowlist expr
        f"WHERE {_KEEP} GROUP BY k ORDER BY c DESC, k"
    ).fetchall()
    for r in rows:
        label = _label_for(cluster_by, r["k"])
        resp.nodes.append(
            LodNode(
                id=f"cluster:{cluster_by}:{label}", label=f"{label} ({r['c']})",
                kind="cluster", count=int(r["c"]),
                ecosystem=label if cluster_by == "ecosystem" else None,
            )
        )
    edge_rows = conn.execute(
        f"SELECT DISTINCT a.k AS s, b.k AS d FROM edges e "  # noqa: S608 — key_sql is a fixed allowlist expr
        f"JOIN (SELECT id,{key_sql} AS k FROM components WHERE {_KEEP}) a ON a.id=e.src "
        f"JOIN (SELECT id,{key_sql} AS k FROM components WHERE {_KEEP}) b ON b.id=e.dst "
        f"WHERE e.kind='DEPENDS_ON' AND a.k<>b.k"
    ).fetchall()
    for r in edge_rows:
        sl, dl = _label_for(cluster_by, r["s"]), _label_for(cluster_by, r["d"])
        resp.edges.append({"src": f"cluster:{cluster_by}:{sl}", "dst": f"cluster:{cluster_by}:{dl}"})
    return resp


def _expand(
    store: GraphStore, cluster_by: str, key_sql: str, expand: str, budget: int, resp: LodResponse
) -> LodResponse:
    conn = store._conn
    # tier is grouped on the numeric column; translate the label back to a value.
    if cluster_by == "tier":
        param: Any = _TIER_VALUES.get(expand.lower(), expand)
    else:
        param = expand
    rows = conn.execute(
        f"SELECT * FROM components WHERE {_KEEP} AND {key_sql}=? "  # noqa: S608 — key_sql is a fixed allowlist expr
        f"ORDER BY name, version, id LIMIT ?",
        (param, budget + 1),
    ).fetchall()
    resp.truncated = len(rows) > budget
    member_ids: set[int] = set()
    for r in rows[:budget]:
        comp = store._row_to_component(r)
        member_ids.add(comp.id)
        resp.nodes.append(
            LodNode(
                id=f"component:{comp.id}", label=comp.display_ref(), kind="component",
                ecosystem=str(comp.attrs.get("ecosystem", "")), tier=comp.tier.label,
                scope=comp.attrs.get("scope"), component_id=comp.id,
            )
        )
    if member_ids:
        placeholders = ",".join("?" for _ in member_ids)
        ids = list(member_ids)
        edge_rows = conn.execute(
            f"SELECT src,dst FROM edges WHERE kind='DEPENDS_ON' "  # noqa: S608 — placeholders are bound params
            f"AND src IN ({placeholders}) AND dst IN ({placeholders})",
            ids + ids,
        ).fetchall()
        for r in edge_rows:
            resp.edges.append({"src": f"component:{r['src']}", "dst": f"component:{r['dst']}"})
    return resp


_TIER_VALUES = {t.label: int(t) for t in Tier}
