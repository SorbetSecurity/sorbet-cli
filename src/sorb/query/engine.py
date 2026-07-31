"""Query AST → parameterized SQL execution.

Compiles a `ComponentsQuery`/`PathsQuery` into **parameterized** SQL over the
run store: string literals are bound as parameters (never interpolated), so a
value like ``"'; DROP TABLE components; --"`` is matched as a literal string
and can do nothing. Field names map to real columns or to SQLite JSON1
extraction over the `attrs` blob; an unknown field is a `QueryError`, not a
silent empty result.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from sorb.graph.store import Component, GraphStore
from sorb.query.errors import QueryError
from sorb.query.parser import (
    BoolExpr,
    Comparison,
    ComponentsQuery,
    PathsQuery,
    parse_query,
)

#: query field → SQL column on `components`
_COLUMN_FIELDS = {
    "purl": "purl",
    "name": "name",
    "version": "version",
    "ctype": "ctype",
    "type": "ctype",
    "confidence": "confidence",
    "tier": "tier_cap",
}

#: field → attrs JSON key (values are strings in the attrs blob)
_ATTR_FIELDS = {
    "ecosystem": "ecosystem",
    "scope": "scope",
    "cpe": "cpe",
    "license": "licenses_declared",
    "state": "state",
    "layer": "layer",
    "modified": "modified",
    "predicted": "predicted",
    "from_base_image": "from_base_image",
    "introduced_by.base_image": "from_base_image",  # sugar: has a base-image origin
    "observed": "observed",  # live-host runtime observation
    "observed_ports": "observed_ports",
    "seen_in": "seen_in",  # fleet provenance: which host(s) contain it
    "not_after": "not_after",  # CBOM: certificate expiry
    "not_before": "not_before",
    "key_size": "key_size",
    "algorithm": "signature_algorithm",
    "asset_type": "asset_type",
    "weak_crypto": "weak_crypto",
}

_TIER_NAMES = {"inferred": 1, "declared": 2, "locked": 3, "installed": 4, "observed": 5}


@dataclass
class QueryResult:
    kind: str  # "components" | "paths" | "aggregation"
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)


def run_query(store: GraphStore, text: str) -> QueryResult:
    ast = parse_query(text)
    if isinstance(ast, PathsQuery):
        return _run_paths(store, ast)
    return _run_components(store, ast, text)


# -- components ------------------------------------------------------------------------------


def _run_components(store: GraphStore, q: ComponentsQuery, text: str) -> QueryResult:
    where_sql: str = ""
    params: list[Any] = []
    if q.condition is not None:
        where_sql, params = _compile_condition(q.condition, text)

    conn = store._conn
    if q.count_by:
        col_sql = _field_sql(q.count_by, text)
        base = f"SELECT {col_sql} AS bucket, COUNT(*) AS count FROM components"  # noqa: S608
        if where_sql:
            base += f" WHERE {where_sql}"
        base += " GROUP BY bucket ORDER BY count DESC, bucket"
        rows = [
            {q.count_by: _pretty_bucket(q.count_by, r["bucket"]), "count": int(r["count"])}
            for r in conn.execute(base, params)
        ]
        return QueryResult(kind="aggregation", columns=[q.count_by, "count"], rows=rows)

    sql = "SELECT * FROM components"
    if where_sql:
        sql += f" WHERE {where_sql}"
    sql += " ORDER BY name, version, id"
    comps = [store._row_to_component(r) for r in conn.execute(sql, params)]
    return QueryResult(
        kind="components",
        columns=["purl", "name", "version", "ecosystem", "tier", "confidence", "scope"],
        rows=[_component_row(c) for c in comps],
    )


def _component_row(c: Component) -> dict[str, Any]:
    return {
        "id": c.id,
        "purl": c.purl,
        "name": c.name,
        "version": c.version,
        "ecosystem": c.attrs.get("ecosystem") or (c.purl[4:].split("/", 1)[0] if c.purl else c.ctype),
        "tier": c.tier.label,
        "confidence": round(c.confidence, 4),
        "scope": c.attrs.get("scope"),
        "excluded": bool(c.attrs.get("excluded")),
    }


def _compile_condition(node: object, text: str) -> tuple[str, list[Any]]:
    if isinstance(node, BoolExpr):
        lsql, lp = _compile_condition(node.left, text)
        rsql, rp = _compile_condition(node.right, text)
        return f"({lsql} {node.op.upper()} {rsql})", lp + rp
    if isinstance(node, Comparison):
        return _compile_comparison(node, text)
    raise QueryError("internal: unexpected condition node")


def _compile_comparison(c: Comparison, text: str) -> tuple[str, list[Any]]:
    col = _field_sql(c.field, text)
    value = c.value

    # tier names → numbers on tier_cap
    if c.field == "tier" and isinstance(value, str):
        if value.lower() not in _TIER_NAMES:
            raise QueryError(f"unknown tier {value!r} (inferred|declared|locked|installed|observed)",
                             c.pos, text)
        value = _TIER_NAMES[value.lower()]

    if c.op == "~":  # glob → LIKE with a translated pattern, or a regexp fallback
        if not isinstance(value, str):
            raise QueryError("~ (glob match) needs a string pattern", c.pos, text)
        like = _glob_to_like(value)
        return f"{col} LIKE ? ESCAPE '\\'", [like]

    sql_op = {"=": "=", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}.get(c.op)
    if sql_op is None:
        raise QueryError(f"unsupported operator {c.op!r}", c.pos, text)

    # booleans over attrs are stored as the string "true"/"false" or absent
    if isinstance(value, bool) and c.field in _ATTR_FIELDS:
        if value:
            return f"{col} = 'true'", []
        return f"({col} IS NULL OR {col} != 'true')", []
    return f"{col} {sql_op} ?", [value]


def _field_sql(field_name: str, text: str) -> str:
    if field_name in _COLUMN_FIELDS:
        return _COLUMN_FIELDS[field_name]
    if field_name in _ATTR_FIELDS:
        # SQLite JSON1: json_extract(attrs, '$.key'); key is from a fixed allowlist
        return f"json_extract(attrs, '$.{_ATTR_FIELDS[field_name]}')"
    if field_name.startswith("attrs.") and _safe_key(field_name[6:]):
        return f"json_extract(attrs, '$.{field_name[6:]}')"
    raise QueryError(
        f"unknown field {field_name!r} "
        "(known: purl, name, version, ctype, confidence, tier, ecosystem, scope, "
        "license, cpe, state, layer, or attrs.<key>)",
        -1, text,
    )


def _safe_key(key: str) -> bool:
    return bool(key) and all(c.isalnum() or c in "_-" for c in key)


def _glob_to_like(pattern: str) -> str:
    out = []
    for ch in pattern:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in "%_\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _pretty_bucket(field_name: str, raw: Any) -> str:
    if field_name == "tier" and raw is not None:
        from sorb.model import Tier

        try:
            return Tier(int(raw)).label
        except (ValueError, KeyError):
            return str(raw)
    return "(none)" if raw is None else str(raw)


# -- paths -----------------------------------------------------------------------------------


def _run_paths(store: GraphStore, q: PathsQuery) -> QueryResult:
    """paths from <src ref> to <dst component>: provenance chains to graph roots."""
    dst_comps = _resolve(store, q.dst)
    if not dst_comps:
        return QueryResult(kind="paths", columns=["path"], rows=[])
    src_matcher = _src_matcher(q.src)
    rows: list[dict[str, Any]] = []
    for comp in dst_comps:
        for path in store.paths_to_roots(comp.id):
            if not path:
                continue
            root = path[0]
            if src_matcher(root):
                rows.append({
                    "path": [
                        {
                            "kind": step.kind,
                            "label": step.label,
                            "component_id": step.component_id,
                            # The condition the edge into this step carries, if
                            # any. A marker-gated hop is not an unconditional
                            # dependency, and rendering it as one reads as a
                            # claim the graph never made.
                            "marker": step.edge_attrs.get("marker"),
                        }
                        for step in path
                    ],
                    "target": comp.display_ref(),
                })
    # Shortest first: the most direct provenance is the one worth reading, and
    # sorting by label alone buries `. → rich` under every long way round.
    rows.sort(key=lambda r: (len(r["path"]), [s["label"] for s in r["path"]]))
    return QueryResult(kind="paths", columns=["path"], rows=rows)


def _resolve(store: GraphStore, ref: str) -> list[Component]:
    if ref.startswith(("project:", "source:")):
        return []  # a start ref, not a component target
    return store.find_component(ref)


def _src_matcher(ref: str):  # type: ignore[no-untyped-def]
    if ref.startswith("project:"):
        want = ref.split(":", 1)[1]
        return lambda step: step.kind == "project" and (step.label == want or step.label.endswith(want))
    if ref.startswith("source:"):
        return lambda step: step.kind == "source"
    # a component/purl start: match the root step's label by glob
    return lambda step: fnmatch.fnmatch(step.label, ref) or step.label == ref
