"""Fleet aggregation & cross-source queries.

Org-scale merge of many per-host/-image stores into one graph. It is
*streaming and digest-first*: stores are opened one at a time and reduced into a
dedup index keyed by component identity, so peak memory is proportional to the
number of **distinct** components, not the fleet size — 100 near-identical hosts
cost about as much as one. Each merged component keeps per-source provenance
(`seen_in`: which host, which version, observed-running + ports), so the flagship
question — "which hosts run OpenSSL < 3.0.14, and is it observed running?" — is a
single query whose rows expand back to the responsible hosts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sorb.graph.store import Component, GraphStore


@dataclass
class FleetStats:
    sources: int = 0
    total_components: int = 0
    distinct_components: int = 0
    observed: int = 0


@dataclass
class _Agg:
    comp: Component
    seen_in: list[dict[str, Any]] = field(default_factory=list)
    observed: bool = False


def _identity(comp: Component) -> str:
    if comp.purl:
        return f"purl:{comp.purl}"
    eco = str(comp.attrs.get("ecosystem", comp.ctype))
    return f"nv:{comp.ctype}:{eco}:{comp.name.lower()}:{comp.version or ''}"


def _source_label(store: GraphStore, fallback: str) -> str:
    subj = store.get_meta("subject")
    if subj:
        return subj
    return fallback


def merge_fleet(
    store_paths: Iterable[str | Path], out_path: str | Path
) -> tuple[GraphStore, FleetStats]:
    """Stream-merge many run stores into one fleet graph (memory-bounded)."""
    index: dict[str, _Agg] = {}
    stats = FleetStats()
    labels: list[str] = []

    for raw in store_paths:
        path = Path(raw)
        store = GraphStore.open_readonly(path)
        try:
            label = _source_label(store, path.stem)
            labels.append(label)
            stats.sources += 1
            for comp in store.components():
                if comp.attrs.get("excluded"):
                    continue
                stats.total_components += 1
                observed = comp.attrs.get("observed") == "true"
                entry = {
                    "source": label,
                    "version": comp.version,
                    "observed": observed,
                    "ports": comp.attrs.get("observed_ports", ""),
                }
                key = _identity(comp)
                agg = index.get(key)
                if agg is None:
                    index[key] = _Agg(comp=comp, seen_in=[entry], observed=observed)
                else:
                    agg.seen_in.append(entry)
                    agg.observed = agg.observed or observed
                    if (comp.tier_cap, comp.confidence) > (agg.comp.tier_cap, agg.comp.confidence):
                        agg.comp = comp
        finally:
            store.close()

    out = GraphStore.create(out_path)
    out.add_source("s1", "fleet", f"{len(labels)} sources", {"kind": "fleet"})
    out.set_meta("subject", "fleet:" + ",".join(sorted(set(labels))))
    out.set_meta("target", "fleet")
    out.set_meta("fleet_sources", json.dumps(sorted(set(labels))))

    for key in sorted(index):
        agg = index[key]
        c = agg.comp
        attrs: dict[str, Any] = dict(c.attrs)
        attrs.pop("observed", None)
        attrs["seen_in"] = json.dumps(agg.seen_in, sort_keys=True)
        attrs["seen_count"] = str(len({e["source"] for e in agg.seen_in}))
        if agg.observed:
            attrs["observed"] = "true"
            stats.observed += 1
        out.add_component(
            purl=c.purl, ctype=c.ctype, name=c.name, version=c.version,
            qualifiers=c.qualifiers, hashes=c.hashes, confidence=c.confidence,
            tier_cap=c.tier_cap, attrs=attrs,
        )
    stats.distinct_components = len(index)
    out.commit()
    return out, stats


@dataclass(frozen=True, slots=True)
class FleetRow:
    name: str
    version: str | None
    source: str  # the host/image
    observed: bool
    ports: str


def fleet_rows(store: GraphStore, query: str) -> list[FleetRow]:
    """Run a component query, then expand each hit to one row per source host.

    This is the flagship query shape: `components where name = openssl and
    version < 3.0.14 and observed = true` → the vulnerable component, expanded to
    the specific hosts it was seen (and observed) on."""
    from sorb.query import run_query

    result = run_query(store, query)
    rows: list[FleetRow] = []
    for r in result.rows:
        cid = r.get("id")
        comp = store.component_by_id(cid) if isinstance(cid, int) else None
        if comp is None:
            continue
        seen = json.loads(comp.attrs.get("seen_in", "[]"))
        if not seen:
            seen = [{"source": "?", "version": comp.version, "observed": False, "ports": ""}]
        for entry in seen:
            rows.append(FleetRow(
                name=comp.name, version=entry.get("version") or comp.version,
                source=entry.get("source", "?"), observed=bool(entry.get("observed")),
                ports=str(entry.get("ports", "")),
            ))
    return rows
