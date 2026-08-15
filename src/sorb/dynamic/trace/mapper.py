"""Observation → graph mapping + phantom/unused reporting.

Runtime observations are the **top trust tier**: an observed component's
version is pinned, its confidence upgraded, and an ``OBSERVED_IN`` edge
records the trace session. The mapper also produces the two runtime drift
findings:

- **phantom** (``drift:observed-not-declared``): a dependency loaded at
  runtime that no manifest/lockfile declares — works only by accident
  (hoisting). Emitted as a real observed-tier component *and* a drift finding.
- **unused** (``declared-never-observed``): a declared/installed component in
  a traced ecosystem that no trace ever loaded — prunable (verify all paths
  first).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sorb.dynamic.trace.model import TraceResult
from sorb.graph.store import Component, GraphStore
from sorb.ident import make_purl
from sorb.model import EdgeType, Tier


@dataclass
class ObservationReport:
    observed: list[str] = field(default_factory=list)  # component display refs
    phantom: list[str] = field(default_factory=list)  # observed but undeclared
    unused: list[str] = field(default_factory=list)  # declared but never observed
    warnings: list[tuple[str, str]] = field(default_factory=list)


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def map_observations(
    store: GraphStore, trace: TraceResult, *, session_label: str = "trace"
) -> ObservationReport:
    """Apply a trace's observations to the reconciled graph. Mutates `store`."""
    report = ObservationReport()
    traced_ecos = {o.ecosystem for o in trace.modules() if o.ecosystem}

    # index emitted components by (ecosystem, normalized name)
    by_key: dict[tuple[str, str], list[Component]] = {}
    for comp in store.components():
        if comp.attrs.get("excluded") or comp.attrs.get("state"):
            continue
        eco = str(comp.attrs.get("ecosystem", comp.ctype))
        by_key.setdefault((eco, _norm(comp.name)), []).append(comp)

    observed_keys: set[tuple[str, str]] = set()
    for obs in trace.modules():
        eco = obs.ecosystem or "pypi"
        key = (eco, _norm(obs.identifier))
        observed_keys.add(key)
        matches = by_key.get(key)
        if matches:
            for comp in matches:
                _mark_observed(store, comp.id, comp.confidence, session_label, obs.detail)
                report.observed.append(comp.display_ref())
        else:
            # phantom: loaded but no component accounts for it
            cid = _add_phantom(store, eco, obs.identifier, obs.detail, session_label)
            report.phantom.append(f"{obs.identifier}@{obs.detail or '?'}")
            report.warnings.append(
                (
                    "SORB-W036",
                    f"{obs.identifier} is loaded at runtime but not declared "
                    "(phantom dependency — works only by hoisting accident)",
                )
            )
            store.add_annotation(
                "component",
                cid,
                "drift:observed-not-declared",
                f"{obs.identifier} imported at runtime ({session_label}) but no manifest "
                "or lockfile declares it",
            )

    # unused: declared/installed components in a traced ecosystem never observed
    for (eco, _name), comps in sorted(by_key.items()):
        if eco not in traced_ecos:
            continue
        if (eco, _name) in observed_keys:
            continue
        for comp in comps:
            scope = str(comp.attrs.get("scope", ""))
            if scope in ("build", "dev", "test"):
                continue  # build/dev deps aren't expected in a runtime trace
            report.unused.append(comp.display_ref())
            store.add_annotation(
                "component",
                comp.id,
                "declared-never-observed",
                f"{comp.name} is declared/installed but never loaded in trace "
                f"'{session_label}' — possibly unused (verify all code paths)",
            )
            report.warnings.append(
                ("SORB-W037", f"{comp.name}: declared but never observed at runtime")
            )
    store.commit()
    return report


def _mark_observed(
    store: GraphStore, cid: int, confidence: float, session_label: str, version: str
) -> None:
    comp = store.component_by_id(cid)
    if comp is None:
        return
    attrs = dict(comp.attrs)
    attrs["scope"] = "runtime-observed"
    store.update_component_attrs(cid, attrs)
    store._conn.execute(
        "UPDATE components SET tier_cap=?, confidence=? WHERE id=?",
        (int(Tier.OBSERVED), min(1.0, max(confidence, 0.98)), cid),
    )
    store.add_annotation(
        "component", cid, "runtime-observed",
        f"loaded at runtime in trace '{session_label}'",
    )
    store.add_edge(EdgeType.OBSERVED_IN, cid, store.source_node_id(0), {"session": session_label})


def _add_phantom(
    store: GraphStore, eco: str, name: str, version: str, session_label: str
) -> int:
    purl = make_purl(eco, name, version or None) if version else None
    return store.add_component(
        purl=purl,
        ctype="library",
        name=name,
        version=version or None,
        qualifiers={},
        hashes={},
        confidence=0.98,
        tier_cap=int(Tier.OBSERVED),
        attrs={"ecosystem": eco, "scope": "runtime-observed", "phantom": True,
               "observed_in": session_label},
    )
