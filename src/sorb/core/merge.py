"""`sorb merge` engine.

N-input merge of native results and imported foreign SBOMs into one graph:
identity-based dedup (digest → purl → name-tuple), per-input provenance on
every merged component, ``merge-conflict`` annotations when inputs disagree —
never last-writer-wins. Strategies: union (default), hierarchical (each input
a DESCRIBES subtree), intersect.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from sorb.graph.store import Component, GraphStore
from sorb.model import (
    ComponentClaim,
    EdgeType,
    Finding,
    ProjectClaim,
    evidence_from_dict,
)

STRATEGIES = ("union", "hierarchical", "intersect")


def _identity_keys(comp: Component) -> list[str]:
    keys = [f"digest:{a}:{v.lower()}" for a, v in sorted(comp.hashes.items())]
    if comp.purl:
        keys.append(f"purl:{comp.purl}")
    else:
        eco = str(comp.attrs.get("ecosystem", comp.ctype))
        # An unresolved component still has an identity across inputs. Merging
        # on name alone would be wrong where versions differ, but a component
        # with no version has none to differ on: two inputs describing
        # "flask, version unknown" describe the same thing.
        version = comp.version or "-"
        keys.append(f"name:{comp.ctype}:{eco}:{comp.name.lower()}:{version}")
    return keys


def _family(comp: Component) -> str:
    eco = str(comp.attrs.get("ecosystem", comp.ctype))
    return f"{eco}:{comp.name.lower()}"


def merge_stores(
    inputs: list[tuple[str, GraphStore]],
    db_path: str | Path,
    *,
    strategy: str = "union",
) -> tuple[GraphStore, dict[str, int]]:
    """Merge inputs into a new store at `db_path`. Returns (store, stats)."""
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown merge strategy {strategy!r} (expected {STRATEGIES})")
    out = GraphStore.create(db_path)
    out.add_source("s1", "merge", "+".join(label for label, _ in inputs), {"strategy": strategy})
    out.set_meta("subject", "merge:" + "+".join(sorted(label for label, _ in inputs)))
    out.set_meta("target", "merge")
    out.set_meta("merge_strategy", strategy)

    # ---- gather + bucket by identity across inputs -------------------------------
    entries: list[tuple[str, Component, GraphStore]] = []
    for label, store in inputs:
        for comp in store.components():
            if comp.attrs.get("excluded"):
                continue
            entries.append((label, comp, store))

    parent: dict[int, int] = {}

    def find(i: int) -> int:
        parent.setdefault(i, i)
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    by_key: dict[str, int] = {}
    for i, (_label, comp, _store) in enumerate(entries):
        find(i)
        for key in _identity_keys(comp):
            if key in by_key:
                union(i, by_key[key])
            else:
                by_key[key] = i

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(entries)):
        groups[find(i)].append(i)

    all_labels = {label for label, _ in inputs}
    stats = {"inputs": len(inputs), "merged": 0, "conflicts": 0, "dropped_intersect": 0}

    # ---- write merged components ---------------------------------------------------
    id_map: dict[tuple[str, int], int] = {}  # (input label, source cid) → merged cid
    family_members: dict[str, list[int]] = defaultdict(list)
    ordered_groups = sorted(
        groups.values(), key=lambda g: (entries[g[0]][1].name.lower(), entries[g[0]][1].version or "")
    )
    for members in ordered_groups:
        labels = {entries[i][0] for i in members}
        if strategy == "intersect" and labels != all_labels:
            stats["dropped_intersect"] += 1
            continue
        best_i = max(members, key=lambda i: (entries[i][1].tier_cap, entries[i][1].confidence))
        _blabel, best, _bstore = entries[best_i]
        hashes: dict[str, str] = {}
        licenses: str | None = None
        for i in members:
            hashes.update(entries[i][1].hashes)
            licenses = licenses or entries[i][1].attrs.get("licenses_declared")
        attrs: dict[str, Any] = dict(best.attrs)
        attrs["merge_sources"] = sorted(labels)
        if licenses:
            attrs["licenses_declared"] = licenses
        cid = out.add_component(
            purl=best.purl,
            ctype=best.ctype,
            name=best.name,
            version=best.version,
            qualifiers=best.qualifiers,
            hashes=hashes,
            confidence=best.confidence,
            tier_cap=best.tier_cap,
            attrs=attrs,
        )
        stats["merged"] += 1
        family_members[_family(best)].append(cid)
        for i in members:
            label, comp, store = entries[i]
            id_map[(label, comp.id)] = cid
            evidence = tuple(
                evidence_from_dict(e) for e in store.evidence_for_component(comp.id)
            )
            if evidence:
                claim = ComponentClaim(
                    ctype=comp.ctype, name=comp.name, version=comp.version, purl=comp.purl
                )
                fid = out.add_finding(Finding(claim=claim, evidence=evidence))
                out.link_finding(fid, cid)

    # ---- disagreements: same family, different versions across inputs ----------------
    for family, cids in sorted(family_members.items()):
        if len(cids) < 2:
            continue
        versions: dict[str, list[str]] = {}
        for cid in cids:
            merged_comp = out.component_by_id(cid)
            if merged_comp is not None:
                versions[merged_comp.version or "?"] = sorted(
                    merged_comp.attrs.get("merge_sources", [])
                )
        if len(versions) > 1:
            stats["conflicts"] += 1
            detail = "; ".join(f"{v} (from {', '.join(sources)})" for v, sources in sorted(versions.items()))
            for cid in cids:
                out.add_annotation(
                    "component", cid, "merge-conflict",
                    f"{family.split(':', 1)[1]}: inputs disagree — {detail}",
                )

    # ---- edges remapped per input ------------------------------------------------------
    seen_edges: set[tuple[str, int, int]] = set()
    for label, store in inputs:
        for e in store.edges():
            src = id_map.get((label, e["src"]))
            dst = id_map.get((label, e["dst"]))
            if src is None or dst is None or src == dst:
                continue
            edge_key = (str(e["kind"]), src, dst)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            out.add_edge(EdgeType(e["kind"]), src, dst, e["attrs"])

    # ---- hierarchical: each input becomes a DESCRIBES subtree ----------------------------
    if strategy == "hierarchical":
        for label, _store in inputs:
            pid = out.add_project(ProjectClaim(path=label, name=label, kind="merge-input"), "s1")
            pnode = out.project_node_id(pid)
            for (in_label, _scid), cid in id_map.items():
                if in_label == label:
                    out.add_edge(EdgeType.DESCRIBES, pnode, cid)

    out.commit()
    return out, stats
