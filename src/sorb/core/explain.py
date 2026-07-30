"""`sorb explain` engine.

Resolves a purl | name | path | digest to components in the latest (or given)
run store and renders provenance paths + evidence.
"""

from __future__ import annotations

from sorb.graph.store import Component, GraphStore
from sorb.model import Tier


def explain(store: GraphStore, ref: str) -> str | None:
    comps = store.find_component(ref)
    if not comps:
        return None
    blocks = [_explain_one(store, c) for c in comps[:5]]
    if len(comps) > 5:
        blocks.append(f"… and {len(comps) - 5} more matches")
    return "\n\n".join(blocks)


def _explain_one(store: GraphStore, comp: Component) -> str:
    lines: list[str] = []
    scope = comp.attrs.get("scope")
    scope_part = f"   scope: {scope}" if scope else ""
    lines.append(
        f"{comp.display_ref()}   confidence {comp.confidence:.2f}{scope_part}"
    )
    lines.append("")

    # container layer attribution (layer → created_by → Dockerfile)
    ordinal = comp.attrs.get("layer_ordinal")
    if ordinal is not None:
        line = f"  Introduced by layer {int(ordinal) + 1}"
        if comp.attrs.get("introduced_by"):
            line += f" — {comp.attrs['introduced_by']}"
        if comp.attrs.get("dockerfile_line") is not None:
            line += f" (Dockerfile:{comp.attrs['dockerfile_line']})"
        lines.append(line)
        if comp.attrs.get("from_base_image"):
            lines.append(f"  Inherited from base image: {comp.attrs['from_base_image']}")
        if comp.attrs.get("state"):
            removed_in = comp.attrs.get("removed_in_layer")
            note = f"  State: {comp.attrs['state']}"
            if removed_in is not None:
                note += f" (gone since layer {int(removed_in) + 1})"
            lines.append(note)
        lines.append("")

    paths = store.paths_to_roots(comp.id)
    real_paths = [p for p in paths if len(p) > 1]
    if real_paths:
        lines.append(f"  Introduced via {len(real_paths)} path{'s' if len(real_paths) != 1 else ''}:")
        for i, path in enumerate(real_paths[:8], start=1):
            for depth, step in enumerate(path):
                attrs = step.edge_attrs
                notes = []
                if attrs.get("scope"):
                    notes.append(str(attrs["scope"]))
                if attrs.get("requested"):
                    notes.append(f"requested {attrs['requested']}")
                if attrs.get("marker"):
                    notes.append(f"marker: {attrs['marker']}")
                note = f"  [{', '.join(notes)}]" if notes else ""
                if depth == 0:
                    kind = " (workspace)" if step.kind == "project" else ""
                    lines.append(f"  {i}. {step.label}{kind}")
                else:
                    indent = "   " + "   " * depth
                    lines.append(f"{indent}└─ {step.label}{note}")
        if len(real_paths) > 8:
            lines.append(f"  … and {len(real_paths) - 8} more paths")
        lines.append("")

    evidence = store.evidence_for_component(comp.id)
    tiers = {e["tier"] for e in evidence}
    lines.append(
        f"  Evidence ({len(evidence)} record{'s' if len(evidence) != 1 else ''}, "
        f"{len(tiers)} technique class{'es' if len(tiers) != 1 else ''}):"
    )
    tier_order = {t.label: int(t) for t in Tier}
    for ev in sorted(evidence, key=lambda e: -tier_order.get(e["tier"], 0)):
        loc = ev["location"]
        where = loc.get("path", "?")
        span = loc.get("span")
        if span:
            where += f":{span[0]}"
        detail = ""
        if ev.get("captured"):
            first_line = str(ev["captured"]).splitlines()[0][:60]
            detail = f"          {first_line}"
        lines.append(f"  • {ev['tier']:<10} {where}{detail}")
        for mod in ev.get("modifiers", []):
            lines.append(f"      modifier: {mod}")

    annotations = store.annotations_for("component", comp.id)
    if annotations:
        lines.append("")
        notes_str = "; ".join(
            f"{a['code']}{': ' + a['detail'] if a['detail'] else ''}" for a in annotations
        )
        lines.append(f"  Notes: {notes_str}")
    return "\n".join(lines)
