"""Human output renderers: table, tree, summary.

These return plain strings; the CLI decides where they go. Deterministic and
pipe-friendly.
"""

from __future__ import annotations

from collections import defaultdict

from sorb.emit.canonical import emitted_components
from sorb.graph.store import GraphStore
from sorb.warnings import ANNOTATION_WARNING_CODES


def render_table(store: GraphStore) -> str:
    comps = emitted_components(store)
    if not comps:
        return "no components found"
    headers = ("NAME", "VERSION", "ECOSYSTEM", "TIER", "CONF", "SCOPE")
    rows = []
    for c in comps:
        eco = c.attrs.get("ecosystem") or (c.purl[4:].split("/", 1)[0] if c.purl else c.ctype)
        rows.append(
            (
                c.name,
                c.version or f"({c.attrs.get('requested', '?')})",
                eco,
                c.tier.label,
                f"{c.confidence:.2f}",
                c.attrs.get("scope", "-"),
            )
        )
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    for r in rows:
        lines.append("  ".join(r[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def render_summary(store: GraphStore) -> str:
    counters = store.counters()
    annotations = store.all_annotations()
    drift = [a for a in annotations if a["code"].startswith("drift:")]
    lines = [
        f"components: {counters['components']} "
        f"({counters['high_confidence']} high confidence)",
        "by ecosystem: "
        + ", ".join(f"{k}={v}" for k, v in counters["by_ecosystem"].items()),
        "by tier: " + ", ".join(f"{k}={v}" for k, v in counters["by_tier"].items()),
    ]
    if counters.get("excluded"):
        lines.append(
            f"retained in graph, not emitted: {counters['excluded']} "
            "(below threshold, or removed/superseded during image build — "
            "--min-confidence 0 / --include-removed to emit)"
        )
    if drift:
        lines.append(f"drift findings: {len(drift)}")
        for a in drift[:10]:
            code = ANNOTATION_WARNING_CODES.get(a["code"], "")
            lines.append(f"  ⚠ {a['code']} {a['detail']}".rstrip() + (f"  [{code}]" if code else ""))
    return "\n".join(lines)


def render_tree(store: GraphStore) -> str:
    comps = {c.id: c for c in emitted_components(store)}
    children: dict[int, list[int]] = defaultdict(list)
    has_parent: set[int] = set()
    project_children: dict[str, list[int]] = defaultdict(list)
    projects = {store.project_node_id(p["id"]): p["path"] for p in store.projects()}
    for e in store.edges():
        if e["kind"] != "DEPENDS_ON":
            continue
        src, dst = e["src"], e["dst"]
        if dst not in comps:
            continue
        if src in comps:
            children[src].append(dst)
            has_parent.add(dst)
        elif src in projects:
            project_children[projects[src]].append(dst)
            has_parent.add(dst)

    lines: list[str] = []

    def label(cid: int) -> str:
        c = comps[cid]
        return f"{c.name}@{c.version or '?'} [{c.tier.label} {c.confidence:.2f}]"

    def walk(cid: int, prefix: str, seen: frozenset[int]) -> None:
        kids = sorted(set(children.get(cid, [])), key=lambda i: comps[i].name)
        for i, kid in enumerate(kids):
            last = i == len(kids) - 1
            connector = "└─ " if last else "├─ "
            if kid in seen:
                lines.append(f"{prefix}{connector}{label(kid)} (cycle)")
                continue
            lines.append(f"{prefix}{connector}{label(kid)}")
            walk(kid, prefix + ("   " if last else "│  "), seen | {kid})

    for proj in sorted(project_children):
        lines.append(f"{proj or '.'}")
        roots = sorted(set(project_children[proj]), key=lambda i: comps[i].name)
        for i, cid in enumerate(roots):
            last = i == len(roots) - 1
            lines.append(f"{'└─ ' if last else '├─ '}{label(cid)}")
            walk(cid, "   " if last else "│  ", frozenset({cid}))
    orphans = sorted(
        (cid for cid in comps if cid not in has_parent and not children.get(cid)),
        key=lambda i: comps[i].name,
    )
    floating = [cid for cid in orphans if comps[cid].ctype == "os-package"]
    if floating:
        lines.append(f"(os packages: {len(floating)} — see table output)")
    return "\n".join(lines) if lines else render_table(store)
