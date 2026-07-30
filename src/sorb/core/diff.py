"""`sorb diff` engine.

Semantic diff over two evidence graphs: added / removed / version-changed
(compared under the ecosystem's version scheme, so 1.10 > 1.9 in semver and
EVR rules hold for rpm), scope and confidence changes, and layer-level image
diffs. Inputs may be native runs, imported foreign SBOMs, or image refs
(scan-then-diff at the CLI layer).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sorb.graph.store import Component, GraphStore
from sorb.ident import compare


@dataclass(frozen=True, slots=True)
class VersionChange:
    name: str
    eco: str
    old: str
    new: str
    direction: str  # "upgraded" | "downgraded" | "changed"


@dataclass
class DiffResult:
    added: list[tuple[str, str | None, str]] = field(default_factory=list)  # name, version, eco
    removed: list[tuple[str, str | None, str]] = field(default_factory=list)
    version_changes: list[VersionChange] = field(default_factory=list)
    scope_changes: list[tuple[str, str, str]] = field(default_factory=list)  # name, old, new
    confidence_changes: list[tuple[str, float, float]] = field(default_factory=list)
    layers_added: list[str] = field(default_factory=list)
    layers_removed: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any(
            (self.added, self.removed, self.version_changes, self.scope_changes,
             self.confidence_changes, self.layers_added, self.layers_removed)
        )


def _emitted(store: GraphStore) -> dict[str, Component]:
    out: dict[str, Component] = {}
    for c in store.components():
        if c.attrs.get("excluded") or c.attrs.get("state"):
            continue
        eco = str(c.attrs.get("ecosystem", c.ctype))
        ns = f"{c.attrs.get('namespace', '')}" if c.attrs.get("namespace") else ""
        out.setdefault(f"{eco}:{ns}:{c.name.lower()}", c)
    return out


def diff_stores(a: GraphStore, b: GraphStore) -> DiffResult:
    """Semantic diff a → b (what changed going from A to B)."""
    result = DiffResult()
    old, new = _emitted(a), _emitted(b)
    for family in sorted(new.keys() - old.keys()):
        c = new[family]
        result.added.append((c.name, c.version, str(c.attrs.get("ecosystem", c.ctype))))
    for family in sorted(old.keys() - new.keys()):
        c = old[family]
        result.removed.append((c.name, c.version, str(c.attrs.get("ecosystem", c.ctype))))
    for family in sorted(old.keys() & new.keys()):
        ca, cb = old[family], new[family]
        eco = str(cb.attrs.get("ecosystem", cb.ctype))
        if ca.version != cb.version and ca.version and cb.version:
            order = compare(eco, cb.version, ca.version)
            direction = "upgraded" if order > 0 else "downgraded" if order < 0 else "changed"
            result.version_changes.append(
                VersionChange(name=cb.name, eco=eco, old=ca.version, new=cb.version,
                              direction=direction)
            )
        scope_a = str(ca.attrs.get("scope", "")) or "-"
        scope_b = str(cb.attrs.get("scope", "")) or "-"
        if scope_a != scope_b:
            result.scope_changes.append((cb.name, scope_a, scope_b))
        if abs(ca.confidence - cb.confidence) >= 0.05:
            result.confidence_changes.append((cb.name, ca.confidence, cb.confidence))

    layers_a = {la["digest"] for la in a.layers()}
    layers_b = {lb["digest"] for lb in b.layers()}
    result.layers_added = sorted(layers_b - layers_a)
    result.layers_removed = sorted(layers_a - layers_b)
    return result


def render_diff(result: DiffResult, label_a: str, label_b: str) -> str:
    lines = [f"diff {label_a} → {label_b}"]
    if result.empty:
        lines.append("  no semantic changes")
        return "\n".join(lines)
    for name, version, eco in result.added:
        lines.append(f"  + {name}@{version or '?'} [{eco}]")
    for name, version, eco in result.removed:
        lines.append(f"  - {name}@{version or '?'} [{eco}]")
    for ch in result.version_changes:
        arrow = "↑" if ch.direction == "upgraded" else "↓" if ch.direction == "downgraded" else "~"
        lines.append(f"  {arrow} {ch.name} {ch.old} → {ch.new} [{ch.eco}, {ch.direction}]")
    for name, old, new in result.scope_changes:
        lines.append(f"  ± {name} scope {old} → {new}")
    for name, conf_old, conf_new in result.confidence_changes:
        lines.append(f"  ± {name} confidence {conf_old:.2f} → {conf_new:.2f}")
    for digest in result.layers_added:
        lines.append(f"  + layer {digest[:19]}…")
    for digest in result.layers_removed:
        lines.append(f"  - layer {digest[:19]}…")
    return "\n".join(lines)
