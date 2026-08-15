"""Environment snapshots + before/after diff.

A snapshot is the installed-state component set of an environment at a moment.
Diffing snapshots around a provisioning step (``sorb snapshot -- pip install
x``) names exactly what that step installed, upgraded, or removed — the audit
tool for base-image build scripts and CI steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sorb.graph.store import GraphStore


@dataclass(frozen=True, slots=True)
class SnapshotEntry:
    ecosystem: str
    name: str
    version: str | None


@dataclass
class Snapshot:
    entries: frozenset[SnapshotEntry] = field(default_factory=frozenset)

    @classmethod
    def from_store(cls, store: GraphStore) -> Snapshot:
        """Installed-state components (the observable environment)."""
        entries = set()
        for comp in store.components():
            if comp.attrs.get("excluded") or comp.attrs.get("state"):
                continue
            if comp.tier < 4:  # < INSTALLED: not part of the on-disk environment
                continue
            entries.add(
                SnapshotEntry(
                    ecosystem=str(comp.attrs.get("ecosystem", comp.ctype)),
                    name=comp.name,
                    version=comp.version,
                )
            )
        return cls(entries=frozenset(entries))


@dataclass
class SnapshotDiff:
    installed: list[SnapshotEntry] = field(default_factory=list)
    removed: list[SnapshotEntry] = field(default_factory=list)
    upgraded: list[tuple[str, str | None, str | None]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.installed or self.removed or self.upgraded)


def diff_snapshots(before: Snapshot, after: Snapshot) -> SnapshotDiff:
    """What changed from `before` to `after` (what the step did)."""
    diff = SnapshotDiff()
    before_by_name = {(e.ecosystem, e.name): e for e in before.entries}
    after_by_name = {(e.ecosystem, e.name): e for e in after.entries}
    for key, entry in sorted(after_by_name.items()):
        prior = before_by_name.get(key)
        if prior is None:
            diff.installed.append(entry)
        elif prior.version != entry.version:
            diff.upgraded.append((entry.name, prior.version, entry.version))
    for key, entry in sorted(before_by_name.items()):
        if key not in after_by_name:
            diff.removed.append(entry)
    return diff


def render_diff(diff: SnapshotDiff) -> str:
    if diff.empty:
        return "  no installed-state changes"
    lines = []
    for e in diff.installed:
        lines.append(f"  + {e.name}@{e.version or '?'} [{e.ecosystem}]")
    for name, old, new in diff.upgraded:
        lines.append(f"  ↑ {name} {old or '?'} → {new or '?'}")
    for e in diff.removed:
        lines.append(f"  - {e.name}@{e.version or '?'} [{e.ecosystem}]")
    return "\n".join(lines)
