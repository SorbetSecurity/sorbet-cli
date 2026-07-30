"""Package-DB time travel.

The package database file in *each* layer that touches it is parsed, so
upgrades and removals across the build are tracked instead of only seeing the
final DB. This module owns the pure diffing logic; the orchestrator runs the
catalogers per layer and feeds the observed states in (layering rule:
container and catalogers never import each other).
"""

from __future__ import annotations

from dataclasses import dataclass

#: (ecosystem, package name) — the family key inside one DB path's timeline
FamilyKey = tuple[str, str]

#: one DB snapshot: family → version
Snapshot = dict[FamilyKey, str]


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    kind: str  # "upgraded" | "removed"
    eco: str
    name: str
    old_version: str
    old_ordinal: int  # layer that installed old_version (last write before change)
    new_version: str | None  # None for removals
    new_ordinal: int  # layer where the change became visible


def diff_timeline(states: dict[int, Snapshot]) -> list[TimelineEvent]:
    """Diff DB snapshots (ordinal → family → version), oldest→newest.

    A version change between consecutive snapshots is an ``upgraded`` event
    (downgrades ride the same event kind — the versions tell the story);
    a family disappearing is a ``removed`` event.
    """
    events: list[TimelineEvent] = []
    ordinals = sorted(states)
    if not ordinals:
        return events
    prev: Snapshot = {}
    prev_write: dict[FamilyKey, int] = {}  # family → ordinal that set current version
    prev_ordinal: int | None = None
    for ordinal in ordinals:
        cur = states[ordinal]
        if prev_ordinal is not None:
            for fam, old_version in prev.items():
                eco, name = fam
                if fam not in cur:
                    events.append(
                        TimelineEvent(
                            kind="removed",
                            eco=eco,
                            name=name,
                            old_version=old_version,
                            old_ordinal=prev_write.get(fam, prev_ordinal),
                            new_version=None,
                            new_ordinal=ordinal,
                        )
                    )
                elif cur[fam] != old_version:
                    events.append(
                        TimelineEvent(
                            kind="upgraded",
                            eco=eco,
                            name=name,
                            old_version=old_version,
                            old_ordinal=prev_write.get(fam, prev_ordinal),
                            new_version=cur[fam],
                            new_ordinal=ordinal,
                        )
                    )
        for fam, version in cur.items():
            if fam not in prev or prev[fam] != version:
                prev_write[fam] = ordinal
        prev = cur
        prev_ordinal = ordinal
    return events


def first_seen(states: dict[int, Snapshot], fam: FamilyKey, version: str) -> int | None:
    """Earliest ordinal at which the family is present *at this version* —
    the layer that introduced the finally-installed package."""
    for ordinal in sorted(states):
        if states[ordinal].get(fam) == version:
            return ordinal
    return None
