"""Pure npm resolver.

node-semver range algebra + npm resolution semantics: for every requested
range pick the highest satisfying version, then walk that version's
dependencies breadth-first. Hoisting differences don't affect the *graph*,
only on-disk layout, so the resolved set matches ``npm ls --json``.

Modes:
- **full resolution** — no lockfile, provider online (or cache-warm);
- **verify** — a lockfile exists: never invent versions, only check that the
  locked graph satisfies the declared ranges (feeds drift detection);
- **degrade** — offline with no lock: explicit ``resolution: incomplete``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from sorb.resolve.provider import RegistryMetadataProvider
from sorb.resolve.semver import max_satisfying, satisfies


@dataclass
class ResolutionResult:
    """Resolved (name, version) set with requested-range edges."""

    resolved: dict[str, str] = field(default_factory=dict)  # name → version
    edges: list[tuple[str, str, str, str]] = field(default_factory=list)
    # (dependent name or "" for root, dep name, requested range, resolved version)
    incomplete: list[tuple[str, str, str]] = field(default_factory=list)
    # (name, range, reason)


def resolve_npm(
    declared: dict[str, str],
    provider: RegistryMetadataProvider,
    *,
    max_depth: int = 50,
) -> ResolutionResult:
    """Resolve declared name→range pairs to a concrete dependency set."""
    result = ResolutionResult()
    queue: deque[tuple[str, str, str, int]] = deque(
        ("", name, range_, 0) for name, range_ in sorted(declared.items())
    )
    while queue:
        parent, name, range_, depth = queue.popleft()
        if depth > max_depth:
            result.incomplete.append((name, range_, "max resolution depth reached"))
            continue
        if name in result.resolved:
            # npm semantics: one version per name in the resolved set is enough
            # for SBOM purposes IF it satisfies; otherwise resolve the second
            # version too (nested install) — record both.
            if satisfies(result.resolved[name], range_):
                result.edges.append((parent, name, range_, result.resolved[name]))
                continue
        versions = provider.npm_versions(name)
        if not versions:
            result.incomplete.append(
                (name, range_, "registry metadata unavailable (offline and not cached?)")
            )
            continue
        picked = max_satisfying(versions, range_)
        if picked is None:
            result.incomplete.append((name, range_, "no published version satisfies the range"))
            continue
        result.edges.append((parent, name, range_, picked))
        already = result.resolved.get(name)
        result.resolved[name] = picked if already is None else already
        if already is None or already != picked:
            key = name if already is None else f"{name}@{picked}"
            if already is not None:
                result.resolved[key] = picked
            deps = provider.npm_dependencies(name, picked) or {}
            for dep_name, dep_range in sorted(deps.items()):
                queue.append((name, dep_name, dep_range, depth + 1))
    return result


@dataclass(frozen=True)
class LockVerification:
    """One declared range checked against the locked version."""

    name: str
    requested: str
    locked: str
    satisfied: bool


def verify_lock(declared: dict[str, str], locked: dict[str, str]) -> list[LockVerification]:
    """Verify-mode (lock present): report declared ranges the lock does not
    satisfy — drift input, never new versions."""
    out: list[LockVerification] = []
    for name, range_ in sorted(declared.items()):
        lv = locked.get(name)
        if lv is None:
            continue  # declared-not-locked belongs to the drift pass, not range checking
        if range_.startswith(("file:", "link:", "git", "npm:", "workspace:", "http")):
            continue  # non-registry specifiers have no range semantics
        out.append(
            LockVerification(
                name=name, requested=range_, locked=lv, satisfied=satisfies(lv, range_)
            )
        )
    return out
