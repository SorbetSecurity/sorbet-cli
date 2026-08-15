"""Maven nearest-wins dependency mediation.

Maven picks, for each ``group:artifact``, the version whose declaration is
*nearest* to the root in the dependency tree (breadth-first; first-seen wins
ties at equal depth), with the root POM's ``dependencyManagement`` taking
precedence over everything transitive. The declared trees are supplied by the
caller (parsed POMs or conformance fixtures) — no network.
"""

from __future__ import annotations

from collections import deque

#: declared dependency lists: (group:artifact, version) → [(ga, version), …]
DependencyTree = dict[tuple[str, str], list[tuple[str, str]]]


def mediate(
    root_dependencies: list[tuple[str, str]],
    tree: DependencyTree,
    dependency_management: dict[str, str] | None = None,
) -> dict[str, str]:
    """Mediated (group:artifact) → version, nearest-wins + root depMgmt."""
    managed = dependency_management or {}
    selected: dict[str, str] = {}
    seen_depth: dict[str, int] = {}
    queue: deque[tuple[str, str, int]] = deque(
        (ga, version, 0) for ga, version in root_dependencies
    )
    visited: set[tuple[str, str]] = set()
    while queue:
        ga, version, depth = queue.popleft()
        effective = managed.get(ga, version) if depth > 0 else version
        # the root's own declarations still defer to explicit root depMgmt
        if depth == 0 and ga in managed:
            effective = managed[ga]
        prev_depth = seen_depth.get(ga)
        if prev_depth is None or depth < prev_depth:
            selected[ga] = effective
            seen_depth[ga] = depth
        # walk the tree of the *declared* version (Maven resolves POMs of the
        # version it saw, then mediates)
        if (ga, version) in visited:
            continue
        visited.add((ga, version))
        for dep_ga, dep_version in tree.get((ga, version), []):
            queue.append((dep_ga, dep_version, depth + 1))
    return selected
