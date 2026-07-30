"""Go Minimal Version Selection.

MVS is fully deterministic from the module requirement graph: the build list
is, for every module reachable from the main module, the *maximum* of the
minimum versions required along any path (Go's semver ordering). No network —
the graph is supplied by the caller (go.mod files, conformance fixtures, or a
registry metadata provider).
"""

from __future__ import annotations

from sorb.ident import compare

#: requirement graph: (module, version) → [(module, version), …]
ModuleGraph = dict[tuple[str, str], list[tuple[str, str]]]


def mvs_build_list(
    main: str,
    root_requires: list[tuple[str, str]],
    graph: ModuleGraph,
    replace: dict[str, tuple[str, str]] | None = None,
) -> dict[str, str]:
    """The MVS build list: module → selected version.

    `replace` maps an original module path to its replacement (path, version)
    — applied before graph lookup, as `go.mod replace` does.
    """
    replace = replace or {}
    selected: dict[str, str] = {}
    stack: list[tuple[str, str]] = list(root_requires)
    visited: set[tuple[str, str]] = set()
    while stack:
        module, version = stack.pop()
        if module in replace:
            module, version = replace[module]
        if (module, version) in visited or module == main:
            continue
        visited.add((module, version))
        current = selected.get(module)
        if current is None or compare("golang", version, current) > 0:
            selected[module] = version
        # requirements of *this exact version* participate regardless of
        # whether it wins selection — that is what makes MVS minimal & stable
        for dep in graph.get((module, version), []):
            stack.append(dep)
    return selected
