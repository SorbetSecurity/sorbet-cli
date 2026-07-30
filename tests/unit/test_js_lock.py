"""npm lockfile v2/v3 nearest-ancestor resolution.

The dependency graph these tests assert is the part of a lockfile that only
appears once packages carry their own ``dependencies`` maps — the normal shape
of every lockfile npm 7+ writes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sorb.model import EdgeType

sys.path.insert(0, str(Path(__file__).parent.parent))
from catalog_harness import catalog  # noqa: E402


def _lock(packages: dict[str, object], version: int = 3) -> str:
    return json.dumps(
        {"name": "app", "version": "1.0.0", "lockfileVersion": version, "packages": packages}
    )


def _edges(findings: list) -> set[tuple[str, str]]:  # type: ignore[type-arg]
    out: set[tuple[str, str]] = set()
    for f in findings:
        for e in f.edges:
            if e.kind is EdgeType.DEPENDS_ON:
                out.add((e.src, e.dst))
    return out


HOISTED = _lock(
    {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
        "node_modules/b": {"version": "2.0.0"},
    }
)


@pytest.mark.timeout(30)
def test_hoisted_transitive_dependency_resolves() -> None:
    """The common shape: `a` depends on `b`, npm hoists `b` to the root.

    Resolution has to walk outward from `node_modules/a` to the root. A
    resolver that fails to shorten the search path spins here forever.
    """
    findings = catalog({"package-lock.json": HOISTED}, "package-lock.json")
    assert ("purl:pkg:npm/a@1.0.0", "purl:pkg:npm/b@2.0.0") in _edges(findings)


@pytest.mark.timeout(30)
def test_nested_copy_wins_over_hoisted() -> None:
    """A version conflict nests a private copy; the nearest one must win."""
    findings = catalog(
        {
            "package-lock.json": _lock(
                {
                    "": {"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}},
                    "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
                    "node_modules/a/node_modules/b": {"version": "1.9.0"},
                    "node_modules/b": {"version": "2.0.0"},
                }
            )
        },
        "package-lock.json",
    )
    edges = _edges(findings)
    assert ("purl:pkg:npm/a@1.0.0", "purl:pkg:npm/b@1.9.0") in edges
    assert ("purl:pkg:npm/a@1.0.0", "purl:pkg:npm/b@2.0.0") not in edges


@pytest.mark.timeout(30)
def test_unresolvable_and_scoped_deps_terminate() -> None:
    """A dependency with no entry anywhere must return, not spin."""
    findings = catalog(
        {
            "package-lock.json": _lock(
                {
                    "": {"dependencies": {"@scope/x": "^1.0.0"}},
                    "node_modules/@scope/x": {
                        "version": "1.0.0",
                        "dependencies": {"absent": "^1.0.0", "c": "^3.0.0"},
                    },
                    "node_modules/c": {"version": "3.0.0"},
                }
            )
        },
        "package-lock.json",
    )
    edges = _edges(findings)
    assert ("purl:pkg:npm/%40scope/x@1.0.0", "purl:pkg:npm/c@3.0.0") in edges
    assert not any(dst.endswith("absent") for _src, dst in edges)


@pytest.mark.timeout(30)
def test_workspace_member_resolves_to_root() -> None:
    findings = catalog(
        {
            "package-lock.json": _lock(
                {
                    "": {"dependencies": {"a": "^1.0.0"}},
                    "packages/ws": {"name": "ws", "version": "0.1.0",
                                    "dependencies": {"a": "^1.0.0"}},
                    "node_modules/ws": {"link": True, "resolved": "packages/ws"},
                    "node_modules/a": {"version": "1.0.0"},
                }
            )
        },
        "package-lock.json",
    )
    assert any(dst == "purl:pkg:npm/a@1.0.0" for _src, dst in _edges(findings))


@pytest.mark.timeout(60)
def test_deep_chain_is_linear_not_quadratic() -> None:
    """A 400-deep nesting chain must finish quickly."""
    packages: dict[str, object] = {"": {"dependencies": {"p0": "^1.0.0"}}}
    key = ""
    for i in range(400):
        key = f"{key}/node_modules/p{i}" if key else f"node_modules/p{i}"
        packages[key] = {"version": "1.0.0", "dependencies": {f"p{i + 1}": "^1.0.0"}}
    packages[f"{key}/node_modules/p400"] = {"version": "1.0.0"}
    findings = catalog({"package-lock.json": _lock(packages)}, "package-lock.json")
    assert len(_edges(findings)) >= 400
