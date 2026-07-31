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


# -- Bun ---------------------------------------------------------------------------------


def test_bun_lock_is_jsonc_with_trailing_commas() -> None:
    """Bun writes trailing commas, which strict JSON rejects.

    Commas inside string values (integrity hashes contain none, but URLs and
    metadata can) must survive the strip untouched.
    """
    lock = """{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", }, },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-A9lIwHPqLvKvI2Y3ZzHmwPCLHnMWSlaZSbHiHZUOgN8yQ4B4pIVTdQXBnRQmDRTIRRUR/GxLNTYtxdlUEQeRSg=="],
    "camel-case": ["camel-case@4.1.2", "", {}, "sha512-gxGWBrTkLJprsWBmqf5bkH8gAI7xzWMPGGDeAhcTOMBrLoSFsuxfDdxWK5pFQwvVUuUJdC0eGP1jzXeVzVIYQg=="],
    "app/node_modules/camel-case": ["camel-case@3.0.0", "", {}, ""],
    "bun-tracestrings": ["bun-tracestrings@github:oven-sh/bun.report#912ca63", "", {}, ""],
    "types": ["@types/bun@workspace:*", "", {}, ""],
  },
}
"""
    found = catalog({"bun.lock": lock}, "bun.lock")
    pairs = {(f.claim.name, f.claim.version) for f in found}
    assert ("left-pad", "1.3.0") in pairs
    # npm allows one name at several versions; both survive
    assert ("camel-case", "4.1.2") in pairs and ("camel-case", "3.0.0") in pairs
    # a protocol reference is not a released version
    assert ("bun-tracestrings", None) in pairs
    assert ("@types/bun", None) in pairs

    left = next(f for f in found if f.claim.name == "left-pad")
    assert left.claim.purl == "pkg:npm/left-pad@1.3.0"
    assert dict(left.claim.hashes).get("sha512")  # SRI decoded to hex


def test_bun_jsonc_stripper_leaves_strings_alone() -> None:
    from sorb.catalogers.js import strip_jsonc_trailing_commas

    assert strip_jsonc_trailing_commas('{"a": [1, 2,], }') == '{"a": [1, 2] }'
    # a comma-then-brace *inside a string* is not a trailing comma
    assert strip_jsonc_trailing_commas('{"u": "a,}b"}') == '{"u": "a,}b"}'


# -- Deno --------------------------------------------------------------------------------


def test_deno_lock_splits_jsr_and_npm_and_strips_peer_suffixes() -> None:
    """deno.lock keys carry `_peer@ver` suffixes recording peer resolution.

    A semver never contains an underscore, but a package *name* can
    (`@types/babel__core`), so the version — not the name — ends at the first
    underscore.
    """
    lock = json.dumps(
        {
            "version": "5",
            "specifiers": {"jsr:@std/assert@^1": "1.0.6"},
            "jsr": {"@std/assert@1.0.6": {"integrity": "ab" * 32}},
            "npm": {
                "chalk@5.3.0": {"integrity": "sha512-" + "A" * 86 + "=="},
                "@types/babel__core@7.20.5": {"integrity": "sha512-" + "B" * 86 + "=="},
                "@rollup/plugin-babel@5.3.1_@babel+core@7.28.5_rollup@2.80.0": {},
            },
        }
    )
    found = catalog({"deno.lock": lock}, "deno.lock")
    got = {(f.claim.ecosystem, f.claim.name, f.claim.version) for f in found}
    assert ("jsr", "@std/assert", "1.0.6") in got
    assert ("npm", "chalk", "5.3.0") in got
    assert ("npm", "@types/babel__core", "7.20.5") in got  # __ is part of the name
    assert ("npm", "@rollup/plugin-babel", "5.3.1") in got  # peer suffix dropped
    # the two registries keep their own purl types
    assert {f.claim.purl for f in found if f.claim.name == "@std/assert"} == {
        "pkg:jsr/%40std/assert@1.0.6"
    }


def test_aliased_npm_install_is_not_dropped() -> None:
    """`npm i wrap-ansi-cjs@npm:wrap-ansi@7.0.0` installs under another name.

    Requiring the directory to match the declared name discarded every aliased
    package — node:20-alpine ships exactly this, and wrap-ansi@7.0.0 vanished.
    """
    real = json.dumps({"name": "wrap-ansi", "version": "7.0.0", "license": "MIT"})
    path = "usr/lib/node_modules/npm/node_modules/wrap-ansi-cjs/package.json"
    found = catalog({path: real}, path)
    assert len(found) == 1
    claim = found[0].claim
    assert (claim.name, claim.version) == ("wrap-ansi", "7.0.0")
    assert claim.purl == "pkg:npm/wrap-ansi@7.0.0"
    # the directory it was installed under is recorded, not silently dropped
    assert dict(claim.attrs)["installed-as"] == "wrap-ansi-cjs"

    # a normally-installed package carries no alias marker
    plain = json.dumps({"name": "left-pad", "version": "1.3.0"})
    ppath = "node_modules/left-pad/package.json"
    pfound = catalog({ppath: plain}, ppath)
    assert "installed-as" not in dict(pfound[0].claim.attrs)
