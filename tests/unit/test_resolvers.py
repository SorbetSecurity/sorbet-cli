"""Semver algebra, npm resolver + verify mode + provider
caching, Go MVS, Maven mediation, enrichment."""

from __future__ import annotations

import json

import httpx
import pytest

from sorb.cache import Cas
from sorb.resolve.maven import mediate
from sorb.resolve.mvs import mvs_build_list
from sorb.resolve.npm import resolve_npm, verify_lock
from sorb.resolve.provider import RegistryMetadataProvider
from sorb.resolve.semver import Version, max_satisfying, satisfies

# -- node-semver conformance (recorded node-semver behavior) ----------------------------

SATISFIES_CASES = [
    ("1.2.3", "^1.2.3", True),
    ("1.9.9", "^1.2.3", True),
    ("2.0.0", "^1.2.3", False),
    ("0.2.5", "^0.2.3", True),
    ("0.3.0", "^0.2.3", False),
    ("0.0.3", "^0.0.3", True),
    ("0.0.4", "^0.0.3", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("1.9.0", "~1", True),
    ("2.0.0", "~1", False),
    ("1.2.3", "1.2.x", True),
    ("1.3.0", "1.2.x", False),
    ("1.5.0", "1.x", True),
    ("1.5.0", "*", True),
    ("2.0.0", ">=1.2.3 <3", True),
    ("3.0.0", ">=1.2.3 <3", False),
    ("1.2.3", "1.2.3 - 2.3.4", True),
    ("2.3.4", "1.2.3 - 2.3.4", True),
    ("2.3.5", "1.2.3 - 2.3.4", False),
    ("2.3.9", "1.2.3 - 2.3", True),
    ("2.4.0", "1.2.3 - 2.3", False),
    ("1.0.0", "1.2.3 || >=2", False),
    ("2.5.0", "1.2.3 || >=2", True),
    ("1.2.3", "1.2.3 || >=2", True),
    # prerelease opt-in rules
    ("1.2.3-alpha.1", "^1.2.3", False),
    ("1.2.3-alpha.1", ">=1.2.3-alpha.0", True),
    ("1.2.4-alpha.1", ">=1.2.3-alpha.0", False),
    ("1.3.0", ">1.2", True),
    ("1.2.9", ">1.2", False),
    ("1.1.9", "<1.2", True),
    ("1.2.0", "<1.2", False),
]


def test_semver_satisfies_conformance() -> None:
    for version, range_, expected in SATISFIES_CASES:
        assert satisfies(version, range_) is expected, f"{version} vs {range_!r}"


def test_semver_ordering_and_max_satisfying() -> None:
    assert Version.parse("1.10.0") > Version.parse("1.9.0")
    assert Version.parse("1.0.0-alpha") < Version.parse("1.0.0")
    assert Version.parse("1.0.0-alpha.2") > Version.parse("1.0.0-alpha.1")
    assert Version.parse("1.0.0-alpha.beta") > Version.parse("1.0.0-alpha.2")
    versions = ["1.2.2", "1.2.3", "1.9.9", "2.0.0", "2.0.1-rc.1"]
    assert max_satisfying(versions, "^1.2.3") == "1.9.9"
    assert max_satisfying(versions, ">=2") == "2.0.0"  # prerelease not opted in
    assert max_satisfying(versions, "^3") is None


# -- npm resolver + provider -----------------------------------------------------------


def packument(name: str, versions: dict[str, dict[str, str]]) -> dict:
    return {"name": name, "versions": {v: {"dependencies": deps} for v, deps in versions.items()}}


REGISTRY: dict[str, dict] = {
    p["name"]: p
    for p in [
        packument("a", {"1.0.0": {"b": "^2.0.0"}, "1.1.0": {"b": "^2.1.0", "c": "~3.2.0"}}),
        packument("b", {"2.0.0": {}, "2.1.0": {"d": "1.x"}, "3.0.0": {}}),
        packument("c", {"3.2.0": {}, "3.2.5": {"d": ">=1.2.0 <2"}, "3.3.0": {}}),
        packument("d", {"1.0.0": {}, "1.2.4": {}, "2.0.0": {}}),
    ]
}

# committed `npm ls --json`-style ground truth for the tree rooted at a@^1.0.0, e…
NPM_LS_EXPECTED = {"a": "1.1.0", "b": "2.1.0", "c": "3.2.5", "d": "1.2.4"}


def registry_provider(tmp_path, offline: bool = False) -> RegistryMetadataProvider:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        name = request.url.path.lstrip("/")
        if name in REGISTRY:
            return httpx.Response(200, json=REGISTRY[name])
        return httpx.Response(404)

    provider = RegistryMetadataProvider(
        cas=Cas(tmp_path / "cas"),
        offline=offline,
        transport=httpx.MockTransport(handler),
    )
    provider._calls = calls  # type: ignore[attr-defined]
    return provider


def test_npm_resolution_matches_recorded_tree(tmp_path) -> None:
    provider = registry_provider(tmp_path)
    result = resolve_npm({"a": "^1.0.0"}, provider)
    assert not result.incomplete
    assert {k: v for k, v in result.resolved.items() if "@" not in k} == NPM_LS_EXPECTED
    # requested-range edges recorded
    assert ("a", "b", "^2.1.0", "2.1.0") in result.edges


def test_npm_second_resolve_is_network_free(tmp_path) -> None:
    provider = registry_provider(tmp_path)
    resolve_npm({"a": "^1.0.0"}, provider)
    first = provider.network_requests
    assert first > 0
    # fresh provider over the same CAS: socket guard is on, cache must carry it
    cached = RegistryMetadataProvider(
        cas=Cas(tmp_path / "cas"),
        transport=httpx.MockTransport(lambda r: httpx.Response(500)),
    )
    result = resolve_npm({"a": "^1.0.0"}, cached)
    assert not result.incomplete
    assert cached.network_requests == 0


def test_npm_offline_no_lock_is_incomplete(tmp_path) -> None:
    provider = registry_provider(tmp_path, offline=True)
    result = resolve_npm({"a": "^1.0.0"}, provider)
    assert result.incomplete and result.incomplete[0][0] == "a"
    assert "offline" in result.incomplete[0][2] or "unavailable" in result.incomplete[0][2]


def test_npm_unsatisfiable_range(tmp_path) -> None:
    provider = registry_provider(tmp_path)
    result = resolve_npm({"a": "^9.0.0"}, provider)
    assert result.incomplete and "no published version" in result.incomplete[0][2]


def test_verify_lock_flags_out_of_range() -> None:
    checks = verify_lock(
        {"lodash": "^4.17.21", "left-pad": "^1.0.0", "linked": "file:../linked"},
        {"lodash": "4.17.21", "left-pad": "0.9.0"},
    )
    by = {c.name: c for c in checks}
    assert by["lodash"].satisfied is True
    assert by["left-pad"].satisfied is False
    assert "linked" not in by  # non-registry specifiers skipped


# -- Go MVS -----------------------------------------------------------------------------


def test_mvs_conformance() -> None:
    """Recorded from `go list -m all` semantics for a diamond with mixed minimums."""
    graph = {
        ("example.com/x", "v1.1.0"): [("example.com/z", "v1.2.0")],
        ("example.com/x", "v1.4.0"): [("example.com/z", "v1.2.0")],
        ("example.com/y", "v1.2.0"): [("example.com/x", "v1.4.0"), ("example.com/z", "v1.3.0")],
        ("example.com/z", "v1.2.0"): [],
        ("example.com/z", "v1.3.0"): [],
    }
    build = mvs_build_list(
        "example.com/main",
        [("example.com/x", "v1.1.0"), ("example.com/y", "v1.2.0")],
        graph,
    )
    assert build == {
        "example.com/x": "v1.4.0",  # y needs a newer x than main asked for
        "example.com/y": "v1.2.0",
        "example.com/z": "v1.3.0",  # max of the minimums (1.2.0, 1.3.0)
    }


def test_mvs_replace_directive() -> None:
    graph = {("example.com/fork", "v1.5.0"): []}
    build = mvs_build_list(
        "m",
        [("example.com/orig", "v1.0.0")],
        graph,
        replace={"example.com/orig": ("example.com/fork", "v1.5.0")},
    )
    assert build == {"example.com/fork": "v1.5.0"}


# -- Maven mediation ----------------------------------------------------------------------


def test_maven_nearest_wins() -> None:
    """Recorded `mvn dependency:tree` mediation: depth 1 beats depth 2."""
    tree = {
        ("org.a:a", "1.0"): [("org.log:log", "2.0")],
        ("org.b:b", "1.0"): [("org.mid:mid", "1.0")],
        ("org.mid:mid", "1.0"): [("org.log:log", "3.0")],
    }
    mediated = mediate([("org.a:a", "1.0"), ("org.b:b", "1.0"), ("org.log:log", "1.0")], tree)
    # root's own declaration (depth 0) is nearest of all
    assert mediated["org.log:log"] == "1.0"

    mediated2 = mediate([("org.a:a", "1.0"), ("org.b:b", "1.0")], tree)
    # depth-1 (via a) beats depth-2 (via b→mid)
    assert mediated2["org.log:log"] == "2.0"


def test_maven_dependency_management_precedence() -> None:
    tree = {("org.a:a", "1.0"): [("org.log:log", "2.0")]}
    mediated = mediate(
        [("org.a:a", "1.0")], tree, dependency_management={"org.log:log": "2.9"}
    )
    assert mediated["org.log:log"] == "2.9"  # root depMgmt overrides transitive


# -- enrichment -----------------------------------------------------------------------------


def test_enrichment_is_additive_and_degrades(tmp_path, monkeypatch) -> None:
    from sorb.core.config import load_config
    from sorb.core.enrich import enrich_components
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"lodash": "^4.17.21"}}))
    (project / "node_modules/lodash").mkdir(parents=True)
    (project / "node_modules/lodash/package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.21"})
    )
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    offline_result = run_scan(str(project), cfg, store_path=tmp_path / "off.sorb.db")

    meta = {
        "name": "lodash",
        "description": "Lodash modular utilities.",
        "homepage": "https://lodash.com/",
        "versions": {"4.17.21": {"license": "MIT"}},
    }
    provider = RegistryMetadataProvider(
        cas=Cas(tmp_path / "cas"),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=meta)),
    )
    store = GraphStore.open_rw(offline_result.store_path)
    try:
        n, warnings = enrich_components(store, provider)
        assert n == 1 and not warnings
        store.commit()
        lodash = store.find_component("lodash@4.17.21")[0]
        # additive-only, source-marked; identity untouched
        assert lodash.attrs["description"] == "Lodash modular utilities."
        assert lodash.attrs["enrichment_source"] == "npm-registry"
        assert lodash.version == "4.17.21"
    finally:
        store.close()

    # unreachable registry → warning, not failure
    broken = RegistryMetadataProvider(
        cas=Cas(tmp_path / "cas2"),
        transport=httpx.MockTransport(lambda r: httpx.Response(500)),
    )
    store2 = GraphStore.open_rw(offline_result.store_path)
    try:
        _n, warnings2 = enrich_components(store2, broken)
        assert warnings2 and warnings2[0][0] == "SORB-W014"
    finally:
        store2.close()


def test_lock_outside_range_becomes_drift(tmp_path) -> None:
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"left-pad": "^1.3.0"}})
    )
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": {"left-pad": "^1.3.0"}},
                    "node_modules/left-pad": {"version": "0.9.0"},
                },
            }
        )
    )
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(project), cfg, store_path=tmp_path / "run.sorb.db")
    assert any(code == "SORB-W035" for code, _ in result.warnings)
    store = GraphStore.open_readonly(result.store_path)
    try:
        codes = {a["code"] for a in store.all_annotations()}
        assert "drift:lock-outside-range" in codes
    finally:
        store.close()


@pytest.mark.parametrize("eco,a,b,expected", [("golang", "v1.10.0", "v1.9.0", 1)])
def test_ident_compare_used_by_mvs(eco: str, a: str, b: str, expected: int) -> None:
    from sorb.ident import compare

    assert compare(eco, a, b) == expected
