"""Native-driver selection, machine-output parsers, and the
bridge that makes native findings indistinguishable downstream."""

from __future__ import annotations

import json
from pathlib import Path

from sorb.dynamic.drivers import driver_for
from sorb.dynamic.drivers.bridge import native_resolution_to_findings
from sorb.dynamic.drivers.ecosystems import (
    BazelDriver,
    GradleDriver,
    MavenDriver,
    NpmLsDriver,
    Pep517Driver,
    PnpmLsDriver,
    SwiftDriver,
)
from sorb.model import EdgeType, Tier


def _project(root: Path, *files: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for f in files:
        (root / f).write_text("x")
    return root


def test_driver_selection(tmp_path: Path) -> None:
    assert isinstance(driver_for(_project(tmp_path / "mvn", "pom.xml")), MavenDriver)
    assert isinstance(driver_for(_project(tmp_path / "g", "build.gradle.kts")), GradleDriver)
    assert isinstance(driver_for(_project(tmp_path / "py", "setup.py")), Pep517Driver)
    assert isinstance(driver_for(_project(tmp_path / "sw", "Package.swift")), SwiftDriver)
    assert isinstance(driver_for(_project(tmp_path / "bz", "MODULE.bazel")), BazelDriver)
    npm = _project(tmp_path / "npm", "package.json")
    assert isinstance(driver_for(npm), NpmLsDriver)
    pnpm = _project(tmp_path / "pnpm", "package.json", "pnpm-lock.yaml")
    assert isinstance(driver_for(pnpm), PnpmLsDriver)
    assert driver_for(_project(tmp_path / "empty")) is None


# -- parsers (fixture-tested, no toolchain) ------------------------------------------------

MVN_TREE = """com.acme:app:jar:1.0.0
+- com.google.guava:guava:jar:33.0.0-jre:compile
|  \\- com.google.guava:failureaccess:jar:1.0.2:compile
\\- junit:junit:jar:4.13.2:test
"""


def test_maven_tree_parser() -> None:
    res = MavenDriver().parse(MVN_TREE.encode(), b"")
    by_name = {d.name: d for d in res.deps}
    assert res.project_name == "com.acme:app"
    assert by_name["com.google.guava:guava"].version == "33.0.0-jre"
    assert by_name["com.google.guava:guava"].direct is True
    assert by_name["com.google.guava:failureaccess"].direct is False
    assert by_name["com.google.guava:failureaccess"].parent == "com.google.guava:guava"
    assert by_name["junit:junit"].scope == "test"


def test_gradle_init_script_json_parser() -> None:
    payload = {"org.slf4j:slf4j-api:2.0.9": "runtimeClasspath",
               "junit:junit:4.13.2": "testRuntimeClasspath"}
    stdout = ("some gradle noise\nSORB_DEPS_JSON:" + json.dumps(payload) + "\n").encode()
    res = GradleDriver().parse(stdout, b"")
    by_name = {d.name: d for d in res.deps}
    assert by_name["org.slf4j:slf4j-api"].version == "2.0.9"
    assert by_name["junit:junit"].scope == "test"


def test_npm_ls_parser() -> None:
    doc = {
        "name": "app",
        "dependencies": {
            "lodash": {"version": "4.17.21"},
            "mocha": {"version": "10.0.0", "dev": True,
                       "dependencies": {"minimist": {"version": "1.2.8"}}},
        },
    }
    res = NpmLsDriver().parse(json.dumps(doc).encode(), b"")
    by_name = {d.name: d for d in res.deps}
    assert by_name["lodash"].version == "4.17.21" and by_name["lodash"].direct is True
    assert by_name["mocha"].scope == "dev"
    assert by_name["minimist"].version == "1.2.8" and by_name["minimist"].direct is False
    assert by_name["minimist"].parent == "mocha"


def test_pep517_metadata_parser() -> None:
    line = "SORB_METADATA_JSON:" + json.dumps(
        {"name": "dynpkg", "requires_dist": ["requests>=2.0", "click (==8.1.7)"]}
    )
    res = Pep517Driver().parse((line + "\n").encode(), b"")
    assert res.project_name == "dynpkg"
    by_name = {d.name: d for d in res.deps}
    assert "requests" in by_name and "click" in by_name
    assert by_name["click"].version == "8.1.7"  # pinned == extracted


def test_pep517_error_degrades() -> None:
    res = Pep517Driver().parse(b"SORB_PEP517_ERROR:RuntimeError('dynamic boom')\n", b"")
    assert not res.raw_ok and res.warnings


def test_swift_and_bazel_parsers() -> None:
    swift_doc = {
        "name": "App",
        "dependencies": [
            {"identity": "swift-nio", "version": "2.62.0",
             "url": "https://github.com/apple/swift-nio.git",
             "dependencies": [{"identity": "swift-atomics", "version": "1.2.0"}]}
        ],
    }
    res = SwiftDriver().parse(json.dumps(swift_doc).encode(), b"")
    by_name = {d.name: d for d in res.deps}
    assert by_name["swift-nio"].version == "2.62.0"
    assert by_name["swift-nio"].namespace == "github.com/apple"
    assert by_name["swift-atomics"].parent == "swift-nio"

    bazel_doc = {"key": "<root>", "root": True, "dependencies": [
        {"key": "rules_go@0.46.0", "dependencies": [{"key": "gazelle@0.35.0"}]}
    ]}
    bres = BazelDriver().parse(json.dumps(bazel_doc).encode(), b"")
    bnames = {d.name: d for d in bres.deps}
    assert bnames["rules_go"].version == "0.46.0"
    assert bnames["gazelle"].parent == "rules_go"


# -- bridge: native findings are indistinguishable downstream ------------------------------


def test_bridge_produces_locked_tier_findings() -> None:
    res = MavenDriver().parse(MVN_TREE.encode(), b"")
    findings = native_resolution_to_findings(res, ".", "s1")
    assert findings
    guava = next(f for f in findings if f.claim.name == "com.google.guava:guava")
    # tier and shape are identical to any locked-tier lockfile finding
    assert guava.evidence[0].tier is Tier.LOCKED
    assert guava.claim.purl == "pkg:maven/com.google.guava/guava@33.0.0-jre"
    assert guava.claim.version == "33.0.0-jre"
    assert guava.evidence[0].confidence > 0.9
    edge = guava.edges[0]
    assert edge.kind is EdgeType.DEPENDS_ON and edge.direct is True


def test_native_upgrades_gradle_from_incomplete(tmp_path: Path, monkeypatch) -> None:
    """A no-lock Gradle project goes from resolution:incomplete
    to a full locked-tier graph under native mode — via the pipeline, with the
    driver run stubbed (no toolchain needed offline)."""
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.dynamic.drivers.base import NativeResolution, ResolvedDep
    from sorb.graph.store import GraphStore

    project = tmp_path / "gradle-app"
    project.mkdir()
    (project / "build.gradle.kts").write_text(
        'dependencies {\n  implementation("com.google.guava:guava:33.0.0-jre")\n}\n'
    )

    # --- pure mode: declared-tier, resolution:incomplete (no lock) ---
    pure_cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    pure = run_scan(str(project), pure_cfg, store_path=tmp_path / "pure.sorb.db")
    ps = GraphStore.open_readonly(pure.store_path)
    try:
        guava = ps.find_component("com.google.guava:guava")[0]
        assert guava.tier is Tier.DECLARED
        assert any(a["code"] == "resolution-incomplete"
                   for a in ps.annotations_for("component", guava.id))
    finally:
        ps.close()

    # --- native mode: stub the sandboxed driver run to return a resolution ---
    fake = NativeResolution(
        driver_id="gradle",
        deps=[
            ResolvedDep(ecosystem="maven", name="com.google.guava:guava",
                        version="33.0.0-jre", namespace="com.google.guava", direct=True),
            ResolvedDep(ecosystem="maven", name="com.google.guava:failureaccess",
                        version="1.0.2", namespace="com.google.guava", direct=False,
                        parent="com.google.guava:guava"),
        ],
        project_kind="gradle-project",
    )
    monkeypatch.setattr(
        "sorb.dynamic.drivers.run_native_driver", lambda *a, **k: fake
    )
    native_cfg = load_config(
        flags={"resolve": "native"}, env={}, user_config_path=tmp_path / "nc.toml"
    )
    native = run_scan(str(project), native_cfg, store_path=tmp_path / "native.sorb.db")
    ns = GraphStore.open_readonly(native.store_path)
    try:
        guava = ns.find_component("com.google.guava:guava@33.0.0-jre")[0]
        assert guava.tier is Tier.LOCKED  # upgraded to locked tier
        # transitive that only native resolution could find
        assert ns.find_component("com.google.guava:failureaccess@1.0.2")
        # downstream can't tell it was native: it's just a locked-tier component
        evidence = ns.evidence_for_component(guava.id)
        assert any(e["tier"] == "locked" for e in evidence)
    finally:
        ns.close()
