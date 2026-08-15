"""Determinism, tier caps, family pinning, orphan modifier."""

from __future__ import annotations

import random
from dataclasses import replace
from pathlib import Path

from sorb.core.reconcile import reconcile
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.graph.store import GraphStore
from sorb.model import (
    ComponentClaim,
    Coordinates,
    EdgeClaim,
    EdgeType,
    EvidenceRecord,
    Finding,
    ProjectClaim,
    Scope,
    Tier,
)


def _finding(
    name: str,
    version: str | None,
    tier: Tier,
    eco: str = "pypi",
    technique: str = "lockfile-parse",
    confidence: float = 0.9,
    path: str = "f",
) -> Finding:
    purl = f"pkg:{eco}/{name}@{version}" if version else None
    return Finding(
        claim=ComponentClaim(
            ctype="library", name=name, version=version, purl=purl, ecosystem=eco
        ),
        evidence=(
            EvidenceRecord(
                technique=technique,
                tier=tier,
                detector="t/x@1",
                location=Coordinates(source_id="s1", path=path),
                confidence=confidence,
            ),
        ),
    )


def _run(tmp_path: Path, findings: list[Finding], name: str = "r") -> GraphStore:
    store = GraphStore.create(tmp_path / f"{name}.db")
    store.set_meta("subject", "test")
    fids = [(store.add_finding(f), f) for f in findings]
    reconcile(store, fids, [], "s1")
    return store


def test_shuffled_input_identical_output(tmp_path: Path) -> None:
    findings = [
        _finding("requests", "2.31.0", Tier.LOCKED),
        _finding("requests", "2.32.0", Tier.INSTALLED, technique="installed-state"),
        _finding("urllib3", "2.2.1", Tier.LOCKED),
        _finding("lodash", "4.17.21", Tier.LOCKED, eco="npm"),
        _finding("lodash", None, Tier.DECLARED, eco="npm", technique="manifest-parse"),
    ]
    exports = []
    for seed in (1, 2, 3):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        store = _run(tmp_path, shuffled, name=f"r{seed}")
        # The SBOM projection is the product — it must not depend on input order.
        exports.append(emit_cyclonedx(store, reproducible=True))
        store.close()
    assert exports[0] == exports[1] == exports[2]


def test_inferred_pileup_never_exceeds_cap(tmp_path: Path) -> None:
    findings = [
        _finding("zlib", "1.2.13", Tier.INFERRED, eco="generic",
                 technique="file-fingerprint", confidence=0.84, path=f"p{i}")
        for i in range(20)
    ]
    store = _run(tmp_path, findings)
    comps = store.components()
    assert len(comps) == 1
    assert comps[0].confidence <= 0.85  # confidence cap table
    store.close()


def test_single_version_family_pins_highest_tier(tmp_path: Path) -> None:
    store = _run(
        tmp_path,
        [
            _finding("requests", "2.31.0", Tier.LOCKED),
            _finding("requests", "2.32.0", Tier.INSTALLED, technique="installed-state"),
            _finding("requests", None, Tier.DECLARED, technique="manifest-parse"),
        ],
    )
    comps = store.components()
    assert len(comps) == 1
    assert comps[0].version == "2.32.0"  # installed wins
    anns = {a["code"] for a in store.annotations_for("component", comps[0].id)}
    assert "drift:locked-vs-installed" in anns
    store.close()


def test_multi_version_npm_stays_separate(tmp_path: Path) -> None:
    store = _run(
        tmp_path,
        [
            _finding("minimist", "0.0.8", Tier.LOCKED, eco="npm"),
            _finding("minimist", "1.2.8", Tier.LOCKED, eco="npm"),
        ],
    )
    assert len(store.components()) == 2  # nested versions are legitimate in npm
    store.close()


def test_same_tier_conflict_annotated(tmp_path: Path) -> None:
    store = _run(
        tmp_path,
        [
            _finding("requests", "2.31.0", Tier.LOCKED, path="poetry.lock"),
            _finding("requests", "2.30.0", Tier.LOCKED, path="uv.lock"),
        ],
    )
    comps = store.components()
    assert len(comps) == 1
    anns = {a["code"] for a in store.annotations_for("component", comps[0].id)}
    assert "version-conflict" in anns
    store.close()


def test_versionless_declared_merges_into_single_concrete(tmp_path: Path) -> None:
    store = _run(
        tmp_path,
        [
            _finding("lodash", "4.17.21", Tier.LOCKED, eco="npm"),
            _finding("lodash", None, Tier.DECLARED, eco="npm", technique="manifest-parse"),
        ],
    )
    comps = store.components()
    assert len(comps) == 1
    assert comps[0].version == "4.17.21"
    assert len(store.evidence_for_component(comps[0].id)) == 2
    store.close()


# -- scope propagation ------------------------------------------------------------------


def _scope_store(tmp_path: Path, findings: list[Finding], name: str) -> GraphStore:
    store = GraphStore.create(tmp_path / f"{name}.db")
    store.set_meta("subject", "test")
    fids = [(store.add_finding(f), f) for f in findings]
    reconcile(store, fids, [ProjectClaim(path=".", name="proj", kind="python")], "s1")
    return store


def _scopes(store: GraphStore) -> dict[str, str | None]:
    return {c.name: c.attrs.get("scope") for c in store.components()}


def _dep(src: str, dst: str, **kw: object) -> EdgeClaim:
    return EdgeClaim(kind=EdgeType.DEPENDS_ON, src=src, dst=dst, **kw)  # type: ignore[arg-type]


def test_optional_dependency_is_not_scoped_runtime(tmp_path: Path) -> None:
    """`[project.optional-dependencies]` declares availability, not a requirement.

    Scoping an extra `runtime` puts every dev tool a project lists under an
    extra into `--scope runtime` output.
    """
    store = _scope_store(
        tmp_path,
        [
            replace(
                _finding("typer", "0.12.0", Tier.INSTALLED, technique="installed-state"),
                edges=(_dep("project:.", "family:pypi/typer", scope=Scope.RUNTIME, direct=True),),
            ),
            replace(
                _finding("mypy", "1.10.0", Tier.INSTALLED, technique="installed-state"),
                edges=(_dep("project:.", "family:pypi/mypy", scope=Scope.OPTIONAL, direct=True),),
            ),
        ],
        "optional",
    )
    scopes = _scopes(store)
    assert scopes["typer"] == "runtime"
    assert scopes["mypy"] == "optional"
    store.close()


def test_extras_gated_edge_does_not_promote_to_runtime(tmp_path: Path) -> None:
    """`idna[all]` naming a test tool must not make it a runtime dependency.

    An environment marker is different: it says *where* a real dependency
    applies, so it keeps propagating.
    """
    idna = replace(
        _finding("idna", "3.18", Tier.INSTALLED, technique="installed-state"),
        edges=(
            _dep("project:.", "family:pypi/idna", scope=Scope.RUNTIME, direct=True),
            _dep("purl:pkg:pypi/idna@3.18", "family:pypi/pytest", marker='extra == "all"'),
            _dep("purl:pkg:pypi/idna@3.18", "family:pypi/anyio", marker='python_version < "3.11"'),
        ),
    )
    store = _scope_store(
        tmp_path,
        [
            idna,
            _finding("pytest", "8.3.2", Tier.INSTALLED, technique="installed-state"),
            _finding("anyio", "4.4.0", Tier.INSTALLED, technique="installed-state"),
        ],
        "extras",
    )
    scopes = _scopes(store)
    assert scopes["idna"] == "runtime"
    assert scopes["pytest"] == "optional"  # gated behind an extra nobody requested
    assert scopes["anyio"] == "runtime"  # environment marker: still a real dependency
    conditional = {
        c.name: c.attrs.get("conditional") for c in store.components()
    }
    assert conditional["pytest"] is True
    store.close()


def test_conan_manifest_and_lock_reconcile_to_one_component(tmp_path: Path) -> None:
    """A conanfile declaration and its conan.lock entry are one package.

    The lock's purl carries a recipe revision the manifest cannot know, so
    without family merging the same dependency is reported twice.
    """
    manifest = _finding("zlib", "1.3.1", Tier.DECLARED, eco="conan", technique="manifest-parse")
    locked = replace(
        _finding("zlib", "1.3.1", Tier.LOCKED, eco="conan"),
        claim=ComponentClaim(
            ctype="library", name="zlib", version="1.3.1", ecosystem="conan",
            purl="pkg:conan/zlib@1.3.1?rrev=f1fadf0d3b196dc0332750354ad8ab7b",
        ),
    )
    store = _run(tmp_path, [manifest, locked], name="conan")
    comps = [c for c in store.components() if c.name == "zlib"]
    assert len(comps) == 1, [c.purl for c in comps]
    assert comps[0].version == "1.3.1"
    assert comps[0].tier is Tier.LOCKED  # the lock pins it
    assert "rrev=" in (comps[0].purl or "")  # and its revision survives
    assert len(store.evidence_for_component(comps[0].id)) == 2
    store.close()


def _vcpkg(name: str, version: str, triplet: str, tier: Tier, technique: str) -> Finding:
    qualifiers = (("triplet", triplet),)
    return replace(
        _finding(name, version, tier, eco="vcpkg", technique=technique),
        claim=ComponentClaim(
            ctype="library", name=name, version=version, ecosystem="vcpkg",
            purl=f"pkg:vcpkg/{name}@{version}?triplet={triplet}", qualifiers=qualifiers,
        ),
    )


def test_vcpkg_port_merges_within_a_triplet(tmp_path: Path) -> None:
    """The per-port SPDX and the install database describe one library.

    They disagree only on the port-version suffix (`1.3.2` vs `1.3.2#1`), so
    without a family merge the same installed port is reported twice.
    """
    store = _run(
        tmp_path,
        [
            _vcpkg("zlib", "1.3.2", "x64-linux", Tier.DECLARED, "imported-sbom"),
            _vcpkg("zlib", "1.3.2#1", "x64-linux", Tier.INSTALLED, "installed-state"),
        ],
        name="vcpkg-one",
    )
    comps = [c for c in store.components() if c.name == "zlib"]
    assert len(comps) == 1, [(c.version, c.purl) for c in comps]
    assert comps[0].tier is Tier.INSTALLED
    assert len(store.evidence_for_component(comps[0].id)) == 2
    store.close()


def test_vcpkg_triplets_stay_separate(tmp_path: Path) -> None:
    """Static and dynamic builds of one port are different artifacts.

    The triplet carries linkage, which is security-relevant: a statically
    linked port lives inside the final binary. Merging them would erase that.
    """
    store = _run(
        tmp_path,
        [
            _vcpkg("zlib", "1.3.2", "x64-windows", Tier.INSTALLED, "installed-state"),
            _vcpkg("zlib", "1.3.2", "x64-windows-static", Tier.INSTALLED, "installed-state"),
        ],
        name="vcpkg-two",
    )
    comps = [c for c in store.components() if c.name == "zlib"]
    assert len(comps) == 2, [(c.version, c.purl) for c in comps]
    assert {c.qualifiers.get("triplet") for c in comps} == {"x64-windows", "x64-windows-static"}
    store.close()
