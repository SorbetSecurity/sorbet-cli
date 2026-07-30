"""Determinism, tier caps, family pinning, orphan modifier."""

from __future__ import annotations

import random
from pathlib import Path

from sorb.core.reconcile import reconcile
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.graph.store import GraphStore
from sorb.model import (
    ComponentClaim,
    Coordinates,
    EvidenceRecord,
    Finding,
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
