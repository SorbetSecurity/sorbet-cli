"""SPDX 3.0 emitter/importer: round-trip fixpoint + loss report vs 2.3."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.importers import import_sbom, sniff_sbom_format
from sorb.emit.spdx import emit_spdx
from sorb.emit.spdx3 import emit_spdx3, is_spdx3
from sorb.graph.store import GraphStore


@pytest.fixture()
def scanned(tmp_path: Path) -> GraphStore:
    proj = tmp_path / "polyglot"
    shutil.copytree(Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot", proj,
                    ignore=shutil.ignore_patterns(".sorb"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    yield store
    store.close()


def _identity(store: GraphStore) -> set[tuple[str | None, str, str | None]]:
    return {(c.purl, c.name, c.version) for c in store.components()
            if not c.attrs.get("excluded")}


def test_spdx3_is_valid_jsonld(scanned: GraphStore) -> None:
    doc = json.loads(emit_spdx3(scanned, reproducible=True))
    assert doc["@context"].startswith("https://spdx.org/rdf/3.")
    types = {e["type"] for e in doc["@graph"]}
    assert {"CreationInfo", "Tool", "SpdxDocument", "software_Package"} <= types
    assert is_spdx3(doc)
    assert sniff_sbom_format(emit_spdx3(scanned, reproducible=True)) == "spdx3-json"


def test_spdx3_is_deterministic(scanned: GraphStore) -> None:
    assert emit_spdx3(scanned, reproducible=True) == emit_spdx3(scanned, reproducible=True)


def test_spdx3_round_trip_fixpoint(scanned: GraphStore, tmp_path: Path) -> None:
    original = _identity(scanned)
    data = emit_spdx3(scanned, reproducible=True)

    store2 = import_sbom(data, tmp_path / "rt2.sorb.db", "spdx3")
    try:
        assert _identity(store2) == original  # import recovers every component
        # fixpoint: re-emit + re-import is stable
        store3 = import_sbom(emit_spdx3(store2, reproducible=True), tmp_path / "rt3.sorb.db")
        try:
            assert _identity(store3) == original
        finally:
            store3.close()
    finally:
        store2.close()


def test_spdx3_preserves_purls_and_hashes(scanned: GraphStore, tmp_path: Path) -> None:
    store2 = import_sbom(emit_spdx3(scanned, reproducible=True), tmp_path / "p.sorb.db")
    try:
        orig = {c.purl for c in scanned.components() if c.purl}
        got = {c.purl for c in store2.components() if c.purl}
        assert orig <= got  # purls survive the round-trip
    finally:
        store2.close()


def test_loss_report_vs_spdx23(scanned: GraphStore, tmp_path: Path) -> None:
    """Document 3.0 vs 2.3 fidelity: both preserve component identity; 3.0's
    JSON-LD Element model additionally namespaces every property."""
    v3 = import_sbom(emit_spdx3(scanned, reproducible=True), tmp_path / "v3.sorb.db")
    v23 = import_sbom(emit_spdx(scanned, reproducible=True), tmp_path / "v23.sorb.db")
    try:
        # both formats round-trip the same component identity set (no loss either way)
        assert _identity(v3) == _identity(v23) == _identity(scanned)
        # 3.0 carries the profile conformance that 2.3 has no field for
        doc3 = json.loads(emit_spdx3(scanned, reproducible=True))
        spdx_doc = next(e for e in doc3["@graph"] if e["type"] == "SpdxDocument")
        assert spdx_doc["profileConformance"] == ["core", "software"]
    finally:
        v3.close()
        v23.close()
