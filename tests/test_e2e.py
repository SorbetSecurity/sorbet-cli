"""End-to-end acceptance for the core scan pipeline (+ snapshot gates).

`sorb scan` on the polyglot corpus fixture produces evidence-backed
CycloneDX + SPDX + native outputs; `explain` answers provenance; output is
byte-deterministic; exit codes are disjoint.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sorb.cli.main import app
from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.emit.native import export_native, import_native
from sorb.emit.spdx import emit_spdx
from sorb.graph.store import GraphStore

runner = CliRunner()


def _scan(polyglot: Path, tmp_path: Path, name: str = "run"):
    cfg = load_config(target=polyglot, flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    return run_scan(str(polyglot), cfg, store_path=tmp_path / f"{name}.sorb.db")


@pytest.fixture()
def scanned(polyglot: Path, tmp_path: Path):
    result = _scan(polyglot, tmp_path)
    store = GraphStore.open_readonly(result.store_path)
    yield result, store
    store.close()


def test_components_match_expected(polyglot: Path, scanned) -> None:
    result, store = scanned
    expected = json.loads((polyglot / "expected.json").read_text())
    got = {
        (c.name, c.version, c.tier.label, c.attrs.get("ecosystem"))
        for c in store.components()
    }
    want = {
        (e["name"], e["version"], e["tier"], e["ecosystem"]) for e in expected["components"]
    }
    assert got == want

    by_name = {c.name: c for c in store.components()}
    for e in expected["components"]:
        comp = by_name[e["name"]]
        if "scope" in e:
            assert comp.attrs.get("scope") == e["scope"], e["name"]
        if e.get("conditional"):
            assert comp.attrs.get("conditional") is True, e["name"]

    codes = {a["code"] for a in store.all_annotations()}
    assert set(expected["annotation_codes"]) <= codes
    for code, names in expected["drift"].items():
        subjects = {
            store.component_by_id(a["subject_id"]).name
            for a in store.all_annotations()
            if a["code"] == code and a["subject_kind"] == "component"
        }
        assert set(names) == subjects, code
    assert not result.had_scan_errors


def test_every_component_has_evidence(scanned) -> None:
    _result, store = scanned
    for c in store.components():
        evidence = store.evidence_for_component(c.id)
        assert evidence, f"{c.name} has no evidence — every component must be evidence-backed"
        for ev in evidence:
            assert ev["detector"], "evidence must carry detector attribution"
            assert ev["location"]["path"], "evidence must carry a location"


def test_orphan_installed_state_penalized(scanned) -> None:
    _result, store = scanned
    junk = store.find_component("leftover-junk")[0]
    # installed-state base rate 0.95 × orphan modifier 0.8
    assert junk.confidence == pytest.approx(0.95 * 0.8, abs=0.01)


def test_cyclonedx_structure(scanned, monkeypatch) -> None:
    _result, store = scanned
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    doc = json.loads(emit_cyclonedx(store, reproducible=True))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    comps = {c["name"]: c for c in doc["components"]}
    lodash = comps["lodash"]
    assert lodash["purl"] == "pkg:npm/lodash@4.17.21"
    assert lodash["evidence"]["identity"][0]["methods"], "evidence visible in SBOM"
    assert lodash["evidence"]["occurrences"], "occurrences visible in SBOM"
    assert any(h["alg"] == "SHA-512" for h in lodash.get("hashes", []))
    refs = {c["bom-ref"] for c in doc["components"]} | {"sorb:subject"}
    for dep in doc["dependencies"]:
        assert dep["ref"] in refs
        for d in dep["dependsOn"]:
            assert d in refs
    # transitive edges must survive into the SBOM: debug's dependency on ms is
    # only recoverable by resolving it outward to the hoisted copy
    deps_of = {d["ref"]: set(d["dependsOn"]) for d in doc["dependencies"]}
    assert "pkg:npm/ms@2.1.2" in deps_of["pkg:npm/debug@4.3.4"]
    assert doc["compositions"][0]["aggregate"] == "complete"


def test_spdx_structure(scanned, monkeypatch) -> None:
    _result, store = scanned
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    doc = json.loads(emit_spdx(store, reproducible=True))
    assert doc["spdxVersion"] == "SPDX-2.3"
    ids = {p["SPDXID"] for p in doc["packages"]} | {"SPDXRef-DOCUMENT"}
    for rel in doc["relationships"]:
        assert rel["spdxElementId"] in ids and rel["relatedSpdxElement"] in ids
    purls = {
        r["referenceLocator"]
        for p in doc["packages"]
        for r in p.get("externalRefs", [])
        if r["referenceType"] == "purl"
    }
    assert "pkg:npm/lodash@4.17.21" in purls


def test_snapshot_determinism(polyglot: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    r1 = _scan(polyglot, tmp_path, "one")
    r2 = _scan(polyglot, tmp_path, "two")
    assert r1.serial == r2.serial, "identical input must reuse the serial"
    s1, s2 = GraphStore.open_readonly(r1.store_path), GraphStore.open_readonly(r2.store_path)
    try:
        assert emit_cyclonedx(s1, reproducible=True) == emit_cyclonedx(s2, reproducible=True)
        assert emit_spdx(s1, reproducible=True) == emit_spdx(s2, reproducible=True)
    finally:
        s1.close()
        s2.close()


def test_native_roundtrip_fixpoint(scanned, tmp_path: Path) -> None:
    _result, store = scanned
    exported = export_native(store)
    imported = import_native(exported, tmp_path / "reimport.sorb.db")
    assert export_native(imported) == exported
    imported.close()


def test_lineage_reuses_serial(polyglot: Path, tmp_path: Path) -> None:
    _scan(polyglot, tmp_path, "one")
    _scan(polyglot, tmp_path, "two")
    index = json.loads((polyglot / ".sorb" / "results" / "index.json").read_text())
    lineage = next(iter(index["subjects"].values()))
    assert len(lineage) == 2
    assert lineage[0]["serial"] == lineage[1]["serial"]
    assert lineage[1]["reason"] == "identical (serial reused)"


def test_explain_shows_paths_and_evidence(polyglot: Path, tmp_path: Path) -> None:
    from sorb.core.explain import explain

    result = _scan(polyglot, tmp_path)
    store = GraphStore.open_readonly(result.store_path)
    try:
        text = explain(store, "pkg:npm/lodash@4.17.21")
        assert text is not None
        assert "Introduced via 2 paths" in text
        assert "apps/web (workspace)" in text
        assert "installed" in text and "locked" in text and "declared" in text
        assert "requested ^4.17.21" in text
    finally:
        store.close()


def test_cli_explain_warning_known_and_unknown() -> None:
    ok = runner.invoke(app, ["explain-warning", "SORB-W031"])
    assert ok.exit_code == 0 and "installed-not-declared" in ok.output
    bad = runner.invoke(app, ["explain-warning", "SORB-W999"])
    assert bad.exit_code == 1 and "Known codes" in bad.output


def test_cli_scan_fail_on_drift(polyglot: Path) -> None:
    clean = runner.invoke(app, ["scan", str(polyglot), "-o", "summary"])
    assert clean.exit_code == 0
    policy = runner.invoke(app, ["scan", str(polyglot), "-o", "summary", "--fail-on", "drift"])
    assert policy.exit_code == 2  # policy failure, distinct from scan errors


def test_detector_failure_degrades_to_gap(polyglot: Path, tmp_path: Path) -> None:
    (polyglot / "package-lock.json").write_text("{ this is not json")
    result = _scan(polyglot, tmp_path)
    assert result.had_scan_errors  # exit code 1 territory, scan still completed
    store = GraphStore.open_readonly(result.store_path)
    try:
        gaps = [a for a in store.all_annotations() if a["code"] == "analysis-gap"]
        assert gaps and "package-lock.json" in gaps[0]["detail"]
        assert store.components(), "scan continued past the broken file"
    finally:
        store.close()


def test_unknown_target_types_rejected_explicitly() -> None:
    # git:// is the remaining unimplemented scheme (host://, disk:// are supported)
    res = runner.invoke(app, ["scan", "git://example.com/repo"])
    assert res.exit_code == 1
    assert "not supported yet" in res.output


def test_host_and_disk_targets_are_routed(tmp_path: Path) -> None:
    # host:// / disk:// are implemented; an empty host root scans to nothing,
    # a missing disk image errors cleanly — neither is rejected as "unsupported".
    empty = tmp_path / "emptyroot"
    empty.mkdir()
    res = runner.invoke(app, ["scan", f"host://{empty}", "-o", "summary"])
    assert res.exit_code == 0 and "not supported" not in res.output
    bad = runner.invoke(app, ["scan", "disk:///no/such/image.raw"])
    assert bad.exit_code == 1 and "not supported" not in bad.output


def test_image_target_routed_to_container_subsystem_honors_offline() -> None:
    # image: targets are supported; --offline with nothing cached must be a
    # clean typed error (exit 1), never a network attempt (socket guard proves it)
    res = runner.invoke(app, ["scan", "image:nginx:1.27", "--offline"])
    assert res.exit_code == 1
    assert "--offline" in res.output or "cache" in res.output
