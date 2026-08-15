"""Importers, convert+loss, merge, diff, validate, sign/attest/verify, lineage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.diff import diff_stores
from sorb.core.merge import merge_stores
from sorb.core.pipeline import run_scan
from sorb.emit.capabilities import loss_report
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.emit.importers import import_sbom, sniff_sbom_format
from sorb.emit.spdx import emit_spdx
from sorb.emit.validate import validate_sbom
from sorb.graph.store import GraphStore


def _scan_project(tmp_path: Path, name: str, deps: dict[str, str]) -> GraphStore:
    project = tmp_path / name
    (project / "node_modules").mkdir(parents=True)
    (project / "package.json").write_text(json.dumps({"name": name, "dependencies": {}}))
    for dep, version in deps.items():
        (project / "node_modules" / dep).mkdir()
        (project / "node_modules" / dep / "package.json").write_text(
            json.dumps({"name": dep, "version": version, "license": "MIT"})
        )
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(project), cfg, store_path=tmp_path / f"{name}.sorb.db")
    return GraphStore.open_readonly(result.store_path)


# -- importers ------------------------------------------------------------------------


def test_import_own_cyclonedx_is_fixpoint(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    store = _scan_project(tmp_path, "app", {"lodash": "4.17.21", "left-pad": "1.3.0"})
    try:
        emitted = emit_cyclonedx(store, reproducible=True)
        original = {(c.name, c.version, c.purl) for c in store.components()}
    finally:
        store.close()
    imported = import_sbom(emitted, tmp_path / "imported.sorb.db", source_name="app.cdx.json")
    try:
        got = {(c.name, c.version, c.purl) for c in imported.components()}
        assert original <= got  # equivalent component set reconstructed
        for c in imported.components():
            evidence = imported.evidence_for_component(c.id)
            assert evidence and evidence[0]["technique"] == "imported-sbom"
            assert evidence[0]["tier"] == "declared"  # never confusable with scanned
        assert imported.get_meta("imported_format") == "cyclonedx-1.6"
    finally:
        imported.close()


def test_import_own_spdx_and_tagvalue(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    store = _scan_project(tmp_path, "app2", {"lodash": "4.17.21"})
    try:
        emitted = emit_spdx(store, reproducible=True)
    finally:
        store.close()
    imported = import_sbom(emitted, tmp_path / "spdx.sorb.db", source_name="app.spdx.json")
    try:
        names = {c.name for c in imported.components()}
        assert "lodash" in names
    finally:
        imported.close()

    tv = (
        "SPDXVersion: SPDX-2.3\nDocumentName: tv-doc\nDocumentNamespace: https://x/1\n"
        "PackageName: lodash\nSPDXID: SPDXRef-Package-lodash\nPackageVersion: 4.17.21\n"
        "PackageLicenseDeclared: MIT\n"
        "ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21\n"
        "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-lodash\n"
    )
    assert sniff_sbom_format(tv.encode()) == "spdx-tv"
    imported_tv = import_sbom(tv.encode(), tmp_path / "tv.sorb.db", source_name="doc.spdx")
    try:
        lodash = imported_tv.find_component("pkg:npm/lodash@4.17.21")
        assert lodash and lodash[0].attrs["licenses_declared"] == "MIT"
    finally:
        imported_tv.close()


def test_import_cyclonedx_xml(tmp_path) -> None:
    xml = (
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" serialNumber="urn:uuid:x" version="1">'
        "<components>"
        '<component type="library" bom-ref="a"><name>lodash</name><version>4.17.21</version>'
        "<purl>pkg:npm/lodash@4.17.21</purl></component>"
        '<component type="library" bom-ref="b"><name>left-pad</name><version>1.3.0</version></component>'
        '</components><dependencies><dependency ref="a"><dependency ref="b"/></dependency></dependencies></bom>'
    )
    store = import_sbom(xml.encode(), tmp_path / "xml.sorb.db", source_name="bom.xml")
    try:
        assert {c.name for c in store.components()} == {"lodash", "left-pad"}
        deps = [e for e in store.edges() if e["kind"] == "DEPENDS_ON"]
        assert len(deps) == 1
    finally:
        store.close()


# -- convert + loss report ----------------------------------------------------------------


def test_loss_report_names_dropped_facts(tmp_path) -> None:
    store = _scan_project(tmp_path, "app3", {"lodash": "4.17.21"})
    try:
        report = loss_report(store, "spdx-json")
        assert any("evidence-records" in line for line in report)
        assert any("confidence-scores" in line for line in report)
        assert loss_report(store, "sorb") == []  # native is lossless
    finally:
        store.close()


def test_spdx_roundtrip_preserves_what_spdx_expresses(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    store = _scan_project(tmp_path, "app4", {"lodash": "4.17.21"})
    try:
        spdx1 = emit_spdx(store, reproducible=True)
    finally:
        store.close()
    imported = import_sbom(spdx1, tmp_path / "rt.sorb.db", source_name="rt.spdx.json")
    try:
        doc1, doc2 = json.loads(spdx1), json.loads(emit_spdx(imported, reproducible=True))

        def essence(doc):
            return {
                (
                    p["name"],
                    p.get("versionInfo"),
                    next(
                        (r["referenceLocator"] for r in p.get("externalRefs", [])
                         if r["referenceType"] == "purl"),
                        None,
                    ),
                )
                for p in doc["packages"]
            }

        assert essence(doc1) == essence(doc2)
    finally:
        imported.close()


# -- merge ----------------------------------------------------------------------------------


def test_merge_conflict_and_strategies(tmp_path) -> None:
    a = _scan_project(tmp_path, "svc-a", {"lodash": "4.17.21", "shared": "1.0.0"})
    b = _scan_project(tmp_path, "svc-b", {"lodash": "4.17.20", "only-b": "2.0.0"})
    try:
        merged, stats = merge_stores(
            [("a.sbom", a), ("b.sbom", b)], tmp_path / "merged.sorb.db"
        )
        try:
            assert stats["conflicts"] == 1  # lodash version disagreement
            lodash = merged.find_component("lodash")
            details = [
                ann["detail"]
                for c in lodash
                for ann in merged.annotations_for("component", c.id)
                if ann["code"] == "merge-conflict"
            ]
            assert details and "a.sbom" in details[0] and "b.sbom" in details[0]
            shared = merged.find_component("shared@1.0.0")[0]
            assert shared.attrs["merge_sources"] == ["a.sbom"]
        finally:
            merged.close()

        intersected, istats = merge_stores(
            [("a.sbom", a), ("b.sbom", b)], tmp_path / "int.sorb.db", strategy="intersect"
        )
        try:
            names = {c.name for c in intersected.components()}
            assert "only-b" not in names and "shared" not in names
        finally:
            intersected.close()

        hier, _ = merge_stores(
            [("a.sbom", a), ("b.sbom", b)], tmp_path / "hier.sorb.db", strategy="hierarchical"
        )
        try:
            describes = [e for e in hier.edges() if e["kind"] == "DESCRIBES"]
            assert describes  # per-input DESCRIBES subtrees
            assert len(hier.projects()) == 2
        finally:
            hier.close()
    finally:
        a.close()
        b.close()


# -- diff -----------------------------------------------------------------------------------


def test_diff_semantic_with_version_schemes(tmp_path) -> None:
    old = _scan_project(tmp_path, "rel1", {"lodash": "4.9.0", "gone": "1.0.0"})
    new = _scan_project(tmp_path, "rel2", {"lodash": "4.10.0", "fresh": "0.1.0"})
    try:
        result = diff_stores(old, new)
        assert ("fresh", "0.1.0", "npm") in result.added
        assert ("gone", "1.0.0", "npm") in result.removed
        change = result.version_changes[0]
        # semver: 4.10.0 > 4.9.0 even though "4.10" < "4.9" as strings
        assert change.name == "lodash" and change.direction == "upgraded"
    finally:
        old.close()
        new.close()


# -- validate ---------------------------------------------------------------------------------


def test_validate_own_output_and_broken_sbom(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    store = _scan_project(tmp_path, "app5", {"lodash": "4.17.21"})
    try:
        cdx = emit_cyclonedx(store, reproducible=True)
        spdx = emit_spdx(store, reproducible=True)
    finally:
        store.close()
    assert validate_sbom(cdx).structurally_valid
    assert validate_sbom(spdx).structurally_valid

    broken = {"bomFormat": "CycloneDX", "specVersion": "1.6",
              "components": [{"type": "library"}]}  # missing name
    report = validate_sbom(json.dumps(broken).encode())
    assert not report.structurally_valid
    assert any("'name'" in e for e in report.schema_errors)

    missing_supplier = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": {"components": []}},
        "components": [{"type": "library", "name": "widget", "version": "1.0", "purl": "pkg:npm/widget@1.0"}],
        "dependencies": [],
    }
    report2 = validate_sbom(json.dumps(missing_supplier).encode())
    assert report2.structurally_valid
    assert any("supplier missing for component 'widget'" in f for f in report2.ntia_findings)


# -- sign / attest / verify ---------------------------------------------------------------------


def test_sign_attest_verify_roundtrip(tmp_path) -> None:
    from sorb.emit.signing import attest, generate_keypair, sign_detached, verify

    key_path, pub_path = generate_keypair(tmp_path / "keys")
    sbom = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6",
         "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555", "version": 1,
         "components": []}
    ).encode()
    subject = "sha256:" + "ab" * 32

    envelope = attest(
        sbom, subject_name="acme/api", subject_digest=subject,
        private_key_pem=key_path.read_bytes(),
    )
    steps = verify(envelope, public_key_pem=pub_path.read_bytes(), expected_subject_digest=subject)
    assert all(s.ok for s in steps)
    assert [s.name for s in steps][:3] == ["envelope-validity", "identity-policy", "subject-binding"]

    # wrong subject digest fails AT THE BINDING STEP with that step named
    wrong = verify(
        envelope, public_key_pem=pub_path.read_bytes(),
        expected_subject_digest="sha256:" + "cd" * 32,
    )
    assert wrong[-1].name == "subject-binding" and not wrong[-1].ok

    # tampered envelope fails at envelope-validity
    tampered = envelope.replace(b'"payload"', b'"payloxd"', 1)
    bad = verify(tampered, public_key_pem=pub_path.read_bytes())
    assert bad[0].name == "envelope-validity" and not bad[0].ok

    # wrong key fails the identity policy
    _key2, pub2 = generate_keypair(tmp_path / "keys2")
    other = verify(envelope, public_key_pem=pub2.read_bytes())
    assert not other[0].ok or (other[1].name == "identity-policy" and not other[1].ok)

    # detached bundle over exact bytes
    bundle = sign_detached(sbom, private_key_pem=key_path.read_bytes())
    dsteps = verify(bundle, public_key_pem=pub_path.read_bytes(), sbom_bytes=sbom)
    assert dsteps[0].ok
    flipped = verify(bundle, public_key_pem=pub_path.read_bytes(), sbom_bytes=sbom + b" ")
    assert not flipped[0].ok


def test_verify_lineage_superseded_flagged(tmp_path) -> None:
    from sorb.emit.signing import attest, generate_keypair, verify

    key_path, pub_path = generate_keypair(tmp_path / "keys")
    serial = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    sbom = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6",
         "serialNumber": f"urn:uuid:{serial}", "version": 1, "components": []}
    ).encode()
    envelope = attest(
        sbom, subject_name="x", subject_digest="sha256:" + "ab" * 32,
        private_key_pem=key_path.read_bytes(),
    )
    lineage = {"subjects": {"image:x": [
        {"serial": serial, "run_id": "r1"},
        {"serial": "ffffffff-0000-1111-2222-333333333333", "run_id": "r2"},
    ]}}
    steps = verify(envelope, public_key_pem=pub_path.read_bytes(), lineage_index=lineage)
    last = steps[-1]
    assert last.name == "lineage-consistency" and not last.ok
    assert "superseded" in last.detail


# -- lineage / document versioning -----------------------------------------------------------------


def test_doc_version_increments_and_reissue_reason(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    project = tmp_path / "proj"
    (project / "node_modules/lodash").mkdir(parents=True)
    (project / "package.json").write_text(json.dumps({"name": "app", "dependencies": {}}))
    (project / "node_modules/lodash/package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.20"})
    )
    cfg = load_config(target=project, flags={}, env={}, user_config_path=tmp_path / "nc.toml")

    r1 = run_scan(str(project), cfg, store_path=tmp_path / "v1.sorb.db")
    r1_again = run_scan(str(project), cfg, store_path=tmp_path / "v1b.sorb.db")
    (project / "node_modules/lodash/package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.21"})
    )
    r2 = run_scan(str(project), cfg, store_path=tmp_path / "v2.sorb.db")

    s1 = GraphStore.open_readonly(r1.store_path)
    s1b = GraphStore.open_readonly(r1_again.store_path)
    s2 = GraphStore.open_readonly(r2.store_path)
    try:
        assert s1.get_meta("doc_version") == "1"
        assert s1b.get_meta("doc_version") == "1"  # identical re-scan = same document
        assert s2.get_meta("doc_version") == "2"
        assert s2.get_meta("reissue_reason") == "subject-changed"
        doc2 = json.loads(emit_cyclonedx(s2, reproducible=True))
        assert doc2["version"] == 2
        supersedes = [p for p in doc2["metadata"]["properties"] if p["name"] == "sorb:supersedes"]
        assert supersedes and supersedes[0]["value"].startswith("urn:cdx:")
        assert supersedes[0]["value"].endswith("/1")
    finally:
        s1.close()
        s1b.close()
        s2.close()


def test_import_rejects_garbage(tmp_path) -> None:
    with pytest.raises(ValueError, match="not a recognized SBOM"):
        import_sbom(b"hello world", tmp_path / "x.sorb.db")


def test_export_import_diff_is_a_noop(tmp_path, monkeypatch) -> None:
    """An SBOM diffed against the store it came from must show no changes.

    `sorb diff v1.cdx.json image:app:2.0 --fail-on-change` is the documented CI
    gate; if a round-trip drops confidence and scope, the gate fires on every
    unchanged build.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    store = _scan_project(tmp_path, "rt", {"lodash": "4.17.21", "left-pad": "1.3.0"})
    try:
        for label, emit in (("cdx", emit_cyclonedx), ("spdx", emit_spdx)):
            imported = import_sbom(
                emit(store, reproducible=True),
                tmp_path / f"rt-{label}.sorb.db",
                source_name=f"rt.{label}.json",
            )
            try:
                result = diff_stores(imported, store)
                assert result.confidence_changes == [], label
                assert result.scope_changes == [], label
                assert result.version_changes == [], label
            finally:
                imported.close()
    finally:
        store.close()


def test_diff_does_not_invent_layer_changes_against_an_sbom(tmp_path) -> None:
    """An SBOM records no layers, so a live image's layers are not "added".

    Reporting them flips `--fail-on-change` on every unchanged image build.
    """
    from sorb.model import EdgeType  # noqa: F401  (kept local to this case)

    with_layers = GraphStore.create(tmp_path / "img.db")
    with_layers.add_source("s1", "oci", "img", {})
    with_layers.add_layer("sha256:" + "aa" * 32, "s1", 0, "ADD rootfs /")
    with_layers.commit()
    without = GraphStore.create(tmp_path / "doc.db")
    without.add_source("s1", "sbom", "img.cdx.json", {})
    without.commit()
    try:
        assert diff_stores(without, with_layers).layers_added == []
        assert diff_stores(with_layers, without).layers_removed == []
        # two real images still diff their layers
        other = GraphStore.create(tmp_path / "img2.db")
        other.add_source("s1", "oci", "img2", {})
        other.add_layer("sha256:" + "bb" * 32, "s1", 0, "ADD rootfs /")
        other.commit()
        try:
            assert diff_stores(with_layers, other).layers_added == ["sha256:" + "bb" * 32]
        finally:
            other.close()
    finally:
        with_layers.close()
        without.close()


def test_verify_refuses_contradictory_subject_arguments(tmp_path) -> None:
    """Passing both --sbom and --subject-digest for different artifacts is an error.

    Silently preferring one reports "verification passed" for a subject the
    caller never asked about.
    """
    from sorb.emit.signing import attest, generate_keypair, verify

    key_path, pub_path = generate_keypair(tmp_path / "keys")
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    subject = "sha256:" + "ab" * 32
    envelope = attest(
        sbom, subject_name="acme/api", subject_digest=subject,
        private_key_pem=key_path.read_bytes(),
    )
    steps = verify(
        envelope,
        public_key_pem=pub_path.read_bytes(),
        expected_subject_digest=subject,
        sbom_bytes=b"a completely different artifact",
    )
    assert steps[-1].name == "subject-binding" and not steps[-1].ok

    # ...and the honest single-argument forms still pass.
    assert all(
        s.ok
        for s in verify(
            envelope, public_key_pem=pub_path.read_bytes(), expected_subject_digest=subject
        )
    )
