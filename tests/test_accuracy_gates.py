"""Confidence data versioning, the corpus precision/recall gate, and the
differential harness — plus CLI e2e for the SBOM document commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent / "corpus"))
sys.path.insert(0, str(Path(__file__).parent / "differential"))

from corpus_harness import GATE, materialize_fixture, run_corpus  # noqa: E402

from sorb.cli.main import app  # noqa: E402

runner = CliRunner()
CORPUS_MANIFEST = Path(__file__).parent / "corpus" / "manifest.json"


# -- confidence machinery is data-driven -------------------------------------------------


def test_base_rates_are_versioned_data() -> None:
    import tomllib
    from importlib import resources

    doc = tomllib.loads(
        (resources.files("sorb") / "data" / "base_rates.toml").read_text(encoding="utf-8")
    )
    assert doc["version"] >= 2
    assert "lockfile-parse" in doc["base_rates"]


def test_changing_base_rate_changes_output_without_code(monkeypatch) -> None:
    import sorb.catalogers.base as base
    from sorb.catalogers.base import CatalogerContext
    from sorb.model import Coordinates, Tier
    from sorb.source.base import Entry

    class _Src:
        def coords(self, path, span=None):  # noqa: ANN001
            return Coordinates(source_id="s1", path=path, span=span)

    ctx = CatalogerContext(source=_Src(), detector="x@1")  # type: ignore[arg-type]
    entry = Entry(path="x.lock", size=1)
    before = ctx.evidence("lockfile-parse", Tier.LOCKED, entry).confidence
    monkeypatch.setitem(base._BASE_RATES, "lockfile-parse", 0.5)
    after = ctx.evidence("lockfile-parse", Tier.LOCKED, entry).confidence
    assert before != after and after == 0.5


def test_modifier_applications_visible_in_evidence(monkeypatch, tmp_path) -> None:
    from sorb.catalogers.base import CatalogerContext
    from sorb.model import Coordinates, Tier
    from sorb.source.base import Entry

    class _Src:
        def coords(self, path, span=None):  # noqa: ANN001
            return Coordinates(source_id="s1", path=path, span=span)

    ctx = CatalogerContext(source=_Src(), detector="x@1")  # type: ignore[arg-type]
    entry = Entry(path="tests/fixtures/package.json", size=1, role="fixture")
    ev = ctx.evidence("manifest-parse", Tier.DECLARED, entry)
    assert any("path-role-fixture" in m for m in ev.modifiers)  # reason recorded
    assert ev.confidence < 0.5


# -- corpus gate ----------------------------------------------------------------------------


def test_corpus_gate_green_and_report_renders(tmp_path) -> None:
    report = run_corpus(CORPUS_MANIFEST, tmp_path)
    rendered = report.to_dict()
    assert rendered["targets"][0]["per_detector"]  # per-detector metrics present
    assert report.advisory  # corpus < blocking size: advisory mode
    failures = report.gate_failures()
    assert not failures, f"corpus gate failed: {failures} — {rendered}"
    (tmp_path / "corpus-report.json").write_text(json.dumps(rendered, indent=2))


def test_broken_cataloger_fails_the_gate(tmp_path, monkeypatch) -> None:
    """A deliberately-broken cataloger trips the gate."""
    from sorb.catalogers.os_pkgs import DpkgCataloger
    from sorb.ident import make_purl
    from sorb.model import ComponentClaim, Finding, Tier

    original = DpkgCataloger.parse

    def broken(self, ctx, entry, blob):  # noqa: ANN001
        yield from original(self, ctx, entry, blob)
        for i in range(3):  # ghost components: precision poison
            yield Finding(
                claim=ComponentClaim(
                    ctype="os-package",
                    name=f"ghost-{i}",
                    version="9.9.9",
                    purl=make_purl("deb", f"ghost-{i}", "9.9.9", namespace="debian"),
                    ecosystem="deb",
                ),
                evidence=(ctx.evidence("os-package-db", Tier.INSTALLED, entry),),
            )

    monkeypatch.setattr(DpkgCataloger, "parse", broken)
    report = run_corpus(CORPUS_MANIFEST, tmp_path)
    failures = report.gate_failures()
    assert failures and any("precision" in f for f in failures)
    assert report.targets[0].unexpected  # the ghosts are named in the report


# -- differential harness ---------------------------------------------------------------------


def test_differential_ledger_covers_all_disagreements(tmp_path) -> None:
    import differential_harness as diff_harness  # noqa: E402

    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    fixture = Path(__file__).parent / "corpus" / "fixtures" / "polyglot"
    scan_dir = tmp_path / "polyglot"
    materialize_fixture(fixture, scan_dir)
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(scan_dir), cfg, store_path=tmp_path / "ours.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        ours = {str(c.purl).split("?", 1)[0] for c in store.components() if c.purl}
    finally:
        store.close()

    theirs_doc = diff_harness.load_fixture_output("syft", "polyglot")
    assert theirs_doc is not None
    theirs = diff_harness.normalize_purls(theirs_doc)
    report = diff_harness.compare("polyglot", "syft", ours, theirs)
    assert report.agreements >= 10
    assert report.disagreements  # the replace-directive divergence exists

    ledger = diff_harness.load_ledger()
    unexplained = report.unexplained(ledger)
    assert unexplained == [], f"unexplained disagreements: {unexplained}"

    # a new unexplained disagreement fails the (scheduled) job
    shorter = [e for e in ledger if e.purl != "pkg:npm/pnpm@9.1.0"]
    assert report.unexplained(shorter), "removing a ledger entry must surface the disagreement"


# -- CLI e2e for the SBOM command family -------------------------------------------------------


def test_cli_convert_validate_diff_merge_sign_verify(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1751500800")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))

    project = tmp_path / "proj"
    (project / "node_modules/lodash").mkdir(parents=True)
    (project / "package.json").write_text(json.dumps({"name": "app", "dependencies": {}}))
    (project / "node_modules/lodash/package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.21"})
    )
    sbom = tmp_path / "app.cdx.json"
    res = runner.invoke(
        app, ["scan", str(project), "-o", "cyclonedx-json", "-f", str(sbom), "--reproducible"]
    )
    assert res.exit_code == 0, res.output

    # convert → spdx with loss report
    out_spdx = tmp_path / "app.spdx.json"
    res = runner.invoke(
        app,
        ["convert", str(sbom), "-o", "spdx-json", "-f", str(out_spdx), "--loss-report", "--reproducible"],
    )
    assert res.exit_code == 0, res.output
    assert "evidence-records" in res.output  # loss report names dropped facts
    assert json.loads(out_spdx.read_text())["spdxVersion"] == "SPDX-2.3"

    # validate
    res = runner.invoke(app, ["validate", str(sbom)])
    assert res.exit_code == 0, res.output
    res = runner.invoke(app, ["validate", str(sbom), "--require", "ntia"])
    assert res.exit_code == 2  # supplier data absent → NTIA profile fails (policy exit)

    # diff (sbom vs itself → no changes)
    res = runner.invoke(app, ["diff", str(sbom), str(sbom)])
    assert res.exit_code == 0 and "no semantic changes" in res.output

    # merge two sboms
    sbom2 = tmp_path / "app2.cdx.json"
    (project / "node_modules/lodash/package.json").write_text(
        json.dumps({"name": "lodash", "version": "4.17.20"})
    )
    res = runner.invoke(
        app, ["scan", str(project), "-o", "cyclonedx-json", "-f", str(sbom2), "--reproducible"]
    )
    assert res.exit_code == 0
    res = runner.invoke(app, ["merge", str(sbom), str(sbom2), "-o", "summary"])
    assert res.exit_code == 0, res.output
    assert "1 conflicts" in res.output

    # sign + verify
    from sorb.emit.signing import generate_keypair

    key, pub = generate_keypair(tmp_path / "keys")
    res = runner.invoke(app, ["sign", str(sbom), "--key", str(key)])
    assert res.exit_code == 0, res.output
    res = runner.invoke(
        app, ["verify", str(sbom) + ".sig", "--key", str(pub), "--sbom", str(sbom)]
    )
    assert res.exit_code == 0, res.output
    assert "verification passed" in res.output

    # attest + verify with subject binding
    subject = "sha256:" + "ab" * 32
    res = runner.invoke(
        app,
        ["attest", str(sbom), "--key", str(key), "--subject-digest", subject],
    )
    assert res.exit_code == 0, res.output
    res = runner.invoke(
        app,
        ["verify", str(sbom) + ".att", "--key", str(pub), "--subject-digest", subject],
    )
    assert res.exit_code == 0, res.output
    res = runner.invoke(
        app,
        ["verify", str(sbom) + ".att", "--key", str(pub), "--subject-digest", "sha256:" + "cd" * 32],
    )
    assert res.exit_code == 2
    assert "subject-binding" in res.output


def test_gate_thresholds_documented() -> None:
    assert GATE["precision"] >= 0.98


# -- no-hallucination gate ------------------------------------------------------------------


def test_every_emitted_component_is_backed_by_its_cited_bytes(tmp_path) -> None:
    """Nothing may be asserted without support.

    The corpus gate checks precision and recall against an expected set; this
    checks the stronger property that set cannot express — that each emitted
    component is re-derivable from the file its evidence cites, using none of
    the cataloger code that produced it.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    from evidence_audit import audit_run
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan

    fixture = Path(__file__).parent / "corpus" / "fixtures" / "polyglot"
    scan_dir = materialize_fixture(fixture, tmp_path / "polyglot")
    cfg = load_config(
        target=scan_dir, flags={"evidence": "full"}, env={}, user_config_path=tmp_path / "nc.toml"
    )
    result = run_scan(str(scan_dir), cfg, store_path=tmp_path / "audit.sorb.db")

    report = audit_run(result.store_path, scan_dir)
    assert report.checked > 0, "audit examined nothing"
    assert not report.no_evidence, f"components with no evidence: {report.no_evidence[:5]}"
    assert report.ok, "unbacked components:\n" + "\n".join(
        str(u) for u in report.unbacked[:10]
    )


def test_the_audit_actually_catches_a_hallucination(tmp_path) -> None:
    """A gate that cannot fail is not a gate.

    Plant a component whose evidence cites a real file that does not support
    it, and require the audit to say so.
    """
    sys.path.insert(0, str(Path(__file__).parent))
    from evidence_audit import audit_store
    from sorb.graph.store import GraphStore
    from sorb.model import ComponentClaim as Claim
    from sorb.model import Coordinates, EvidenceRecord, Finding, Tier

    (tmp_path / "go.mod").write_text("module example.com/app\n\nrequire real/dep v1.0.0\n")
    store = GraphStore.create(tmp_path / "h.sorb.db")
    store.add_source("s1", "dir", str(tmp_path), {})
    for name, version in (("real/dep", "v1.0.0"), ("totally-invented", "9.9.9")):
        fid = store.add_finding(
            Finding(
                claim=Claim(ctype="library", name=name, version=version, ecosystem="golang"),
                evidence=(
                    EvidenceRecord(
                        technique="manifest-parse", tier=Tier.DECLARED, detector="t/x@1",
                        location=Coordinates(source_id="s1", path="go.mod"),
                    ),
                ),
            )
        )
        cid = store.add_component(
            purl=None, ctype="library", name=name, version=version, qualifiers={},
            hashes={}, confidence=0.9, tier_cap=int(Tier.DECLARED),
            attrs={"ecosystem": "golang"},
        )
        store.link_finding(fid, cid)
    store.commit()
    try:
        report = audit_store(store, tmp_path)
        assert not report.ok, "the audit passed a component that is not in the cited file"
        flagged = {u.component for u in report.unbacked}
        assert flagged == {"totally-invented"}, flagged
        assert report.backed == 1
    finally:
        store.close()
