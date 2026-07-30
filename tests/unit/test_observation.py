"""Observation mapping (phantom/unused), snapshot diff, and the
sorb trace/snapshot/watch CLI flows."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from sorb.cli.main import app
from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.dynamic.snapshot import Snapshot, SnapshotEntry, diff_snapshots
from sorb.dynamic.trace.mapper import map_observations
from sorb.dynamic.trace.model import Observation, TraceResult
from sorb.graph.store import GraphStore
from sorb.model import Tier

runner = CliRunner()


def _npm_project(tmp_path: Path, installed: dict[str, str]) -> Path:
    project = tmp_path / "app"
    (project / "node_modules").mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"lodash": "^4.0.0"}})
    )
    for name, version in installed.items():
        (project / "node_modules" / name).mkdir()
        (project / "node_modules" / name / "package.json").write_text(
            json.dumps({"name": name, "version": version})
        )
    return project


def test_observed_pins_and_upgrades_tier(tmp_path: Path) -> None:
    project = _npm_project(tmp_path, {"lodash": "4.17.21"})
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(project), cfg, store_path=tmp_path / "run.sorb.db")
    trace = TraceResult(
        command=["node", "app.js"], exit_code=0, backend="none",
        observations=[Observation("node-require-probe", "module", "lodash", "4.17.21", "npm")],
    )
    store = GraphStore.open_rw(result.store_path)
    try:
        report = map_observations(store, trace)
        lodash = store.find_component("lodash")[0]
        assert lodash.tier is Tier.OBSERVED  # observed pins the tier
        assert lodash.attrs["scope"] == "runtime-observed"
        assert any(e["kind"] == "OBSERVED_IN" for e in store.edges())
        assert "lodash@4.17.21" in report.observed or lodash.display_ref() in report.observed
    finally:
        store.close()


def test_phantom_dependency_caught(tmp_path: Path) -> None:
    """An imported-but-undeclared hoisted dep is caught."""
    # left-pad is hoisted into node_modules but NOT declared/installed as a
    # first-class component the scan knows about
    project = _npm_project(tmp_path, {"lodash": "4.17.21"})
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(project), cfg, store_path=tmp_path / "run.sorb.db")
    trace = TraceResult(
        command=["node", "app.js"], exit_code=0, backend="none",
        observations=[
            Observation("node-require-probe", "module", "lodash", "4.17.21", "npm"),
            Observation("node-require-probe", "module", "left-pad", "1.3.0", "npm"),
        ],
    )
    store = GraphStore.open_rw(result.store_path)
    try:
        report = map_observations(store, trace)
        assert any("left-pad" in p for p in report.phantom)
        assert any(code == "SORB-W036" for code, _ in report.warnings)
        phantom = store.find_component("left-pad@1.3.0")[0]
        assert phantom.attrs.get("phantom") is True
        assert phantom.tier is Tier.OBSERVED
        codes = {a["code"] for a in store.annotations_for("component", phantom.id)}
        assert "drift:observed-not-declared" in codes
    finally:
        store.close()


def test_unused_declared_annotated(tmp_path: Path) -> None:
    """A declared/installed component in a traced ecosystem, never loaded."""
    project = _npm_project(tmp_path, {"lodash": "4.17.21", "left-pad": "1.3.0"})
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(project), cfg, store_path=tmp_path / "run.sorb.db")
    # only lodash is loaded; left-pad is installed but never observed
    trace = TraceResult(
        command=["node", "app.js"], exit_code=0, backend="none",
        observations=[Observation("node-require-probe", "module", "lodash", "4.17.21", "npm")],
    )
    store = GraphStore.open_rw(result.store_path)
    try:
        report = map_observations(store, trace)
        assert any("left-pad" in u for u in report.unused)
        left_pad = store.find_component("left-pad@1.3.0")[0]
        codes = {a["code"] for a in store.annotations_for("component", left_pad.id)}
        assert "declared-never-observed" in codes
    finally:
        store.close()


def test_snapshot_diff_names_what_a_step_installed() -> None:
    """Snapshot-diff names exactly what a step installed."""
    before = Snapshot(entries=frozenset({
        SnapshotEntry("pypi", "requests", "2.31.0"),
    }))
    after = Snapshot(entries=frozenset({
        SnapshotEntry("pypi", "requests", "2.32.0"),  # upgraded
        SnapshotEntry("pypi", "urllib3", "2.2.1"),  # installed
    }))
    diff = diff_snapshots(before, after)
    assert [e.name for e in diff.installed] == ["urllib3"]
    assert diff.upgraded == [("requests", "2.31.0", "2.32.0")]
    assert not diff.removed


# -- CLI flows ---------------------------------------------------------------------------------


def test_cli_trace_end_to_end(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    project = tmp_path / "pyapp"
    project.mkdir()
    # a real installed dist (packaging) declared + imported by the traced script
    (project / "pyproject.toml").write_text(
        '[project]\nname = "pyapp"\ndependencies = ["packaging"]\n'
    )
    script = project / "run.py"
    script.write_text("import packaging.version\nprint('ran')\n")
    res = runner.invoke(app, ["trace", "--target", str(project), "--", sys.executable, str(script)])
    assert res.exit_code == 0, res.output
    assert "observed" in res.output


def test_cli_trace_fail_on_phantom(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    project = tmp_path / "pyapp"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "pyapp"\n')  # declares nothing
    # import a dist that is installed in the venv but not declared → phantom
    script = project / "run.py"
    script.write_text("import httpx\nprint('ran')\n")
    res = runner.invoke(
        app,
        ["trace", "--target", str(project), "--fail-on", "phantom-deps", "--", sys.executable, str(script)],
    )
    assert res.exit_code == 2  # phantom dependency → policy failure
    assert "phantom" in res.output.lower()


def test_cli_watch_survives_target_restart(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    project = tmp_path / "pyapp"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "pyapp"\ndependencies = ["packaging"]\n')
    # a command that fails: watch must survive it, not crash
    res = runner.invoke(
        app,
        ["watch", "--target", str(project), "--iterations", "2", "--",
         sys.executable, "-c", "import sys; sys.exit(3)"],
    )
    assert res.exit_code == 0, res.output
    assert "watch complete" in res.output
    assert "session 2" in res.output
