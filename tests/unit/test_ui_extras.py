"""UI extras: findings/drift board, diff, fleet dashboard endpoints."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.ui.config import ServerConfig
from sorb.ui.server import create_app


@pytest.fixture()
def served(tmp_path: Path):
    fixture = Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot"
    proj = tmp_path / "polyglot"
    shutil.copytree(fixture, proj, ignore=shutil.ignore_patterns(".sorb"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    config = ServerConfig(run=str(result.store_path), target=str(proj), extra_allowed_hosts=("testserver",))
    client = TestClient(create_app(config))
    client.headers.update({"Authorization": f"Bearer {config.token}"})
    return client


def test_drift_endpoint_groups_findings(served) -> None:
    data = served.get("/api/runs/current/drift").json()
    assert "findings" in data and "total" in data
    # the polyglot fixture carries drift annotations (phantom/installed-not-declared)
    assert data["total"] >= 1
    for group in data["findings"]:
        assert {"code", "category", "count", "items"} <= set(group)


def test_diff_same_run_is_empty(served) -> None:
    data = served.get("/api/diff", params={"a": "current", "b": "current"}).json()
    assert data["empty"] is True
    assert data["added"] == [] and data["removed"] == []


def test_fleet_endpoint_on_non_fleet_run(served) -> None:
    data = served.get("/api/runs/current/fleet").json()
    assert data["is_fleet"] is False


def test_new_nav_views_in_spa(served) -> None:
    js = served.get("/assets/app.js").text
    for view in ("viewFindings", "viewFleet", "viewDiff"):
        assert view in js
    # nav registers the new routes
    assert '"findings"' in js and '"diff"' in js and '"fleet"' in js


def test_diff_between_two_runs(tmp_path: Path) -> None:
    # build two runs in one workspace so the server can resolve both ids
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("flask==3.0.0\n")
    cfg = load_config(target=proj, flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    r1 = run_scan(str(proj), cfg)
    (proj / "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
    r2 = run_scan(str(proj), cfg)

    config = ServerConfig(target=str(proj), extra_allowed_hosts=("testserver",))
    client = TestClient(create_app(config))
    client.headers.update({"Authorization": f"Bearer {config.token}"})
    data = client.get("/api/diff", params={"a": r1.run_id, "b": r2.run_id}).json()
    added = {c["name"] for c in data["added"]}
    assert "requests" in added  # the second run added requests
    assert data["empty"] is False
