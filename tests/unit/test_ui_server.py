"""Graph API contract tests: auth/skeleton, read endpoints, LOD.

Everything runs in-process against the FastAPI `TestClient` — no socket is bound,
no network is touched (the suite-wide socket guard stays satisfied).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sorb.core.config import load_config
from sorb.core.explain import explain
from sorb.core.pipeline import run_scan
from sorb.emit.validate import validate_sbom
from sorb.graph.store import GraphStore
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
    return client, config, result.store_path


# -- auth + DNS-rebinding defense --------------------------------------------------------


def test_requests_without_token_401(served) -> None:
    client, config, _ = served
    bare = TestClient(create_app(config))  # no auth header
    assert bare.get("/api/runs").status_code == 401
    assert client.get("/api/runs").status_code == 200  # with token


def test_token_via_query_param_sets_cookie(served) -> None:
    client, config, _ = served
    fresh = TestClient(create_app(config))
    r = fresh.get(f"/?token={config.token}")
    assert r.status_code == 200
    assert "sorb_token" in r.cookies  # pinned for subsequent asset/API loads


def test_dns_rebinding_wrong_host_rejected(served) -> None:
    client, _, _ = served
    r = client.get("/api/runs", headers={"Host": "attacker.example"})
    assert r.status_code == 400


def test_cross_origin_rejected(served) -> None:
    client, _, _ = served
    r = client.get("/api/runs", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_strict_csp_forbids_external_origins(served) -> None:
    client, _, _ = served
    csp = client.get("/api/runs").headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "http://" not in csp and "https://" not in csp  # no external origin allowed
    assert "object-src 'none'" in csp


def test_non_loopback_without_auth_refuses() -> None:
    with pytest.raises(ValueError, match="beyond loopback"):
        ServerConfig(bind="0.0.0.0", auth="none").validate()
    ServerConfig(bind="0.0.0.0", auth="token").validate()  # explicit auth is fine


# -- read endpoints ----------------------------------------------------------------------


def test_openapi_schema_published(served) -> None:
    client, _, _ = served
    schema = client.get("/api/openapi.json").json()
    assert schema["openapi"].startswith("3.")
    paths = schema["paths"]
    for p in ("/api/runs", "/api/runs/{run_id}/components", "/api/query", "/api/export"):
        assert p in paths


def test_runs_list_and_summary(served) -> None:
    client, _, _ = served
    runs = client.get("/api/runs").json()["runs"]
    assert runs and "run" in runs[0]
    summary = client.get("/api/runs/current").json()
    assert summary["counters"]["components"] > 0
    assert "by_ecosystem" in summary["counters"]


def test_components_pagination_cursor(served) -> None:
    client, _, _ = served
    page1 = client.get("/api/runs/current/components?limit=5").json()
    assert len(page1["rows"]) == 5
    assert page1["cursor"]
    page2 = client.get(f"/api/runs/current/components?limit=5&cursor={page1['cursor']}").json()
    ids1 = {r["id"] for r in page1["rows"]}
    ids2 = {r["id"] for r in page2["rows"]}
    assert ids1.isdisjoint(ids2)  # no overlap across pages
    assert page1["total"] == page2["total"]


def test_components_filter_uses_query_dsl(served) -> None:
    client, _, _ = served
    r = client.get("/api/runs/current/components", params={"filter": 'purl ~ "pkg:npm/*"'}).json()
    assert r["rows"]
    assert all(row["purl"].startswith("pkg:npm/") for row in r["rows"])


def test_component_detail_has_evidence_and_paths(served) -> None:
    client, _, store_path = served
    cid = client.get("/api/runs/current/components?limit=1").json()["rows"][0]["id"]
    detail = client.get(f"/api/runs/current/component/{cid}").json()
    assert detail["id"] == cid
    assert "evidence" in detail and "paths" in detail and "annotations" in detail


def test_explain_endpoint_matches_cli(served) -> None:
    """Parity: /explain JSON text ≡ CLI explain output."""
    client, _, store_path = served
    store = GraphStore.open_readonly(store_path)
    ref = store.components()[0].display_ref()
    cli_text = explain(store, ref)
    store.close()
    api = client.get("/api/runs/current/explain", params={"ref": ref}).json()
    assert api["text"] == cli_text
    assert api["components"]


def test_layers_endpoint(served) -> None:
    client, _, _ = served
    r = client.get("/api/runs/current/layers")
    assert r.status_code == 200
    assert "layers" in r.json()


# -- query endpoint + export -------------------------------------------------------------


def test_query_endpoint(served) -> None:
    client, _, _ = served
    r = client.post("/api/query", json={"query": "components where scope = runtime | count by ecosystem"})
    body = r.json()
    assert body["kind"] == "aggregation" and body["rows"]


def test_query_endpoint_bad_query_400_with_position(served) -> None:
    client, _, _ = served
    r = client.post("/api/query", json={"query": "components where x <"})
    assert r.status_code == 400
    assert "pos" in r.json()["detail"]


def test_export_full_and_subgraph_validate(served) -> None:
    client, _, _ = served
    full = client.post("/api/export", json={"format": "cyclonedx"})
    assert full.headers["content-type"].startswith("application/vnd.cyclonedx")
    assert validate_sbom(full.content).structurally_valid

    ids = [r["id"] for r in client.get("/api/runs/current/components?limit=2").json()["rows"]]
    sub = client.post("/api/export", json={"format": "cyclonedx", "component_ids": ids})
    doc = json.loads(sub.content)
    assert len(doc["components"]) == len(ids)  # exactly the selected subgraph
    assert validate_sbom(sub.content).structurally_valid


def test_export_by_query_selection(served) -> None:
    client, _, _ = served
    sub = client.post("/api/export", json={"format": "spdx", "query": 'components where purl ~ "pkg:npm/*"'})
    assert validate_sbom(sub.content).structurally_valid


# -- LOD --------------------------------------------------------------------------------


def test_lod_overview_and_expand(served) -> None:
    client, _, _ = served
    overview = client.get("/api/runs/current/lod").json()
    clusters = [n for n in overview["nodes"] if n["kind"] == "cluster"]
    assert clusters
    key = clusters[0]["id"].split(":")[-1]
    expanded = client.get("/api/runs/current/lod", params={"expand": key}).json()
    assert all(n["kind"] == "component" for n in expanded["nodes"])
    assert expanded["node_budget"] >= len(expanded["nodes"])


def test_lod_respects_node_budget(served) -> None:
    client, _, _ = served
    overview = client.get("/api/runs/current/lod").json()
    key = next(n["id"].split(":")[-1] for n in overview["nodes"] if n["kind"] == "cluster")
    resp = client.get("/api/runs/current/lod", params={"expand": key, "budget": 1}).json()
    assert len(resp["nodes"]) <= 1


# -- allow-scan gating -------------------------------------------------------------------


def test_scan_endpoint_disabled_by_default(served) -> None:
    client, _, _ = served
    r = client.post("/api/scan", json={"target": "."})
    assert r.status_code == 403


def _scan_client(tmp_path: Path):  # type: ignore[no-untyped-def]
    config = ServerConfig(allow_scan=True, target=str(tmp_path), extra_allowed_hosts=("testserver",))
    app = create_app(config)
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {config.token}"})
    return client, app.state.sorb


def test_scan_endpoint_starts_a_scan(tmp_path: Path) -> None:
    """`--allow-scan` plus a runner-installed launcher actually runs the scan."""
    client, state = _scan_client(tmp_path)
    launched: list[str] = []
    state.scan_launcher = launched.append
    r = client.post("/api/scan", json={"target": str(tmp_path)})
    assert r.status_code == 200 and r.json()["accepted"]
    assert launched == [str(tmp_path)]


def test_scan_endpoint_without_a_launcher_says_so(tmp_path: Path) -> None:
    """A bare app has no worker; it must report that, not claim acceptance."""
    client, _state = _scan_client(tmp_path)
    r = client.post("/api/scan", json={"target": str(tmp_path)})
    assert r.status_code == 503


def test_scan_endpoint_rejects_a_concurrent_scan(tmp_path: Path) -> None:
    client, state = _scan_client(tmp_path)
    state.scan_launcher = lambda target: None
    state.scan_status = "scanning"
    assert client.post("/api/scan", json={"target": str(tmp_path)}).status_code == 409
