"""LOD clustering: SQL grouping, cluster edges, expand-once, node budget."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sorb.graph.store import GraphStore
from sorb.ui.lod import DEFAULT_NODE_BUDGET, lod


@pytest.fixture()
def synth(tmp_path: Path) -> GraphStore:
    store = GraphStore.create(tmp_path / "synth.sorb.db")
    conn = store._conn
    ecos = ["npm", "pypi", "cargo"]
    for i in range(60):
        eco = ecos[i % 3]
        attrs = {"ecosystem": eco, "scope": "runtime", "layer": f"layer-{i % 2}"}
        if i % 20 == 0:
            attrs["excluded"] = "below threshold"  # excluded rows must never appear
        conn.execute(
            "INSERT INTO components(id,purl,ctype,name,version,qualifiers,hashes,confidence,tier_cap,attrs)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (i + 1, f"pkg:{eco}/p{i}@1.0", "library", f"p{i}", "1.0", "{}", "{}", 0.9,
             4 if i % 2 else 2, json.dumps(attrs)),
        )
    # a cross-ecosystem dependency between two kept components:
    # id2 (i=1 → pypi) -> id3 (i=2 → cargo)
    conn.execute("INSERT INTO edges(kind,src,dst,attrs) VALUES('DEPENDS_ON',2,3,'{}')")
    conn.commit()
    return store


def test_overview_clusters_by_ecosystem(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="ecosystem")
    clusters = {n.label.split(" ")[0]: n.count for n in resp.nodes}
    assert set(clusters) == {"npm", "pypi", "cargo"}
    # 60 components, 3 excluded (i=0,20,40 → npm,npm,npm), so npm has fewer
    assert sum(clusters.values()) == 57


def test_overview_has_cross_cluster_edge(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="ecosystem")
    assert {"src": "cluster:ecosystem:pypi", "dst": "cluster:ecosystem:cargo"} in resp.edges


def test_expand_returns_real_members_once(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="ecosystem", expand="pypi")
    assert resp.nodes and all(n.kind == "component" for n in resp.nodes)
    ids = [n.component_id for n in resp.nodes]
    assert len(ids) == len(set(ids))  # exactly once
    assert all(n.ecosystem == "pypi" for n in resp.nodes)


def test_expand_excludes_filtered_components(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="ecosystem", expand="npm")
    # component id 1,21,41 are excluded; none should appear
    assert not ({1, 21, 41} & {n.component_id for n in resp.nodes})


def test_cluster_by_tier(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="tier")
    labels = {n.id.split(":")[-1] for n in resp.nodes}
    assert labels <= {"declared", "installed"}  # tier_cap 2 and 4


def test_cluster_by_layer(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="layer")
    labels = {n.id.split(":")[-1] for n in resp.nodes}
    assert labels == {"layer-0", "layer-1"}


def test_node_budget_enforced(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="ecosystem", expand="pypi", node_budget=3)
    assert len(resp.nodes) <= 3
    assert resp.truncated
    assert resp.node_budget == 3


def test_unknown_cluster_mode_falls_back(synth: GraphStore) -> None:
    resp = lod(synth, cluster_by="bogus")
    assert resp.node_budget == DEFAULT_NODE_BUDGET
    assert {n.label.split(" ")[0] for n in resp.nodes} == {"npm", "pypi", "cargo"}
