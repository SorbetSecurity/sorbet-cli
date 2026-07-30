"""Store lifecycle, concurrent readers, cycle-safe paths."""

from __future__ import annotations

from pathlib import Path

from sorb.graph.store import GraphStore
from sorb.model import (
    ComponentClaim,
    Coordinates,
    EdgeType,
    EvidenceRecord,
    Finding,
    ProjectClaim,
    Tier,
)


def _finding(name: str, version: str) -> Finding:
    return Finding(
        claim=ComponentClaim(ctype="library", name=name, version=version, ecosystem="npm"),
        evidence=(
            EvidenceRecord(
                technique="lockfile-parse",
                tier=Tier.LOCKED,
                detector="t/x@1",
                location=Coordinates(source_id="s1", path="lock.json", span=(1, 2)),
                confidence=0.9,
            ),
        ),
    )


def test_create_write_read(tmp_path: Path) -> None:
    db = tmp_path / "run.sorb.db"
    store = GraphStore.create(db)
    store.set_meta("subject", "test")
    fid = store.add_finding(_finding("a", "1.0.0"))
    cid = store.add_component(
        purl="pkg:npm/a@1.0.0", ctype="library", name="a", version="1.0.0",
        qualifiers={}, hashes={}, confidence=0.9, tier_cap=3, attrs={},
    )
    store.link_finding(fid, cid)
    store.commit()

    reader = GraphStore.open_readonly(db)
    comps = reader.components()
    assert len(comps) == 1 and comps[0].purl == "pkg:npm/a@1.0.0"
    assert reader.evidence_for_component(cid)[0]["tier"] == "locked"
    assert reader.get_meta("subject") == "test"
    reader.close()
    store.close()


def test_find_component_by_purl_name_digest(tmp_path: Path) -> None:
    store = GraphStore.create(tmp_path / "r.db")
    store.add_component(
        purl="pkg:npm/a@1.0.0", ctype="library", name="a", version="1.0.0",
        qualifiers={}, hashes={"sha256": "ab" * 32}, confidence=0.9, tier_cap=3, attrs={},
    )
    store.commit()
    assert store.find_component("pkg:npm/a@1.0.0")
    assert store.find_component("pkg:npm/a")  # version-insensitive purl
    assert store.find_component("a@1.0.0")
    assert store.find_component("a")
    assert store.find_component("ab" * 32)
    assert not store.find_component("nope")
    store.close()


def test_path_query_cycles_dont_hang(tmp_path: Path) -> None:
    store = GraphStore.create(tmp_path / "r.db")
    ids = [
        store.add_component(
            purl=f"pkg:npm/c{i}@1.0.0", ctype="library", name=f"c{i}", version="1.0.0",
            qualifiers={}, hashes={}, confidence=0.9, tier_cap=3, attrs={},
        )
        for i in range(3)
    ]
    pid = store.add_project(ProjectClaim(path=".", name="root", kind="npm"), "s1")
    pnode = store.project_node_id(pid)
    store.add_edge(EdgeType.DEPENDS_ON, pnode, ids[0])
    store.add_edge(EdgeType.DEPENDS_ON, ids[0], ids[1])
    store.add_edge(EdgeType.DEPENDS_ON, ids[1], ids[2])
    store.add_edge(EdgeType.DEPENDS_ON, ids[2], ids[0])  # cycle
    store.commit()
    paths = store.paths_to_roots(ids[2])
    assert paths, "must terminate and find the project root"
    assert paths[0][0].kind == "project"
    labels = [s.label for s in paths[0]]
    assert labels == [".", "pkg:npm/c0@1.0.0", "pkg:npm/c1@1.0.0", "pkg:npm/c2@1.0.0"]
    store.close()
