"""Fleet merge at scale + the flagship cross-source query."""

from __future__ import annotations

import tracemalloc
from pathlib import Path

from sorb.graph.store import GraphStore
from sorb.host.fleet import fleet_rows, merge_fleet


def _make_host(path: Path, host: str, openssl_version: str, observed: bool) -> None:
    store = GraphStore.create(path)
    store.add_source("s1", "host", host, {})
    store.set_meta("subject", f"host:{host}")

    def add(name: str, version: str, *, obs: bool = False, eco: str = "deb") -> None:
        attrs = {"ecosystem": eco}
        if obs:
            attrs["observed"] = "true"
            attrs["observed_ports"] = "443"
        store.add_component(
            purl=f"pkg:{eco}/{name}@{version}", ctype="os-package", name=name,
            version=version, qualifiers=(), hashes={}, confidence=0.98, tier_cap=4,
            attrs=attrs,
        )

    add("openssl", openssl_version, obs=observed)
    add("nginx", "1.24.0", obs=observed)
    add("zlib", "1.2.13")
    store.commit()
    store.close()


def _build_fleet(root: Path, n: int = 100) -> list[Path]:
    paths: list[Path] = []
    for i in range(n):
        # 40% vulnerable (3.0.11), 30% safe (3.0.14), 30% safe (3.0.15)
        if i % 10 < 4:
            version, observed = "3.0.11", (i % 10 < 3)  # 30% of hosts run it observed
        elif i % 10 < 7:
            version, observed = "3.0.14", True
        else:
            version, observed = "3.0.15", False
        p = root / f"host{i:03d}.sorb.db"
        _make_host(p, f"host{i:03d}", version, observed)
        paths.append(p)
    return paths


def test_fleet_merges_under_memory_budget(tmp_path: Path) -> None:
    paths = _build_fleet(tmp_path, n=100)
    tracemalloc.start()
    store, stats = merge_fleet(paths, tmp_path / "fleet.sorb.db")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    try:
        assert stats.sources == 100
        assert stats.total_components == 300  # 3 per host
        # digest-first dedup: 3 openssl versions + nginx + zlib = 5 distinct
        assert stats.distinct_components == 5
        # streaming keeps peak proportional to distinct components, not fleet size
        assert peak < 40 * 1024 * 1024
    finally:
        store.close()


def test_flagship_query_returns_per_host_rows(tmp_path: Path) -> None:
    """'which hosts run OpenSSL < 3.0.14 and is it observed running?'"""
    paths = _build_fleet(tmp_path, n=100)
    store, _ = merge_fleet(paths, tmp_path / "fleet.sorb.db")
    try:
        rows = fleet_rows(
            store,
            'components where name = openssl and version < "3.0.14" and observed = true',
        )
        # only the 3.0.11 component matches; expanded to its hosts
        assert rows, "the vulnerable+observed openssl should be found"
        assert all(r.name == "openssl" and r.version == "3.0.11" for r in rows)
        vulnerable_observed = {r.source for r in rows if r.observed}
        # hosts with i%10 in {0,1,2} are 3.0.11 AND observed → 30 hosts
        assert len(vulnerable_observed) == 30
        assert all(r.ports == "443" for r in rows if r.observed)
    finally:
        store.close()


def test_seen_in_provenance_preserved(tmp_path: Path) -> None:
    paths = _build_fleet(tmp_path, n=20)
    store, _ = merge_fleet(paths, tmp_path / "fleet.sorb.db")
    try:
        import json

        openssl_311 = next(
            c for c in store.components()
            if c.name == "openssl" and c.version == "3.0.11"
        )
        seen = json.loads(openssl_311.attrs["seen_in"])
        assert {e["source"] for e in seen} == {f"host:host{i:03d}" for i in range(20) if i % 10 < 4}
        assert openssl_311.attrs["observed"] == "true"  # observed on at least one host
    finally:
        store.close()
