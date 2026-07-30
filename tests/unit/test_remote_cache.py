"""Remote shared cache + incremental detector cache.

The reference server is driven in-process (`WsgiTransport`) so nothing binds a
socket. Correctness of the incremental cache is proven by scanning the corpus
with and without the cache and asserting identical results.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from sorb.cache import Cas
from sorb.cache.remote import RemoteCas
from sorb.cache.server import CasServer, WsgiTransport
from sorb.core.config import load_config
from sorb.core.detect_cache import CachedDetect, DetectCache
from sorb.core.pipeline import run_scan
from sorb.graph.store import GraphStore
from sorb.model import ComponentClaim, EvidenceRecord, Finding, Tier


class _FailingTransport:
    """Simulates an unreachable / timed-out server (fail-open path)."""

    def request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        return (0, b"")


# -- reference server + client -----------------------------------------------------------


def test_remote_cas_roundtrip(tmp_path: Path) -> None:
    server = CasServer(root=tmp_path / "server")
    remote = RemoteCas(WsgiTransport(server))
    assert remote.get("k1") is None  # miss
    assert remote.put("k1", b"hello-findings")
    assert remote.get("k1") == b"hello-findings"  # hit
    assert remote.has("k1") and not remote.has("absent")
    assert remote.stats()["remote_hits"] == 1
    assert remote.stats()["remote_misses"] == 1


def test_remote_cas_fails_open() -> None:
    remote = RemoteCas(_FailingTransport())
    assert remote.get("k") is None  # never raises
    assert not remote.put("k", b"x")
    assert remote.errors > 0 and not remote.healthy


def test_wsgi_transport_reports_404_for_missing() -> None:
    transport = WsgiTransport(CasServer(root=None))
    status, _ = transport.request("GET", "/cas/" + "0" * 64)
    assert status == 404


# -- DetectCache tiers -------------------------------------------------------------------


def _sample() -> CachedDetect:
    ev = EvidenceRecord(technique="lockfile-parse", tier=Tier.LOCKED, detector="x@1",
                        location=__import__("sorb.model", fromlist=["Coordinates"]).Coordinates(
                            source_id="s1", path="p"))
    finding = Finding(claim=ComponentClaim(ctype="library", name="lodash", version="4.17.21"),
                      evidence=(ev,))
    return CachedDetect(findings=[finding], warnings=[("SORB-W001", "x")], gaps=["g"])


def test_detect_cache_local_roundtrip(tmp_path: Path) -> None:
    cache = DetectCache(local=Cas(tmp_path / "c"))
    assert cache.get("k") is None
    cache.put("k", _sample())
    got = cache.get("k")
    assert got is not None
    assert got.findings[0].claim.name == "lodash"
    assert got.warnings == [("SORB-W001", "x")] and got.gaps == ["g"]
    assert cache.stats()["local_hits"] == 1


def test_detect_cache_remote_populates_local(tmp_path: Path) -> None:
    server = CasServer(root=tmp_path / "srv")
    local = Cas(tmp_path / "local")
    cache = DetectCache(local=local, remote=RemoteCas(WsgiTransport(server)))
    cache.put("k", _sample())  # write-through to both
    fresh = DetectCache(local=Cas(tmp_path / "local2"), remote=RemoteCas(WsgiTransport(server)))
    got = fresh.get("k")  # local miss → remote hit → populate local2
    assert got is not None and got.findings[0].claim.name == "lodash"
    assert fresh.stats()["remote_hits"] == 1
    assert fresh.local is not None and fresh.local.get("k") is not None  # back-populated


# -- incremental cache correctness + skip (through a real scan) --------------------------


def _components(store: GraphStore) -> set[tuple[str, str | None, str]]:
    return {(c.name, c.version, c.tier.label) for c in store.components()}


def _scan(target: Path, tmp: Path, tag: str, **flags: object) -> GraphStore:
    cfg = load_config(flags=flags, env={}, user_config_path=tmp / "nc.toml")
    result = run_scan(str(target), cfg, store_path=tmp / f"{tag}.sorb.db")
    return GraphStore.open_readonly(result.store_path)


def test_cache_does_not_change_results(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    proj = tmp_path / "polyglot"
    shutil.copytree(Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot", proj,
                    ignore=shutil.ignore_patterns(".sorb"))

    uncached = _scan(proj, tmp_path, "u")
    cold = _scan(proj, tmp_path, "cold", cache=True)  # populates the cache
    warm = _scan(proj, tmp_path, "warm", cache=True)  # should hit
    try:
        assert _components(uncached) == _components(cold) == _components(warm)
        warm_stats = json.loads(warm.get_meta("cache_stats") or "{}")
        assert warm_stats.get("hits", 0) > 0  # detector work was skipped
        cold_stats = json.loads(cold.get_meta("cache_stats") or "{}")
        assert cold_stats.get("stores", 0) > 0  # cold populated it
    finally:
        uncached.close()
        cold.close()
        warm.close()


def test_remote_outage_warns_never_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path / "cache"))
    # make every remote transport fail, without touching the network
    import sorb.cache.remote as remote_mod
    from sorb.core.events import ProgressBus, WarningRaised

    monkeypatch.setattr(remote_mod, "HttpTransport", lambda *a, **k: _FailingTransport())
    proj = tmp_path / "polyglot"
    shutil.copytree(Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot", proj,
                    ignore=shutil.ignore_patterns(".sorb"))

    codes: list[str] = []
    bus = ProgressBus()
    bus.subscribe(lambda e: codes.append(e.code) if isinstance(e, WarningRaised) else None)
    cfg = load_config(flags={"cache": True, "remote_cache": "http://cache.invalid"}, env={},
                      user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, bus=bus, store_path=tmp_path / "r.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        assert store.components()  # scan succeeded despite the dead remote
        assert "SORB-W063" in codes  # fail-open surfaced as a warning, not a failure
    finally:
        store.close()
