"""Entry-point plugin loading: discovery, namespacing, ingestion parity.

Plugins are simulated by monkeypatching `importlib.metadata.entry_points` — the
same mechanism a real `pip install sorb-plugin-foo` drives — so no install is
needed and the discovery/validation/namespacing path is exercised directly.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

import sorb.catalogers.base as cat_base
from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher
from sorb.catalogers.plugins import PluginCataloger, discover_plugin_catalogers
from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.base import Emitter, emitter_for
from sorb.graph.store import GraphStore
from sorb.model import ComponentClaim, Finding, Tier
from sorb.source.base import Entry


class AcmeCataloger(Cataloger):
    id = "acme-lock"
    version = 1
    matchers = [Matcher(basename="acme.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        for lineno, line in enumerate(blob.decode().splitlines(), start=1):
            if "==" in line:
                name, _, version = line.partition("==")
                yield Finding(
                    claim=ComponentClaim(ctype="library", name=name.strip(),
                                         version=version.strip(), ecosystem="acme"),
                    evidence=(ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                           span=(lineno, lineno), captured=line),),
                )


class AcmeCsvEmitter(Emitter):
    id = "acme-csv"
    media_type = "text/csv"

    def emit(self, store: GraphStore, *, reproducible: bool = False) -> bytes:
        return b"name,version\n" + b"".join(
            f"{c.name},{c.version or ''}\n".encode() for c in store.components()
        )


class _FakeEP:
    def __init__(self, name: str, obj: object) -> None:
        self.name = name
        self._obj = obj

    def load(self) -> object:
        return self._obj


def _fake_entry_points(cat_obj: object = None, emit_obj: object = None):
    def _ep(group: str | None = None, **_: object) -> list[_FakeEP]:
        if group == "sorb.catalogers" and cat_obj is not None:
            return [_FakeEP("acme", cat_obj)]
        if group == "sorb.emitters" and emit_obj is not None:
            return [_FakeEP("acme", emit_obj)]
        return []
    return _ep


@pytest.fixture()
def restore_registry():
    cat_base.registered()  # ensure builtins loaded before snapshot
    snapshot = list(cat_base._REGISTRY)
    yield
    cat_base._REGISTRY[:] = snapshot


# -- discovery + namespacing -------------------------------------------------------------


def test_plugin_cataloger_discovered_and_namespaced(monkeypatch) -> None:
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_entry_points(AcmeCataloger))
    found = discover_plugin_catalogers()
    assert len(found) == 1
    assert isinstance(found[0], PluginCataloger)
    assert found[0].id == "plugin:acme/acme-lock"
    assert found[0].detector == "plugin:acme/acme-lock@1"


def test_broken_plugin_is_skipped(monkeypatch) -> None:
    import importlib.metadata

    class Broken:
        def load(self) -> object:
            raise RuntimeError("bad plugin")
        name = "broken"

    monkeypatch.setattr(importlib.metadata, "entry_points",
                        lambda group=None, **_: [Broken()] if group == "sorb.catalogers" else [])
    assert discover_plugin_catalogers() == []  # not fatal


def test_non_cataloger_entrypoint_ignored(monkeypatch) -> None:
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "entry_points", _fake_entry_points(object))
    assert discover_plugin_catalogers() == []


# -- ingestion parity: plugin findings scan + reconcile like first-party ------------------


def test_plugin_scan_produces_namespaced_evidence(tmp_path: Path, restore_registry) -> None:
    cat_base.register(PluginCataloger(AcmeCataloger(), namespace="acme"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "acme.lock").write_text("leftpad==1.0.0\nrightpad==2.3.4\n")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "p.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        comps = {c.name: c for c in store.components()}
        assert "leftpad" in comps and "rightpad" in comps
        detail = store.component_detail(comps["leftpad"].id)
        assert detail is not None
        assert any(e["detector"] == "plugin:acme/acme-lock@1" for e in detail.evidence)
    finally:
        store.close()


# -- emitter plugins ---------------------------------------------------------------------


def test_plugin_emitter_resolved(monkeypatch, tmp_path: Path) -> None:
    import importlib.metadata

    import sorb.emit.base as emit_base

    monkeypatch.setattr(importlib.metadata, "entry_points",
                        _fake_entry_points(emit_obj=AcmeCsvEmitter))
    monkeypatch.setattr(emit_base, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(emit_base, "_EMITTERS", {})
    emitter = emitter_for("acme-csv")
    assert emitter is not None and emitter.media_type == "text/csv"
    store = GraphStore.create(tmp_path / "s.sorb.db")
    store.add_source("s1", "dir", "x", {})
    store.add_component(purl=None, ctype="library", name="lodash", version="4.0.0",
                        qualifiers=(), hashes={}, confidence=0.9, tier_cap=3, attrs={})
    store.commit()
    out = emitter.emit(store)
    store.close()
    assert b"lodash,4.0.0" in out
