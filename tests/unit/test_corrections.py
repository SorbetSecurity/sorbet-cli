"""Project corrections: false positives stop emitting, missing components are
asserted, and both are remembered across scans via sorb.corrections.json."""

from __future__ import annotations

import shutil
from pathlib import Path

from sorb.core.config import load_config
from sorb.core.corrections import (
    Correction,
    add_correction,
    apply_corrections,
    load_corrections,
    remove_correction,
)
from sorb.core.pipeline import run_scan
from sorb.graph.store import GraphStore
from sorb.model import Tier

FIXTURE = Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot"


def test_corrections_file_roundtrip(tmp_path: Path) -> None:
    assert load_corrections(tmp_path) == []
    assert add_correction(tmp_path, Correction(kind="false-positive", ref="lodash"))
    assert not add_correction(tmp_path, Correction(kind="false-positive", ref="lodash"))
    assert add_correction(tmp_path, Correction(kind="missing", ref="left-pad@1.3.0",
                                               ecosystem="npm", reason="vendored copy"))
    entries = load_corrections(tmp_path)
    assert [e.kind for e in entries] == ["false-positive", "missing"]
    assert remove_correction(tmp_path, "false-positive", "lodash")
    assert not remove_correction(tmp_path, "false-positive", "lodash")
    assert [e.ref for e in load_corrections(tmp_path)] == ["left-pad@1.3.0"]


def test_apply_marks_fp_and_asserts_missing(tmp_path: Path) -> None:
    store = GraphStore.create(tmp_path / "t.sorb.db")
    store.add_component(purl="pkg:npm/lodash@4.17.21", ctype="library", name="lodash",
                        version="4.17.21", qualifiers={}, hashes={}, confidence=0.9,
                        tier_cap=int(Tier.LOCKED), attrs={"ecosystem": "npm"})
    store.commit()
    fps, added = apply_corrections(store, [
        Correction(kind="false-positive", ref="lodash", reason="test fixture only"),
        Correction(kind="missing", ref="pkg:npm/left-pad@1.3.0", ecosystem="npm"),
    ])
    assert (fps, added) == (1, 1)
    lodash = store.find_component("lodash")[0]
    assert "false positive" in str(lodash.attrs.get("excluded"))
    left_pad = store.find_component("left-pad")[0]
    assert left_pad.version == "1.3.0" and left_pad.attrs.get("asserted") == "true"
    # a second application is idempotent
    assert apply_corrections(store, [
        Correction(kind="false-positive", ref="lodash"),
        Correction(kind="missing", ref="pkg:npm/left-pad@1.3.0"),
    ]) == (0, 0)
    store.close()


def test_corrections_remembered_across_scans(tmp_path: Path) -> None:
    """The whole promise: a recorded correction shapes every later scan."""
    proj = tmp_path / "polyglot"
    shutil.copytree(FIXTURE, proj, ignore=shutil.ignore_patterns(".sorb"))
    add_correction(proj, Correction(kind="false-positive", ref="lodash"))
    add_correction(proj, Correction(kind="missing", ref="acme-internal@1.0.0",
                                    ecosystem="npm", reason="private registry package"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "run.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        lodash = store.find_component("lodash")
        assert lodash and all(c.attrs.get("excluded") for c in lodash)
        asserted = store.find_component("acme-internal")
        assert asserted and asserted[0].version == "1.0.0"
        assert asserted[0].attrs.get("asserted") == "true"
    finally:
        store.close()
