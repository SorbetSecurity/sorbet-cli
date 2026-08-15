"""sorb-accel shim: selection, self-check invariant, and the differential
guarantee that accel vs pure produce byte-identical output.

The Rust `sorb_accel` wheel is not built in this environment, so a Python
stand-in accelerator (parallel-shaped, same result) plays its role — enough to
prove the seam, the load-time self-check, and the byte-identical contract that
the real crate must also satisfy."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

import sorb.accel as accel
from sorb.accel import PureAccelerator, accelerated, load_accelerator, set_accelerator
from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.graph.store import GraphStore


class _GoodAccel:
    """A well-behaved accelerator: same bytes out, just (pretend) faster."""

    name = "sorb-accel"

    def hash_file(self, path: str) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


class _BrokenAccel:
    """A broken accelerator whose hashing disagrees with the reference."""

    name = "sorb-accel"

    def hash_file(self, path: str) -> str:
        return "deadbeef"

    def hash_bytes(self, data: bytes) -> str:
        return "deadbeef"


@pytest.fixture(autouse=True)
def _restore_accel():
    saved = accel.active()
    yield
    set_accelerator(saved if isinstance(saved, PureAccelerator) else PureAccelerator())
    accel._active = saved


# -- selection ---------------------------------------------------------------------------


def test_pure_selected_when_wheel_absent() -> None:
    # sorb_accel is not installed here → the reference is selected
    assert isinstance(load_accelerator(), PureAccelerator)
    assert not accelerated()


def test_no_accel_forces_pure(monkeypatch) -> None:
    assert isinstance(load_accelerator(no_accel=True), PureAccelerator)
    monkeypatch.setenv("SORB_NO_ACCEL", "1")
    assert isinstance(load_accelerator(), PureAccelerator)


# -- the self-check invariant (byte-identical at load time) ------------------------------


def test_self_check_accepts_matching_accelerator() -> None:
    set_accelerator(_GoodAccel())
    assert accelerated()
    assert accel.hash_bytes(b"hi") == hashlib.sha256(b"hi").hexdigest()


def test_self_check_rejects_mismatched_accelerator() -> None:
    set_accelerator(_BrokenAccel())  # its hashing disagrees with the reference
    assert not accelerated()  # → refused, fell back to pure
    assert accel.hash_bytes(b"hi") == hashlib.sha256(b"hi").hexdigest()


# -- the differential guarantee (accel vs pure on the corpus) ----------------------------


def _scan_sbom(target: Path, tmp: Path, tag: str) -> bytes:
    cfg = load_config(flags={}, env={}, user_config_path=tmp / "nc.toml")
    result = run_scan(str(target), cfg, store_path=tmp / f"{tag}.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        return emit_cyclonedx(store, reproducible=True)
    finally:
        store.close()


def test_accel_vs_pure_byte_identical(tmp_path: Path) -> None:
    """Accel and pure produce byte-identical findings."""
    proj = tmp_path / "polyglot"
    shutil.copytree(Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot", proj,
                    ignore=shutil.ignore_patterns(".sorb"))

    set_accelerator(PureAccelerator())
    pure = _scan_sbom(proj, tmp_path, "pure")
    set_accelerator(_GoodAccel())
    fast = _scan_sbom(proj, tmp_path, "fast")
    assert pure == fast  # byte-identical SBOM across the two tiers


def test_no_accel_flag_does_not_change_output(tmp_path: Path) -> None:
    proj = tmp_path / "polyglot"
    shutil.copytree(Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot", proj,
                    ignore=shutil.ignore_patterns(".sorb"))
    a = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    b = load_config(flags={"no_accel": True}, env={}, user_config_path=tmp_path / "nc.toml")
    ra = run_scan(str(proj), a, store_path=tmp_path / "a.sorb.db")
    rb = run_scan(str(proj), b, store_path=tmp_path / "b.sorb.db")
    sa, sb = GraphStore.open_readonly(ra.store_path), GraphStore.open_readonly(rb.store_path)
    try:
        assert emit_cyclonedx(sa, reproducible=True) == emit_cyclonedx(sb, reproducible=True)
    finally:
        sa.close()
        sb.close()


def test_accel_cli(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from sorb.cli.main import app

    res = CliRunner().invoke(app, ["accel"])
    assert res.exit_code == 0
    assert "tier:" in res.output
