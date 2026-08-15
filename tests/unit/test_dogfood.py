"""Self-SBOM dogfooding: `sorb scan` on sorb's own project metadata
produces a valid SBOM listing sorb's declared dependencies."""

from __future__ import annotations

import shutil
from pathlib import Path

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.validate import validate_sbom
from sorb.graph.store import GraphStore

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_scan_sorbs_own_project(tmp_path: Path) -> None:
    proj = tmp_path / "sorb-self"
    proj.mkdir()
    # the release pipeline scans the whole tree; here we scan sorb's own manifest
    shutil.copy2(_REPO_ROOT / "pyproject.toml", proj / "pyproject.toml")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "self.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        names = {c.name for c in store.components()}
        # sorb's own runtime dependencies show up in its self-SBOM
        assert "typer" in names
        assert "pathspec" in names or "blake3" in names
    finally:
        store.close()


def test_self_sbom_validates(tmp_path: Path) -> None:
    from sorb.emit.cyclonedx import emit_cyclonedx

    proj = tmp_path / "sorb-self"
    proj.mkdir()
    shutil.copy2(_REPO_ROOT / "pyproject.toml", proj / "pyproject.toml")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(proj), cfg, store_path=tmp_path / "self.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        sbom = emit_cyclonedx(store, reproducible=True)
        assert validate_sbom(sbom).structurally_valid
    finally:
        store.close()


def test_distribution_artifacts_present() -> None:
    # the distribution artifacts are committed (built/executed in release CI)
    assert (_REPO_ROOT / "Dockerfile").is_file()
    assert (_REPO_ROOT / "action.yml").is_file()
    assert (_REPO_ROOT / ".github/workflows/release.yml").is_file()
    assert (_REPO_ROOT / "packaging/sorb.spec").is_file()
    assert (_REPO_ROOT / "packaging/homebrew/sorb.rb").is_file()
    assert (_REPO_ROOT / "packaging/winget/SorbetSecurity.sorb.yaml").is_file()
