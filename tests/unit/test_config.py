"""Config: fingerprint sensitivity, precedence, section mirroring."""

from __future__ import annotations

from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.errors import UsageError


def _cfg(tmp_path: Path, **kwargs):
    kwargs.setdefault("env", {})
    kwargs.setdefault("user_config_path", tmp_path / "no-user-config.toml")
    return load_config(**kwargs)


def test_fingerprint_changes_iff_detector_relevant(tmp_path: Path) -> None:
    base = _cfg(tmp_path)
    same = _cfg(tmp_path, flags={"output": ["table"], "fail_on": "drift"})
    assert base.fingerprint() == same.fingerprint()  # emission-only fields
    changed = _cfg(tmp_path, flags={"scope": "runtime"})
    assert base.fingerprint() != changed.fingerprint()
    changed2 = _cfg(tmp_path, flags={"env_matrix": ["python=3.12"]})
    assert base.fingerprint() != changed2.fingerprint()


def test_precedence_flags_env_project(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "sorb.toml").write_text('[scan]\nscope = "dev"\nparanoid = true\n')
    cfg = _cfg(tmp_path, target=proj)
    assert cfg.scope == "dev" and cfg.paranoid is True
    assert cfg.origins["scope"].startswith("project")

    cfg = _cfg(tmp_path, target=proj, env={"SORB_SCOPE": "runtime"})
    assert cfg.scope == "runtime"
    assert cfg.origins["scope"].startswith("env")

    cfg = _cfg(tmp_path, target=proj, env={"SORB_SCOPE": "runtime"}, flags={"scope": "all"})
    assert cfg.scope == "all"
    assert cfg.origins["scope"] == "flag"


def test_invalid_values_are_usage_errors(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        _cfg(tmp_path, flags={"scope": "bogus"})
    with pytest.raises(UsageError):
        _cfg(tmp_path, flags={"min_confidence": 3.0})
