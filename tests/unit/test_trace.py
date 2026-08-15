"""Trace backends, fallback chain, and interpreter hooks.

The privilege-free interpreter hooks are exercised for real (a child process
imports installed distributions and the hook records them); the kernel
backends are availability-probed (they need root/entitlements — platform CI)."""

from __future__ import annotations

import sys
from pathlib import Path

from sorb.dynamic.trace import available_backends, run_trace
from sorb.dynamic.trace.backends import (
    EbpfBackend,
    NullBackend,
    StraceBackend,
    backend_chain,
    select_backend,
)
from sorb.dynamic.trace.model import Observation, TraceResult, is_store_path


def test_store_path_filter() -> None:
    assert is_store_path("/app/node_modules/lodash/index.js")
    assert is_store_path("/home/u/.venv/lib/python3.12/site-packages/requests/__init__.py")
    assert is_store_path("/root/.m2/repository/com/acme/x/1.0/x.jar")
    assert not is_store_path("/app/src/main.py")


def test_backend_chain_always_ends_in_null() -> None:
    chain = backend_chain()
    assert isinstance(chain[-1], NullBackend)
    # select_backend never fails: NullBackend is always available
    assert select_backend() is not None


def test_kernel_backends_probe_unavailable() -> None:
    ok, reason = EbpfBackend().available()
    assert ok is False and "platform-CI-gated" in reason
    reports = available_backends()
    assert reports and reports[-1][1] is True  # the fallback is available


def test_python_import_hook_records_distributions(tmp_path: Path) -> None:
    """The Python hook reports the exact loaded-distribution
    set, with zero privileges (NullBackend runs the child directly)."""
    script = tmp_path / "app.py"
    script.write_text(
        "import packaging.version\n"
        "import yaml\n"
        "import httpx\n"
        "print('done')\n"
    )
    result = run_trace([sys.executable, str(script)], backend=NullBackend())
    assert result.exit_code == 0
    assert "python-import-hook" in result.hooks
    dists = {o.identifier for o in result.modules() if o.technique == "python-import-hook"}
    # importing the modules pulls in their distributions by name
    assert "packaging" in dists
    assert "PyYAML" in dists or "pyyaml" in dists
    assert "httpx" in dists
    # versions captured
    packaging_obs = next(o for o in result.modules() if o.identifier == "packaging")
    assert packaging_obs.detail  # a version string
    assert packaging_obs.ecosystem == "pypi"


def test_hook_does_not_record_uninmported(tmp_path: Path) -> None:
    """A distribution that is installed but never imported is NOT observed —
    that's the whole point (observed ≠ installed)."""
    script = tmp_path / "app.py"
    script.write_text("import packaging\nprint('ok')\n")
    result = run_trace([sys.executable, str(script)], backend=NullBackend())
    dists = {o.identifier for o in result.modules()}
    assert "packaging" in dists
    # zstandard is installed (a sorb dep) but this script never imports it
    assert "zstandard" not in dists


def test_run_trace_empty_command_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="empty command"):
        run_trace([])


def test_trace_result_shapes() -> None:
    r = TraceResult(
        command=["x"], exit_code=0, backend="none",
        observations=[
            Observation("python-import-hook", "module", "requests", "2.32.0", "pypi"),
            Observation("strace-file-open", "file", "/app/node_modules/lodash/index.js"),
            Observation("strace-file-open", "file", "/app/src/main.py"),
        ],
    )
    assert len(r.modules()) == 1
    assert len(r.store_files()) == 1  # main.py is not a store path


def test_strace_backend_availability() -> None:
    ok, reason = StraceBackend().available()
    if sys.platform == "linux":
        assert isinstance(ok, bool)
    else:
        assert ok is False and "not Linux" in reason
