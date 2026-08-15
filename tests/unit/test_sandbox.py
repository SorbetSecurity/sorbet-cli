"""Sandbox spec, profile generation, refusal, and the
escape-test suite. Escape tests run natively where the platform's sandbox is
available (macOS here); the Linux/Windows suites run on their CI runners."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest

from sorb.dynamic.sandbox import (
    SandboxSpec,
    SandboxUnavailable,
    run_sandboxed,
    sandbox_available,
    toolchain_read_paths,
)
from sorb.dynamic.sandbox.spec import _ENV_ALLOWLIST

#: Python's install tree, so the interpreter can start inside the sandbox
_PY_ROOTS = toolchain_read_paths(sys.executable)


def _spec(tmp_path: Path, **kw) -> SandboxSpec:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    extra = tuple(kw.pop("extra_read_paths", ())) + _PY_ROOTS
    return SandboxSpec(
        project_root=project, scratch_home=tmp_path / "home", extra_read_paths=extra, **kw
    )


def test_env_is_scrubbed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
    monkeypatch.setenv("NPM_TOKEN", "secret")
    monkeypatch.setenv("PATH", "/usr/bin")
    spec = _spec(tmp_path, extra_env=(("SORB_OUT", "/x"),))
    env = spec.child_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env and "NPM_TOKEN" not in env
    assert env["HOME"] == str(tmp_path / "home")
    assert env["SORB_OUT"] == "/x"
    assert set(env) - {"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "SORB_OUT"} <= set(_ENV_ALLOWLIST)


@pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX paths inside the profile")
def test_macos_profile_denies_by_default(tmp_path: Path) -> None:
    from sorb.dynamic.sandbox.macos import generate_profile

    profile = generate_profile(_spec(tmp_path))
    assert "(deny default)" in profile
    assert "network-outbound" not in profile  # no allow-net → no network at all
    assert str(tmp_path / "project") in profile

    net_profile = generate_profile(_spec(tmp_path, allow_net_hosts=("registry.npmjs.org",)))
    assert "(allow network-outbound)" in net_profile
    assert "registry.npmjs.org" in net_profile  # recorded in the profile comment


def test_refusal_without_sandbox(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "sorb.dynamic.sandbox.spec.sandbox_available", lambda: (False, "test: no primitives")
    )
    with pytest.raises(SandboxUnavailable, match="dangerously-no-sandbox"):
        run_sandboxed(_spec(tmp_path), [sys.executable, "-c", "print(1)"])
    # explicit opt-out runs it (scrubbed env + rlimits still applied)
    result = run_sandboxed(
        _spec(tmp_path), [sys.executable, "-c", "print('ok')"], dangerously_no_sandbox=True
    )
    assert result.exit_code == 0 and result.stdout.strip() == b"ok"


def test_stdout_is_the_result_channel(tmp_path: Path) -> None:
    result = run_sandboxed(
        _spec(tmp_path),
        [sys.executable, "-c", "import sys; sys.stdout.write('RESULT'); sys.stderr.write('noise')"],
        dangerously_no_sandbox=True,
    )
    assert result.stdout == b"RESULT"
    assert b"noise" in result.stderr


def test_timeout(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    slow = SandboxSpec(
        project_root=spec.project_root, scratch_home=spec.scratch_home, timeout_s=1
    )
    result = run_sandboxed(
        slow, [sys.executable, "-c", "import time; time.sleep(30)"],
        dangerously_no_sandbox=True,
    )
    assert result.timed_out


# -- escape tests: run only where the platform sandbox is actually available -------------

_available, _reason = sandbox_available()
_escape = pytest.mark.skipif(not _available, reason=f"sandbox unavailable here: {_reason}")


@_escape
def test_escape_cannot_read_outside_project(tmp_path: Path) -> None:
    """A secret file outside the project (and outside home) is unreadable."""
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("TOP SECRET")
    spec = _spec(tmp_path)
    code = f"open({str(secret)!r}).read(); print('READ')"
    result = run_sandboxed(spec, [sys.executable, "-c", code])
    assert result.exit_code != 0, "sandbox must not read files outside the project root"
    assert b"READ" not in result.stdout


@_escape
def test_escape_project_is_readable(tmp_path: Path) -> None:
    """The project root itself IS readable (build tools need it)."""
    spec = _spec(tmp_path)
    (spec.project_root / "manifest.txt").write_text("declared")
    code = "print(open('manifest.txt').read())"
    result = run_sandboxed(spec, [sys.executable, "-c", code])
    assert result.exit_code == 0 and b"declared" in result.stdout


@_escape
def test_escape_network_denied(tmp_path: Path) -> None:
    """With no --allow-net, opening a socket / resolving DNS fails."""
    spec = _spec(tmp_path)
    code = (
        "import socket; "
        "socket.create_connection(('1.1.1.1', 53), timeout=3); print('CONNECTED')"
    )
    result = run_sandboxed(spec, [sys.executable, "-c", code])
    assert result.exit_code != 0, "network must be denied without --allow-net"
    assert b"CONNECTED" not in result.stdout


@_escape
def test_escape_credentials_invisible(tmp_path: Path) -> None:
    """Ambient credential env vars do not reach the child."""
    import os

    os.environ["SORB_TEST_FAKE_TOKEN"] = "sekret"
    try:
        spec = _spec(tmp_path)
        code = "import os; print(os.environ.get('SORB_TEST_FAKE_TOKEN', 'ABSENT'))"
        result = run_sandboxed(spec, [sys.executable, "-c", code])
        assert result.exit_code == 0
        assert result.stdout.strip() == b"ABSENT"
    finally:
        del os.environ["SORB_TEST_FAKE_TOKEN"]


def test_platform_reports_availability() -> None:
    available, reason = sandbox_available()
    assert isinstance(available, bool) and isinstance(reason, str) and reason
    if platform.system() == "Darwin":
        assert available, "macOS runners ship sandbox-exec"
