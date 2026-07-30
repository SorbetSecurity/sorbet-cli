"""`sorb ui` / `sorb serve` command wiring + live-scan streaming.

The commands' *bootstrap* is exercised by capturing the `ServerConfig` the CLI
builds (runner.serve is stubbed — binding a real socket is both unnecessary here
and blocked by the suite's network guard). The live-scan path is exercised by
driving a real scan through the SSE bridge directly.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sorb.ui.runner as runner_mod
from sorb.cli.main import app
from sorb.core.config import load_config
from sorb.core.events import ProgressBus, ScanStarted, StageCompleted
from sorb.core.pipeline import run_scan
from sorb.ui.sse import EventStream

runner = CliRunner()


@pytest.fixture()
def capture_serve(monkeypatch):
    """Replace runner.serve with a capture so the command never binds a socket."""
    calls: dict = {}

    def fake_serve(config, *, scan_config=None, watch=False, on_ready=None):
        calls["config"] = config
        calls["scan_config"] = scan_config
        calls["watch"] = watch

    monkeypatch.setattr(runner_mod, "serve", fake_serve)
    return calls


# -- command bootstrap -------------------------------------------------------------------


def test_serve_refuses_public_bind_without_auth(capture_serve) -> None:
    res = runner.invoke(app, ["serve", "--bind", "0.0.0.0", "--auth", "none"])
    assert res.exit_code == 3  # usage error, refused before binding
    assert "config" not in capture_serve  # serve() never reached


def test_ui_serves_workspace_with_no_target(capture_serve) -> None:
    res = runner.invoke(app, ["ui", "--no-open"])
    assert res.exit_code == 0
    assert capture_serve["scan_config"] is None  # nothing to scan
    assert capture_serve["config"].require_token


def test_ui_opens_result_file_directly(tmp_path: Path, capture_serve) -> None:
    db = tmp_path / "x.sorb.db"
    db.write_bytes(b"")
    res = runner.invoke(app, ["ui", str(db), "--no-open"])
    assert res.exit_code == 0
    assert capture_serve["scan_config"] is None
    assert capture_serve["config"].run == str(db)


def test_ui_scans_a_target(tmp_path: Path, capture_serve) -> None:
    (tmp_path / "pkg").mkdir()
    res = runner.invoke(app, ["ui", str(tmp_path / "pkg"), "--no-open"])
    assert res.exit_code == 0
    assert capture_serve["scan_config"] is not None  # a scan is scheduled
    assert capture_serve["config"].target == str(tmp_path / "pkg")


def test_ui_watch_flag_threads_through(tmp_path: Path, capture_serve) -> None:
    (tmp_path / "pkg").mkdir()
    res = runner.invoke(app, ["ui", str(tmp_path / "pkg"), "--no-open", "--watch"])
    assert res.exit_code == 0
    assert capture_serve["watch"] is True


# -- live-scan streams through SSE -------------------------------------------------------


def test_live_scan_streams_events_to_subscriber(tmp_path: Path) -> None:
    fixture = Path(__file__).parent.parent / "corpus" / "fixtures" / "polyglot"
    proj = tmp_path / "polyglot"
    shutil.copytree(fixture, proj, ignore=shutil.ignore_patterns(".sorb"))
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")

    async def scenario() -> str:
        bus = ProgressBus()
        stream = EventStream(bus, loop=asyncio.get_running_loop())
        received: list[str] = []

        async def consume() -> None:
            async for chunk in stream.subscribe():
                received.append(chunk)
                if "event: done" in chunk:
                    return

        task = asyncio.create_task(consume())
        await asyncio.sleep(0)
        # run the scan on a worker thread, emitting onto the bus (as the runner does)
        await asyncio.get_running_loop().run_in_executor(
            None, lambda: run_scan(str(proj), cfg, bus=bus, store_path=tmp_path / "run.sorb.db")
        )
        stream.close()
        await asyncio.wait_for(task, timeout=5.0)
        return "".join(received)

    joined = asyncio.run(scenario())
    assert "ScanStarted" in joined  # findings streamed live, before the UI refresh
    assert "StageCompleted" in joined
    assert "event: done" in joined  # completion sentinel → UI reloads the finished graph


def test_scan_events_are_typed() -> None:
    # sanity: the event types the UI listens for are the ones the bus emits
    assert ScanStarted(target="t", subject="s").subject == "s"
    assert StageCompleted(stage="detect", duration_s=0.0).stage == "detect"
