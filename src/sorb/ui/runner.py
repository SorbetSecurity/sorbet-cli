"""Server bootstrap for `sorb ui` / `sorb serve`.

Binds the socket up front so the ephemeral port is known before uvicorn starts —
that lets us print the token URL and open the browser at exactly the right moment.
When a target is given, the scan runs in a background thread that streams progress
onto the same `ProgressBus` the `/api/events` SSE endpoint subscribes to, so the
browser shows stages live and the graph becomes queryable the moment the run
lands.

Everything here still honours the offline guarantees: no telemetry, no external
request, loopback by default, and a scan is only started for a *local* target.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from sorb.core.events import ProgressBus
from sorb.ui.config import ServerConfig

if TYPE_CHECKING:
    from sorb.core.config import Config
    from sorb.ui.server import ServerState


def _bind_socket(host: str, port: int) -> tuple[socket.socket, int]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    actual_port = sock.getsockname()[1]
    sock.set_inheritable(True)
    return sock, actual_port


def serve(
    config: ServerConfig,
    *,
    scan_config: Config | None = None,
    watch: bool = False,
    on_ready: Callable[[str], None] | None = None,
) -> None:
    """Validate, bind, optionally launch a background scan, and run uvicorn.

    `on_ready` is called once with the URL after the port is known (used to print
    the token URL and open the browser). Blocks until the server stops.
    """
    import uvicorn

    config.validate()
    bus = ProgressBus()

    from sorb.ui.server import create_app

    app = create_app(config, bus=bus)
    state = app.state.sorb

    sock, port = _bind_socket(config.bind, config.port)
    state.port = port
    url = config.url(port)

    # Pre-create the SSE stream on the serving loop so a background scan started at
    # startup has somewhere to publish even before the first browser subscribes.
    scan_target = config.target if (config.target and scan_config is not None) else None

    if config.allow_scan and scan_config is not None:
        def launch(target: str) -> None:
            threading.Thread(
                target=_run_scan_thread,
                args=(state, bus, target, scan_config, False),
                daemon=True,
            ).start()

        state.scan_launcher = launch

    @app.on_event("startup")
    async def _startup() -> None:
        import asyncio as _asyncio

        from sorb.ui.sse import EventStream

        state.events = EventStream(bus, loop=_asyncio.get_running_loop())
        if scan_target is not None:
            state.scan_status = "scanning"
            threading.Thread(
                target=_run_scan_thread,
                args=(state, bus, scan_target, scan_config, watch),
                daemon=True,
            ).start()

    if on_ready is not None:
        on_ready(url)

    uv_config = uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on")
    server = uvicorn.Server(uv_config)
    import asyncio

    asyncio.run(server.serve(sockets=[sock]))


def _run_scan_thread(
    state: ServerState, bus: ProgressBus, target: str, cfg: Config, watch: bool = False
) -> None:
    from sorb.core.pipeline import run_scan

    def _once() -> None:
        result = run_scan(target, cfg, bus=bus)
        state.set_current_db(Path(result.store_path))
        state.scan_status = "done"

    try:
        _once()
    except Exception as exc:  # pragma: no cover - surfaced to the UI status
        from sorb.core.events import WarningRaised

        bus.emit(WarningRaised(code="SCAN_FAILED", message=str(exc)))
        state.scan_status = "error"

    # signal end-of-stream so subscribers get a `done` event and refresh; the
    # browser's EventSource then auto-reconnects to the same (reused) stream.
    if state.events is not None:
        state.events.close()
    if watch and Path(target).is_dir():
        _watch_loop(state, bus, target, cfg)  # re-scan on change, streaming each pass


def _tree_signature(root: Path) -> float:
    latest = 0.0
    for path in root.rglob("*"):
        if ".sorb" in path.parts:
            continue
        try:
            latest = max(latest, path.stat().st_mtime)
        except OSError:  # pragma: no cover - race with deletion
            continue
    return latest


def _watch_loop(state: ServerState, bus: ProgressBus, target: str, cfg: Config) -> None:
    import time

    from sorb.core.pipeline import run_scan

    root = Path(target)
    last = _tree_signature(root)
    while True:
        time.sleep(2.0)
        try:
            sig = _tree_signature(root)
        except OSError:  # pragma: no cover
            continue
        if sig <= last:
            continue
        last = sig
        state.scan_status = "scanning"
        try:
            result = run_scan(target, cfg, bus=bus)  # streams onto the reused EventStream
            state.set_current_db(Path(result.store_path))
            state.scan_status = "done"
        except Exception as exc:  # pragma: no cover
            from sorb.core.events import WarningRaised

            bus.emit(WarningRaised(code="SCAN_FAILED", message=str(exc)))
            state.scan_status = "error"
        finally:
            if state.events is not None:
                state.events.close()


def open_browser(url: str) -> None:
    """Open the token URL in the default browser, best-effort and non-blocking."""
    import webbrowser

    def _open() -> None:
        try:
            webbrowser.open(url)
        except Exception:  # pragma: no cover - headless / no browser
            pass

    threading.Thread(target=_open, daemon=True).start()
