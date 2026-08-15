"""The local evidence explorer.

Commands are thin adapters: parse arguments, call into `sorb.core`,
render. Heavy imports stay inside command bodies so `sorb --help`
keeps its startup budget.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:

    pass

from sorb.cli.app import app
from sorb.errors import (
    EXIT_USAGE,
)


@app.command()
def ui(
    target: str | None = typer.Argument(
        None, help="Target to scan then serve · .sorb result file to open · nothing to serve the workspace"
    ),
    bind: str = typer.Option("127.0.0.1", "--bind", help="Interface to bind"),
    port: int = typer.Option(0, "--port", help="Port (0 = ephemeral)"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Auto-open a browser (default on a TTY)"),
    auth: str = typer.Option("token", "--auth", help="token|none — non-loopback binds require token"),
    allow_scan: bool = typer.Option(False, "--allow-scan", help="Permit launching scans from the browser"),
    watch: bool = typer.Option(False, "--watch", help="Re-scan on filesystem change, live-update the UI"),
    offline: bool = typer.Option(False, "--offline", help="Absolute network kill-switch"),
    allowed_host: list[str] = typer.Option(
        [], "--allowed-host",
        help="Extra Host header to accept, for a reverse proxy in front (repeatable)"
    ),
) -> None:
    """Open the local evidence explorer.

    With a target, scan it — findings stream into the UI as they are found — then
    serve. With a `.sorb` result file, open it. With nothing, serve the project's
    results workspace (`.sorb/results/`).
    """
    _serve_ui(target, bind=bind, port=port, auth=auth, allow_scan=allow_scan,
              open_browser=open_browser, watch=watch, offline=offline,
              allowed_hosts=tuple(allowed_host))


@app.command()
def serve(
    target: str | None = typer.Argument(None, help="Optional target/result to serve (never opens a browser)"),
    bind: str = typer.Option("127.0.0.1", "--bind", help="Interface to bind"),
    port: int = typer.Option(0, "--port", help="Port (0 = ephemeral)"),
    auth: str = typer.Option("token", "--auth", help="token|none — non-loopback binds require token"),
    allow_scan: bool = typer.Option(False, "--allow-scan", help="Permit launching scans from the browser"),
    offline: bool = typer.Option(False, "--offline", help="Absolute network kill-switch"),
    allowed_host: list[str] = typer.Option(
        [], "--allowed-host",
        help="Extra Host header to accept, for a reverse proxy in front (repeatable)"
    ),
) -> None:
    """Headless server for CI / shared hosts — the same server, no browser."""
    _serve_ui(target, bind=bind, port=port, auth=auth, allow_scan=allow_scan,
              open_browser=False, watch=False, offline=offline,
              allowed_hosts=tuple(allowed_host))


def _serve_ui(
    target: str | None, *, bind: str, port: int, auth: str, allow_scan: bool,
    open_browser: bool, watch: bool, offline: bool, allowed_hosts: tuple[str, ...] = (),
) -> None:
    """Shared bootstrap for `sorb ui` (opens a browser) and `sorb serve` (headless)."""
    import sys

    from sorb.core.config import load_config
    from sorb.ui.config import ServerConfig
    from sorb.ui.runner import open_browser as _open
    from sorb.ui.runner import serve

    scan_config = None
    server_target: str | None = None
    run_arg: str | None = None
    if target is not None and (target.endswith(".sorb.db") or target.endswith(".sorb.json")):
        run_arg = target  # serve an existing result directly
    elif target is not None:
        # a scannable target — scan it (streaming into the UI), then serve.
        tpath = Path(target)
        scan_config = load_config(
            target=tpath if tpath.is_dir() else None, flags={"offline": offline}
        )
        server_target = target
    if allow_scan and scan_config is None:
        # --allow-scan without a target: the browser can still ask for one, so
        # the worker needs a config to run it with.
        scan_config = load_config(flags={"offline": offline})

    config = ServerConfig(
        bind=bind, port=port, auth=auth, allow_scan=allow_scan,
        open_browser=open_browser, run=run_arg,
        target=server_target if server_target is not None else (target or "."),
        extra_allowed_hosts=allowed_hosts,
    )
    try:
        config.validate()
    except ValueError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_USAGE) from e

    def on_ready(url: str) -> None:
        typer.echo(f"  sorbet UI → {url}", err=True)
        if config.require_token:
            typer.echo("  (the token in the URL is this session's key — keep it local)", err=True)
        if open_browser and sys.stdout.isatty():
            _open(url)

    try:
        serve(config, scan_config=scan_config, watch=watch, on_ready=on_ready)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.echo("\n  stopped", err=True)
