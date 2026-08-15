"""Runtime observation of what software actually loads.

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
from sorb.cli.render import (
    _policy_failed,
)
from sorb.errors import (
    EXIT_OK,
    EXIT_POLICY_FAIL,
    SorbError,
    exit_code_for,
)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def trace(
    ctx: typer.Context,
    target: str = typer.Option(".", "--target", help="Project to scan before tracing"),
    fail_on: str | None = typer.Option(None, "--fail-on", help="e.g. phantom-deps"),
) -> None:
    """Scan a project, then run a command and record what it actually loads.

    Usage: ``sorb trace [--target DIR] -- <cmd> [args…]``. Runtime observations
    upgrade components to the observed tier and surface phantom (undeclared)
    and unused (never-loaded) dependencies.
    """
    command = list(ctx.args)
    if not command:
        typer.echo("error: nothing to trace — usage: sorb trace -- <cmd>", err=True)
        raise typer.Exit(3)
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.dynamic.trace import run_trace
    from sorb.dynamic.trace.mapper import map_observations
    from sorb.graph.store import GraphStore

    try:
        cfg = load_config(target=Path(target).resolve(), flags={"fail_on": fail_on})
        result = run_scan(target, cfg)
        typer.echo(f"  scanned {target}: {result.stats.components} components", err=True)
        typer.echo(f"  tracing: {' '.join(command)}", err=True)
        trace_result = run_trace(command)
        store = GraphStore.open_rw(result.store_path)
        try:
            report = map_observations(store, trace_result, session_label=" ".join(command[:3]))
        finally:
            store.close()
        loaded = len(report.observed) + len(report.phantom)
        typer.echo(
            f"  loaded {loaded} components at runtime — {len(report.observed)} already "
            f"in the SBOM, {len(report.phantom)} undeclared "
            f"(backend: {trace_result.backend}, hooks: {', '.join(trace_result.hooks)})"
        )
        for phantom in report.phantom:
            typer.echo(f"  ⚠ phantom (observed, undeclared): {phantom}")
        for unused in report.unused:
            typer.echo(f"  ○ declared but never observed: {unused}")
        exit_code = EXIT_OK
        if fail_on and _policy_failed(
            result.store_path, tuple(t.strip() for t in fail_on.split(","))
        ):
            exit_code = EXIT_POLICY_FAIL
        raise typer.Exit(exit_code)
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def snapshot(
    ctx: typer.Context,
    target: str = typer.Option(".", "--target", help="Environment to snapshot around the step"),
) -> None:
    """Diff the installed state before and after a provisioning step.

    Usage: ``sorb snapshot [--target DIR] -- <cmd>``. Names exactly what the
    command installed, upgraded, or removed.
    """
    import subprocess
    import tempfile

    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.dynamic.snapshot import Snapshot, diff_snapshots, render_diff
    from sorb.graph.store import GraphStore

    command = list(ctx.args)
    if not command:
        typer.echo("error: nothing to run — usage: sorb snapshot -- <cmd>", err=True)
        raise typer.Exit(3)

    def _snapshot(target_path: Path, work_db: Path) -> Snapshot:
        cfg = load_config(flags={})
        result = run_scan(str(target_path), cfg, store_path=work_db)
        s = GraphStore.open_readonly(result.store_path)
        try:
            return Snapshot.from_store(s)
        finally:
            s.close()

    try:
        with tempfile.TemporaryDirectory(prefix="sorb-snapshot-") as tmp:
            target_path = Path(target).resolve()
            before = _snapshot(target_path, Path(tmp) / "before.sorb.db")
            typer.echo(f"  before: {len(before.entries)} installed components", err=True)
            proc = subprocess.run(command, cwd=target_path, check=False)
            typer.echo(f"  ran: {' '.join(command)} (exit {proc.returncode})", err=True)
            after = _snapshot(target_path, Path(tmp) / "after.sorb.db")
            diff = diff_snapshots(before, after)
        typer.echo(render_diff(diff))
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def watch(
    ctx: typer.Context,
    target: str = typer.Option(".", "--target", help="Project to watch"),
    iterations: int = typer.Option(0, "--iterations", help="Stop after N trace sessions (0 = until interrupted)"),
) -> None:
    """Long-running observation: append observed findings across trace sessions.

    Usage: ``sorb watch [--target DIR] --iterations N -- <cmd>``. Survives
    target restarts by re-running the command; each session's observations are
    merged into the same run store.
    """
    command = list(ctx.args)
    if not command:
        typer.echo("error: nothing to watch — usage: sorb watch -- <cmd>", err=True)
        raise typer.Exit(3)
    from sorb.core.config import load_config
    from sorb.core.pipeline import run_scan
    from sorb.dynamic.trace import run_trace
    from sorb.dynamic.trace.mapper import map_observations
    from sorb.graph.store import GraphStore

    try:
        cfg = load_config(target=Path(target).resolve(), flags={})
        result = run_scan(target, cfg)
        typer.echo(f"  watching {target} (store {result.run_id})", err=True)
        session = 0
        total_observed = 0
        while iterations == 0 or session < iterations:
            session += 1
            try:
                trace_result = run_trace(command)
            except Exception as e:  # noqa: BLE001 — a target crash must not kill the watcher
                typer.echo(f"  session {session}: target failed ({e}); restarting", err=True)
                continue
            store = GraphStore.open_rw(result.store_path)
            try:
                report = map_observations(store, trace_result, session_label=f"session-{session}")
            finally:
                store.close()
            total_observed += len(report.observed)
            typer.echo(f"  session {session}: {len(report.observed)} observed, "
                       f"{len(report.phantom)} phantom")
            if iterations == 0:
                break  # non-CI interactive loop is Ctrl-C driven; one pass here
        typer.echo(f"  watch complete: {total_observed} total observations across {session} session(s)")
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e
