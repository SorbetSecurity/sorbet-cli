"""Scanning a target.

Commands are thin adapters: parse arguments, call into `sorb.core`,
render. Heavy imports stay inside command bodies so `sorb --help`
keeps its startup budget.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:

    from sorb.core.config import Config

from sorb.cli.app import app
from sorb.cli.render import (
    _FORMATS,
    _policy_failed,
    _print_drift_report,
    _render_outputs,
)
from sorb.errors import (
    EXIT_OK,
    EXIT_POLICY_FAIL,
    EXIT_SCAN_ERRORS,
    SorbError,
    UsageError,
    exit_code_for,
)


@app.command()
def scan(
    target: str = typer.Argument(
        ".",
        help="dir, file, image:REF, oci-dir:PATH, docker-archive:TAR, docker:REF, "
        "podman:REF, containerd:REF, container://ID, host://, disk://IMAGE",
    ),
    output: list[str] = typer.Option(
        [], "-o", "--output", help=f"Output format(s): {', '.join(_FORMATS)} (repeatable)"
    ),
    file: list[str] = typer.Option(
        [], "-f", "--file", help="Output file per -o (positional pairing; default stdout)"
    ),
    scope: str | None = typer.Option(None, "--scope", help="runtime|dev|all emission filter"),
    min_confidence: float | None = typer.Option(None, "--min-confidence"),
    paranoid: bool = typer.Option(False, "--paranoid", help="Only ≥ locked-tier components"),
    offline: bool = typer.Option(False, "--offline", help="Absolute network kill-switch"),
    env: list[str] = typer.Option([], "--env", help="Target environment matrix (k=v, repeatable)"),
    project: str | None = typer.Option(None, "--project", help="Limit to a workspace member"),
    resolve: str | None = typer.Option(
        None, "--resolve", help="pure|native|off — native runs the build tool sandboxed"
    ),
    allow_net: list[str] = typer.Option(
        [], "--allow-net", help="Hosts the sandbox/enrichment may reach (repeatable)"
    ),
    dangerously_no_sandbox: bool = typer.Option(
        False, "--dangerously-no-sandbox", help="Run native mode without the sandbox (unsafe)"
    ),
    platform: str | None = typer.Option(
        None, "--platform", help="Image platform, e.g. linux/amd64 (default linux/amd64)"
    ),
    all_platforms: bool = typer.Option(
        False, "--all-platforms", help="Scan every platform in a multi-arch image index"
    ),
    include_removed: bool = typer.Option(
        False, "--include-removed", help="Emit packages deleted during the image build"
    ),
    follow_images: bool = typer.Option(
        False, "--follow-images", help="Chase image refs found in IaC into container scans"
    ),
    dockerfile: str | None = typer.Option(
        None, "--dockerfile", help="Dockerfile to cross-link layer history against"
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Comma list: drift, stale-lockfile, version-conflict, phantom-deps, low-confidence"
    ),
    report: str | None = typer.Option(None, "--report", help="Extra report: drift"),
    log_format: str | None = typer.Option(None, "--log-format", help="auto|json"),
    reproducible: bool = typer.Option(
        False, "--reproducible", help="Honor SOURCE_DATE_EPOCH; byte-identical output"
    ),
    profile: bool = typer.Option(False, "--profile", help="Record per-stage timings in run meta"),
    evidence: str | None = typer.Option(None, "--evidence", help="minimal|standard|full"),
    cache: bool = typer.Option(False, "--cache", help="Reuse detector results by content"),
    remote_cache: str | None = typer.Option(
        None, "--remote-cache", help="Shared HTTP CAS URL (fail-open, honors --offline)"
    ),
    no_accel: bool = typer.Option(
        False, "--no-accel", help="Force the pure-Python reference over sorb-accel"
    ),
) -> None:
    """Scan a target and emit evidence-backed SBOMs."""
    from sorb.core.config import load_config
    from sorb.core.events import ProgressBus, ndjson_sink, tty_sink
    from sorb.core.pipeline import run_scan

    try:
        flags = {
            "scope": scope,
            "min_confidence": min_confidence,
            "paranoid": paranoid or None,
            "offline": offline or None,
            "env_matrix": env or None,
            "project_filter": project,
            "resolve": resolve,
            "allow_net": allow_net or None,
            "dangerously_no_sandbox": dangerously_no_sandbox or None,
            "follow_images": follow_images or None,
            "platform": platform,
            "include_removed": include_removed or None,
            "dockerfile": dockerfile,
            "fail_on": fail_on,
            "log_format": log_format,
            "reproducible": reproducible or None,
            "profile": profile or None,
            "evidence": evidence,
            "output": output or None,
            "cache": cache or None,
            "remote_cache": remote_cache,
            "no_accel": no_accel or None,
        }
        target_path = Path(target) if not target.split(":", 1)[0].isalpha() or Path(target).exists() else None
        cfg = load_config(target=target_path if target_path and target_path.is_dir() else None, flags=flags)

        bus = ProgressBus()
        json_logs = cfg.log_format == "json" or (
            cfg.log_format == "auto" and not sys.stderr.isatty()
        )
        bus.subscribe(ndjson_sink() if json_logs else tty_sink())

        platforms: list[str | None] = [cfg.platform]
        if all_platforms:
            platforms = list(_image_platforms(target, cfg))

        exit_code = EXIT_OK
        for plat in platforms:
            plat_cfg = cfg if plat == cfg.platform else _with_platform(cfg, plat)
            result = run_scan(target, plat_cfg, bus=bus)

            files = list(file)
            if len(platforms) > 1 and files:
                suffix = (plat or "platform").replace("/", "-")
                files = [f"{f}.{suffix}" for f in files]
            outputs = list(cfg.output) or ["table", "summary"]
            _render_outputs(result.store_path, outputs, files, cfg.reproducible)

            if report == "drift":
                _print_drift_report(result.store_path)

            if result.had_scan_errors:
                exit_code = max(exit_code, EXIT_SCAN_ERRORS)
            if cfg.fail_on and _policy_failed(result.store_path, cfg.fail_on):
                exit_code = max(exit_code, EXIT_POLICY_FAIL)
        raise typer.Exit(exit_code)
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


def _image_platforms(target: str, cfg: Config) -> list[str]:
    from sorb.container import list_platforms, parse_container_spec

    spec = parse_container_spec(target)
    if spec is None:
        raise UsageError("--all-platforms only applies to container image targets")
    platforms = list_platforms(spec, offline=cfg.offline)
    if not platforms:
        raise UsageError(f"{target}: no scannable platforms found in the image index")
    return platforms


def _with_platform(cfg: Config, platform: str | None) -> Config:
    from dataclasses import replace

    return replace(cfg, platform=platform)
