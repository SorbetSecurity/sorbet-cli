"""Maintenance: benchmarks, caches, signature data packs, self-update.

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

from sorb.cli.app import app, cache_app, db_app, self_app
from sorb.errors import (
    EXIT_POLICY_FAIL,
    EXIT_USAGE,
    SorbError,
    UsageError,
    exit_code_for,
)


@app.command()
def bench(
    baseline: str | None = typer.Option(None, "--baseline", help="Compare against a baseline JSON (regression gate)"),
    write: str | None = typer.Option(None, "--write", help="Write results as a new baseline JSON"),
    iterations: int = typer.Option(3, "--iterations"),
    check_startup: bool = typer.Option(True, "--startup/--no-startup", help="Also gate `sorb --help` < 300 ms"),
) -> None:
    """Run the benchmark scenarios; gate on regression + startup."""
    import json as _json

    from sorb.bench import (
        STARTUP_BUDGET_MS,
        check_regression,
        run_suite,
        startup_ms,
        write_baseline,
    )

    results = run_suite(iterations=iterations)
    for r in results:
        typer.echo(f"  {r.name:<16} best {r.best_ms:8.1f} ms   mean {r.mean_ms:8.1f} ms")
    failed = False
    if check_startup:
        try:
            st = startup_ms()
        except SorbError as e:
            typer.echo(f"  {'startup':<16} skipped — {e}", err=True)
        else:
            ok = st < STARTUP_BUDGET_MS
            typer.echo(f"  {'startup':<16} {st:8.1f} ms   (budget {STARTUP_BUDGET_MS:.0f} ms) "
                       f"{'OK' if ok else 'OVER'}")
            failed = failed or not ok
    if write:
        write_baseline(results, Path(write))
        typer.echo(f"  baseline written → {write}", err=True)
    if baseline:
        base = _json.loads(Path(baseline).read_text())
        regressions = check_regression(results, base)
        for msg in regressions:
            typer.echo(f"  REGRESSION {msg}", err=True)
        failed = failed or bool(regressions)
    if failed:
        raise typer.Exit(EXIT_POLICY_FAIL)


@app.command()
def accel() -> None:
    """Show the active performance tier (pure reference vs sorb-accel)."""
    from sorb.accel import active, tier

    name = active().name
    typer.echo(f"  tier: {tier()} ({name})")
    if name == "pure":
        typer.echo("  the native `sorb-accel` wheel is not installed — using the pure-Python "
                   "reference (correct, slower). It is a drop-in accelerator, never a behavior change.")


@app.command("config")
def config_cmd(
    target: str = typer.Argument(".", help="Project directory to resolve config for"),
) -> None:
    """Show effective configuration and where each value came from."""
    from dataclasses import fields

    from sorb.core.config import load_config

    cfg = load_config(target=Path(target).resolve())
    typer.echo(f"config fingerprint: {cfg.fingerprint()}\n")
    for f in fields(cfg):
        if f.name == "origins":
            continue
        value = getattr(cfg, f.name)
        origin = cfg.origins.get(f.name, "default")
        typer.echo(f"{f.name:28} = {value!r:32} [{origin}]")


@self_app.command("update")
def self_update(
    bundle: str = typer.Argument(..., help="Path to the update bundle (standalone binary)"),
    signature: str = typer.Option(..., "--signature", help="Detached signature bundle for the update"),
    key: str | None = typer.Option(None, "--key", help="Release public-key PEM (else the embedded key)"),
    install_to: str | None = typer.Option(None, "--install-to", help="Install path (default: dry-run verify)"),
) -> None:
    """Verify and apply a signed bundle update — tampered updates are refused."""
    from sorb.selfupdate import UpdateRefused, apply_update, release_public_key

    pub = Path(key).read_bytes() if key else release_public_key()
    if pub is None:
        typer.echo("error: no release public key (pass --key); bundle self-update only", err=True)
        raise typer.Exit(EXIT_USAGE)
    try:
        result = apply_update(
            Path(bundle), signature_path=Path(signature), public_key_pem=pub,
            install_to=Path(install_to) if install_to else None,
        )
    except UpdateRefused as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_POLICY_FAIL) from e
    typer.echo(f"  ✔ update verified (sha256 {result.sha256[:12]}…) — {result.detail}")


@cache_app.command("stats")
def cache_stats() -> None:
    """Show local cache size and hit/miss counters."""
    from sorb.cache import Cas

    cas = Cas()
    s = cas.stats()
    typer.echo(
        f"  {s['entries']} entries · {s['bytes'] / 1e6:.1f} MB · "
        f"session hits {s['hits']} / misses {s['misses']}"
    )
    cas.close()


@cache_app.command("prune")
def cache_prune(
    max_mb: float = typer.Option(1000.0, "--max-mb", help="Evict LRU entries down to this size"),
) -> None:
    """Evict least-recently-used entries until the cache fits a size budget."""
    from sorb.cache import Cas

    cas = Cas()
    evicted = cas.prune(int(max_mb * 1_000_000))
    typer.echo(f"  evicted {evicted} entries (target {max_mb:.0f} MB)")
    cas.close()


@cache_app.command("clear")
def cache_clear() -> None:
    """Remove every cached detector result and its blobs."""
    from sorb.cache import Cas

    cas = Cas()
    n = cas.prune(0)
    typer.echo(f"  cleared {n} entries")
    cas.close()


@cache_app.command("serve")
def cache_serve(
    bind: str = typer.Option("127.0.0.1", "--bind"),
    port: int = typer.Option(8888, "--port"),
) -> None:
    """Run the reference shared-cache server (HTTP CAS) for a CI fleet."""
    from sorb.cache.server import serve

    typer.echo(f"  sorb cache server on http://{bind}:{port}/ (Ctrl-C to stop)", err=True)
    try:
        serve(bind, port)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.echo("\n  stopped", err=True)


@db_app.command("update")
def db_update(
    pack: str = typer.Argument(..., help="Path to a data-pack tar (or an OCI ref, planned)"),
    key: str | None = typer.Option(None, "--key", help="Public key PEM to verify the pack signature"),
    signature: str | None = typer.Option(None, "--signature", help="Detached signature bundle"),
    allow_unsigned: bool = typer.Option(
        False, "--allow-unsigned", help="Install an unsigned pack (not recommended)"
    ),
) -> None:
    """Install a signed data pack into the local cache (unsigned refused)."""
    from sorb.binary.packs import install_pack
    from sorb.cache import default_cache_dir

    try:
        pack_path = Path(pack)
        if not pack_path.is_file():
            raise UsageError(f"pack file not found: {pack} (OCI-ref pulling is not yet supported)")
        installed = install_pack(
            pack_path.read_bytes(),
            packs_dir=default_cache_dir() / "packs",
            signature=Path(signature).read_bytes() if signature else None,
            public_key_pem=Path(key).read_bytes() if key else None,
            allow_unsigned=allow_unsigned,
        )
        if installed.verified:
            (installed.path / ".verified").write_text("")
        typer.echo(
            f"  installed {installed.name} {installed.version} "
            f"({'signature verified' if installed.verified else 'UNSIGNED'}) → {installed.path}"
        )
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@db_app.command("status")
def db_status() -> None:
    """List installed data packs and their verification state."""
    from sorb.binary.packs import list_installed_packs
    from sorb.cache import default_cache_dir

    packs = list_installed_packs(default_cache_dir() / "packs")
    if not packs:
        typer.echo("  no data packs installed (sorb db update <pack>)")
        return
    for p in packs:
        mark = "✔" if p.verified else "⚠ unsigned"
        typer.echo(f"  {mark}  {p.name} {p.version}")
