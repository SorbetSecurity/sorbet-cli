"""Working with SBOM documents: convert, merge, diff, validate, aggregate.

Commands are thin adapters: parse arguments, call into `sorb.core`,
render. Heavy imports stay inside command bodies so `sorb --help`
keeps its startup budget.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:

    from sorb.graph.store import GraphStore

from sorb.cli.app import app
from sorb.cli.render import (
    _render_outputs,
)
from sorb.errors import (
    EXIT_POLICY_FAIL,
    EXIT_SCAN_ERRORS,
    EXIT_USAGE,
    SorbError,
    UsageError,
    exit_code_for,
)


@app.command()
def convert(
    sbom: str = typer.Argument(..., help="Input: SBOM file (CycloneDX/SPDX/sorb) or run db"),
    output: str = typer.Option("cyclonedx-json", "-o", "--output", help="cyclonedx-json|spdx-json|sorb"),
    file: str | None = typer.Option(None, "-f", "--file", help="Output file (default stdout)"),
    loss_report: bool = typer.Option(False, "--loss-report", help="List facts the target format drops"),
    reproducible: bool = typer.Option(False, "--reproducible"),
) -> None:
    """Any-to-any SBOM conversion through the evidence graph."""
    import tempfile

    from sorb.emit.capabilities import loss_report as compute_loss

    try:
        with tempfile.TemporaryDirectory(prefix="sorb-convert-") as tmp:
            store = _load_store_arg(sbom, Path(tmp), "input")
            try:
                _render_outputs(None, [output], [file] if file else [], reproducible, store=store)
                if loss_report:
                    lines = compute_loss(store, output)
                    typer.echo("", err=True)
                    if lines:
                        typer.echo(f"loss report ({output}):", err=True)
                        for line in lines:
                            typer.echo(f"  – {line}", err=True)
                    else:
                        typer.echo(f"loss report: {output} preserves every present fact", err=True)
            finally:
                store.close()
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@app.command()
def merge(
    sboms: list[str] = typer.Argument(..., help="Two or more inputs (run dbs / SBOM files)"),
    output: str = typer.Option("cyclonedx-json", "-o", "--output"),
    file: str | None = typer.Option(None, "-f", "--file"),
    strategy: str = typer.Option("union", "--strategy", help="union|hierarchical|intersect"),
    reproducible: bool = typer.Option(False, "--reproducible"),
) -> None:
    """Merge SBOMs with identity dedup and conflict surfacing."""
    import tempfile

    from sorb.core.merge import merge_stores

    if len(sboms) < 2:
        typer.echo("error: merge needs at least two inputs", err=True)
        raise typer.Exit(3)
    try:
        with tempfile.TemporaryDirectory(prefix="sorb-merge-") as tmp:
            inputs = []
            try:
                for i, spec in enumerate(sboms):
                    inputs.append((Path(spec).name, _load_store_arg(spec, Path(tmp), f"in{i}")))
                merged, stats = merge_stores(
                    inputs, Path(tmp) / "merged.sorb.db", strategy=strategy
                )
            finally:
                for _label, store in inputs:
                    store.close()
            try:
                typer.echo(
                    f"  merged {stats['inputs']} inputs → {stats['merged']} components "
                    f"({stats['conflicts']} conflicts"
                    + (f", {stats['dropped_intersect']} outside the intersection" if strategy == "intersect" else "")
                    + ")",
                    err=True,
                )
                _render_outputs(None, [output], [file] if file else [], reproducible, store=merged)
            finally:
                merged.close()
    except (SorbError, ValueError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e) if isinstance(e, SorbError) else 3) from e


@app.command()
def diff(
    a: str = typer.Argument(..., help="Old: run db / SBOM file / image ref"),
    b: str = typer.Argument(..., help="New: run db / SBOM file / image ref"),
    fail_on_change: bool = typer.Option(False, "--fail-on-change", help="Exit 2 when anything changed"),
) -> None:
    """Semantic SBOM diff: added/removed/upgraded, scope & confidence."""
    import tempfile

    from sorb.core.diff import diff_stores, render_diff

    try:
        with tempfile.TemporaryDirectory(prefix="sorb-diff-") as tmp:
            store_a = _load_store_arg(a, Path(tmp), "a")
            store_b = _load_store_arg(b, Path(tmp), "b")
            try:
                result = diff_stores(store_a, store_b)
                typer.echo(render_diff(result, a, b))
            finally:
                store_a.close()
                store_b.close()
        if fail_on_change and not result.empty:
            raise typer.Exit(EXIT_POLICY_FAIL)
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@app.command()
def validate(
    sbom: str = typer.Argument(..., help="SBOM file to validate"),
    require: str | None = typer.Option(
        None, "--require", help="Comma list of profiles that must pass: ntia, tr03183"
    ),
) -> None:
    """Structural + NTIA + BSI TR-03183 validation."""
    import json as _json

    from sorb.emit.validate import validate_sbom

    data = Path(sbom).read_bytes()
    report = validate_sbom(data)
    typer.echo(_json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if not report.structurally_valid:
        raise typer.Exit(EXIT_SCAN_ERRORS)
    required = {r.strip() for r in (require or "").split(",") if r.strip()}
    if "ntia" in required and report.ntia_findings:
        raise typer.Exit(EXIT_POLICY_FAIL)
    if "tr03183" in required and report.tr03183_findings:
        raise typer.Exit(EXIT_POLICY_FAIL)


@app.command()
def fleet(
    stores: list[str] = typer.Argument(..., help="Run store paths / globs to aggregate"),
    query: str | None = typer.Option(
        None, "-q", "--query", help="Cross-source query; rows expand per host"
    ),
    out: str | None = typer.Option(None, "-o", "--out", help="Write the merged fleet store here"),
) -> None:
    """Aggregate many host/image stores into one fleet graph and query it.

    Streaming, digest-first dedup with per-source provenance preserved, so
    'which hosts run OpenSSL < 3.0.14 and is it observed running?' is one query:

      sorb fleet '.sorb/results/*.sorb.db' -q 'components where name = openssl
                 and version < "3.0.14" and observed = true'
    """
    import glob
    import tempfile

    from sorb.host.fleet import fleet_rows, merge_fleet

    paths: list[str] = []
    for spec in stores:
        expanded = glob.glob(spec)
        paths.extend(expanded if expanded else [spec])
    paths = [p for p in paths if Path(p).is_file()]
    if not paths:
        typer.echo("error: no run stores matched", err=True)
        raise typer.Exit(EXIT_USAGE)

    with tempfile.TemporaryDirectory(prefix="sorb-fleet-") as tmp:
        out_path = Path(out) if out else Path(tmp) / "fleet.sorb.db"
        store, stats = merge_fleet(paths, out_path)
        try:
            typer.echo(
                f"  merged {stats.sources} sources → {stats.distinct_components} distinct "
                f"components ({stats.total_components} total, {stats.observed} observed)",
                err=True,
            )
            if query:
                from sorb.query import QueryError

                try:
                    rows = fleet_rows(store, query)
                except QueryError as e:
                    typer.echo(f"error: {e}", err=True)
                    raise typer.Exit(EXIT_USAGE) from e
                if not rows:
                    typer.echo("(no matching components)")
                for r in rows:
                    flag = f" · observed:{r.ports or 'yes'}" if r.observed else ""
                    typer.echo(f"  {r.source}  {r.name} {r.version or ''}{flag}")
        finally:
            store.close()


def _load_store_arg(spec: str, tmp_dir: Path, label: str) -> GraphStore:
    """An input for convert/merge/diff: run db, SBOM file, or image ref."""
    from sorb.emit.importers import import_sbom
    from sorb.graph.store import GraphStore

    p = Path(spec)
    if p.is_file() and spec.endswith(".sorb.db"):
        return GraphStore.open_readonly(p)
    if p.is_file():
        return import_sbom(p.read_bytes(), tmp_dir / f"{label}.sorb.db", source_name=p.name)
    from sorb.container import parse_container_spec

    if parse_container_spec(spec) is not None:
        from sorb.core.config import load_config
        from sorb.core.pipeline import run_scan

        cfg = load_config(flags={})
        result = run_scan(spec, cfg, store_path=tmp_dir / f"{label}.sorb.db")
        return GraphStore.open_readonly(result.store_path)
    raise UsageError(f"{spec}: not a run db, SBOM file, or container image ref")
