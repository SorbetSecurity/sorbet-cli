"""Exploring a finished scan: why a component is there, what a layer did.

Commands are thin adapters: parse arguments, call into `sorb.core`,
render. Heavy imports stay inside command bodies so `sorb --help`
keeps its startup budget.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from typing import Any

    from sorb.graph.store import Component, GraphStore

from sorb.cli.app import app
from sorb.errors import (
    EXIT_SCAN_ERRORS,
    EXIT_USAGE,
    SorbError,
    UsageError,
    exit_code_for,
)


@app.command()
def explain(
    ref: str = typer.Argument(..., help="purl | name[@version] | digest | path"),
    run: str | None = typer.Option(None, "--run", help="Run id (default: latest)"),
    target: str = typer.Option(".", "--target", help="Project whose results to read"),
) -> None:
    """Why is this component here? Provenance chain + evidence."""
    from sorb.core.explain import explain as explain_engine
    from sorb.core.workspace import latest_run_db, results_dir_for
    from sorb.graph.store import GraphStore

    results = results_dir_for(Path(target).resolve())
    db = (results / f"{run}.sorb.db") if run else latest_run_db(results)
    if db is None or not db.is_file():
        typer.echo("error: no scan results found — run `sorb scan .` first", err=True)
        raise typer.Exit(EXIT_SCAN_ERRORS)
    store = GraphStore.open_readonly(db)
    try:
        text = explain_engine(store, ref)
        if text is None:
            near = store.near_matches(ref)
            msg = f"error: {ref!r} not found in run {db.stem}"
            if near:
                msg += "\n  did you mean: " + ", ".join(near)
            typer.echo(msg, err=True)
            raise typer.Exit(EXIT_SCAN_ERRORS)
        typer.echo(text)
    finally:
        store.close()


@app.command("explain-warning")
def explain_warning(code: str = typer.Argument(..., help="e.g. SORB-W031")) -> None:
    """Explain a warning code from the registry."""
    from sorb.warnings import lookup, registry

    info = lookup(code)
    if info is None:
        known = ", ".join(sorted(registry()))
        typer.echo(f"error: unknown warning code {code!r}. Known codes: {known}", err=True)
        raise typer.Exit(EXIT_SCAN_ERRORS)
    typer.echo(f"{info.code} — {info.title}\n")
    typer.echo(info.explanation)
    typer.echo(f"\nRemediation: {info.remediation}")


@app.command()
def layers(
    target: str = typer.Argument(..., help="image ref (image:REF, docker:REF, oci-dir:PATH, …)"),
    layer: int | None = typer.Option(
        None, "--layer", help="Drill into one layer: what it introduced, with evidence"
    ),
    platform: str | None = typer.Option(None, "--platform", help="Image platform"),
    offline: bool = typer.Option(False, "--offline", help="Absolute network kill-switch"),
) -> None:
    """Per-layer breakdown of an image: what each layer added, and why.

    Everything shown is already recorded during a scan — the instruction that
    built each layer, the files it added or removed, and which components it
    introduced. This is the same data the UI's layer stack draws.
    """
    from sorb.container import parse_container_spec
    from sorb.core.config import load_config
    from sorb.core.events import ProgressBus
    from sorb.core.pipeline import run_scan
    from sorb.graph.store import GraphStore

    try:
        if parse_container_spec(target) is None:
            raise UsageError(
                f"{target!r} is not a container target; `sorb layers` describes image layers"
            )
        cfg = load_config(flags={"platform": platform, "offline": offline or None})
        result = run_scan(target, cfg, bus=ProgressBus())  # silent bus: this is a report
        store = GraphStore.open_readonly(result.store_path)
        try:
            # the target as typed reads better than the resolved image id,
            # which is what `subject` holds
            _render_layers(store, store.get_meta("target") or result.subject, layer)
        finally:
            store.close()
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e)) from e


@app.command()
def query(
    expr: str = typer.Argument(..., help="Query DSL expression (see docs/usage.md)"),
    target: str = typer.Option(".", "--target", help="Project whose latest run to query"),
    run: str | None = typer.Option(None, "--run", help="Run id or path to a .sorb.db/.sorb.json"),
    output: str = typer.Option("table", "-o", "--output", help="table|json"),
) -> None:
    """Run a graph query over a scan's evidence graph.

    Examples:
      sorb query 'components where purl ~ "pkg:npm/*" and confidence < 0.9'
      sorb query 'components where scope = runtime | count by ecosystem'
      sorb query 'paths from project:apps/web to pkg:npm/minimist@0.0.8'
    """
    import json as _json

    from sorb.core.workspace import latest_run_db, results_dir_for
    from sorb.graph.store import GraphStore
    from sorb.query import QueryError, run_query

    if run and (run.endswith(".sorb.db") or run.endswith(".sorb.json")):
        if run.endswith(".sorb.json"):
            from sorb.emit.native import import_native

            store = import_native(Path(run).read_bytes(), Path(run).with_suffix(".db"))
        else:
            store = GraphStore.open_readonly(Path(run))
    else:
        results = results_dir_for(Path(target).resolve())
        db_path = (results / f"{run}.sorb.db") if run else latest_run_db(results)
        if db_path is None or not db_path.is_file():
            typer.echo("error: no scan results found — run `sorb scan .` first", err=True)
            raise typer.Exit(EXIT_SCAN_ERRORS)
        store = GraphStore.open_readonly(db_path)
    try:
        result = run_query(store, expr)
    except QueryError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_USAGE) from e
    finally:
        pass
    try:
        if output == "json":
            typer.echo(_json.dumps({"kind": result.kind, "columns": result.columns,
                                    "rows": result.rows}, indent=2, default=str))
        else:
            _render_query_table(result)
    finally:
        store.close()


def _render_layers(store: GraphStore, subject: str, only: int | None) -> None:
    from collections import Counter

    layer_rows = store.layers()
    if not layer_rows:
        typer.echo("no layers recorded (not a layered image target)")
        return

    # One pass over file states and components rather than a scan per layer.
    added: Counter[int] = Counter()
    removed: Counter[int] = Counter()
    modified: Counter[int] = Counter()
    for f in store.file_states(None):
        bucket = {"added": added, "removed": removed, "modified": modified}.get(f["state"])
        if bucket is not None:
            bucket[int(f["ordinal"])] += 1

    per_layer: dict[int, list[Component]] = {}
    base_layers: set[int] = set()
    for c in store.components():
        if c.attrs.get("excluded"):
            continue
        ordinal = c.attrs.get("layer_ordinal")
        if ordinal is None:
            continue
        per_layer.setdefault(int(ordinal), []).append(c)
        if c.attrs.get("from_base_image"):
            base_layers.add(int(ordinal))

    if only is not None:
        chosen = [row for row in layer_rows if int(row["ordinal"]) == only]
        if not chosen:
            typer.echo(f"error: no layer {only} (image has {len(layer_rows)})", err=True)
            raise typer.Exit(EXIT_USAGE)
        _render_one_layer(store, chosen[0], per_layer.get(only, []))
        return

    total = sum(len(v) for v in per_layer.values())
    typer.echo(f"{subject}")
    typer.echo(f"  {len(layer_rows)} layers · {total} components attributed to a layer\n")
    typer.echo(f"  {'#':>2}  {'+files':>7} {'~':>5} {'-':>5}  {'comps':>6}  instruction")
    for row in layer_rows:
        ordinal = int(row["ordinal"])
        comps = len(per_layer.get(ordinal, []))
        instruction = (row["created_by"] or "").strip().replace("\n", " ")
        marker = " (base)" if ordinal in base_layers else ""
        typer.echo(
            f"  {ordinal:>2}  {added[ordinal]:>7} {modified[ordinal]:>5} {removed[ordinal]:>5}"
            f"  {comps:>6}  {instruction[:64]}{marker}"
        )
    typer.echo("\n  sorb layers <image> --layer N   for what a layer introduced, with evidence")


def _render_one_layer(
    store: GraphStore, row: dict[str, Any], components: list[Component]
) -> None:
    typer.echo(f"layer {row['ordinal']}  {str(row['digest'])[:23]}…")
    typer.echo(f"  built by: {(row['created_by'] or '?').strip()[:110]}")
    states = _layer_file_states(store, str(row["digest"]))
    typer.echo(
        f"  files: +{states['added']} ~{states['modified']} -{states['removed']}"
        f"   components introduced: {len(components)}\n"
    )
    if not components:
        typer.echo("  (no components attributed to this layer)")
        return
    for c in sorted(components, key=lambda c: (c.name.lower(), c.version or "")):
        evidence = store.evidence_for_component(c.id)
        where = evidence[0]["location"]["path"] if evidence else "?"
        typer.echo(
            f"  {c.name}@{c.version or '?'}  [{c.attrs.get('ecosystem', c.ctype)}]"
            f"  conf {c.confidence:.2f}"
        )
        typer.echo(f"      proven by {where}")


def _layer_file_states(store: GraphStore, digest: str) -> dict[str, int]:
    out = {"added": 0, "modified": 0, "removed": 0}
    for f in store.file_states(None):
        if f["layer_digest"] == digest and f["state"] in out:
            out[f["state"]] += 1
    return out


def _render_query_table(result) -> None:  # type: ignore[no-untyped-def]
    if not result.rows:
        typer.echo("(no results)")
        return
    if result.kind == "paths":
        for row in result.rows:
            chain = " → ".join(
                f"{step['label']} [{step['marker']}]" if step.get("marker") else step["label"]
                for step in row["path"]
            )
            typer.echo(f"  {chain}")
        return
    cols = list(result.rows[0].keys()) if result.kind == "aggregation" else result.columns
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in result.rows)) for c in cols}
    typer.echo("  ".join(c.ljust(widths[c]) for c in cols))
    for r in result.rows:
        typer.echo("  ".join(str(r.get(c, "") if r.get(c) is not None else "").ljust(widths[c]) for c in cols))
