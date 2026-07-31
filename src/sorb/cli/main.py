"""sorb CLI.

Thin adapters: parse args → typed request → sorb.core → render. Heavy imports
happen inside subcommands to keep `sorb --help` under the 300 ms budget.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from typing import Any

    from sorb.core.config import Config
    from sorb.graph.store import Component, GraphStore

from sorb import __version__
from sorb.errors import (
    EXIT_OK,
    EXIT_POLICY_FAIL,
    EXIT_SCAN_ERRORS,
    EXIT_USAGE,
    SorbError,
    UsageError,
    exit_code_for,
)

app = typer.Typer(
    name="sorb",
    help="Evidence-backed dependency analysis and SBOM generation.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)

_FORMATS = ("cyclonedx-json", "spdx-json", "spdx3-json", "sorb", "table", "tree", "summary")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sorb {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """sorb — trustworthy, explainable SBOMs. Start with `sorb scan .`"""


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


def _render_outputs(
    store_path: Path | None,
    outputs: list[str],
    files: list[str],
    reproducible: bool,
    store: GraphStore | None = None,
) -> None:
    from sorb.emit.base import emitter_for
    from sorb.emit.cyclonedx import emit_cyclonedx
    from sorb.emit.human import render_summary, render_table, render_tree
    from sorb.emit.native import export_native
    from sorb.emit.spdx import emit_spdx
    from sorb.graph.store import GraphStore

    owns_store = store is None
    if store is None:
        assert store_path is not None
        store = GraphStore.open_readonly(store_path)
    try:
        for i, fmt in enumerate(outputs):
            plugin_emitter = None if fmt in _FORMATS else emitter_for(fmt)
            if fmt not in _FORMATS and plugin_emitter is None:
                raise UsageError(f"unknown output format {fmt!r} (expected one of {', '.join(_FORMATS)})")
            if plugin_emitter is not None:
                data = plugin_emitter.emit(store, reproducible=reproducible)
            elif fmt == "cyclonedx-json":
                data = emit_cyclonedx(store, reproducible=reproducible)
            elif fmt == "spdx-json":
                data = emit_spdx(store, reproducible=reproducible)
            elif fmt == "spdx3-json":
                from sorb.emit.spdx3 import emit_spdx3

                data = emit_spdx3(store, reproducible=reproducible)
            elif fmt == "sorb":
                data = export_native(store)
            elif fmt == "table":
                data = (render_table(store) + "\n").encode()
            elif fmt == "tree":
                data = (render_tree(store) + "\n").encode()
            else:
                data = (render_summary(store) + "\n").encode()
            dest = files[i] if i < len(files) else None
            if dest:
                Path(dest).write_bytes(data)
                suffix = {"cyclonedx-json": "CycloneDX 1.6", "spdx-json": "SPDX 2.3", "sorb": "sorb native"}.get(fmt, fmt)
                typer.echo(f"  {dest} written ({suffix}) · full details: sorb explain", err=True)
            else:
                sys.stdout.write(data.decode("utf-8", "replace"))
    finally:
        if owns_store:
            store.close()


def _policy_failed(store_path: Path, fail_on: tuple[str, ...]) -> bool:
    from sorb.graph.store import GraphStore

    token_map = {
        "drift": ("drift:",),
        "phantom-deps": ("drift:installed-not-declared", "drift:observed-not-declared"),
        "stale-lockfile": ("stale-lockfile",),
        "version-conflict": ("version-conflict",),
        "unidentified": ("unidentified-binaries",),
        "unpinned-images": ("unpinned-image",),
    }
    store = GraphStore.open_readonly(store_path)
    try:
        codes = {a["code"] for a in store.all_annotations()}
        comps_excluded = any(
            c.attrs.get("excluded") for c in store.components()
        )
        for token in fail_on:
            token = token.strip()
            if token == "low-confidence" and comps_excluded:
                return True
            for prefix in token_map.get(token, (token,)):
                if any(c.startswith(prefix) for c in codes):
                    return True
        return False
    finally:
        store.close()


def _print_drift_report(store_path: Path) -> None:
    from sorb.graph.store import GraphStore
    from sorb.warnings import ANNOTATION_WARNING_CODES

    store = GraphStore.open_readonly(store_path)
    try:
        drift = [a for a in store.all_annotations() if a["code"].startswith("drift:")]
        typer.echo("")
        typer.echo(f"Drift report — {len(drift)} finding(s):")
        for a in drift:
            code = ANNOTATION_WARNING_CODES.get(a["code"], "")
            subject = ""
            if a["subject_kind"] == "component":
                comp = store.component_by_id(a["subject_id"])
                subject = comp.display_ref() if comp else ""
            typer.echo(f"  ⚠ [{code}] {a['code']}  {subject}  {a['detail']}")
    finally:
        store.close()


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
def sign(
    sbom: str = typer.Argument(..., help="SBOM file to sign"),
    key: str | None = typer.Option(None, "--key", help="Private key PEM (with --generate-key, where to write it)"),
    generate_key: bool = typer.Option(False, "--generate-key", help="Generate a keypair first"),
    out: str | None = typer.Option(None, "--out", help="Bundle path (default <sbom>.sig)"),
) -> None:
    """Detached signature bundle over the exact SBOM bytes."""
    from sorb.emit.signing import generate_keypair, sign_detached

    try:
        if generate_key:
            key_path, pub_path = generate_keypair(
                Path(key).parent if key else Path("."), stem=Path(key).stem if key else "sorb"
            )
            typer.echo(f"  keypair written: {key_path} / {pub_path}", err=True)
        elif key is None:
            raise UsageError("--key is required (or pass --generate-key)")
        else:
            key_path = Path(key)
        bundle = sign_detached(Path(sbom).read_bytes(), private_key_pem=key_path.read_bytes())
        dest = Path(out) if out else Path(sbom + ".sig")
        dest.write_bytes(bundle)
        typer.echo(f"  {dest} written (detached signature bundle)", err=True)
    except (SorbError, ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e) if isinstance(e, SorbError) else 1) from e


@app.command()
def attest(
    sbom: str = typer.Argument(..., help="SBOM file to attest (CycloneDX/SPDX JSON)"),
    key: str = typer.Option(..., "--key", help="Private key PEM"),
    subject_name: str = typer.Option("subject", "--subject-name"),
    subject_digest: str = typer.Option(
        ..., "--subject-digest", help="sha256:… digest of the artifact the SBOM describes"
    ),
    out: str | None = typer.Option(None, "--out", help="Envelope path (default <sbom>.att)"),
    attach: str | None = typer.Option(
        None, "--attach", help="Image ref to attach the attestation to (referrers API)"
    ),
) -> None:
    """DSSE in-toto attestation bound to the subject digest."""
    from sorb.emit.signing import attest as make_attestation

    try:
        envelope = make_attestation(
            Path(sbom).read_bytes(),
            subject_name=subject_name,
            subject_digest=subject_digest,
            private_key_pem=Path(key).read_bytes(),
        )
        dest = Path(out) if out else Path(sbom + ".att")
        dest.write_bytes(envelope)
        typer.echo(f"  {dest} written (DSSE in-toto attestation)", err=True)
        if attach:
            from sorb.container.registry import RegistryClient
            from sorb.container.spec import parse_image_ref

            client = RegistryClient(parse_image_ref(attach))
            try:
                _doc, manifest_digest, _raw = client.fetch_manifest()
                pushed = client.attach_attestation(manifest_digest, envelope)
                typer.echo(f"  attached to {attach} as {pushed}", err=True)
            finally:
                client.close()
    except (SorbError, ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(exit_code_for(e) if isinstance(e, SorbError) else 1) from e


@app.command()
def verify(
    artifact: str = typer.Argument(..., help="Attestation (.att) or signature bundle (.sig)"),
    key: str = typer.Option(..., "--key", help="Public key PEM (pinned-key identity policy)"),
    sbom: str | None = typer.Option(
        None,
        "--sbom",
        help="The artifact you hold: the signed file for a detached bundle, or the "
        "subject an attestation must be about. Use --subject-digest instead when "
        "you have the digest but not the bytes; passing both is an error unless "
        "they agree",
    ),
    subject_digest: str | None = typer.Option(None, "--subject-digest"),
    lineage: str | None = typer.Option(
        None, "--lineage", help="results index.json for lineage-consistency checking"
    ),
) -> None:
    """Ordered verification checks, each reported discretely."""
    import json as _json

    from sorb.emit.signing import verify as run_verify

    try:
        steps = run_verify(
            Path(artifact).read_bytes(),
            public_key_pem=Path(key).read_bytes(),
            expected_subject_digest=subject_digest,
            sbom_bytes=Path(sbom).read_bytes() if sbom else None,
            lineage_index=_json.loads(Path(lineage).read_text()) if lineage else None,
        )
    except (ValueError, OSError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1) from e
    failed = False
    for step in steps:
        mark = "○" if step.skipped else ("✔" if step.ok else "✘")
        typer.echo(f"  {mark} {step.name}: {step.detail}")
        failed = failed or not step.ok
    if failed:
        raise typer.Exit(EXIT_POLICY_FAIL)
    typer.echo("  verification passed")


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


self_app = typer.Typer(help="Manage the standalone sorb bundle.")
app.add_typer(self_app, name="self")


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


cache_app = typer.Typer(help="Incremental & shared cache management.")
app.add_typer(cache_app, name="cache")


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


db_app = typer.Typer(help="Signature / base-image / license data packs.")
app.add_typer(db_app, name="db")


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


def main() -> None:
    try:
        app()
    except SorbError as e:
        typer.echo(f"error: {e}", err=True)
        sys.exit(exit_code_for(e))


if __name__ == "__main__":
    main()
