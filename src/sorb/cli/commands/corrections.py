"""`sorb mark` — record project corrections applied to every future scan."""

from __future__ import annotations

from pathlib import Path

import typer

from sorb.cli.app import app
from sorb.core.corrections import (
    Correction,
    add_correction,
    corrections_path,
    load_corrections,
    remove_correction,
)

mark_app = typer.Typer(
    help="Correct the scanner for this project: mark false positives, add missed "
    "components. Corrections persist in sorb.corrections.json and apply to every "
    "future scan of the project."
)
app.add_typer(mark_app, name="mark")


def _root(project: str) -> Path:
    root = Path(project).resolve()
    if not root.is_dir():
        typer.echo(f"error: {project} is not a directory", err=True)
        raise typer.Exit(2)
    return root


@mark_app.command("false-positive")
def false_positive(
    ref: str = typer.Argument(..., help="purl, name, or name@version to stop emitting"),
    reason: str = typer.Option("", "--reason", help="Why this is a false positive"),
    project: str = typer.Option(".", "--project", help="Project root to record it for"),
) -> None:
    """Exclude a component from every future SBOM of this project."""
    root = _root(project)
    if add_correction(root, Correction(kind="false-positive", ref=ref, reason=reason)):
        typer.echo(f"marked {ref} as a false positive → {corrections_path(root)}")
    else:
        typer.echo(f"{ref} is already marked (see {corrections_path(root)})")


@mark_app.command("missing")
def missing(
    ref: str = typer.Argument(..., help="purl or name@version the scanner missed"),
    ecosystem: str = typer.Option("", "--ecosystem", help="Ecosystem (npm, pypi, …)"),
    scope: str = typer.Option("", "--scope", help="runtime|dev|optional"),
    reason: str = typer.Option("", "--reason", help="How you know it is present"),
    project: str = typer.Option(".", "--project", help="Project root to record it for"),
) -> None:
    """Assert a component into every future SBOM of this project."""
    root = _root(project)
    entry = Correction(kind="missing", ref=ref, reason=reason, ecosystem=ecosystem, scope=scope)
    if add_correction(root, entry):
        typer.echo(f"will assert {ref} into future scans → {corrections_path(root)}")
    else:
        typer.echo(f"{ref} is already asserted (see {corrections_path(root)})")


@mark_app.command("list")
def list_corrections(
    project: str = typer.Option(".", "--project", help="Project root"),
) -> None:
    """Show this project's recorded corrections."""
    root = _root(project)
    entries = load_corrections(root)
    if not entries:
        typer.echo("no corrections recorded")
        return
    for e in entries:
        extra = " ".join(filter(None, [e.ecosystem, e.scope, f"— {e.reason}" if e.reason else ""]))
        typer.echo(f"{e.kind:15} {e.ref}  {extra}".rstrip())


@mark_app.command("rm")
def rm(
    ref: str = typer.Argument(..., help="ref of the correction to drop"),
    kind: str = typer.Option(
        "", "--kind", help="false-positive|missing (needed only if ref is ambiguous)"
    ),
    project: str = typer.Option(".", "--project", help="Project root"),
) -> None:
    """Drop a recorded correction."""
    root = _root(project)
    kinds = [kind] if kind else ["false-positive", "missing"]
    matching = [e for e in load_corrections(root) if e.ref == ref and e.kind in kinds]
    if len(matching) > 1:
        typer.echo(f"error: {ref} matches both kinds — pass --kind", err=True)
        raise typer.Exit(2)
    if matching and remove_correction(root, matching[0].kind, ref):
        typer.echo(f"removed {matching[0].kind} correction for {ref}")
    else:
        typer.echo(f"no correction recorded for {ref}")
        raise typer.Exit(1)
