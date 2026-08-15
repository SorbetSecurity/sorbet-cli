"""The Typer application and its sub-command groups.

Kept apart from the commands themselves so a command module can register
against `app` without importing the module that assembles them all.
"""

from __future__ import annotations

import typer

from sorb import __version__

app = typer.Typer(
    name="sorb",
    help="Evidence-backed dependency analysis and SBOM generation.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)

self_app = typer.Typer(help="Manage the standalone sorb bundle.")
cache_app = typer.Typer(help="Incremental & shared cache management.")
db_app = typer.Typer(help="Signature data packs for binary fingerprinting.")

app.add_typer(self_app, name="self")
app.add_typer(cache_app, name="cache")
app.add_typer(db_app, name="db")


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
