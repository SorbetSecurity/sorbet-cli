"""CLI entry point.

Importing a command module registers its commands on the shared Typer app, so
this file only has to assemble them and hand control over.
"""

from __future__ import annotations

from sorb.cli.app import app
from sorb.cli.commands import (  # noqa: F401  (imported for registration)
    admin,
    inspect,
    interop,
    observe,
    scan,
    security,
    serve,
)

__all__ = ["app", "main"]


def main() -> None:
    app()


if __name__ == "__main__":
    main()
