"""The CLI surface itself: every command stays registered and callable.

A guard for refactors that move commands between modules — the risk there is
not a wrong answer but a command that quietly stops existing.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from sorb.cli.main import app

runner = CliRunner()

#: Every top-level command and sub-command group the CLI promises.
EXPECTED_COMMANDS = {
    "scan", "explain", "explain-warning", "layers", "query",
    "convert", "merge", "diff", "validate", "fleet",
    "sign", "attest", "verify",
    "trace", "snapshot", "watch",
    "ui", "serve",
    "bench", "accel", "config", "self", "cache", "db",
}


def _registered() -> set[str]:
    names = {c.name or c.callback.__name__ for c in app.registered_commands}
    names |= {g.name for g in app.registered_groups if g.name}
    return names


def test_every_command_is_registered() -> None:
    missing = EXPECTED_COMMANDS - _registered()
    assert not missing, f"commands disappeared: {sorted(missing)}"


@pytest.mark.parametrize("command", sorted(EXPECTED_COMMANDS))
def test_command_help_works(command: str) -> None:
    """`--help` exercises the whole registration path without doing any work."""
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0, f"{command} --help failed:\n{result.output}"
    assert result.output.strip()


def test_root_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("scan", "explain", "layers"):
        assert command in result.output
