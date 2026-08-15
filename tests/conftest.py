"""Test harness: socket-blocking guard — no test touches the network (DoD)."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "corpus"))

from corpus_harness import materialize_fixture  # noqa: E402

FIXTURES = Path(__file__).parent / "corpus" / "fixtures"


class _NetworkBlocked(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def guard(self: socket.socket, address: object) -> None:
        # loopback stays open: asyncio's Windows event loop bootstraps itself
        # through a socketpair emulated as a 127.0.0.1 connect
        host = address[0] if isinstance(address, tuple) else address
        if not isinstance(address, tuple) or host in ("127.0.0.1", "::1", "localhost"):
            return real_connect(self, address)
        raise _NetworkBlocked("tests must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", guard)


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """No test may read or write the user's real ~/.cache/sorb."""
    monkeypatch.setenv("SORB_CACHE_DIR", str(tmp_path_factory.mktemp("sorb-cache")))


@pytest.fixture()
def polyglot(tmp_path: Path) -> Path:
    """A pristine copy of the polyglot corpus fixture (no .sorb leakage)."""
    return materialize_fixture(FIXTURES / "polyglot", tmp_path / "polyglot")
