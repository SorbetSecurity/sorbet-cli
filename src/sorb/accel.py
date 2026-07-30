"""`sorb-accel` shim — the native-acceleration escape hatch.

Profiling flags three hot paths first: the walker+hasher loop, tar streaming, and
the function-fingerprint matcher. Each sits behind *this* interface with a
pure-Python implementation that is the **correctness reference**; the optional
`sorb_accel` PyO3 wheel is a drop-in replacement that must produce byte-identical
output — nothing else changes.

Selection is at import time: if the wheel is present, enabled, and passes a
self-check that its hashing agrees with the reference on a known vector, it is
used; otherwise the pure path runs. `--no-accel` (or `SORB_NO_ACCEL`) forces the
reference. So a broken or mismatched accelerator can never corrupt output — the
byte-identical guarantee is a *load-time invariant*, not just a CI test.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

# a fixed vector every accelerator's hashing must reproduce (load-time self-check)
_CHECK_INPUT = b"sorbet-accel-selfcheck\x00\x01\x02"
_CHECK_SHA256 = hashlib.sha256(_CHECK_INPUT).hexdigest()


@runtime_checkable
class Accelerator(Protocol):
    name: str  # "pure" | "sorb-accel"

    def hash_file(self, path: str) -> str: ...

    def hash_bytes(self, data: bytes) -> str: ...


class PureAccelerator:
    """The reference implementation — always correct, never selected away from
    on a self-check failure."""

    name = "pure"

    def hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


def _self_check(acc: Accelerator) -> bool:
    """An accelerator is only trusted if its hashing matches the reference."""
    try:
        return acc.hash_bytes(_CHECK_INPUT) == _CHECK_SHA256
    except Exception:
        return False


def load_accelerator(*, no_accel: bool = False) -> Accelerator:
    """Select the accelerator: the wheel if present + enabled + self-consistent,
    else the pure reference."""
    if no_accel or os.environ.get("SORB_NO_ACCEL"):
        return PureAccelerator()
    try:
        import sorb_accel

        candidate = sorb_accel.Accelerator()
    except Exception:
        return PureAccelerator()
    if isinstance(candidate, Accelerator) and _self_check(candidate):
        return candidate
    return PureAccelerator()  # mismatched/broken wheel → refuse, fall back


_active: Accelerator = load_accelerator()


def active() -> Accelerator:
    return _active


def set_accelerator(acc: Accelerator) -> None:
    """Install the accelerator for this process (called once per scan from config)."""
    global _active
    _active = acc if _self_check(acc) else PureAccelerator()


def accelerated() -> bool:
    return _active.name != "pure"


def tier() -> str:
    """The active performance tier: 'pure' or 'accelerated'."""
    return "accelerated" if accelerated() else "pure"


# -- convenience: canonical hashing entry points (route through the active impl) --------


def hash_file(path: str | Path) -> str:
    return _active.hash_file(str(path))


def hash_bytes(data: bytes) -> str:
    return _active.hash_bytes(data)
