"""Native resolver drivers.

``--resolve=native`` invokes the ecosystem's own toolchain **inside the
sandbox** and parses its machine output into the *same* ``NativeResolution``
that reconcile consumes — downstream stages cannot tell which mode produced
the graph. The command construction and the output parser are
separable so parsers are fixture-tested without a toolchain, and the whole
run is gated by sandbox availability (refusing to run when unsandboxed).
"""

from sorb.dynamic.drivers.base import (
    DRIVERS,
    NativeDriver,
    NativeResolution,
    ResolvedDep,
    driver_for,
    run_native_driver,
)

__all__ = [
    "DRIVERS",
    "NativeDriver",
    "NativeResolution",
    "ResolvedDep",
    "driver_for",
    "run_native_driver",
]
