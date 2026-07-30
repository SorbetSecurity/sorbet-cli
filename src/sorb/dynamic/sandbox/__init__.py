"""Sandbox subsystem.

Native-resolution children run with the network denied, the filesystem scoped
to the project plus a throwaway home, no ambient credentials, and resource
limits — or they don't run at all: if the platform's sandbox primitives are
unavailable, native mode **refuses** unless ``--dangerously-no-sandbox``.
"""

from sorb.dynamic.sandbox.spec import (
    BrokerResult,
    SandboxSpec,
    SandboxUnavailable,
    run_sandboxed,
    sandbox_available,
    toolchain_read_paths,
)

__all__ = [
    "BrokerResult",
    "SandboxSpec",
    "SandboxUnavailable",
    "run_sandboxed",
    "sandbox_available",
    "toolchain_read_paths",
]
