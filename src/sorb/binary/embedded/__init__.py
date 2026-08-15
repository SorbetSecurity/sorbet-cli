"""Embedded ground-truth readers.

Cheap, near-perfect signals read straight out of artifacts — checked before
any heuristic: Go buildinfo, cargo-auditable, .NET deps.json, bundled
language-runtime markers. These are what turn a "distroless image → empty
SBOM" into a real inventory.
"""

from sorb.binary.embedded.go_buildinfo import GoBuildInfo, parse_buildinfo

__all__ = ["GoBuildInfo", "parse_buildinfo"]
