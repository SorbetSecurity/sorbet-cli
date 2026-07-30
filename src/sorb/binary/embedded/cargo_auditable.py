"""cargo-auditable reader.

Rust binaries built with ``cargo auditable`` embed a zlib-compressed JSON
dependency list in a ``.dep-v0`` section (ELF/PE/Mach-O). Format:
https://github.com/rust-secure-code/cargo-auditable — ``VersionInfo``:

    {"packages": [{"name", "version", "source", "kind"?, "dependencies"?: [idx…],
                   "root"?: true}]}
"""

from __future__ import annotations

import json
import zlib
from dataclasses import dataclass, field

from sorb.binary.embedded.sections import named_section

SECTION_NAME = ".dep-v0"
_MAX_DECOMPRESSED = 64 << 20


@dataclass(frozen=True, slots=True)
class AuditablePackage:
    name: str
    version: str
    source: str  # "registry" | "git" | "local" | …
    kind: str  # "runtime" | "build"
    dependencies: tuple[int, ...] = ()
    root: bool = False


@dataclass(frozen=True, slots=True)
class AuditableInfo:
    packages: tuple[AuditablePackage, ...] = field(default=())

    @property
    def root_package(self) -> AuditablePackage | None:
        for p in self.packages:
            if p.root:
                return p
        return None


def parse_cargo_auditable(data: bytes) -> AuditableInfo | None:
    """Extract and decode the audit section; None when absent/malformed."""
    section = named_section(data, SECTION_NAME)
    if not section:
        return None
    try:
        decompressed = zlib.decompress(section, bufsize=1 << 16)
        if len(decompressed) > _MAX_DECOMPRESSED:
            return None
        doc = json.loads(decompressed)
    except (zlib.error, json.JSONDecodeError, MemoryError):
        return None
    raw_packages = doc.get("packages")
    if not isinstance(raw_packages, list):
        return None
    packages: list[AuditablePackage] = []
    for p in raw_packages:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            continue
        deps = tuple(int(i) for i in p.get("dependencies", []) if isinstance(i, int))
        packages.append(
            AuditablePackage(
                name=str(p["name"]),
                version=str(p["version"]),
                source=str(p.get("source", "registry")),
                kind=str(p.get("kind", "runtime")),
                dependencies=deps,
                root=bool(p.get("root", False)),
            )
        )
    return AuditableInfo(packages=tuple(packages)) if packages else None
