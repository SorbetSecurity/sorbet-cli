"""`Source` protocol and target autodetection.

Every scan target is presented to detectors through this one interface, so
every cataloger works unmodified against every target type.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from sorb.errors import TargetError
from sorb.model import Coordinates


@dataclass(frozen=True, slots=True)
class SourceRef:
    id: str  # stable id within the run ("s1")
    kind: str  # "dir" | "file" | "archive" | "oci" | …
    ref: str  # human-readable target reference


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    """Identity of the scanned subject (git remote+commit, image digest, …)."""

    subject: str  # canonical subject string used for lineage
    facts: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Entry:
    """One walked file. Carries stat + first-bytes sniff so matchers can
    dispatch on name or content signature without a second read."""

    path: str  # normalized POSIX-style, relative to the source root
    size: int
    role: str | None = None  # fixture|vendored|docs|example|None
    sniff: bytes = b""
    is_symlink: bool = False


@runtime_checkable
class Source(Protocol):
    def root(self) -> SourceRef: ...

    def walk(self) -> Iterator[Entry]: ...

    def open(self, path: str) -> bytes: ...

    def digest(self, path: str) -> str: ...

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates: ...

    def provenance(self) -> SourceProvenance: ...


def open_target(spec: str, base: Path | None = None) -> Source:
    """Turn a target spec into a Source. Dir and file targets open here;
    container specs are dispatched by the pipeline to `sorb.container`;
    host:/disk:/git: specs are recognized and rejected explicitly."""
    from sorb.source.dir import DirSource, FileSource

    if spec.startswith("host://"):
        from sorb.source.host import LiveHostSource

        root = spec[len("host://"):] or "/"
        return LiveHostSource(root=root or "/")
    if spec.startswith("disk://"):
        from sorb.source.diskimage import open_disk_image

        return open_disk_image(spec[len("disk://"):], base=base)
    if spec.startswith("git://"):
        raise TargetError(
            "target type 'git://' is not supported yet in this build "
            "(dir, file, container, host, and disk targets are)"
        )
    for prefix in ("image:", "oci-dir:", "docker-archive:", "container://"):
        if spec.startswith(prefix):
            raise TargetError(
                f"container target {spec!r} must be scanned via `sorb scan` "
                "(the pipeline routes it to the container subsystem)"
            )
    p = (base / spec if base and not Path(spec).is_absolute() else Path(spec)).resolve()
    if p.is_dir():
        return DirSource(p)
    if p.is_file():
        return FileSource(p)
    raise TargetError(f"target not found: {spec}")
