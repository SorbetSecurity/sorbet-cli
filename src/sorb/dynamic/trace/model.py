"""Trace data model + store-path filter (the mapper's input)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: package-store roots — an access under one of these is dependency-relevant
_STORE_PATTERNS = (
    re.compile(r"(^|/)node_modules/"),
    re.compile(r"(^|/)\.pnpm/"),
    re.compile(r"(^|/)site-packages/"),
    re.compile(r"(^|/)dist-packages/"),
    re.compile(r"(^|/)\.venv/"),
    re.compile(r"(^|/)vendor/(bundle|composer)/"),
    re.compile(r"/\.m2/repository/"),
    re.compile(r"/\.cargo/registry/"),
    re.compile(r"/\.cache/go/|/pkg/mod/"),
    re.compile(r"/gems/"),
)


def is_store_path(path: str) -> bool:
    """Does this path land inside a known package store?"""
    return any(p.search(path) for p in _STORE_PATTERNS)


@dataclass(frozen=True, slots=True)
class Observation:
    """One recorded runtime access to dependency-relevant state."""

    technique: str  # "python-import-hook" | "node-require-probe" | "ebpf-file-open" | …
    kind: str  # "module" | "file"
    identifier: str  # dist name (module hook) or file path (file trace)
    detail: str = ""  # e.g. version, or the concrete file path
    ecosystem: str | None = None


@dataclass
class TraceResult:
    """Outcome of a traced command."""

    command: list[str]
    exit_code: int
    backend: str  # the file-trace backend used ("ebpf"/"fanotify"/"strace"/"dtrace"/"etw"/"none")
    hooks: list[str] = field(default_factory=list)  # interpreter hooks that ran
    observations: list[Observation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def modules(self) -> list[Observation]:
        return [o for o in self.observations if o.kind == "module"]

    def store_files(self) -> list[Observation]:
        return [o for o in self.observations if o.kind == "file" and is_store_path(o.identifier)]
