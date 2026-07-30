"""Cataloger framework.

Catalogers are pure: no network, no global state. They register matchers,
receive matched files from the walk stage, and emit Findings + evidence. The
evidence factory stamps detector id/version/location automatically — detectors
cannot mint evidence with wrong attribution.
"""

from __future__ import annotations

import bisect
import fnmatch
import os
import re
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Protocol

from sorb.model import (
    EvidenceRecord,
    Finding,
    ProjectClaim,
    Tier,
)
from sorb.source.base import Entry, Source

# --------------------------------------------------------------------------
# Base rates & modifiers (data-driven)
# --------------------------------------------------------------------------


def _load_rates() -> tuple[dict[str, float], dict[str, float]]:
    raw = tomllib.loads(
        (resources.files("sorb") / "data" / "base_rates.toml").read_text(encoding="utf-8")
    )
    return (
        {k: float(v) for k, v in raw.get("base_rates", {}).items()},
        {k: float(v) for k, v in raw.get("modifiers", {}).items()},
    )


_BASE_RATES, _MODIFIERS = _load_rates()


def base_rate(technique: str) -> float | None:
    """The registered base confidence for a technique, or None if unknown."""
    return _BASE_RATES.get(technique)


_ROLE_MODIFIER_KEYS = {
    "fixture": "path-role-fixture",
    "example": "path-role-example",
    "docs": "path-role-docs",
}


@lru_cache(maxsize=1024)
def _pattern(glob: str) -> re.Pattern[str]:
    """`glob` as a compiled regex, case-folded exactly as `fnmatch` would.

    Every walked file is tested against every matcher, so the pattern is
    translated and case-folded once here rather than on each comparison.
    """
    return re.compile(fnmatch.translate(os.path.normcase(glob)))


@dataclass(frozen=True, slots=True)
class Matcher:
    """Glob and/or magic-byte matcher."""

    glob: str | None = None  # matched against the full POSIX relative path
    basename: str | None = None  # matched against the file name only
    magic: bytes | None = None  # first-bytes prefix

    def matches(self, entry: Entry) -> bool:
        if self.basename is not None:
            name = os.path.normcase(entry.path.rsplit("/", 1)[-1])
            if not _pattern(self.basename).match(name):
                return False
        if self.glob is not None:
            path = os.path.normcase(entry.path)
            pattern = _pattern(self.glob)
            if not (pattern.match(path) or pattern.match("/" + path)):
                return False
        if self.magic is not None and not entry.sniff.startswith(self.magic):
            return False
        return True


class SiblingReader(Protocol):
    def peek(self, path: str) -> bytes | None: ...


@dataclass
class CatalogerContext:
    """Per-work-unit context handed to catalogers."""

    source: Source
    detector: str  # "js/npm-lock@1" — stamped on all evidence
    env_matrix: tuple[str, ...] = ()
    evidence_level: str = "standard"
    projects: list[ProjectClaim] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)  # (code, message)

    # -- sibling access (shard-local peeking) ----------------------

    def peek(self, path: str) -> bytes | None:
        try:
            opener = getattr(self.source, "exists", None)
            if opener is not None and not self.source.exists(path):  # type: ignore[attr-defined]
                return None
            return self.source.open(path)
        except (FileNotFoundError, OSError):
            return None

    def declare_project(self, path: str, name: str, kind: str) -> ProjectClaim:
        p = ProjectClaim(path=path, name=name, kind=kind)
        if p not in self.projects:
            self.projects.append(p)
        return p

    def warn(self, code: str, message: str) -> None:
        self.warnings.append((code, message))

    # -- evidence factory ------------------------------------------------------

    def evidence(
        self,
        technique: str,
        tier: Tier,
        entry: Entry,
        *,
        span: tuple[int, int] | None = None,
        captured: str | None = None,
        extra_modifiers: Iterable[str] = (),
    ) -> EvidenceRecord:
        """Create an evidence record with detector attribution and confidence
        computed as base(technique) × context modifiers, reasons recorded."""
        confidence = _BASE_RATES.get(technique, 0.5)
        modifiers: list[str] = []
        role_key = _ROLE_MODIFIER_KEYS.get(entry.role or "")
        if role_key:
            confidence *= _MODIFIERS[role_key]
            modifiers.append(f"{role_key} x{_MODIFIERS[role_key]}")
        if entry.role == "vendored":
            modifiers.append("vendored (flagged, no penalty)")
        for m in extra_modifiers:
            factor = _MODIFIERS.get(m)
            if factor is not None:
                confidence *= factor
                modifiers.append(f"{m} x{factor}")
            else:
                modifiers.append(m)
        if self.evidence_level == "minimal":
            captured = None
        elif captured is not None and len(captured) > 2000:
            captured = captured[:2000] + "…"
        return EvidenceRecord(
            technique=technique,
            tier=tier,
            detector=self.detector,
            location=self.source.coords(entry.path, span=span),
            captured=_mask_secrets(captured),
            confidence=round(min(confidence, 1.0), 4),
            modifiers=tuple(modifiers),
        )


_SECRET_MARKERS = ("password", "secret", "token", "api_key", "apikey", "private_key")


def _mask_secrets(text: str | None) -> str | None:
    """Crude credential-pattern scrub for captured snippets."""
    if text is None:
        return None
    lowered = text.lower()
    if any(m in lowered for m in _SECRET_MARKERS):
        out_lines = []
        for line in text.splitlines():
            if any(m in line.lower() for m in _SECRET_MARKERS):
                key = line.split("=")[0].split(":")[0]
                out_lines.append(f"{key}: ******")
            else:
                out_lines.append(line)
        return "\n".join(out_lines)
    return text


class Cataloger(ABC):
    """The cataloger contract."""

    id: str  # "js/npm-lock"
    version: int  # parser version → cache key + evidence.detector
    matchers: list[Matcher]

    @property
    def detector(self) -> str:
        return f"{self.id}@{self.version}"

    @abstractmethod
    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]: ...


# --------------------------------------------------------------------------
# Registry & dispatch
# --------------------------------------------------------------------------

_REGISTRY: list[Cataloger] = []


def register(cataloger: Cataloger) -> Cataloger:
    if all(c.id != cataloger.id for c in _REGISTRY):
        _REGISTRY.append(cataloger)
    return cataloger


def registered() -> list[Cataloger]:
    _ensure_builtin_loaded()
    return list(_REGISTRY)


_LITERAL_RE = re.compile(r"[*?\[]")
#: `*.json`, but not `*.deps.json`: the lookup key is the final extension, so a
#: multi-segment suffix would never be found under it.
_EXTENSION_RE = re.compile(r"\*(\.[^.*?\[\]/]+)")

#: (registry length, exact-name table, extension table, everything else). Most
#: matchers require one exact file name or one extension, so a walked file can
#: skip the bulk of them with two dict lookups instead of a pattern match each.
#: The tables are a *candidate filter* only - `Matcher.matches` still decides.
_Index = tuple[
    int,
    dict[str, list[tuple[int, "Matcher"]]],
    dict[str, list[tuple[int, "Matcher"]]],
    list[tuple[int, "Matcher"]],
]
_index: _Index | None = None


def _required_name(matcher: Matcher) -> tuple[str, str] | None:
    """The exact name or extension a path must have for `matcher` to match.

    ("exact", name) or ("extension", ".ext"), or None when nothing cheap can be
    required. A glob's last segment works because `*` also spans `/`, so
    `*var/lib/dpkg/status` can only ever match a file named `status`.
    """
    for pattern in (matcher.basename, matcher.glob):
        if pattern is None:
            continue
        ext = _EXTENSION_RE.fullmatch(pattern)
        if ext:
            return "extension", os.path.normcase(ext.group(1))
        segment = pattern.rsplit("/", 1)[-1]
        if segment and not _LITERAL_RE.search(segment):
            return "exact", os.path.normcase(segment)
    return None


def _dispatch_index() -> _Index:
    global _index
    catalogers = registered()
    if _index is not None and _index[0] == len(catalogers):
        return _index
    exact: dict[str, list[tuple[int, Matcher]]] = {}
    extension: dict[str, list[tuple[int, Matcher]]] = {}
    rest: list[tuple[int, Matcher]] = []
    for pos, cataloger in enumerate(catalogers):
        for matcher in cataloger.matchers:
            required = _required_name(matcher)
            if required is None:
                rest.append((pos, matcher))
                continue
            kind, key = required
            table = exact if kind == "exact" else extension
            table.setdefault(key, []).append((pos, matcher))
    _index = (len(catalogers), exact, extension, rest)
    return _index


def dispatch(entry: Entry) -> list[Cataloger]:
    """Every registered cataloger whose matchers accept `entry`, in registry order."""
    catalogers = registered()
    _size, exact, extension, rest = _dispatch_index()
    name = os.path.normcase(entry.path.rsplit("/", 1)[-1])
    dot = name.rfind(".")

    buckets = [exact.get(name)]
    if dot >= 0:
        buckets.append(extension.get(name[dot:]))
    buckets.append(rest)

    hits: set[int] = set()
    for bucket in buckets:
        for pos, matcher in bucket or ():
            if pos not in hits and matcher.matches(entry):
                hits.add(pos)
    return [catalogers[pos] for pos in sorted(hits)]


_BUILTIN_LOADED = False


def _ensure_builtin_loaded() -> None:
    global _BUILTIN_LOADED
    if _BUILTIN_LOADED:
        return
    _BUILTIN_LOADED = True
    # Import for registration side effects.
    from sorb.catalogers import (  # noqa: F401
        binaries,
        cbom,
        cpp_build,
        cpp_vcpkg,
        dotnet,
        golang,
        host_platform,
        iac_cloud,
        iac_dockerfile,
        iac_k8s,
        iac_terraform,
        js,
        jvm,
        jvm_gradle,
        licenses,
        longtail,
        mlbom,
        mobile,
        native_binary,
        os_pkgs,
        os_rpm,
        python,
        ruby_php,
        table_specs,
        windows_registry,
    )

    # Third-party entry-point catalogers: discovered, namespaced, and
    # registered through the same path as first-party — trusted, in-process.
    from sorb.catalogers.plugins import discover_plugin_catalogers

    for plugin in discover_plugin_catalogers():
        register(plugin)


# --------------------------------------------------------------------------
# Span helper: line range of the first occurrence of a token
# --------------------------------------------------------------------------


class _LineIndex:
    """Offsets of every line start in one file, so a lookup is a bisect.

    Catalogers call these helpers once per finding. Counting newlines or
    splitting the file per call is quadratic in file size, which a large
    lockfile feels sharply.
    """

    __slots__ = ("text", "starts", "_lines")

    def __init__(self, text: str) -> None:
        self.text = text
        starts = [0]
        idx = text.find("\n")
        while idx >= 0:
            starts.append(idx + 1)
            idx = text.find("\n", idx + 1)
        self.starts = starts
        self._lines: list[str] | None = None

    def line_of(self, offset: int) -> int:
        """1-based line number containing `offset`."""
        return bisect.bisect_right(self.starts, offset)

    def lines(self) -> list[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines


_last_index: _LineIndex | None = None


def _index_for(text: str) -> _LineIndex:
    # Catalogers walk one file at a time, so a single-entry memo is enough for
    # every call within a parse to share the same index. The index is returned
    # rather than re-read from the global, so a concurrent scan in another
    # thread can only cost a rebuild, never hand back another file's offsets.
    global _last_index
    cached = _last_index
    if cached is not None and cached.text is text:
        return cached
    fresh = _LineIndex(text)
    _last_index = fresh
    return fresh


def find_span(text: str, token: str) -> tuple[int, int] | None:
    """Locate `token` in `text`; returns a 1-based (startLine, endLine)."""
    idx = text.find(token)
    if idx < 0:
        return None
    line = _index_for(text).line_of(idx)
    return (line, line)


def snippet_at(text: str, token: str, context: int = 0) -> str | None:
    span = find_span(text, token)
    if span is None:
        return None
    lines = _index_for(text).lines()
    start = max(0, span[0] - 1 - context)
    end = min(len(lines), span[1] + context)
    return "\n".join(lines[start:end])
