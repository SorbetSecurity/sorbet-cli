"""Go binary build-info reader.

Go binaries embed ``runtime/debug.BuildInfo``: the exact module list with
versions and checksums. This module locates the ``\\xff Go buildinf:`` magic
and parses the Go ≥1.18 inline-string format (varint-prefixed version and
modinfo strings). Older pointer-based layouts are reported as a gap, never
guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAGIC = b"\xff Go buildinf:"
_HEADER_LEN = 32
_FLAGS_OFFSET = 15
_FLAG_INLINE_STRINGS = 0x2


@dataclass(frozen=True, slots=True)
class GoModule:
    path: str
    version: str
    sum: str | None = None
    replaced_by: GoModule | None = None


@dataclass(frozen=True, slots=True)
class GoBuildInfo:
    go_version: str
    main_path: str | None
    main_module: GoModule | None
    deps: tuple[GoModule, ...]
    settings: tuple[tuple[str, str], ...] = field(default=())


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def _read_string(data: bytes, pos: int) -> tuple[str, int]:
    length, pos = _read_varint(data, pos)
    return data[pos : pos + length].decode("utf-8", errors="replace"), pos + length


def parse_buildinfo(data: bytes) -> GoBuildInfo | None:
    """Return build info if `data` is a Go ≥1.18 binary; None otherwise."""
    idx = data.find(MAGIC)
    if idx < 0 or idx + _HEADER_LEN > len(data):
        return None
    flags = data[idx + _FLAGS_OFFSET]
    if not flags & _FLAG_INLINE_STRINGS:
        return None  # pre-1.18 pointer layout: honest gap, not a guess
    pos = idx + _HEADER_LEN
    try:
        go_version, pos = _read_string(data, pos)
        modinfo, pos = _read_string(data, pos)
    except IndexError:
        return None
    if not go_version:
        return None
    return _parse_modinfo(go_version.strip(), modinfo)


def _parse_modinfo(go_version: str, modinfo: str) -> GoBuildInfo:
    main_path: str | None = None
    main_module: GoModule | None = None
    deps: list[GoModule] = []
    settings: list[tuple[str, str]] = []
    last_dep_index: int | None = None
    for line in modinfo.splitlines():
        parts = line.split("\t")
        kind = parts[0]
        if kind == "path" and len(parts) >= 2:
            main_path = parts[1]
        elif kind == "mod" and len(parts) >= 3:
            main_module = GoModule(
                path=parts[1], version=parts[2], sum=parts[3] if len(parts) > 3 and parts[3] else None
            )
        elif kind == "dep" and len(parts) >= 3:
            deps.append(
                GoModule(
                    path=parts[1],
                    version=parts[2],
                    sum=parts[3] if len(parts) > 3 and parts[3] else None,
                )
            )
            last_dep_index = len(deps) - 1
        elif kind == "=>" and len(parts) >= 3 and last_dep_index is not None:
            original = deps[last_dep_index]
            replacement = GoModule(
                path=parts[1],
                version=parts[2],
                sum=parts[3] if len(parts) > 3 and parts[3] else None,
            )
            deps[last_dep_index] = GoModule(
                path=original.path,
                version=original.version,
                sum=original.sum,
                replaced_by=replacement,
            )
        elif kind == "build" and len(parts) >= 2:
            key, _, value = parts[1].partition("=")
            settings.append((key, value))
    return GoBuildInfo(
        go_version=go_version,
        main_path=main_path,
        main_module=main_module,
        deps=tuple(deps),
        settings=tuple(settings),
    )
