"""Normalized ``BinaryInfo`` model.

Every format adapter parses into this one shape so the embedded extractors,
the link-graph builder, and the fingerprint engines work
against any binary format identically. Parsing is bounded (size + budget
caps) and CAS-cached by blob digest — a `.so` shared by 40 images parses once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    offset: int
    size: int
    flags: str = ""  # e.g. "X" for executable, "A" alloc


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    kind: str = ""  # "func" | "object" | "import" | "export"
    version: str | None = None  # e.g. "GLIBC_2.34" (symbol-version requirement)


@dataclass
class BinaryInfo:
    """Parsed format facts, format-neutral."""

    fmt: str  # "elf" | "pe" | "macho" | "macho-fat" | "wasm"
    arch: str = ""  # "x86_64" | "aarch64" | "i386" | …
    bits: int = 0  # 32 | 64
    endianness: str = "little"
    kind: str = ""  # "exe" | "dylib" | "object" | "core" | …
    interp: str | None = None  # ELF PT_INTERP
    soname: str | None = None  # ELF DT_SONAME
    needed: list[str] = field(default_factory=list)  # DT_NEEDED / import DLLs / dylibs
    rpaths: list[str] = field(default_factory=list)  # RPATH + RUNPATH
    build_id: str | None = None  # ELF .note.gnu.build-id / Mach-O LC_UUID
    sections: list[Section] = field(default_factory=list)
    imported_symbols: list[Symbol] = field(default_factory=list)
    exported_symbols: list[Symbol] = field(default_factory=list)
    version_requirements: list[str] = field(default_factory=list)  # "GLIBC_2.34", …
    has_authenticode: bool = False  # PE code-signature present
    has_clr: bool = False  # PE CLR header present
    version_info: dict[str, str] = field(default_factory=dict)  # PE VS_VERSIONINFO
    strings_hint: list[str] = field(default_factory=list)  # high-signal strings
    #: nested binaries (fat Mach-O slices)
    slices: list[BinaryInfo] = field(default_factory=list)
    #: parse-time notes ("truncated", "unsupported-format-version") → analysis-gap
    warnings: list[str] = field(default_factory=list)

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
