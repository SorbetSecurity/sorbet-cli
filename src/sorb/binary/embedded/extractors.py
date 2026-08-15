"""Embedded ground-truth extractor suite.

Extends the base embedded readers (Go buildinfo, cargo-auditable,
.NET deps.json). Each extractor turns a cheap, near-perfect embedded signal
into installed-tier facts, checked before any heuristic:

- **embedded SBOM sections** — some vendors embed CycloneDX/SPDX (e.g. an
  ``.sbom`` ELF section); ingested and returned for cross-verification, never
  trusted blindly ("verify, don't trust").
- **VS_VERSIONINFO** — PE product/company/version → a component identity.
- **frozen-app archives** — PyInstaller (PYZ cookie), launch4j (jar-in-exe),
  Electron ASAR (bundled node_modules), Node SEA / .NET single-file markers —
  detected so the bundled inventory can be recovered.

Deep unpacking of every frozen format is bounded here (marker + offset
detection); the full extraction reuses the ArchiveSource nesting pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass

from sorb.binary.info import BinaryInfo

# -- embedded SBOM sections --------------------------------------------------------------

_SBOM_SECTIONS = (".sbom", "sbom", "__sbom", ".note.package")


@dataclass(frozen=True, slots=True)
class EmbeddedSbom:
    section: str
    data: bytes


def extract_embedded_sbom(binary: bytes, info: BinaryInfo) -> EmbeddedSbom | None:
    for section in info.sections:
        if section.name in _SBOM_SECTIONS and section.size:
            blob = binary[section.offset : section.offset + section.size]
            head = blob.lstrip()[:64]
            if head.startswith(b"{") or head.startswith(b"SPDX") or b"bomFormat" in blob[:512]:
                return EmbeddedSbom(section=section.name, data=blob)
    return None


# -- frozen-app markers ------------------------------------------------------------------

# PyInstaller archive cookie: MAGIC "MEI\014\013\012\013\016" near EOF
_PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
# launch4j embeds a jar; its stub carries this signature and a trailing PK zip
_LAUNCH4J_MARKER = b"<launch4jConfig>"
# Electron ASAR: the app is an "app.asar" archive; SEA fuse markers
_NODE_SEA_MARKER = b"NODE_SEA_BLOB"
_DOTNET_SINGLEFILE_MARKER = b"\x8b\x12\x02\xb9\x6a\x61\x20\x38\x72\x7b\x93\x02\x14\xd7\xa0\x32"


@dataclass(frozen=True, slots=True)
class FrozenApp:
    kind: str  # "pyinstaller" | "launch4j" | "node-sea" | "dotnet-single-file"
    detail: str = ""


def detect_frozen_app(binary: bytes) -> FrozenApp | None:
    """Detect a frozen/self-contained app bundle (marker scan near EOF)."""
    tail = binary[-(1 << 20):] if len(binary) > (1 << 20) else binary
    if _PYINSTALLER_MAGIC in tail:
        return FrozenApp(kind="pyinstaller", detail="PyInstaller PYZ archive present")
    if _LAUNCH4J_MARKER in binary[:1 << 16] or (binary[:2] == b"MZ" and b"PK\x03\x04" in tail):
        if _LAUNCH4J_MARKER in binary or binary.rstrip().endswith(b"PK\x05\x06") or b"PK\x03\x04" in tail:
            return FrozenApp(kind="launch4j", detail="jar-in-exe (launch4j-style)")
    if _NODE_SEA_MARKER in binary[:1 << 16] or _NODE_SEA_MARKER in tail:
        return FrozenApp(kind="node-sea", detail="Node single-executable application blob")
    if _DOTNET_SINGLEFILE_MARKER in tail:
        return FrozenApp(kind="dotnet-single-file", detail=".NET single-file bundle")
    return None


# -- version-info identity ---------------------------------------------------------------


def versioninfo_identity(info: BinaryInfo) -> tuple[str, str, str | None] | None:
    """(name, version, vendor) from PE VS_VERSIONINFO, or None."""
    vi = info.version_info
    name = vi.get("ProductName") or vi.get("OriginalFilename")
    version = vi.get("ProductVersion") or vi.get("FileVersion")
    if name and version:
        return name, version.split()[0], vi.get("CompanyName")
    return None
