"""In-process PE/COFF reader.

Extracts the imported DLLs (import table), section table, CLR-header presence,
Authenticode presence (security data directory), and VS_VERSIONINFO
product/company/version strings — the "PE VS_VERSIONINFO → product/company
strings" ground-truth signal.
"""

from __future__ import annotations

import struct

from sorb.binary.info import BinaryInfo, Section

_MACHINE = {0x14C: "i386", 0x8664: "x86_64", 0xAA64: "aarch64", 0x1C0: "arm"}
_DIR_IMPORT, _DIR_SECURITY, _DIR_COMLR = 1, 4, 14


def parse_pe(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt="pe")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        info.warnings.append("not a PE (bad NT signature)")
        return info
    coff = e_lfanew + 4
    machine, n_sections = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    characteristics = struct.unpack_from("<H", data, coff + 18)[0]
    info.arch = _MACHINE.get(machine, f"machine-{machine:#x}")
    info.kind = "dll" if characteristics & 0x2000 else "exe"
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    info.bits = 64 if pe32plus else 32

    dd_base = opt + (112 if pe32plus else 96)
    n_dirs = struct.unpack_from("<I", data, opt + (108 if pe32plus else 92))[0]

    def data_dir(idx: int) -> tuple[int, int]:
        if idx >= n_dirs:
            return 0, 0
        return struct.unpack_from("<II", data, dd_base + idx * 8)  # (rva, size)

    # section table
    table = opt + opt_size
    sections: list[tuple[str, int, int, int, int]] = []  # name, vaddr, vsize, rawptr, rawsize
    for i in range(min(n_sections, 4096)):
        base = table + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        flags = ("X" if chars & 0x20000000 else "") + ("A" if chars & 0x40000000 else "")
        info.sections.append(Section(name=name, offset=rawptr, size=rawsize, flags=flags))
        sections.append((name, vaddr, vsize, rawptr, rawsize))

    def rva_to_off(rva: int) -> int | None:
        for _name, vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    # CLR + Authenticode presence
    info.has_clr = data_dir(_DIR_COMLR)[0] != 0
    info.has_authenticode = data_dir(_DIR_SECURITY)[0] != 0

    # import table → needed DLLs
    imp_rva, _imp_size = data_dir(_DIR_IMPORT)
    if imp_rva:
        info.needed = _read_imports(data, rva_to_off(imp_rva), rva_to_off)

    # VS_VERSIONINFO from the .rsrc section (best-effort string scan)
    info.version_info = _read_version_info(data, sections)
    return info


def _read_imports(data: bytes, off: int | None, rva_to_off) -> list[str]:  # type: ignore[no-untyped-def]
    if off is None:
        return []
    dlls: list[str] = []
    seen: set[str] = set()
    for i in range(4096):
        base = off + i * 20  # IMAGE_IMPORT_DESCRIPTOR
        if base + 20 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, base + 12)[0]
        if name_rva == 0:  # null terminator descriptor
            break
        name_off = rva_to_off(name_rva)
        if name_off is None or name_off >= len(data):
            continue
        end = data.find(b"\x00", name_off)
        name = data[name_off : end if end >= 0 else name_off].decode("latin-1")
        if name and name.lower() not in seen:
            seen.add(name.lower())
            dlls.append(name)
    return dlls


_VI_KEYS = ("ProductName", "CompanyName", "FileVersion", "ProductVersion", "OriginalFilename")


def _read_version_info(data: bytes, sections: list[tuple[str, int, int, int, int]]) -> dict[str, str]:
    """Extract VS_VERSIONINFO string values by scanning the .rsrc section.

    UTF-16LE key\\0value\\0 pairs; a targeted scan avoids a full resource-tree
    walk while still recovering the product/company/version strings.
    """
    rsrc = next((s for s in sections if s[0] == ".rsrc"), None)
    if rsrc is None:
        return {}
    _n, _v, _vs, rawptr, rawsize = rsrc
    blob = data[rawptr : rawptr + rawsize]
    out: dict[str, str] = {}
    for key in _VI_KEYS:
        needle = key.encode("utf-16-le")
        idx = blob.find(needle)
        if idx < 0:
            continue
        pos = idx + len(needle)
        while pos + 2 <= len(blob) and blob[pos : pos + 2] == b"\x00\x00":  # padding to value
            pos += 2
        end = blob.find(b"\x00\x00", pos)
        if end < 0:
            continue
        raw = blob[pos : end + 1] if (end - pos) % 2 else blob[pos:end]
        try:
            value = raw.decode("utf-16-le").strip("\x00").strip()
        except UnicodeDecodeError:
            continue
        if value and all(32 <= ord(c) < 0xFFFD for c in value):
            out[key] = value
    return out
