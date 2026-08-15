"""Minimal CLR metadata reader (part of the embedded reader family).

Reads just enough ECMA-335 metadata from a .NET PE to recover **assembly
identity** (name + version, table 0x20) and **referenced assemblies**
(AssemblyRef, table 0x23) — in-process, no external tooling. Anything
malformed returns None (hostile input rule).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_BSJB = 0x424A5342

#: #~ column kinds: fixed byte widths, or heap/index markers resolved at runtime
_S, _G, _B = "S", "G", "B"  # string / guid / blob heap indexes

#: coded-index groups: (tag bits, member tables) — width depends on row counts
_CODED: dict[str, tuple[int, tuple[int, ...]]] = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, tuple(range(0x00, 0x2C))),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "CustomAttributeType": (3, (0x06, 0x0A)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
}

#: table schemas for tables 0x00–0x2C (ECMA-335 §II.22); ints are byte widths,
#: strings name a heap (_S/_G/_B), "t:0xNN" a simple table index, "c:Name" a coded index
_SCHEMAS: dict[int, list[str]] = {
    0x00: ["2", _S, _G, _G, _G],  # Module
    0x01: ["c:ResolutionScope", _S, _S],  # TypeRef
    0x02: ["4", _S, _S, "c:TypeDefOrRef", "t:0x04", "t:0x06"],  # TypeDef
    0x04: ["2", _S, _B],  # Field
    0x06: ["4", "2", "2", _S, _B, "t:0x08"],  # MethodDef
    0x08: ["2", "2", _S],  # Param
    0x09: ["t:0x02", "c:TypeDefOrRef"],  # InterfaceImpl
    0x0A: ["c:MemberRefParent", _S, _B],  # MemberRef
    0x0B: ["2", "c:HasConstant", _B],  # Constant
    0x0C: ["c:HasCustomAttribute", "c:CustomAttributeType", _B],  # CustomAttribute
    0x0D: ["c:HasFieldMarshal", _B],  # FieldMarshal
    0x0E: ["2", "c:HasDeclSecurity", _B],  # DeclSecurity
    0x0F: ["2", "4", "t:0x02"],  # ClassLayout
    0x10: ["4", "t:0x04"],  # FieldLayout
    0x11: [_B],  # StandAloneSig
    0x12: ["t:0x02", "t:0x14"],  # EventMap
    0x14: ["2", _S, "c:TypeDefOrRef"],  # Event
    0x15: ["t:0x02", "t:0x17"],  # PropertyMap
    0x17: ["2", _S, _B],  # Property
    0x18: ["2", "t:0x06", "c:HasSemantics"],  # MethodSemantics
    0x19: ["t:0x02", "c:MethodDefOrRef", "c:MethodDefOrRef"],  # MethodImpl
    0x1A: [_S],  # ModuleRef
    0x1B: [_B],  # TypeSpec
    0x1C: ["2", "c:MemberForwarded", _S, "t:0x1A"],  # ImplMap
    0x1D: ["4", "t:0x04"],  # FieldRVA
    0x20: ["4", "2", "2", "2", "2", "4", _B, _S, _S],  # Assembly
    0x21: ["4"],  # AssemblyProcessor
    0x22: ["4", "4", "4"],  # AssemblyOS
    0x23: ["2", "2", "2", "2", "4", _B, _S, _S, _B],  # AssemblyRef
    0x24: ["4", "4", _B, "t:0x23"],  # AssemblyRefProcessor (approx.)
    0x25: ["4", "4", "4", "t:0x23"],  # AssemblyRefOS
    0x26: ["4", _S, _B],  # File
    0x27: ["4", "4", _S, _S, "c:Implementation"],  # ExportedType
    0x28: ["4", "4", _S, "c:Implementation"],  # ManifestResource
    0x29: ["t:0x02", "t:0x02"],  # NestedClass
    0x2A: ["2", "2", "c:TypeOrMethodDef", _S],  # GenericParam
    0x2B: ["c:MethodDefOrRef", _B],  # MethodSpec
    0x2C: ["t:0x2A", "c:TypeDefOrRef"],  # GenericParamConstraint
}


@dataclass(frozen=True, slots=True)
class AssemblyIdentity:
    name: str
    version: str  # "major.minor.build.revision"
    references: tuple[tuple[str, str], ...] = ()  # (name, version)


def _pe_rva_to_offset(data: bytes) -> tuple[int, int, list[tuple[int, int, int]]] | None:
    """(clr_header_rva, clr_size, sections[(virtual_addr, raw_size, raw_ptr)])."""
    try:
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        # data directory 14 (COM descriptor / CLR header)
        dd_base = opt + (96 if magic == 0x10B else 112)
        clr_rva, clr_size = struct.unpack_from("<II", data, dd_base + 14 * 8)
        if not clr_rva:
            return None
        sections = []
        table = opt + opt_size
        for i in range(n_sections):
            base = table + i * 40
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, base + 8)
            sections.append((vaddr, rsize, rptr))
        return clr_rva, clr_size, sections
    except (struct.error, IndexError):
        return None


def _rva(sections: list[tuple[int, int, int]], rva: int) -> int | None:
    for vaddr, rsize, rptr in sections:
        if vaddr <= rva < vaddr + rsize:
            return rptr + (rva - vaddr)
    return None


def parse_assembly_identity(data: bytes) -> AssemblyIdentity | None:
    """Assembly name/version (+AssemblyRefs) from a .NET PE; None if not CLR."""
    try:
        pe = _pe_rva_to_offset(data)
        if pe is None:
            return None
        clr_rva, _clr_size, sections = pe
        clr_off = _rva(sections, clr_rva)
        if clr_off is None:
            return None
        md_rva, _md_size = struct.unpack_from("<II", data, clr_off + 8)
        md = _rva(sections, md_rva)
        if md is None or struct.unpack_from("<I", data, md)[0] != _BSJB:
            return None
        version_len = struct.unpack_from("<I", data, md + 12)[0]
        pos = md + 16 + ((version_len + 3) & ~3)
        n_streams = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        streams: dict[str, tuple[int, int]] = {}
        for _ in range(n_streams):
            offset, size = struct.unpack_from("<II", data, pos)
            end = data.index(b"\x00", pos + 8)
            name = data[pos + 8 : end].decode("latin-1")
            streams[name] = (md + offset, size)
            pos = pos + 8 + (((end - (pos + 8)) + 1 + 3) & ~3)

        tables = streams.get("#~") or streams.get("#-")
        strings = streams.get("#Strings")
        if tables is None or strings is None:
            return None
        return _parse_tables(data, tables[0], strings[0], streams["#Strings"][1])
    except (struct.error, IndexError, ValueError):
        return None


def _parse_tables(
    data: bytes, base: int, strings_off: int, strings_size: int
) -> AssemblyIdentity | None:
    heap_sizes = data[base + 6]
    s_width = 4 if heap_sizes & 0x01 else 2
    g_width = 4 if heap_sizes & 0x02 else 2
    b_width = 4 if heap_sizes & 0x04 else 2
    valid = struct.unpack_from("<Q", data, base + 8)[0]
    present = [i for i in range(64) if valid & (1 << i)]
    rows: dict[int, int] = {}
    pos = base + 24
    for t in present:
        rows[t] = struct.unpack_from("<I", data, pos)[0]
        pos += 4

    def table_index_width(t: int) -> int:
        return 4 if rows.get(t, 0) > 0xFFFF else 2

    def coded_width(name: str) -> int:
        bits, members = _CODED[name]
        max_rows = max((rows.get(t, 0) for t in members), default=0)
        return 4 if max_rows >= (1 << (16 - bits)) else 2

    def row_size(t: int) -> int:
        schema = _SCHEMAS.get(t)
        if schema is None:
            raise ValueError(f"unknown metadata table 0x{t:02X}")
        size = 0
        for col in schema:
            if col == _S:
                size += s_width
            elif col == _G:
                size += g_width
            elif col == _B:
                size += b_width
            elif col.startswith("t:"):
                size += table_index_width(int(col[2:], 16))
            elif col.startswith("c:"):
                size += coded_width(col[2:])
            else:
                size += int(col)
        return size

    def string_at(idx: int) -> str:
        start = strings_off + idx
        end = data.index(b"\x00", start, strings_off + strings_size + 1)
        return data[start:end].decode("utf-8", "replace")

    def read_string_idx(off: int) -> int:
        return int(struct.unpack_from("<I" if s_width == 4 else "<H", data, off)[0])

    offset = pos
    assembly: tuple[str, str] | None = None
    refs: list[tuple[str, str]] = []
    for t in present:
        n = rows[t]
        size = row_size(t)
        if t == 0x20 and n >= 1:
            row = offset  # first Assembly row
            major, minor, build, rev = struct.unpack_from("<HHHH", data, row + 4)
            name_idx = read_string_idx(row + 4 + 8 + 4 + b_width)
            assembly = (string_at(name_idx), f"{major}.{minor}.{build}.{rev}")
        elif t == 0x23:
            for i in range(n):
                row = offset + i * size
                major, minor, build, rev = struct.unpack_from("<HHHH", data, row)
                name_idx = read_string_idx(row + 8 + 4 + b_width)
                refs.append((string_at(name_idx), f"{major}.{minor}.{build}.{rev}"))
        offset += n * size
    if assembly is None:
        return None
    return AssemblyIdentity(name=assembly[0], version=assembly[1], references=tuple(refs))
