"""Minimal ELF / PE named-section readers.

Just enough in-process format parsing to locate a named section's bytes
(e.g. cargo-auditable's ``.dep-v0``) — the full binary format-adapter layer
lives elsewhere. Anything malformed returns None; never raises on hostile input.
"""

from __future__ import annotations

import struct

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"


def elf_section(data: bytes, name: str) -> bytes | None:
    """Bytes of the ELF section called `name`, or None."""
    try:
        if data[:4] != ELF_MAGIC or len(data) < 64:
            return None
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        if is64:
            e_shoff = struct.unpack_from(f"{endian}Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 0x3E)[0]
        else:
            e_shoff = struct.unpack_from(f"{endian}I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 0x30)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 0x32)[0]
        if not e_shoff or e_shnum == 0 or e_shstrndx >= e_shnum or e_shentsize < 40:
            return None

        def section_header(idx: int) -> tuple[int, int, int]:
            base = e_shoff + idx * e_shentsize
            sh_name = struct.unpack_from(f"{endian}I", data, base)[0]
            if is64:
                sh_offset = struct.unpack_from(f"{endian}Q", data, base + 0x18)[0]
                sh_size = struct.unpack_from(f"{endian}Q", data, base + 0x20)[0]
            else:
                sh_offset = struct.unpack_from(f"{endian}I", data, base + 0x10)[0]
                sh_size = struct.unpack_from(f"{endian}I", data, base + 0x14)[0]
            return sh_name, sh_offset, sh_size

        _n, str_off, str_size = section_header(e_shstrndx)
        strtab = data[str_off : str_off + str_size]
        for i in range(e_shnum):
            sh_name, sh_offset, sh_size = section_header(i)
            if sh_name < len(strtab):
                end = strtab.find(b"\x00", sh_name)
                sec = strtab[sh_name : end if end >= 0 else len(strtab)]
                if sec.decode("latin-1") == name:
                    if sh_offset + sh_size <= len(data):
                        return data[sh_offset : sh_offset + sh_size]
                    return None
        return None
    except (struct.error, IndexError, ValueError):
        return None


def pe_section(data: bytes, name: str) -> bytes | None:
    """Bytes of the PE section called `name` (max 8 chars), or None."""
    try:
        if data[:2] != PE_MAGIC or len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        table = coff + 20 + opt_size
        want = name.encode("latin-1")[:8].ljust(8, b"\x00")
        for i in range(n_sections):
            base = table + i * 40
            if data[base : base + 8] != want:
                continue
            raw_size = struct.unpack_from("<I", data, base + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
            if raw_ptr + raw_size <= len(data):
                return data[raw_ptr : raw_ptr + raw_size]
            return None
        return None
    except (struct.error, IndexError, ValueError):
        return None


def named_section(data: bytes, name: str) -> bytes | None:
    if data[:4] == ELF_MAGIC:
        return elf_section(data, name)
    if data[:2] == PE_MAGIC:
        return pe_section(data, name)
    return None
