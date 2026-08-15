"""In-process Mach-O reader incl. fat/universal.

Load commands parsed for LC_LOAD_DYLIB (needed dylibs), LC_ID_DYLIB (soname),
LC_UUID (stable identity → build-id), LC_RPATH, and LC_MAIN/LC_LOAD_DYLINKER
(interp). Fat binaries yield one `BinaryInfo` slice per architecture.
"""

from __future__ import annotations

import struct

from sorb.binary.info import BinaryInfo

_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "aarch64"}

_LC_LOAD_DYLIB = 0xC
_LC_ID_DYLIB = 0xD
_LC_LOAD_WEAK_DYLIB = 0x18
_LC_REEXPORT_DYLIB = 0x1F
_LC_UUID = 0x1B
_LC_RPATH = 0x1C
_LC_LOAD_DYLINKER = 0xE
_LC_MAIN = 0x80000028
_MH_MAGICS = {0xFEEDFACE: (False, ">"), 0xCEFAEDFE: (False, "<"),
              0xFEEDFACF: (True, ">"), 0xCFFAEDFE: (True, "<")}
_FAT_MAGICS = {0xCAFEBABE: ">", 0xBEBAFECA: "<"}
_FILETYPE = {1: "object", 2: "exe", 6: "dylib", 8: "bundle"}


def parse_macho(data: bytes) -> BinaryInfo:
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in _FAT_MAGICS:
        return _parse_fat(data, _FAT_MAGICS[magic])
    return _parse_thin(data)


def _parse_fat(data: bytes, endian: str) -> BinaryInfo:
    info = BinaryInfo(fmt="macho-fat")
    nfat = struct.unpack_from(f"{endian}I", data, 4)[0]
    for i in range(min(nfat, 64)):
        base = 8 + i * 20
        if base + 20 > len(data):
            break
        _cputype, _sub, offset, size, _align = struct.unpack_from(f"{endian}IIIII", data, base)
        if offset + size <= len(data) and offset >= 8:
            slice_info = _parse_thin(data[offset : offset + size])
            info.slices.append(slice_info)
    if info.slices:
        info.arch = ",".join(s.arch for s in info.slices)
    return info


def _parse_thin(data: bytes) -> BinaryInfo:
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in _MH_MAGICS:
        return BinaryInfo(fmt="macho", warnings=["bad Mach-O magic"])
    is64, endian = _MH_MAGICS[magic]
    info = BinaryInfo(fmt="macho", bits=64 if is64 else 32,
                      endianness="little" if endian == "<" else "big")
    cputype, _cpusub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        f"{endian}IIIIII", data, 4
    )
    info.arch = _CPU.get(cputype, f"cpu-{cputype}")
    info.kind = _FILETYPE.get(filetype, f"type-{filetype}")
    pos = 32 if is64 else 28
    for _ in range(min(ncmds, 65536)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(f"{endian}II", data, pos)
        if cmdsize < 8 or pos + cmdsize > len(data):
            break
        body = data[pos : pos + cmdsize]
        if cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB):
            name = _lc_str(body, endian, 8)
            if name:
                info.needed.append(name)
        elif cmd == _LC_ID_DYLIB:
            info.soname = _lc_str(body, endian, 8)
        elif cmd == _LC_RPATH:
            rp = _lc_str(body, endian, 8)
            if rp:
                info.rpaths.append(rp)
        elif cmd == _LC_LOAD_DYLINKER:
            info.interp = _lc_str(body, endian, 8)
        elif cmd == _LC_UUID and cmdsize >= 24:
            info.build_id = body[8:24].hex()
        pos += cmdsize
    return info


def _lc_str(body: bytes, endian: str, str_offset_field: int) -> str | None:
    """A Mach-O lc_str: a 4-byte offset into the command, then a C string."""
    if len(body) < str_offset_field + 4:
        return None
    off = struct.unpack_from(f"{endian}I", body, str_offset_field)[0]
    if off >= len(body):
        return None
    end = body.find(b"\x00", off)
    return body[off : end if end >= 0 else len(body)].decode("latin-1") or None
