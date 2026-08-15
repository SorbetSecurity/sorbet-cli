"""A read-only Windows registry hive (`regf`) parser.

Enough of the on-disk format to navigate keys and read string/dword values from
an **offline** SOFTWARE/SYSTEM hive — no Windows, no `reg.exe`, no ntdll. Cells
are addressed relative to the first hbin at 0x1000; keys (`nk`), value lists,
values (`vk`), and the four subkey-list kinds (`lf`/`lh`/`li`/`ri`) are all we
need for the Uninstall-keys and Services readers layered on top.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_HBIN_BASE = 0x1000

# registry value types we decode
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7


def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "little")


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


class Hive:
    """A parsed registry hive; `root()` returns the top `Key`."""

    def __init__(self, data: bytes) -> None:
        if data[:4] != b"regf":
            raise ValueError("not a regf registry hive")
        self.data = data
        self.root_offset = _u32(data, 0x24)

    def _cell(self, rel_offset: int) -> int:
        """Absolute offset of a cell's *data* (past its 4-byte size field)."""
        return _HBIN_BASE + rel_offset + 4

    def root(self) -> Key:
        return Key(self, self.root_offset)


@dataclass
class Key:
    hive: Hive
    offset: int  # relative offset of the nk cell

    def _base(self) -> int:
        return self.hive._cell(self.offset)

    @property
    def name(self) -> str:
        d = self.hive.data
        b = self._base()
        if d[b:b + 2] != b"nk":
            return ""
        flags = _u16(d, b + 0x02)
        name_len = _u16(d, b + 0x48)
        raw = d[b + 0x4C:b + 0x4C + name_len]
        if flags & 0x20:  # KEY_COMP_NAME → ASCII
            return raw.decode("latin-1", "replace")
        return raw.decode("utf-16-le", "replace")

    def subkeys(self) -> list[Key]:
        d = self.hive.data
        b = self._base()
        count = _u32(d, b + 0x14)
        list_off = _u32(d, b + 0x1C)
        if count == 0 or list_off in (0, 0xFFFFFFFF):
            return []
        return [Key(self.hive, off) for off in self._subkey_offsets(list_off)]

    def _subkey_offsets(self, list_off: int) -> list[int]:
        d = self.hive.data
        b = self.hive._cell(list_off)
        sig = d[b:b + 2]
        count = _u16(d, b + 2)
        offsets: list[int] = []
        if sig in (b"lf", b"lh"):
            for i in range(count):
                offsets.append(_u32(d, b + 4 + i * 8))  # (offset, hash) pairs
        elif sig == b"li":
            for i in range(count):
                offsets.append(_u32(d, b + 4 + i * 4))
        elif sig == b"ri":
            for i in range(count):
                sub = _u32(d, b + 4 + i * 4)
                offsets.extend(self._subkey_offsets(sub))
        return offsets

    def subkey(self, name: str) -> Key | None:
        lname = name.lower()
        for k in self.subkeys():
            if k.name.lower() == lname:
                return k
        return None

    def path(self, *parts: str) -> Key | None:
        node: Key | None = self
        for part in parts:
            if node is None:
                return None
            node = node.subkey(part)
        return node

    def values(self) -> dict[str, object]:
        d = self.hive.data
        b = self._base()
        count = _u32(d, b + 0x24)
        list_off = _u32(d, b + 0x28)
        out: dict[str, object] = {}
        if count == 0 or list_off in (0, 0xFFFFFFFF):
            return out
        lb = self.hive._cell(list_off)
        for i in range(count):
            vk_off = _u32(d, lb + i * 4)
            name, value = self._read_value(vk_off)
            out[name] = value
        return out

    def _read_value(self, vk_off: int) -> tuple[str, object]:
        d = self.hive.data
        b = self.hive._cell(vk_off)
        if d[b:b + 2] != b"vk":
            return ("", None)
        name_len = _u16(d, b + 0x02)
        data_len = _u32(d, b + 0x04)
        data_off = _u32(d, b + 0x08)
        data_type = _u32(d, b + 0x0C)
        flags = _u16(d, b + 0x10)
        raw_name = d[b + 0x14:b + 0x14 + name_len]
        name = raw_name.decode("latin-1" if flags & 1 else "utf-16-le", "replace")
        inline = bool(data_len & 0x80000000)
        length = data_len & 0x7FFFFFFF
        if inline:
            raw = struct.pack("<I", data_off)[:length]
        else:
            db = self.hive._cell(data_off)
            raw = d[db:db + length]
        return (name, _decode_value(data_type, raw))


def _decode_value(vtype: int, raw: bytes) -> object:
    if vtype in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if vtype == REG_DWORD and len(raw) >= 4:
        return _u32(raw, 0)
    if vtype == REG_MULTI_SZ:
        return [s for s in raw.decode("utf-16-le", "replace").split("\x00") if s]
    return raw
