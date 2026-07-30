"""A read-only FAT12/16/32 filesystem reader.

The self-contained, dependency-free path for `DiskImageSource`: FAT is the
simplest real on-disk filesystem, so it is the one we implement in-process (LFN
long names included). ext4/XFS/Btrfs/NTFS and the container formats (qcow2/VMDK/
VHDX) come from the optional `dissect` backend; FAT keeps a fully offline,
byte-deterministic fixture path that runs identically on every OS.

Everything is pure byte arithmetic over an in-memory image slice — no mounts, no
root, no platform filesystem calls.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass


def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "little")


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def looks_like_fat(data: bytes) -> bool:
    if len(data) < 512:
        return False
    if data[510:512] != b"\x55\xaa":
        return False
    return data[0x36:0x3B] in (b"FAT12", b"FAT16", b"FAT  ") or data[0x52:0x5A].startswith(
        (b"FAT32", b"FAT")
    )


@dataclass(frozen=True, slots=True)
class FatFile:
    path: str
    first_cluster: int
    size: int


class FatFs:
    """FAT12/16/32 reader over an image byte slice."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.bps = _u16(data, 0x0B) or 512
        self.spc = data[0x0D] or 1
        reserved = _u16(data, 0x0E)
        num_fats = data[0x10] or 1
        self.root_entries = _u16(data, 0x11)
        total16 = _u16(data, 0x13)
        spf16 = _u16(data, 0x16)
        total32 = _u32(data, 0x20)
        spf32 = _u32(data, 0x24)
        self.spf = spf16 or spf32
        total = total16 or total32
        self.fat_start = reserved * self.bps
        self.root_start = (reserved + num_fats * self.spf) * self.bps
        root_sectors = (self.root_entries * 32 + self.bps - 1) // self.bps
        self.data_start = self.root_start + root_sectors * self.bps
        data_sectors = total - (reserved + num_fats * self.spf + root_sectors)
        self.cluster_count = data_sectors // self.spc if self.spc else 0
        if self.cluster_count < 4085:
            self.fat_bits = 12
        elif self.cluster_count < 65525:
            self.fat_bits = 16
        else:
            self.fat_bits = 32
        self.root_cluster = _u32(data, 0x2C)  # FAT32 only

    # -- FAT / clusters ------------------------------------------------------

    def _fat_entry(self, cluster: int) -> int:
        if self.fat_bits == 16:
            return _u16(self.data, self.fat_start + cluster * 2)
        if self.fat_bits == 32:
            return _u32(self.data, self.fat_start + cluster * 4) & 0x0FFFFFFF
        # FAT12: 12-bit packed
        off = self.fat_start + (cluster * 3) // 2
        val = _u16(self.data, off)
        return (val >> 4) if (cluster & 1) else (val & 0x0FFF)

    def _eoc(self, entry: int) -> bool:
        limits = {12: 0x0FF8, 16: 0xFFF8, 32: 0x0FFFFFF8}
        return entry >= limits[self.fat_bits] or entry < 2

    def _chain(self, start: int) -> list[int]:
        chain: list[int] = []
        c = start
        seen: set[int] = set()
        while 2 <= c and not self._eoc(c) and c not in seen:
            seen.add(c)
            chain.append(c)
            c = self._fat_entry(c)
        return chain

    def _cluster_bytes(self, cluster: int) -> bytes:
        off = self.data_start + (cluster - 2) * self.spc * self.bps
        return self.data[off:off + self.spc * self.bps]

    def _read_chain(self, start: int, size: int) -> bytes:
        buf = b"".join(self._cluster_bytes(c) for c in self._chain(start))
        return buf[:size] if size else buf

    # -- directories ---------------------------------------------------------

    def iter_files(self) -> Iterator[FatFile]:
        if self.fat_bits == 32:
            root = self._read_chain(self.root_cluster, 0)
        else:
            root = self.data[self.root_start:self.root_start + self.root_entries * 32]
        yield from self._walk("", root, depth=0)

    def _walk(self, prefix: str, dir_bytes: bytes, depth: int) -> Iterator[FatFile]:
        if depth > 32:
            return
        lfn: list[bytes] = []
        for i in range(0, len(dir_bytes), 32):
            e = dir_bytes[i:i + 32]
            if len(e) < 32 or e[0] == 0x00:
                break
            if e[0] == 0xE5:  # deleted
                lfn = []
                continue
            attr = e[0x0B]
            if attr == 0x0F:  # LFN component
                lfn.insert(0, e)
                continue
            if attr & 0x08:  # volume label
                lfn = []
                continue
            name = _lfn_name(lfn) or _short_name(e)
            lfn = []
            if name in (".", ".."):
                continue
            first = _u16(e, 0x1A) | (_u16(e, 0x14) << 16)
            size = _u32(e, 0x1C)
            path = f"{prefix}{name}"
            if attr & 0x10:  # directory
                if first >= 2:
                    yield from self._walk(path + "/", self._read_chain(first, 0), depth + 1)
            else:
                yield FatFile(path=path, first_cluster=first, size=size)

    def read(self, first_cluster: int, size: int) -> bytes:
        if first_cluster < 2:
            return b""
        return self._read_chain(first_cluster, size)


def _short_name(e: bytes) -> str:
    raw = e[:11]
    base = raw[:8].rstrip(b" ").decode("ascii", "replace")
    ext = raw[8:11].rstrip(b" ").decode("ascii", "replace")
    name = f"{base}.{ext}" if ext else base
    return name.lower()


def _lfn_name(parts: list[bytes]) -> str:
    if not parts:
        return ""
    chunks: list[str] = []
    for e in parts:
        raw = e[0x01:0x0B] + e[0x0E:0x1A] + e[0x1C:0x20]
        chunks.append(raw.decode("utf-16-le", "replace"))
    name = "".join(chunks)
    end = name.find("\x00")
    if end >= 0:
        name = name[:end]
    return name.strip("￿")
