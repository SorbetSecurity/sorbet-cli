"""`DiskImageSource` — agentless offline disk-image scanning.

`disk://<path>` opens a disk image read-only, entirely in user space: no kernel
mount, no root, no platform filesystem calls, so "scan an EBS snapshot from a Mac
laptop" works identically everywhere. The self-contained path handles raw images
with an MBR/GPT partition table and FAT filesystems (see `fatfs`). The broader
matrix — qcow2/VMDK/VHDX containers, LVM, ext4/XFS/Btrfs/NTFS — comes from the
optional `dissect` backend (the `disk` extra), wrapped behind this same Source so
detectors never know the difference.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from sorb.errors import TargetError
from sorb.model import Coordinates
from sorb.source.base import Entry, SourceProvenance, SourceRef
from sorb.source.fatfs import FatFs, looks_like_fat
from sorb.source.roles import classify

_SNIFF_LEN = 64
_SECTOR = 512

# MBR partition type bytes we treat as FAT.
_FAT_TYPES = {0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E}
_GPT_PROTECTIVE = 0xEE


@dataclass(frozen=True, slots=True)
class Partition:
    index: int
    offset: int  # byte offset into the image
    size: int  # bytes
    type_hint: str  # "fat" | "ntfs" | "linux" | "unknown"


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 8], "little")


def parse_partitions(data: bytes) -> list[Partition]:
    """MBR + GPT partition table → byte ranges. Empty if the image is a bare FS."""
    if len(data) < _SECTOR or data[510:512] != b"\x55\xaa":
        return []
    parts: list[Partition] = []
    gpt = False
    for i in range(4):
        entry = data[0x1BE + i * 16:0x1BE + i * 16 + 16]
        ptype = entry[4]
        if ptype == 0:
            continue
        if ptype == _GPT_PROTECTIVE:
            gpt = True
            continue
        lba = _u32(entry, 8)
        nsec = _u32(entry, 12)
        if nsec == 0:
            continue
        parts.append(Partition(
            index=len(parts) + 1, offset=lba * _SECTOR, size=nsec * _SECTOR,
            type_hint=_mbr_hint(ptype),
        ))
    if gpt and len(data) >= 2 * _SECTOR and data[_SECTOR:_SECTOR + 8] == b"EFI PART":
        parts.extend(_parse_gpt(data))
    return parts


def _mbr_hint(ptype: int) -> str:
    if ptype in _FAT_TYPES:
        return "fat"
    if ptype == 0x07:
        return "ntfs"
    if ptype in (0x83, 0x8E):
        return "linux"
    return "unknown"


def _parse_gpt(data: bytes) -> list[Partition]:
    header = data[_SECTOR:2 * _SECTOR]
    entry_lba = _u64(header, 72)
    n_entries = _u32(header, 80)
    entry_size = _u32(header, 84)
    parts: list[Partition] = []
    base = entry_lba * _SECTOR
    for i in range(min(n_entries, 128)):
        e = data[base + i * entry_size:base + i * entry_size + entry_size]
        if len(e) < 56 or e[:16] == b"\x00" * 16:
            continue
        first_lba = _u64(e, 32)
        last_lba = _u64(e, 40)
        if last_lba < first_lba:
            continue
        parts.append(Partition(
            index=len(parts) + 1, offset=first_lba * _SECTOR,
            size=(last_lba - first_lba + 1) * _SECTOR, type_hint="unknown",
        ))
    return parts


def open_disk_image(spec: str, base: Path | None = None) -> DiskImageSource:
    path = (base / spec if base and not Path(spec).is_absolute() else Path(spec)).resolve()
    if not path.is_file():
        raise TargetError(f"disk image not found: {spec}")
    return DiskImageSource(path)


class DiskImageSource:
    """A disk image presented as a Source (built-in FAT, dissect for the rest)."""

    def __init__(self, image: Path, source_id: str = "s1") -> None:
        self._image = image.resolve()
        self._id = source_id
        self._data = self._image.read_bytes()
        # path -> (FatFs, FatFile); populated by the built-in reader.
        self._index: dict[str, tuple[FatFs, int, int]] = {}
        self._dissect_files: dict[str, bytes] = {}
        self._backend = self._mount()

    def _mount(self) -> str:
        partitions = parse_partitions(self._data)
        slices: list[tuple[int, bytes]] = []
        if not partitions and looks_like_fat(self._data):
            slices.append((0, self._data))  # bare FAT image, no partition table
        for p in partitions:
            sub = self._data[p.offset:p.offset + p.size]
            if looks_like_fat(sub):
                slices.append((p.index, sub))
        if slices:
            for idx, sub in slices:
                fs = FatFs(sub)
                prefix = f"p{idx}/" if idx else ""
                for f in fs.iter_files():
                    self._index[prefix + f.path] = (fs, f.first_cluster, f.size)
            return "fat"
        # non-FAT: defer to dissect if available
        if self._try_dissect():
            return "dissect"
        raise TargetError(
            f"{self._image.name}: no FAT filesystem found and the optional disk backend "
            "is not installed — `pip install 'sorbet[disk]'` for qcow2/ext4/NTFS/… support"
        )

    def _try_dissect(self) -> bool:
        try:
            from dissect.target import Target
        except ImportError:
            return False
        try:
            target = Target.open(str(self._image))
            for fs in target.filesystems:
                for entry in fs.walk("/"):
                    if entry.is_file():
                        try:
                            self._dissect_files[entry.path.lstrip("/")] = entry.open().read()
                        except OSError:
                            continue
        except Exception:  # pragma: no cover - dissect not exercised offline
            return False
        return bool(self._dissect_files)

    # -- Source protocol -----------------------------------------------------

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="disk", ref=str(self._image))

    def walk(self) -> Iterator[Entry]:
        if self._backend == "dissect":
            for path, data in sorted(self._dissect_files.items()):
                yield Entry(path=path, size=len(data), role=classify(path), sniff=data[:_SNIFF_LEN])
            return
        for path in sorted(self._index):
            blob = self._read(path)
            yield Entry(path=path, size=len(blob), role=classify(path), sniff=blob[:_SNIFF_LEN])

    def _read(self, path: str) -> bytes:
        if self._backend == "dissect":
            return self._dissect_files.get(path, b"")
        entry = self._index.get(path)
        if entry is None:
            raise FileNotFoundError(path)
        fs, first, size = entry
        return fs.read(first, size)

    def open(self, path: str) -> bytes:
        return self._read(path)

    def exists(self, path: str) -> bool:
        return path in self._index or path in self._dissect_files

    def digest(self, path: str) -> str:
        return hashlib.sha256(self._read(path)).hexdigest()

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates:
        return Coordinates(source_id=self._id, path=path, span=span)

    def provenance(self) -> SourceProvenance:
        image_digest = hashlib.sha256(self._data).hexdigest()
        return SourceProvenance(
            subject=f"disk:{self._image.name}:sha256:{image_digest}",
            facts={"image": self._image.name, "backend": self._backend,
                   "image_sha256": image_digest},
        )
