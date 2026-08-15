"""DiskImageSource over a built-in FAT16 reader.

A valid FAT16 image (with LFN long names) is synthesized byte-for-byte, so the
disk-image scan path is exercised fully offline and deterministically — the
`disk://` target, partition/BPB parsing, cluster-chain reads, and detector
dispatch — and the resulting SBOM is byte-identical across platforms.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.emit.cyclonedx import emit_cyclonedx
from sorb.graph.store import GraphStore
from sorb.source.diskimage import DiskImageSource, parse_partitions
from sorb.source.fatfs import FatFs, looks_like_fat

# -- a minimal, correct FAT16 image builder ---------------------------------------------

_BPS = 512
_SPC = 1
_RESERVED = 1
_NUM_FATS = 1
_ROOT_ENTRIES = 512
_TOTAL = 8192
_SPF = 32


def _lfn_checksum(short11: bytes) -> int:
    s = 0
    for c in short11:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _lfn_entries(name: str, short11: bytes) -> list[bytes]:
    cksum = _lfn_checksum(short11)
    u = name.encode("utf-16-le")
    chars = [u[k:k + 2] for k in range(0, len(u), 2)]
    chars.append(b"\x00\x00")
    while len(chars) % 13:
        chars.append(b"\xff\xff")
    nent = len(chars) // 13
    entries: list[bytes] = []
    for seq in range(1, nent + 1):
        part = chars[(seq - 1) * 13:seq * 13]
        e = bytearray(32)
        e[0] = seq | (0x40 if seq == nent else 0)
        e[0x0B] = 0x0F
        e[0x0D] = cksum
        for k in range(5):
            e[0x01 + k * 2:0x03 + k * 2] = part[k]
        for k in range(6):
            e[0x0E + k * 2:0x10 + k * 2] = part[5 + k]
        for k in range(2):
            e[0x1C + k * 2:0x1E + k * 2] = part[11 + k]
        entries.append(bytes(e))
    entries.reverse()  # physical order: last logical part (with 0x40) first
    return entries


def build_fat16(files: dict[str, bytes]) -> bytes:
    root_sectors = (_ROOT_ENTRIES * 32 + _BPS - 1) // _BPS
    data_start = (_RESERVED + _NUM_FATS * _SPF + root_sectors) * _BPS
    fat_off = _RESERVED * _BPS
    root_off = (_RESERVED + _NUM_FATS * _SPF) * _BPS
    img = bytearray(_TOTAL * _BPS)

    img[0:3] = b"\xeb\x3c\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 0x0B, _BPS)
    img[0x0D] = _SPC
    struct.pack_into("<H", img, 0x0E, _RESERVED)
    img[0x10] = _NUM_FATS
    struct.pack_into("<H", img, 0x11, _ROOT_ENTRIES)
    struct.pack_into("<H", img, 0x13, _TOTAL)
    img[0x15] = 0xF8
    struct.pack_into("<H", img, 0x16, _SPF)
    img[0x26] = 0x29
    img[0x36:0x3B] = b"FAT16"
    img[510:512] = b"\x55\xaa"

    struct.pack_into("<H", img, fat_off, 0xFFF8)
    struct.pack_into("<H", img, fat_off + 2, 0xFFFF)

    next_cluster = 2
    dirp = root_off
    for i, (name, content) in enumerate(files.items()):
        nclu = max(1, (len(content) + _BPS - 1) // _BPS)
        start = next_cluster
        for j in range(nclu):
            cl = start + j
            nxt = 0xFFFF if j == nclu - 1 else cl + 1
            struct.pack_into("<H", img, fat_off + cl * 2, nxt)
        off = data_start + (start - 2) * _BPS
        img[off:off + len(content)] = content
        next_cluster += nclu

        short = (f"FILE{i:04d}".encode() + b"   ")[:11]
        for e in _lfn_entries(name, short):
            img[dirp:dirp + 32] = e
            dirp += 32
        de = bytearray(32)
        de[0:11] = short
        de[0x0B] = 0x20
        struct.pack_into("<H", de, 0x1A, start)
        struct.pack_into("<I", de, 0x1C, len(content))
        img[dirp:dirp + 32] = de
        dirp += 32
    return bytes(img)


_FILES = {
    "requirements.txt": b"flask==3.0.0\nrequests==2.31.0\n",
    "app/go.mod": b"module example.com/app\n\ngo 1.21\n\nrequire github.com/pkg/errors v0.9.1\n",
}


@pytest.fixture()
def disk_image(tmp_path: Path) -> Path:
    img = tmp_path / "mini.raw"
    img.write_bytes(build_fat16(_FILES))
    return img


# -- unit: FAT reader --------------------------------------------------------------------


def test_fat_image_is_recognized(disk_image: Path) -> None:
    data = disk_image.read_bytes()
    assert looks_like_fat(data)
    assert parse_partitions(data) == []  # bare FS, no partition table


def test_fat_reader_lists_files_with_long_names(disk_image: Path) -> None:
    fs = FatFs(disk_image.read_bytes())
    files = {f.path: f for f in fs.iter_files()}
    assert "requirements.txt" in files  # LFN long name decoded
    assert "app/go.mod" in files  # subdirectory walked
    assert fs.read(files["requirements.txt"].first_cluster,
                   files["requirements.txt"].size) == _FILES["requirements.txt"]


# -- DiskImageSource + full scan ---------------------------------------------------------


def test_disk_source_walk(disk_image: Path) -> None:
    src = DiskImageSource(disk_image)
    assert src.root().kind == "disk"
    paths = {e.path for e in src.walk()}
    assert "requirements.txt" in paths and "app/go.mod" in paths
    assert src.open("requirements.txt") == _FILES["requirements.txt"]


def test_disk_scan_finds_components(tmp_path: Path, disk_image: Path) -> None:
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(f"disk://{disk_image}", cfg, store_path=tmp_path / "disk.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        names = {c.name for c in store.components()}
        assert "flask" in names and "requests" in names  # requirements.txt
        assert any("errors" in n for n in names)  # go.mod require
    finally:
        store.close()


def test_disk_scan_is_byte_identical(tmp_path: Path, disk_image: Path) -> None:
    """Deterministic image → byte-identical SBOM across runs."""
    def scan_once(tag: str) -> bytes:
        cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
        result = run_scan(f"disk://{disk_image}", cfg, store_path=tmp_path / f"{tag}.sorb.db")
        store = GraphStore.open_readonly(result.store_path)
        try:
            return emit_cyclonedx(store, reproducible=True)
        finally:
            store.close()

    assert scan_once("a") == scan_once("b")


def test_mbr_partition_table_parsing() -> None:
    # a 2-partition MBR pointing at LBA 2048 (a common alignment)
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"
    struct.pack_into("<B", mbr, 0x1BE + 4, 0x0C)  # FAT32 LBA type
    struct.pack_into("<I", mbr, 0x1BE + 8, 2048)  # LBA start
    struct.pack_into("<I", mbr, 0x1BE + 12, 4096)  # sectors
    struct.pack_into("<B", mbr, 0x1BE + 16 + 4, 0x83)  # Linux
    struct.pack_into("<I", mbr, 0x1BE + 16 + 8, 6144)
    struct.pack_into("<I", mbr, 0x1BE + 16 + 12, 4096)
    parts = parse_partitions(bytes(mbr) + b"\x00" * 4096)
    assert len(parts) == 2
    assert parts[0].type_hint == "fat" and parts[0].offset == 2048 * 512
    assert parts[1].type_hint == "linux"
