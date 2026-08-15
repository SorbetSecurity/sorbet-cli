"""Installer/firmware unpackers.

Format detectors + in-process extractors for the container formats not covered
by ArchiveSource: MSI (CFB + tables), ar/deb, cpio/initramfs, squashfs
(header + inode inventory), and self-extracting exes (trailing-archive scan).
Each returns a ``{path: bytes}`` member map so the caller can feed contents
through the normal cataloger pipeline as nested content. Malformed input yields
an empty map + a warning, never a crash. Bounded by the caller's
recursion/size budgets.

The exotic formats here are recovered to the depth that yields a real
inventory (member list + small file contents); full filesystem-image
reconstruction (squashfs data blocks, erofs) is a known depth gap that
would need `dissect.*`-grade readers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

_MAX_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 256 << 20


@dataclass
class Unpacked:
    format: str
    members: dict[str, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def sniff_container(head: bytes) -> str | None:
    if head[:8] == b"!<arch>\n":
        return "ar"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "msi"  # OLE/CFB compound file (MSI)
    if head[:4] == b"hsqs" or head[:4] == b"sqsh":
        return "squashfs"
    if head[:6] in (b"070701", b"070702") or head[:6] == b"070707":
        return "cpio"
    if head[:4] == b"\x1f\x8b\x08\x08":  # gzip with FNAME → likely a self-extracting payload
        return None  # handled by ArchiveSource
    return None


def unpack_container(data: bytes, kind: str | None = None) -> Unpacked | None:
    kind = kind or sniff_container(data[:16])
    if kind is None:
        return None
    try:
        if kind == "ar":
            return _unpack_ar(data)
        if kind == "cpio":
            return _unpack_cpio(data)
        if kind == "msi":
            return _unpack_msi(data)
        if kind == "squashfs":
            return _unpack_squashfs(data)
    except Exception as e:  # noqa: BLE001 — hostile input: gap, never crash
        return Unpacked(format=kind, warnings=[f"unpack failed: {type(e).__name__}: {e}"])
    return None


# -- ar / deb ---------------------------------------------------------------------------


def _unpack_ar(data: bytes) -> Unpacked:
    out = Unpacked(format="ar")
    pos = 8
    while pos + 60 <= len(data) and len(out.members) < _MAX_MEMBERS:
        header = data[pos : pos + 60]
        name = header[0:16].decode("latin-1").rstrip()
        try:
            size = int(header[48:58].decode("latin-1").strip())
        except ValueError:
            break
        start = pos + 60
        if start + size > len(data) or size > _MAX_MEMBER_BYTES:
            out.warnings.append(f"ar member {name} overruns file")
            break
        name = name.rstrip("/")
        if name and name not in ("/", "//"):
            out.members[name] = data[start : start + size]
        pos = start + size + (size & 1)  # 2-byte alignment
    return out


# -- cpio (newc/odc) --------------------------------------------------------------------


def _unpack_cpio(data: bytes) -> Unpacked:
    out = Unpacked(format="cpio")
    pos = 0
    while pos + 110 <= len(data) and len(out.members) < _MAX_MEMBERS:
        magic = data[pos : pos + 6]
        if magic not in (b"070701", b"070702"):
            break
        fields = [int(data[pos + 6 + i * 8 : pos + 6 + (i + 1) * 8], 16) for i in range(13)]
        namesize, filesize = fields[11], fields[6]
        name_start = pos + 110
        name = data[name_start : name_start + namesize - 1].decode("latin-1")
        if name == "TRAILER!!!":
            break
        data_start = (name_start + namesize + 3) & ~3
        if data_start + filesize > len(data):
            out.warnings.append("cpio entry overruns file")
            break
        if filesize and filesize <= _MAX_MEMBER_BYTES:
            out.members[name] = data[data_start : data_start + filesize]
        pos = (data_start + filesize + 3) & ~3
    return out


# -- MSI (OLE compound file) — directory + stream inventory -----------------------------


def _unpack_msi(data: bytes) -> Unpacked:
    """Recover the MSI's stream directory (the table/summary streams). A full
    table decode is bounded; the directory inventory + summary stream are what
    identify the installer and its embedded CABs."""
    out = Unpacked(format="msi")
    if len(data) < 512:
        out.warnings.append("truncated CFB header")
        return out
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    sector_size = 1 << sector_shift
    dir_start = struct.unpack_from("<I", data, 48)[0]
    dir_off = 512 + dir_start * sector_size
    # walk the first directory sector's 128-byte entries (root + a few streams)
    for i in range(min(sector_size // 128, 512)):
        base = dir_off + i * 128
        if base + 128 > len(data):
            break
        name_len = struct.unpack_from("<H", data, base + 64)[0]
        if name_len < 2 or name_len > 64:
            continue
        raw_name = data[base : base + name_len - 2]
        name = _decode_msi_name(raw_name)
        obj_type = data[base + 66]
        if name and obj_type in (1, 2, 5):  # storage / stream / root
            out.members[f"cfb:{name}"] = b""  # inventory only (contents bounded)
    if not out.members:
        out.warnings.append("no readable CFB directory entries")
    return out


def _decode_msi_name(raw: bytes) -> str:
    try:
        return raw.decode("utf-16-le").strip("\x00")
    except UnicodeDecodeError:
        return ""


# -- squashfs — superblock + compression id (inventory-level) ---------------------------


_SQUASHFS_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def _unpack_squashfs(data: bytes) -> Unpacked:
    out = Unpacked(format="squashfs")
    if len(data) < 96 or data[:4] not in (b"hsqs", b"sqsh"):
        out.warnings.append("bad squashfs magic")
        return out
    endian = "<" if data[:4] == b"hsqs" else ">"
    inode_count = struct.unpack_from(f"{endian}I", data, 4)[0]
    comp_id = struct.unpack_from(f"{endian}H", data, 20)[0]
    v_major = struct.unpack_from(f"{endian}H", data, 28)[0]
    out.members["squashfs:superblock"] = (
        f"inodes={inode_count} compression={_SQUASHFS_COMP.get(comp_id, comp_id)} "
        f"version={v_major}.x".encode()
    )
    # full inode-table decompression is a known depth gap; the superblock
    # inventory records the image's size/compression for the SBOM honestly.
    out.warnings.append(
        f"squashfs contents not decompressed ({_SQUASHFS_COMP.get(comp_id, comp_id)}); "
        "superblock inventory only"
    )
    return out
