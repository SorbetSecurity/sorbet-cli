"""ArchiveSource + nesting, with recursion budgets.

Presents a tar (plain/gz/bz2/xz/zst) or zip archive through the `Source`
protocol so every cataloger works unmodified against archive contents.
Coordinates chain mechanically through `parent`: evidence for a
file inside an archive inside a layer records the full physical path.

Budgets are owned by the caller (the orchestrator) and shared
across all archives of one scan: exceeding a budget degrades to an explicit
warning, never an OOM (zip-bomb guard).
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import tarfile
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sorb.errors import DetectorFailure, TargetError
from sorb.model import Coordinates
from sorb.source.base import Entry, Source, SourceProvenance, SourceRef
from sorb.source.roles import classify

_SNIFF_LEN = 64

#: magic prefixes for compressed/archive container formats
_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_BZ2_MAGIC = b"BZh"
_ZIP_MAGIC = b"PK\x03\x04"


@dataclass
class ArchiveBudget:
    """Per-scan archive-recursion budget. Mutable, shared."""

    max_depth: int = 4
    max_members: int = 200_000
    max_total_bytes: int = 4 << 30  # decompressed bytes across the scan
    max_member_bytes: int = 1 << 30
    used_bytes: int = 0
    used_members: int = 0
    exhausted_reasons: list[str] = field(default_factory=list)

    def charge_member(self, size: int, what: str) -> bool:
        """Charge one member of `size` bytes; False (+reason) when over budget."""
        if self.used_members >= self.max_members:
            self._exhaust(f"{what}: member-count budget ({self.max_members}) reached")
            return False
        if size > self.max_member_bytes:
            self._exhaust(f"{what}: member exceeds size budget ({size} > {self.max_member_bytes})")
            return False
        if self.used_bytes + size > self.max_total_bytes:
            self._exhaust(f"{what}: total decompressed-size budget reached")
            return False
        self.used_members += 1
        self.used_bytes += size
        return True

    def _exhaust(self, reason: str) -> None:
        if reason not in self.exhausted_reasons:
            self.exhausted_reasons.append(reason)


def sniff_archive_kind(head: bytes, name: str = "") -> str | None:
    """Classify bytes as an archive container we can open, or None."""
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith(_GZIP_MAGIC):
        return "tar+gzip"
    if head.startswith(_ZSTD_MAGIC):
        return "tar+zstd"
    if head.startswith(_XZ_MAGIC):
        return "tar+xz"
    if head.startswith(_BZ2_MAGIC):
        return "tar+bz2"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    # GNU tar with no ustar magic in the sniff window: extension fallback
    if name.endswith((".tar",)):
        return "tar"
    return None


def _normalize_member_path(raw: str) -> str | None:
    """Normalize an archive member path; None when it escapes the root."""
    p = posixpath.normpath(raw.lstrip("/")).lstrip("/")
    if not p or p == "." or p.startswith("../") or p == "..":
        return None
    return unicodedata.normalize("NFC", p)


def _decompress_zstd(data: bytes, budget: ArchiveBudget, what: str) -> bytes:
    import zstandard

    limit = min(budget.max_total_bytes - budget.used_bytes, budget.max_member_bytes)
    out = io.BytesIO()
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))
    while True:
        chunk = reader.read(1 << 20)
        if not chunk:
            break
        if out.tell() + len(chunk) > limit:
            raise DetectorFailure(f"{what}: zstd stream exceeds archive budget", path=what)
        out.write(chunk)
    return out.getvalue()


class ArchiveSource:
    """Tar/zip archive presented as a Source. Random access after one index pass."""

    def __init__(
        self,
        data: bytes | Path,
        *,
        name: str,
        source_id: str = "s1",
        parent_coords: Coordinates | None = None,
        layer_digest: str | None = None,
        budget: ArchiveBudget | None = None,
    ) -> None:
        self._name = name
        self._id = source_id
        self._parent = parent_coords
        self._layer_digest = layer_digest
        self._budget = budget if budget is not None else ArchiveBudget()
        self._digest_cache: dict[str, str] = {}
        raw = data.read_bytes() if isinstance(data, Path) else data
        self._raw_sha256 = hashlib.sha256(raw).hexdigest()
        kind = sniff_archive_kind(raw[:512], name)
        if kind is None:
            raise TargetError(f"not a recognized archive: {name}")
        if kind == "tar+zstd":
            raw = _decompress_zstd(raw, self._budget, name)
            kind = "tar"
        self._kind = "zip" if kind == "zip" else "tar"
        # Member index: path -> (size, is_symlink, link_target|None)
        self._members: dict[str, tuple[int, bool, str | None]] = {}
        self._order: list[str] = []
        self._tar: tarfile.TarFile | None = None
        self._zip: zipfile.ZipFile | None = None
        self._tar_members: dict[str, tarfile.TarInfo] = {}
        try:
            if self._kind == "zip":
                self._zip = zipfile.ZipFile(io.BytesIO(raw))
                self._index_zip()
            else:
                self._tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
                self._index_tar()
        except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
            raise TargetError(f"cannot open archive {name}: {e}") from e

    # -- indexing -------------------------------------------------------------

    def _index_tar(self) -> None:
        assert self._tar is not None
        for info in self._tar.getmembers():
            if not (info.isfile() or info.issym() or info.islnk()):
                continue
            path = _normalize_member_path(info.name)
            if path is None:
                continue
            is_symlink = info.issym()
            link_target = info.linkname if (info.issym() or info.islnk()) else None
            self._members[path] = (info.size, is_symlink, link_target)
            self._tar_members[path] = info
            self._order.append(path)

    def _index_zip(self) -> None:
        assert self._zip is not None
        for zi in self._zip.infolist():
            if zi.is_dir():
                continue
            path = _normalize_member_path(zi.filename)
            if path is None:
                continue
            self._members[path] = (zi.file_size, False, None)
            self._order.append(path)

    # -- Source protocol -------------------------------------------------------

    def root(self) -> SourceRef:
        return SourceRef(id=self._id, kind="archive", ref=self._name)

    def walk(self) -> Iterator[Entry]:
        for path in self._order:
            size, is_symlink, _target = self._members[path]
            if is_symlink:
                yield Entry(path=path, size=0, is_symlink=True)
                continue
            if not self._budget.charge_member(size, f"{self._name}!{path}"):
                return  # budget exhausted: stop walking, reasons recorded
            sniff = b""
            try:
                sniff = self._read_member(path, limit=_SNIFF_LEN)
            except (DetectorFailure, OSError, KeyError):
                continue
            yield Entry(
                path=path,
                size=size,
                role=classify(path),
                sniff=sniff,
                is_symlink=False,
            )

    def open(self, path: str) -> bytes:
        if path not in self._members:
            raise FileNotFoundError(path)
        size, is_symlink, _target = self._members[path]
        if is_symlink:
            return b""
        if size > self._budget.max_member_bytes:
            raise DetectorFailure(
                f"{self._name}!{path}: member exceeds size budget", path=path
            )
        return self._read_member(path)

    def exists(self, path: str) -> bool:
        return path in self._members

    def digest(self, path: str) -> str:
        if path not in self._digest_cache:
            self._digest_cache[path] = hashlib.sha256(self.open(path)).hexdigest()
        return self._digest_cache[path]

    def coords(self, path: str, span: tuple[int, int] | None = None) -> Coordinates:
        return Coordinates(
            source_id=self._id,
            path=path,
            layer_digest=self._layer_digest,
            span=span,
            parent=self._parent,
        )

    def provenance(self) -> SourceProvenance:
        return SourceProvenance(subject=f"archive:{self._name}:sha256:{self._raw_sha256}")

    # -- internals --------------------------------------------------------------

    def _read_member(self, path: str, limit: int | None = None) -> bytes:
        declared, _sym, _target = self._members[path]
        cap = declared if limit is None else min(limit, declared)
        if self._kind == "zip":
            assert self._zip is not None
            with self._zip.open(path if path in self._zip.namelist() else self._zip_name(path)) as f:
                data = f.read(cap + 1)
        else:
            assert self._tar is not None
            member = self._tar_members[path]
            fobj = self._tar.extractfile(member)
            if fobj is None:
                return b""
            with fobj:
                data = fobj.read(cap + 1)
        if limit is None and len(data) > declared:
            # a member lying about its size is a bomb signature
            raise DetectorFailure(
                f"{self._name}!{path}: member larger than declared size", path=path
            )
        return data[:cap] if limit is not None else data

    def _zip_name(self, path: str) -> str:
        assert self._zip is not None
        for cand in self._zip.namelist():
            if _normalize_member_path(cand) == path:
                return cand
        raise KeyError(path)

    @property
    def budget(self) -> ArchiveBudget:
        return self._budget

    def link_target(self, path: str) -> str | None:
        """Symlink/hardlink target of a member, when it is a link."""
        entry = self._members.get(path)
        return entry[2] if entry else None

    def member_paths(self) -> list[str]:
        """All member paths in archive order (files + links)."""
        return list(self._order)

    def entry_for(self, path: str) -> Entry | None:
        """Build an Entry for one member without a full walk (SquashView use)."""
        info = self._members.get(path)
        if info is None:
            return None
        size, is_symlink, _target = info
        if is_symlink:
            return Entry(path=path, size=0, is_symlink=True)
        try:
            sniff = self._read_member(path, limit=_SNIFF_LEN)
        except (DetectorFailure, OSError, KeyError):
            return None
        return Entry(path=path, size=size, role=classify(path), sniff=sniff, is_symlink=False)


def open_nested(
    blob: bytes,
    *,
    name: str,
    outer: Source,
    outer_path: str,
    budget: ArchiveBudget,
    depth: int,
) -> ArchiveSource | None:
    """Wrap a blob that is itself an archive (NestedSource).

    Coordinate chaining is mechanical: the nested source's coordinates carry
    `outer.coords(outer_path)` as parent. Returns None when the blob is not an
    archive or the depth budget is exhausted (reason recorded on the budget).
    """
    if sniff_archive_kind(blob[:512], name) is None:
        return None
    if depth >= budget.max_depth:
        budget._exhaust(f"{outer_path}: archive nesting depth {budget.max_depth} reached")
        return None
    parent = outer.coords(outer_path)
    return ArchiveSource(
        blob,
        name=name,
        source_id=parent.source_id,
        parent_coords=parent,
        layer_digest=parent.layer_digest,
        budget=budget,
    )
