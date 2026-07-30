"""Minimal read-only boltdb (bbolt) reader for containerd metadata.

Just enough of the bolt file format to walk buckets and read values —
in-process, no CGo, no shelling out. The format:

- fixed-size pages; pages 0 and 1 are meta pages (magic ``0xED0CDAED``);
  the live meta is the one with the higher txid.
- branch pages: 16-byte elements ``{pos u32, ksize u32, pgid u64}``.
- leaf pages: 16-byte elements ``{flags u32, pos u32, ksize u32, vsize u32}``;
  ``flags & 1`` marks a nested-bucket element whose value is a 16-byte bucket
  header ``{root u64, sequence u64}`` — root 0 means the bucket is *inline*
  and its page follows the header inside the value.

Anything unexpected raises `BoltReadError`; callers translate that into a
typed, honest degradation.
"""

from __future__ import annotations

import struct

_MAGIC = 0xED0CDAED
_PAGE_HEADER = 16  # id u64, flags u16, count u16, overflow u32
_FLAG_BRANCH = 0x01
_FLAG_LEAF = 0x02
_BUCKET_LEAF_FLAG = 0x01
_BUCKET_HEADER = 16  # root u64, sequence u64


class BoltReadError(RuntimeError):
    pass


class _Page:
    """A page view: either a real page (by pgid) or an inline bucket page."""

    __slots__ = ("data", "off")

    def __init__(self, data: bytes, off: int) -> None:
        self.data = data
        self.off = off

    def header(self) -> tuple[int, int]:
        if self.off + _PAGE_HEADER > len(self.data):
            raise BoltReadError("page header out of bounds")
        flags, count = struct.unpack_from("<HH", self.data, self.off + 8)
        return flags, count


class BoltFile:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 64:
            raise BoltReadError("file too small to be a bolt database")
        meta0 = self._read_meta(0, 4096)
        page_size = meta0[0]
        best = meta0
        try:
            meta1 = self._read_meta(1, page_size)
            if meta1[2] > meta0[2]:
                best = meta1
        except BoltReadError:
            pass
        self.page_size, self.root_pgid, self.txid = best

    def _read_meta(self, page_no: int, assumed_page_size: int) -> tuple[int, int, int]:
        off = page_no * assumed_page_size
        if off + _PAGE_HEADER + 40 > len(self.data):
            raise BoltReadError("meta page out of bounds")
        magic, _version, page_size, _flags = struct.unpack_from(
            "<IIII", self.data, off + _PAGE_HEADER
        )
        if magic != _MAGIC:
            raise BoltReadError("bad bolt magic")
        root_pgid, _seq = struct.unpack_from("<QQ", self.data, off + _PAGE_HEADER + 16)
        txid = struct.unpack_from("<Q", self.data, off + _PAGE_HEADER + 40)[0]
        return page_size, root_pgid, txid

    def _page(self, pgid: int) -> _Page:
        off = pgid * self.page_size
        if off >= len(self.data):
            raise BoltReadError(f"page {pgid} out of bounds")
        return _Page(self.data, off)

    # -- lookups -------------------------------------------------------------

    def _leaf_elements(self, page: _Page) -> list[tuple[int, bytes, bytes]]:
        """(flags, key, value) triples of a leaf page."""
        flags, count = page.header()
        if not flags & _FLAG_LEAF:
            raise BoltReadError("expected a leaf page")
        out: list[tuple[int, bytes, bytes]] = []
        base = page.off + _PAGE_HEADER
        for i in range(count):
            eoff = base + i * 16
            eflags, pos, ksize, vsize = struct.unpack_from("<IIII", page.data, eoff)
            kstart = eoff + pos
            key = page.data[kstart : kstart + ksize]
            value = page.data[kstart + ksize : kstart + ksize + vsize]
            out.append((eflags, key, value))
        return out

    def _lookup_in(self, page: _Page, key: bytes) -> tuple[int, bytes] | None:
        """Find `key` under a (possibly branch) page. Returns (flags, value)."""
        flags, count = page.header()
        if flags & _FLAG_LEAF:
            for eflags, k, v in self._leaf_elements(page):
                if k == key:
                    return eflags, v
            return None
        if flags & _FLAG_BRANCH:
            base = page.off + _PAGE_HEADER
            chosen_pgid: int | None = None
            for i in range(count):
                eoff = base + i * 16
                pos, ksize, pgid = struct.unpack_from("<IIQ", page.data, eoff)
                k = page.data[eoff + pos : eoff + pos + ksize]
                if k <= key or i == 0:
                    chosen_pgid = pgid
                else:
                    break
            if chosen_pgid is None:
                return None
            return self._lookup_in(self._page(chosen_pgid), key)
        raise BoltReadError("page is neither branch nor leaf")

    def get(self, path: list[bytes]) -> bytes | None:
        """Walk nested buckets along `path[:-1]` and read the value at `path[-1]`."""
        if not path:
            return None
        page = self._page(self.root_pgid)
        for i, key in enumerate(path):
            found = self._lookup_in(page, key)
            if found is None:
                return None
            eflags, value = found
            last = i == len(path) - 1
            if last:
                return None if eflags & _BUCKET_LEAF_FLAG else value
            if not eflags & _BUCKET_LEAF_FLAG:
                return None  # a plain value where a bucket was expected
            if len(value) < _BUCKET_HEADER:
                raise BoltReadError("truncated bucket header")
            root = struct.unpack_from("<Q", value, 0)[0]
            if root == 0:
                # Inline bucket: a self-contained leaf page follows the
                # 16-byte bucket header inside the value bytes.
                page = _Page(value, _BUCKET_HEADER)
            else:
                page = self._page(root)
        return None


def bolt_get(data: bytes, path: list[bytes]) -> bytes | None:
    """Convenience: one-shot value lookup, raising BoltReadError on format problems."""
    return BoltFile(data).get(path)
