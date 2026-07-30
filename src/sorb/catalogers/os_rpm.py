"""rpm database catalogers: sqlite, ndb, Berkeley DB.

All three rpmdb storage backends are read **natively, in-process — no
librpm**: the stored value in every backend is the same rpm
*header blob* (network-byte-order tag table + data store), decoded here for
NEVRA, vendor, license, SOURCERPM and the sigmd5 package id.

Honesty note: these readers are validated against format-exact synthesized
fixtures; real-rootfs golden corpus coverage is planned. Malformed or
unsupported databases degrade to `DetectorFailure` (→ analysis-gap), never a
guess or a crash.
"""

from __future__ import annotations

import sqlite3
import struct
from collections.abc import Iterable, Iterator

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_family, ref_purl
from sorb.catalogers.os_pkgs import _os_release_id
from sorb.errors import DetectorFailure
from sorb.ident import make_purl
from sorb.model import ComponentClaim, EdgeClaim, EdgeType, Finding, Scope, Tier
from sorb.source.base import Entry

# -- rpm header blob decoding (shared by all backends) -----------------------------

_HEADER_MAGIC = b"\x8e\xad\xe8"

# tag ids we extract (rpmtag.h)
_TAG_NAME = 1000
_TAG_VERSION = 1001
_TAG_RELEASE = 1002
_TAG_EPOCH = 1003
_TAG_VENDOR = 1011
_TAG_LICENSE = 1014
_TAG_ARCH = 1022
_TAG_SOURCERPM = 1044
_TAG_REQUIRENAME = 1049
_TAG_SIGMD5 = 261

# type ids (rpmtd)
_T_CHAR, _T_INT8, _T_INT16, _T_INT32, _T_INT64 = 1, 2, 3, 4, 5
_T_STRING, _T_BIN, _T_STRING_ARRAY, _T_I18NSTRING = 6, 7, 8, 9

_WANTED = {
    _TAG_NAME,
    _TAG_VERSION,
    _TAG_RELEASE,
    _TAG_EPOCH,
    _TAG_VENDOR,
    _TAG_LICENSE,
    _TAG_ARCH,
    _TAG_SOURCERPM,
    _TAG_REQUIRENAME,
    _TAG_SIGMD5,
}


def parse_header_blob(blob: bytes) -> dict[int, object]:
    """Decode one rpm header blob into {tag: value} for the tags we need."""
    if blob[:3] == _HEADER_MAGIC:
        blob = blob[8:]
    if len(blob) < 8:
        raise DetectorFailure("rpm header blob too short")
    il, dl = struct.unpack(">II", blob[:8])
    if il > 65536 or dl > 256 << 20:
        raise DetectorFailure(f"rpm header blob implausible (il={il}, dl={dl})")
    entries_end = 8 + il * 16
    store = blob[entries_end : entries_end + dl]
    if len(blob) < entries_end:
        raise DetectorFailure("rpm header blob truncated (index)")
    out: dict[int, object] = {}
    for i in range(il):
        tag, typ, offset, count = struct.unpack_from(">iiii", blob, 8 + i * 16)
        if tag not in _WANTED or offset < 0 or offset > len(store):
            continue
        out[tag] = _read_value(store, typ, offset, count)
    return out


def _read_value(store: bytes, typ: int, offset: int, count: int) -> object:
    if typ in (_T_STRING, _T_I18NSTRING):
        end = store.find(b"\x00", offset)
        return store[offset : end if end >= 0 else len(store)].decode("utf-8", "replace")
    if typ == _T_STRING_ARRAY:
        values: list[str] = []
        pos = offset
        for _ in range(count):
            end = store.find(b"\x00", pos)
            if end < 0:
                break
            values.append(store[pos:end].decode("utf-8", "replace"))
            pos = end + 1
        return values
    if typ == _T_INT32:
        return list(struct.unpack_from(f">{count}i", store, offset))
    if typ == _T_INT16:
        return list(struct.unpack_from(f">{count}h", store, offset))
    if typ in (_T_INT8, _T_CHAR):
        return list(store[offset : offset + count])
    if typ == _T_INT64:
        return list(struct.unpack_from(f">{count}q", store, offset))
    if typ == _T_BIN:
        return store[offset : offset + count]
    return None


# -- storage backends ------------------------------------------------------------------


def read_sqlite_rpmdb(blob: bytes) -> Iterator[bytes]:
    """`rpmdb.sqlite`: table Packages(hnum, blob) holds header blobs."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(blob)
        rows = conn.execute("SELECT blob FROM Packages ORDER BY hnum").fetchall()
    except sqlite3.Error as e:
        raise DetectorFailure(f"cannot read rpmdb.sqlite: {e}") from e
    finally:
        conn.close()
    for (header,) in rows:
        if isinstance(header, bytes):
            yield header


_NDB_HEADER_MAGIC = int.from_bytes(b"RpmP", "little")
_NDB_SLOT_MAGIC = int.from_bytes(b"Slot", "little")
_NDB_BLOB_MAGIC = int.from_bytes(b"BlbS", "little")
_NDB_PAGE = 4096
_NDB_SLOT_SIZE = 16
_NDB_BLOB_HEADER = 16


def read_ndb_rpmdb(blob: bytes) -> Iterator[bytes]:
    """`Packages.db` (ndb backend): slot pages → blob areas."""
    if len(blob) < 32:
        raise DetectorFailure("ndb rpmdb too short")
    magic, _version, _generation, slot_npages = struct.unpack_from("<IIII", blob, 0)
    if magic != _NDB_HEADER_MAGIC:
        raise DetectorFailure("not an ndb rpm Packages.db (bad magic)")
    if not 0 < slot_npages <= 2048:
        raise DetectorFailure(f"ndb rpmdb implausible slot page count {slot_npages}")
    slots_end = min(slot_npages * _NDB_PAGE, len(blob))
    pos = 2 * _NDB_SLOT_SIZE  # the header occupies the first two slot entries
    while pos + _NDB_SLOT_SIZE <= slots_end:
        slot_magic, pkg_index, blk_offset, blk_count = struct.unpack_from("<IIII", blob, pos)
        pos += _NDB_SLOT_SIZE
        if slot_magic != _NDB_SLOT_MAGIC or pkg_index == 0 or blk_offset == 0:
            continue
        blob_pos = blk_offset * _NDB_BLOB_HEADER
        if blob_pos + _NDB_BLOB_HEADER > len(blob):
            continue
        bmagic, bindex, _cksum, blen = struct.unpack_from("<IIII", blob, blob_pos)
        if bmagic != _NDB_BLOB_MAGIC or bindex != pkg_index:
            continue
        start = blob_pos + _NDB_BLOB_HEADER
        if start + blen <= len(blob) and blk_count * _NDB_BLOB_HEADER >= blen:
            yield blob[start : start + blen]


_BDB_HASH_MAGIC = 0x00061561
_BDB_P_OVERFLOW = 7
_BDB_HASH_PAGE_TYPES = (2, 13)  # P_HASH_UNSORTED, P_HASH
_BDB_H_KEYDATA = 1
_BDB_H_OFFPAGE = 3


def read_bdb_rpmdb(blob: bytes) -> Iterator[bytes]:
    """`Packages` (Berkeley DB hash): hash pages hold key/value item pairs;
    large values live on overflow-page chains (H_OFFPAGE)."""
    if len(blob) < 512:
        raise DetectorFailure("BDB rpmdb too short")
    for order in ("<", ">"):
        (magic,) = struct.unpack_from(f"{order}I", blob, 12)
        if magic == _BDB_HASH_MAGIC:
            byte_order = order
            break
    else:
        raise DetectorFailure("not a Berkeley DB hash database (bad magic)")
    (page_size,) = struct.unpack_from(f"{byte_order}I", blob, 20)
    if page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        raise DetectorFailure(f"BDB: implausible page size {page_size}")
    n_pages = len(blob) // page_size

    def page_header(pgno: int) -> tuple[int, int, int, int]:
        """(type, entries, hf_offset, next_pgno) of a page."""
        base = pgno * page_size
        (next_pgno,) = struct.unpack_from(f"{byte_order}I", blob, base + 16)
        entries, hf_offset = struct.unpack_from(f"{byte_order}HH", blob, base + 20)
        ptype = blob[base + 25]
        return ptype, entries, hf_offset, next_pgno

    def read_overflow_chain(pgno: int, total: int) -> bytes:
        out = bytearray()
        seen: set[int] = set()
        while pgno and pgno not in seen and pgno < n_pages:
            seen.add(pgno)
            ptype, _entries, hf_offset, next_pgno = page_header(pgno)
            if ptype != _BDB_P_OVERFLOW:
                break
            base = pgno * page_size
            out.extend(blob[base + 26 : base + 26 + hf_offset])
            pgno = next_pgno
        return bytes(out[:total]) if total else bytes(out)

    for pgno in range(1, n_pages):
        ptype, entries, _hf, _next = page_header(pgno)
        if ptype not in _BDB_HASH_PAGE_TYPES or entries == 0:
            continue
        base = pgno * page_size
        offsets = struct.unpack_from(f"{byte_order}{entries}H", blob, base + 26)
        # entries alternate key, value — values are the header blobs
        for i in range(1, entries, 2):
            item_off = base + offsets[i]
            if item_off >= base + page_size:
                continue
            item_type = blob[item_off]
            if item_type == _BDB_H_OFFPAGE:
                ov_pgno, tlen = struct.unpack_from(f"{byte_order}II", blob, item_off + 4)
                data = read_overflow_chain(ov_pgno, tlen)
                if data:
                    yield data
            elif item_type == _BDB_H_KEYDATA:
                # items are packed from the page end downward: item i ends
                # where item i-1 starts (the first item ends at the page end)
                end = base + (offsets[i - 1] if i > 0 else page_size)
                yield blob[item_off + 1 : end]


# -- the cataloger ------------------------------------------------------------------------


class RpmCataloger(Cataloger):
    id = "os/rpm"
    version = 1
    matchers = [
        Matcher(glob="*var/lib/rpm/rpmdb.sqlite"),
        Matcher(glob="*usr/lib/sysimage/rpm/rpmdb.sqlite"),
        Matcher(glob="*var/lib/rpm/Packages.db"),
        Matcher(glob="*usr/lib/sysimage/rpm/Packages.db"),
        Matcher(glob="*var/lib/rpm/Packages"),
        Matcher(glob="*usr/lib/sysimage/rpm/Packages"),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        name = entry.path.rsplit("/", 1)[-1]
        if name == "rpmdb.sqlite":
            headers = read_sqlite_rpmdb(blob)
        elif name == "Packages.db":
            headers = read_ndb_rpmdb(blob)
        else:
            headers = read_bdb_rpmdb(blob)
        distro = _os_release_id(ctx, entry) or "rpm"
        for header in headers:
            try:
                tags = parse_header_blob(header)
            except DetectorFailure:
                continue  # one corrupt row never kills the DB read
            finding = self._finding(ctx, entry, tags, distro)
            if finding is not None:
                yield finding

    def _finding(
        self,
        ctx: CatalogerContext,
        entry: Entry,
        tags: dict[int, object],
        distro: str,
    ) -> Finding | None:
        name = tags.get(_TAG_NAME)
        version = tags.get(_TAG_VERSION)
        release = tags.get(_TAG_RELEASE)
        if not isinstance(name, str) or not isinstance(version, str):
            return None
        full_version = f"{version}-{release}" if isinstance(release, str) and release else version
        epoch_val = tags.get(_TAG_EPOCH)
        epoch = (
            int(epoch_val[0])
            if isinstance(epoch_val, list) and epoch_val and isinstance(epoch_val[0], int)
            else None
        )
        arch = tags.get(_TAG_ARCH) if isinstance(tags.get(_TAG_ARCH), str) else None
        qualifiers: dict[str, str] = {"distro": distro}
        if arch:
            qualifiers["arch"] = str(arch)
        if epoch is not None:
            qualifiers["epoch"] = str(epoch)
        purl = make_purl("rpm", name, full_version, namespace=distro, qualifiers=qualifiers)
        hashes: tuple[tuple[str, str], ...] = ()
        sigmd5 = tags.get(_TAG_SIGMD5)
        if isinstance(sigmd5, bytes) and sigmd5:
            hashes = (("md5", sigmd5.hex()),)
        edges: list[EdgeClaim] = []
        requires = tags.get(_TAG_REQUIRENAME)
        if isinstance(requires, list):
            for req in requires:
                if not isinstance(req, str):
                    continue
                # capability/file requires are not package names; keep plain names
                if req.startswith(("rpmlib(", "config(", "/")) or "(" in req:
                    continue
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=ref_purl(purl),
                        dst=ref_family("rpm", req),
                        scope=Scope.RUNTIME,
                        direct=False,
                    )
                )
        attrs: list[tuple[str, str]] = []
        sourcerpm = tags.get(_TAG_SOURCERPM)
        if isinstance(sourcerpm, str) and sourcerpm:
            attrs.append(("source-package", sourcerpm))
        vendor = tags.get(_TAG_VENDOR)
        if isinstance(vendor, str) and vendor:
            attrs.append(("vendor", vendor))
        license_ = tags.get(_TAG_LICENSE)
        return Finding(
            claim=ComponentClaim(
                ctype="os-package",
                name=name,
                version=full_version,
                purl=purl,
                ecosystem="rpm",
                namespace=distro,
                qualifiers=tuple(sorted(qualifiers.items())),
                hashes=hashes,
                licenses_declared=license_ if isinstance(license_, str) else None,
                attrs=tuple(attrs),
            ),
            evidence=(
                ctx.evidence(
                    "os-package-db",
                    Tier.INSTALLED,
                    entry,
                    captured=f"{name}-{full_version}" + (f".{arch}" if arch else ""),
                ),
            ),
            edges=tuple(edges),
        )


register(RpmCataloger())
