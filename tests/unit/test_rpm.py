"""rpm database readers — sqlite, ndb, BerkeleyDB (format-exact
synthesized fixtures)."""

from __future__ import annotations

import sqlite3
import struct

from sorb.catalogers.base import CatalogerContext
from sorb.catalogers.os_rpm import (
    RpmCataloger,
    parse_header_blob,
    read_bdb_rpmdb,
    read_ndb_rpmdb,
    read_sqlite_rpmdb,
)
from sorb.source.base import Entry

# -- header blob encoder (format-exact per rpm's header layout) ----------------------

_T_INT32, _T_STRING, _T_BIN, _T_STRING_ARRAY, _T_I18NSTRING = 4, 6, 7, 8, 9


def encode_header(tags: list[tuple[int, int, object]]) -> bytes:
    """Encode (tag, type, value) triples into an rpm header blob (BE index +
    store), matching rpm's alignment rules for the types we use."""
    index = b""
    store = bytearray()
    for tag, typ, value in tags:
        if typ in (_T_STRING, _T_I18NSTRING):
            offset = len(store)
            count = 1
            store += str(value).encode() + b"\x00"
        elif typ == _T_STRING_ARRAY:
            assert isinstance(value, list)
            offset = len(store)
            count = len(value)
            for s in value:
                store += str(s).encode() + b"\x00"
        elif typ == _T_INT32:
            while len(store) % 4:
                store += b"\x00"
            offset = len(store)
            vals = value if isinstance(value, list) else [value]
            count = len(vals)
            for v in vals:
                store += struct.pack(">i", int(v))
        elif typ == _T_BIN:
            assert isinstance(value, bytes)
            offset = len(store)
            count = len(value)
            store += value
        else:
            raise AssertionError(f"unsupported type {typ}")
        index += struct.pack(">iiii", tag, typ, offset, count)
    return struct.pack(">II", len(tags), len(store)) + index + bytes(store)


CURL_HEADER = encode_header(
    [
        (1000, _T_STRING, "curl"),
        (1001, _T_STRING, "8.6.0"),
        (1002, _T_STRING, "1.fc40"),
        (1003, _T_INT32, [1]),
        (1011, _T_STRING, "Fedora Project"),
        (1014, _T_I18NSTRING, "MIT"),
        (1022, _T_STRING, "x86_64"),
        (1044, _T_STRING, "curl-8.6.0-1.fc40.src.rpm"),
        (1049, _T_STRING_ARRAY, ["openssl-libs", "rpmlib(CompressedFileNames)", "/bin/sh"]),
        (261, _T_BIN, bytes(range(16))),
    ]
)

BASH_HEADER = encode_header(
    [
        (1000, _T_STRING, "bash"),
        (1001, _T_STRING, "5.2.26"),
        (1002, _T_STRING, "3.fc40"),
        (1014, _T_I18NSTRING, "GPL-3.0-or-later"),
        (1022, _T_STRING, "x86_64"),
        (1044, _T_STRING, "bash-5.2.26-3.fc40.src.rpm"),
    ]
)


def test_parse_header_blob() -> None:
    tags = parse_header_blob(CURL_HEADER)
    assert tags[1000] == "curl" and tags[1001] == "8.6.0" and tags[1002] == "1.fc40"
    assert tags[1003] == [1]
    assert tags[1044] == "curl-8.6.0-1.fc40.src.rpm"
    assert tags[261] == bytes(range(16))
    # magic-prefixed form is accepted too
    assert parse_header_blob(b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + CURL_HEADER)[1000] == "curl"


# -- storage-format fixtures ------------------------------------------------------------


def make_sqlite_rpmdb(headers: list[bytes]) -> bytes:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)")
    for i, h in enumerate(headers, start=1):
        conn.execute("INSERT INTO Packages(hnum, blob) VALUES(?, ?)", (i, h))
    conn.commit()
    data = conn.serialize()
    conn.close()
    return bytes(data)


def make_ndb_rpmdb(headers: list[bytes]) -> bytes:
    """ndb layout: 32-byte header, 16-byte slots, blob areas of 16-byte blocks."""
    slot_npages = 1
    out = bytearray(slot_npages * 4096)
    struct.pack_into(
        "<IIII", out, 0, int.from_bytes(b"RpmP", "little"), 0, 1, slot_npages
    )
    blob_areas = bytearray()
    slot_pos = 32
    next_blk = (slot_npages * 4096) // 16
    for i, h in enumerate(headers, start=1):
        blk_offset = next_blk
        blob = struct.pack("<IIII", int.from_bytes(b"BlbS", "little"), i, 0, len(h)) + h
        pad = (-len(blob)) % 16
        blob += b"\x00" * pad
        blob_areas += blob
        blk_count = len(blob) // 16
        struct.pack_into(
            "<IIII", out, slot_pos, int.from_bytes(b"Slot", "little"), i, blk_offset, blk_count
        )
        slot_pos += 16
        next_blk += blk_count
    return bytes(out) + bytes(blob_areas)


def make_bdb_rpmdb(headers: list[bytes]) -> bytes:
    """BDB hash db: meta page + one hash page whose values point at overflow chains."""
    page_size = 4096
    n_data_pages = sum((len(h) + (page_size - 26) - 1) // (page_size - 26) for h in headers)
    pages = bytearray(page_size * (2 + n_data_pages))
    # meta page 0: magic at 12, pagesize at 20
    struct.pack_into("<I", pages, 12, 0x00061561)
    struct.pack_into("<I", pages, 20, page_size)

    # hash page 1
    hbase = page_size
    entries = len(headers) * 2
    struct.pack_into("<HH", pages, hbase + 20, entries, 0)
    pages[hbase + 25] = 2  # P_HASH_UNSORTED

    item_end = page_size  # items packed from the page end downward
    offsets: list[int] = []
    next_free_page = 2
    for i, h in enumerate(headers, start=1):
        # key item: H_KEYDATA record-number key
        key_item = b"\x01" + struct.pack("<I", i)
        item_end -= len(key_item)
        pages[hbase + item_end : hbase + item_end + len(key_item)] = key_item
        offsets.append(item_end)
        # value item: H_OFFPAGE → overflow chain
        first_page = next_free_page
        value_item = b"\x03\x00\x00\x00" + struct.pack("<II", first_page, len(h))
        item_end -= len(value_item)
        pages[hbase + item_end : hbase + item_end + len(value_item)] = value_item
        offsets.append(item_end)
        # overflow pages
        pos = 0
        while pos < len(h):
            chunk = h[pos : pos + (page_size - 26)]
            pbase = next_free_page * page_size
            next_free_page += 1
            remaining = len(h) - pos - len(chunk)
            nxt = next_free_page if remaining > 0 else 0
            struct.pack_into("<I", pages, pbase + 16, nxt)
            struct.pack_into("<HH", pages, pbase + 20, 1, len(chunk))
            pages[pbase + 25] = 7  # P_OVERFLOW
            pages[pbase + 26 : pbase + 26 + len(chunk)] = chunk
            pos += len(chunk)
    for j, off in enumerate(offsets):
        struct.pack_into("<H", pages, hbase + 26 + j * 2, off)
    return bytes(pages)


def test_read_sqlite_rpmdb() -> None:
    blobs = list(read_sqlite_rpmdb(make_sqlite_rpmdb([CURL_HEADER, BASH_HEADER])))
    assert len(blobs) == 2
    assert parse_header_blob(blobs[0])[1000] == "curl"


def test_read_ndb_rpmdb() -> None:
    blobs = list(read_ndb_rpmdb(make_ndb_rpmdb([CURL_HEADER, BASH_HEADER])))
    assert len(blobs) == 2
    assert parse_header_blob(blobs[1])[1000] == "bash"


def test_read_bdb_rpmdb() -> None:
    blobs = list(read_bdb_rpmdb(make_bdb_rpmdb([CURL_HEADER, BASH_HEADER])))
    assert len(blobs) == 2
    assert {parse_header_blob(b)[1000] for b in blobs} == {"curl", "bash"}


class _MapSource:
    """Tiny in-memory Source for cataloger context in tests."""

    def __init__(self, files: dict[str, bytes]):
        self._files = files

    def exists(self, path: str) -> bool:
        return path in self._files

    def open(self, path: str) -> bytes:
        return self._files[path]

    def coords(self, path: str, span=None):  # noqa: ANN001
        from sorb.model import Coordinates

        return Coordinates(source_id="s1", path=path, span=span)


def _parse_with_cataloger(path: str, blob: bytes, extra: dict[str, bytes] | None = None):
    cataloger = RpmCataloger()
    files = {path: blob, **(extra or {})}
    ctx = CatalogerContext(source=_MapSource(files), detector=cataloger.detector)  # type: ignore[arg-type]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    return list(cataloger.parse(ctx, entry, blob))


def test_cataloger_all_three_formats() -> None:
    os_release = b'ID=fedora\nVERSION_ID="40"\n'
    for path, blob in (
        ("var/lib/rpm/rpmdb.sqlite", make_sqlite_rpmdb([CURL_HEADER, BASH_HEADER])),
        ("usr/lib/sysimage/rpm/Packages.db", make_ndb_rpmdb([CURL_HEADER, BASH_HEADER])),
        ("var/lib/rpm/Packages", make_bdb_rpmdb([CURL_HEADER, BASH_HEADER])),
    ):
        findings = _parse_with_cataloger(path, blob, {"etc/os-release": os_release})
        by_name = {f.claim.name: f for f in findings}
        assert set(by_name) == {"curl", "bash"}, path
        curl = by_name["curl"]
        assert curl.claim.version == "8.6.0-1.fc40"
        assert curl.claim.purl is not None and curl.claim.purl.startswith("pkg:rpm/fedora/curl@")
        assert "epoch=1" in curl.claim.purl
        assert dict(curl.claim.attrs)["source-package"] == "curl-8.6.0-1.fc40.src.rpm"
        assert dict(curl.claim.hashes).get("md5") == bytes(range(16)).hex()
        assert curl.evidence[0].tier.label == "installed"
        # capability/file requires are filtered; plain package names survive
        deps = {e.dst for e in curl.edges}
        assert deps == {"family:rpm/openssl-libs"}


def test_malformed_db_degrades() -> None:
    import pytest

    from sorb.errors import DetectorFailure

    with pytest.raises(DetectorFailure):
        list(read_ndb_rpmdb(b"garbage" * 100))
    with pytest.raises(DetectorFailure):
        list(read_bdb_rpmdb(b"\x00" * 4096))


# -- WAL-mode rpmdb (what every real rpm database actually is) -----------------------


def make_wal_sqlite_rpmdb(path, headers: list[bytes]) -> bytes:
    """A real on-disk WAL-mode rpmdb, checkpointed — byte-for-byte what an
    image ships. `conn.serialize()` produces a rollback-journal database, so it
    cannot reproduce this; only a real file can."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)")
    for i, h in enumerate(headers, start=1):
        conn.execute("INSERT INTO Packages(hnum, blob) VALUES(?, ?)", (i, h))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    return path.read_bytes()


def test_read_wal_mode_sqlite_rpmdb(tmp_path) -> None:
    """SQLite cannot use WAL journaling on a deserialized in-memory database, so
    a real rpmdb read naively fails with "unable to open database file" — which
    silently cost every rpm package on Fedora/Rocky images."""
    blob = make_wal_sqlite_rpmdb(tmp_path / "rpmdb.sqlite", [CURL_HEADER, BASH_HEADER])
    assert blob[18] == 2 and blob[19] == 2, "fixture must really be in WAL mode"
    assert len(list(read_sqlite_rpmdb(blob))) == 2

    findings = _parse_with_cataloger(
        "usr/lib/sysimage/rpm/rpmdb.sqlite", blob, {"etc/os-release": b"ID=fedora\n"}
    )
    assert {f.claim.name for f in findings} == {"curl", "bash"}


def test_uncheckpointed_wal_is_reported(tmp_path) -> None:
    """Pages committed to the -wal but not checkpointed are not in the main file.
    Reporting a short package list as complete would be a silent inaccuracy."""
    blob = make_wal_sqlite_rpmdb(tmp_path / "rpmdb.sqlite", [CURL_HEADER])
    cataloger = RpmCataloger()
    files = {
        "var/lib/rpm/rpmdb.sqlite": blob,
        "var/lib/rpm/rpmdb.sqlite-wal": b"\x37\x7f\x06\x82" + b"\x00" * 60,
    }
    ctx = CatalogerContext(source=_MapSource(files), detector=cataloger.detector)  # type: ignore[arg-type]
    entry = Entry(path="var/lib/rpm/rpmdb.sqlite", size=len(blob), sniff=blob[:64])
    list(cataloger.parse(ctx, entry, blob))
    assert any(code == "SORB-W016" for code, _ in ctx.warnings)
