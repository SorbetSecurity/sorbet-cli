"""Signature database — pack format + reader.

The signatures pack is a SQLite database (mmap-friendly, hash-prefix indexed)
distributed as a signed OCI artifact and pulled by ``sorb db update``. Four
signature classes share it:

- ``symbols``     — exported/mangled symbol sets per (library, version range)
- ``constants``   — high-signal immovable constants (zlib CRC tables, OpenSSL
                    version strings…), each with a learned precision score
- ``functions``   — position-independent function-shape hashes
- ``sourcefiles`` — per-file content hashes for vendored-tree identification

The reader is offline and read-only; the pack loader enforces
``schema``/``min_sorb_version`` (reusing the base-images loader contract) and
refuses unsigned or identity-mismatched packs.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from sorb import __version__
from sorb.errors import SubsystemDegraded

PACK_NAME = "signatures"
PACK_SCHEMA = 1

SIGDB_DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS libraries (
    id INTEGER PRIMARY KEY, name TEXT, version TEXT, purl TEXT, ecosystem TEXT
);
CREATE TABLE IF NOT EXISTS symbols (
    library_id INT, symbol TEXT
);
CREATE TABLE IF NOT EXISTS constants (
    library_id INT, value BLOB, precision REAL
);
CREATE TABLE IF NOT EXISTS functions (
    library_id INT, fn_hash TEXT
);
CREATE TABLE IF NOT EXISTS sourcefiles (
    library_id INT, path TEXT, content_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS ix_symbols ON symbols(symbol);
CREATE INDEX IF NOT EXISTS ix_constants ON constants(value);
CREATE INDEX IF NOT EXISTS ix_functions ON functions(fn_hash);
CREATE INDEX IF NOT EXISTS ix_sourcefiles ON sourcefiles(content_sha256);
"""


@dataclass(frozen=True, slots=True)
class LibraryRef:
    id: int
    name: str
    version: str
    purl: str | None
    ecosystem: str


class SignatureDB:
    """Read/write access to a signatures pack."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        conn.row_factory = sqlite3.Row

    @classmethod
    def create(cls, path: str | Path) -> SignatureDB:
        conn = sqlite3.connect(path)
        conn.executescript(SIGDB_DDL)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema',?)", (str(PACK_SCHEMA),))
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('min_sorb_version',?)", ("0.1.0",)
        )
        conn.commit()
        return cls(conn)

    @classmethod
    def open(cls, path: str | Path) -> SignatureDB:
        p = Path(path)
        if not p.is_file():
            raise SubsystemDegraded(f"signatures pack not found at {p}")
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        db = cls(conn)
        db._validate(str(p))
        return db

    def _validate(self, origin: str) -> None:
        from packaging.version import InvalidVersion, Version

        schema = self.get_meta("schema")
        if schema is None or int(schema) != PACK_SCHEMA:
            raise SubsystemDegraded(
                f"signatures pack {origin} has schema {schema!r}; this sorb needs {PACK_SCHEMA}"
            )
        min_v = self.get_meta("min_sorb_version") or "0"
        try:
            if Version(__version__) < Version(min_v):
                raise SubsystemDegraded(
                    f"signatures pack {origin} requires sorb ≥ {min_v} (this is {__version__})"
                )
        except InvalidVersion as e:
            raise SubsystemDegraded(f"signatures pack {origin}: bad min_sorb_version: {e}") from e

    # -- meta ---------------------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))

    @property
    def version(self) -> str:
        return self.get_meta("pack_version") or "0"

    # -- write path (used by the build pipeline) ----------------------------------------

    def add_library(
        self, name: str, version: str, purl: str | None, ecosystem: str
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO libraries(name, version, purl, ecosystem) VALUES(?,?,?,?)",
            (name, version, purl, ecosystem),
        )
        return int(cur.lastrowid or 0)

    def add_symbols(self, lib_id: int, symbols: list[str]) -> None:
        self._conn.executemany(
            "INSERT INTO symbols(library_id, symbol) VALUES(?,?)",
            [(lib_id, s) for s in symbols],
        )

    def add_constants(self, lib_id: int, constants: list[tuple[bytes, float]]) -> None:
        self._conn.executemany(
            "INSERT INTO constants(library_id, value, precision) VALUES(?,?,?)",
            [(lib_id, v, p) for v, p in constants],
        )

    def add_functions(self, lib_id: int, fn_hashes: list[str]) -> None:
        self._conn.executemany(
            "INSERT INTO functions(library_id, fn_hash) VALUES(?,?)",
            [(lib_id, h) for h in fn_hashes],
        )

    def add_sourcefiles(self, lib_id: int, files: list[tuple[str, str]]) -> None:
        self._conn.executemany(
            "INSERT INTO sourcefiles(library_id, path, content_sha256) VALUES(?,?,?)",
            [(lib_id, path, sha) for path, sha in files],
        )

    def commit(self) -> None:
        self._conn.commit()

    # -- read path (fingerprint engines) ------------------------------------------------

    def library(self, lib_id: int) -> LibraryRef | None:
        row = self._conn.execute("SELECT * FROM libraries WHERE id=?", (lib_id,)).fetchone()
        if row is None:
            return None
        return LibraryRef(
            id=int(row["id"]), name=row["name"], version=row["version"],
            purl=row["purl"], ecosystem=row["ecosystem"] or "generic",
        )

    def symbols_for_library(self, lib_id: int) -> set[str]:
        return {
            r["symbol"] for r in self._conn.execute(
                "SELECT symbol FROM symbols WHERE library_id=?", (lib_id,)
            )
        }

    def library_ids_for_symbols(self, symbols: set[str]) -> dict[int, int]:
        """lib_id → count of matched symbols (for symbol-set voting)."""
        if not symbols:
            return {}
        counts: dict[int, int] = {}
        placeholders = ",".join("?" for _ in symbols)
        for row in self._conn.execute(
            f"SELECT library_id, COUNT(*) AS n FROM symbols "  # noqa: S608
            f"WHERE symbol IN ({placeholders}) GROUP BY library_id",
            tuple(symbols),
        ):
            counts[int(row["library_id"])] = int(row["n"])
        return counts

    def constants_hits(self, blob: bytes) -> dict[int, list[tuple[bytes, float]]]:
        """lib_id → [(constant, precision)] found in `blob`."""
        hits: dict[int, list[tuple[bytes, float]]] = {}
        for row in self._conn.execute("SELECT library_id, value, precision FROM constants"):
            value = row["value"]
            if value and value in blob:
                hits.setdefault(int(row["library_id"]), []).append(
                    (bytes(value), float(row["precision"]))
                )
        return hits

    def function_matches(self, fn_hashes: set[str]) -> dict[int, int]:
        """lib_id → count of matched function-shape hashes."""
        if not fn_hashes:
            return {}
        counts: dict[int, int] = {}
        placeholders = ",".join("?" for _ in fn_hashes)
        for row in self._conn.execute(
            f"SELECT library_id, COUNT(*) AS n FROM functions "  # noqa: S608
            f"WHERE fn_hash IN ({placeholders}) GROUP BY library_id",
            tuple(fn_hashes),
        ):
            counts[int(row["library_id"])] = int(row["n"])
        return counts

    def library_function_count(self, lib_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM functions WHERE library_id=?", (lib_id,)
        ).fetchone()
        return int(row["n"]) if row else 0

    def sourcefiles_for_library(self, lib_id: int) -> dict[str, str]:
        return {
            r["path"]: r["content_sha256"]
            for r in self._conn.execute(
                "SELECT path, content_sha256 FROM sourcefiles WHERE library_id=?", (lib_id,)
            )
        }

    def libraries_by_source_hash(self, hashes: set[str]) -> dict[int, int]:
        """lib_id → count of matching source-file content hashes."""
        if not hashes:
            return {}
        counts: dict[int, int] = {}
        placeholders = ",".join("?" for _ in hashes)
        for row in self._conn.execute(
            f"SELECT library_id, COUNT(*) AS n FROM sourcefiles "  # noqa: S608
            f"WHERE content_sha256 IN ({placeholders}) GROUP BY library_id",
            tuple(hashes),
        ):
            counts[int(row["library_id"])] = int(row["n"])
        return counts

    def close(self) -> None:
        self._conn.close()


def default_sigdb_path(packs_dir: Path) -> Path | None:
    """Locate the newest unpacked signatures pack under the cache."""
    root = packs_dir / PACK_NAME
    if not root.is_dir():
        return None
    for version_dir in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True):
        db = version_dir / "signatures.db"
        if db.is_file():
            return db
    return None
