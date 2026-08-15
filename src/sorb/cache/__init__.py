"""Content-addressed local cache.

Layout under ``$SORB_CACHE_DIR`` (default ``~/.cache/sorb``)::

    cas/sha256/ab/cd/<hex>   value blobs (layer tars, finding batches, metadata)
    cas.db                   SQLite index: key → (blob digest, created, last_used, size)
    packs/<name>/<version>/  verified data packs

Key discipline: callers embed everything that changes the value in
the key — e.g. ``layer-findings:<layer digest>:<detector fp>:<config fp>`` —
so shipping a parser fix invalidates exactly that parser's entries.

The cache is **fail-open**: any IO/DB error degrades to a miss (a scan must
never fail because the cache is down).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path

__all__ = ["Cas", "default_cache_dir"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    key        TEXT PRIMARY KEY,
    digest     TEXT NOT NULL,
    size       INT  NOT NULL,
    created    REAL NOT NULL,
    last_used  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_entries_lru ON entries(last_used);
"""


def default_cache_dir() -> Path:
    env = os.environ.get("SORB_CACHE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "sorb"


class Cas:
    """Content-addressed store with a keyed index. Single-process use."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = root or default_cache_dir()
        self._conn: sqlite3.Connection | None = None
        self.hits = 0
        self.misses = 0
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._root / "cas.db")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except (OSError, sqlite3.Error):
            self._conn = None  # fail-open: everything becomes a miss

    @property
    def available(self) -> bool:
        return self._conn is not None

    @property
    def packs_dir(self) -> Path:
        return self._root / "packs"

    # -- blob store -------------------------------------------------------------

    def _blob_path(self, digest: str) -> Path:
        return self._root / "cas" / "sha256" / digest[:2] / digest[2:4] / digest

    def put_blob(self, data: bytes) -> str:
        """Store bytes; returns the sha256 hex digest (idempotent)."""
        digest = hashlib.sha256(data).hexdigest()
        try:
            p = self._blob_path(digest)
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                tmp = p.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(p)
        except OSError:
            pass
        return digest

    def get_blob(self, digest: str) -> bytes | None:
        try:
            p = self._blob_path(digest)
            if p.is_file():
                return p.read_bytes()
        except OSError:
            pass
        return None

    def has_blob(self, digest: str) -> bool:
        try:
            return self._blob_path(digest).is_file()
        except OSError:
            return False

    # -- keyed values -----------------------------------------------------------

    def put(self, key: str, data: bytes) -> None:
        if self._conn is None:
            return
        digest = self.put_blob(data)
        now = time.time()
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO entries(key, digest, size, created, last_used)"
                " VALUES(?,?,?,?,?)",
                (key, digest, len(data), now, now),
            )
            self._conn.commit()
        except sqlite3.Error:
            pass

    def get(self, key: str) -> bytes | None:
        if self._conn is None:
            self.misses += 1
            return None
        try:
            row = self._conn.execute(
                "SELECT digest FROM entries WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                self.misses += 1
                return None
            data = self.get_blob(str(row[0]))
            if data is None:
                self.misses += 1
                return None
            self._conn.execute(
                "UPDATE entries SET last_used=? WHERE key=?", (time.time(), key)
            )
            self._conn.commit()
            self.hits += 1
            return data
        except sqlite3.Error:
            self.misses += 1
            return None

    # -- maintenance --------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        total_entries = 0
        total_bytes = 0
        if self._conn is not None:
            try:
                row = self._conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM entries"
                ).fetchone()
                total_entries, total_bytes = int(row[0]), int(row[1])
            except sqlite3.Error:
                pass
        return {
            "entries": total_entries,
            "bytes": total_bytes,
            "hits": self.hits,
            "misses": self.misses,
        }

    def prune(self, max_bytes: int) -> int:
        """Evict LRU entries until the indexed size fits `max_bytes`. Returns evicted count."""
        if self._conn is None:
            return 0
        evicted = 0
        try:
            total = int(
                self._conn.execute("SELECT COALESCE(SUM(size),0) FROM entries").fetchone()[0]
            )
            for key, digest, size in self._conn.execute(
                "SELECT key, digest, size FROM entries ORDER BY last_used"
            ).fetchall():
                if total <= max_bytes:
                    break
                self._conn.execute("DELETE FROM entries WHERE key=?", (key,))
                remaining = self._conn.execute(
                    "SELECT COUNT(*) FROM entries WHERE digest=?", (digest,)
                ).fetchone()[0]
                if not remaining:
                    try:
                        self._blob_path(str(digest)).unlink(missing_ok=True)
                    except OSError:
                        pass
                total -= int(size)
                evicted += 1
            self._conn.commit()
        except sqlite3.Error:
            pass
        return evicted

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
