"""Native interchange format `.sorb.json`.

Lossless export of a run store (graph + findings + evidence + annotations),
schema-version tagged; imports back into a fresh SQLite store. The SQLite file
is the working store; this is the interchange projection.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sorb.emit.canonical import canonical_json
from sorb.graph.store import SCHEMA_VERSION, GraphStore


def export_native(store: GraphStore) -> bytes:
    conn = store._conn
    doc: dict[str, Any] = {"format": "sorb", "schema_version": SCHEMA_VERSION}
    doc["meta"] = store.all_meta()

    def rows(table: str, order: str = "id") -> list[dict[str, Any]]:
        out = []
        for row in conn.execute(f"SELECT * FROM {table} ORDER BY {order}"):  # noqa: S608
            out.append({k: row[k] for k in row.keys()})
        return out

    doc["sources"] = rows("sources", "id")
    doc["files"] = rows("files")
    doc["findings"] = rows("findings")
    doc["evidence"] = rows("evidence")
    doc["components"] = rows("components")
    doc["edges"] = rows("edges")
    doc["annotations"] = rows("annotations")
    doc["projects"] = rows("projects")
    doc["layers"] = rows("layers", "ordinal, digest")
    doc["file_states"] = rows("file_states")
    doc["resources"] = rows("resources")
    return canonical_json(doc)


def import_native(data: bytes | dict[str, Any], db_path: str | Path) -> GraphStore:
    doc = json.loads(data) if isinstance(data, (bytes, str)) else data
    if doc.get("format") != "sorb":
        raise ValueError("not a sorb native document (missing format: sorb)")
    version = int(doc.get("schema_version", 0))
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"document schema_version {version} is newer than this sorb "
            f"(supports ≤ {SCHEMA_VERSION}); upgrade sorb"
        )
    store = GraphStore.create(db_path)
    conn = store._conn
    for key, value in (doc.get("meta") or {}).items():
        if key != "schema_version":
            store.set_meta(key, value)

    def insert_all(table: str, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            cols = list(row.keys())
            placeholders = ",".join("?" for _ in cols)
            conn.execute(
                f"INSERT OR REPLACE INTO {table}({','.join(cols)}) VALUES({placeholders})",  # noqa: S608
                [row[c] for c in cols],
            )

    for table in (
        "sources",
        "files",
        "findings",
        "evidence",
        "components",
        "edges",
        "annotations",
        "projects",
        "layers",
        "file_states",
        "resources",
    ):
        insert_all(table, doc.get(table) or [])
    store.commit()
    return store
