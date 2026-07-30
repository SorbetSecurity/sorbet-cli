"""Subgraph export for the UI (`/api/export`).

Reuses the SBOM emitters unchanged. A *selection* (a set of component ids, e.g.
from a query-console result) is exported by copying the run store to a temporary
database and marking the unselected components ``excluded`` — the emitters already
skip excluded components (`emitted_components`), so the selected subgraph emits
through the exact same code path as a full SBOM, and the result validates.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path

from sorb.graph.store import GraphStore

_MEDIA = {
    "cyclonedx": ("application/vnd.cyclonedx+json", "sbom.cdx.json"),
    "spdx": ("application/spdx+json", "sbom.spdx.json"),
    "native": ("application/json", "graph.sorb.json"),
}


def _emit(store: GraphStore, fmt: str) -> bytes:
    if fmt == "cyclonedx":
        from sorb.emit.cyclonedx import emit_cyclonedx

        return emit_cyclonedx(store, reproducible=True)
    if fmt == "spdx":
        from sorb.emit.spdx import emit_spdx

        return emit_spdx(store, reproducible=True)
    if fmt == "native":
        from sorb.emit.native import export_native

        return export_native(store)
    raise ValueError(f"unknown export format {fmt!r} (cyclonedx|spdx|native)")


def export_sbom(
    db_path: Path,
    fmt: str,
    *,
    component_ids: Iterable[int] | None = None,
) -> tuple[bytes, str, str]:
    """Return ``(body, media_type, filename)`` for a full-run or subgraph SBOM."""
    if fmt not in _MEDIA:
        raise ValueError(f"unknown export format {fmt!r} (cyclonedx|spdx|native)")
    media_type, filename = _MEDIA[fmt]

    ids = None if component_ids is None else set(component_ids)
    if not ids:
        store = GraphStore.open_readonly(db_path)
        try:
            return _emit(store, fmt), media_type, filename
        finally:
            store.close()

    # Subgraph: copy → mark unselected excluded → emit through the normal path.
    with tempfile.TemporaryDirectory(prefix="sorb-export-") as tmp:
        copy = Path(tmp) / "subgraph.sorb.db"
        shutil.copy2(db_path, copy)
        # SQLite names its side files "<db>-wal" / "<db>-shm"; without them a
        # copy taken mid-scan would be missing the most recent commits.
        for suffix in ("-wal", "-shm"):
            side = db_path.with_name(db_path.name + suffix)
            if side.exists():
                shutil.copy2(side, copy.with_name(copy.name + suffix))
        store = GraphStore.open_rw(copy)
        try:
            keep = ",".join(str(int(i)) for i in ids) or "-1"
            store._conn.execute(  # noqa: S608 — keep-list is int-sanitized above
                f"UPDATE components SET attrs = json_set(coalesce(attrs,'{{}}'), "
                f"'$.excluded', json('true')) WHERE id NOT IN ({keep})"
            )
            store.commit()
            return _emit(store, fmt), media_type, filename
        finally:
            store.close()


def selection_from_query(db_path: Path, query: str) -> list[int]:
    """Resolve a query-DSL `components` expression to the ids it selects."""
    from sorb.query import run_query

    store = GraphStore.open_readonly(db_path)
    try:
        result = run_query(store, query)
        ids: list[int] = []
        for row in result.rows:
            cid = row.get("id")
            if isinstance(cid, int):
                ids.append(cid)
        return ids
    finally:
        store.close()


def parse_ids(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            out.append(int(json.loads(part)) if part.lstrip("-").isdigit() else int(part))
    return out
