"""Canonical serialization core.

- Stable ordering by identity key; sorted JSON keys; ``\\n`` line ending.
- Content-derived serial numbers: same subject + same findings ⇒ same serial —
  identical re-scans are recognizably identical documents.
- Wall-clock timestamps live only in run metadata; ``--reproducible`` honors
  ``SOURCE_DATE_EPOCH`` so two scans of identical input are byte-identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from sorb.graph.store import Component, GraphStore

_SORB_NAMESPACE = uuid.UUID("6f3b8f2e-1f7a-4b62-9f6e-2c4d8a2b10ca")


def canonical_json(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def component_sort_key(c: Component) -> tuple[str, str, str]:
    return (c.purl or "", c.name.lower(), c.version or "")


def content_serial(store: GraphStore) -> str:
    """Deterministic serial derived from subject identity + reconciled content."""
    subject = store.get_meta("subject") or ""
    payload: list[Any] = [subject]
    for c in sorted(store.components(), key=component_sort_key):
        if c.attrs.get("excluded"):
            continue
        payload.append(
            [c.purl or "", c.name, c.version or "", sorted(c.hashes.items()), c.tier_cap]
        )
    for e in store.edges():
        payload.append([e["kind"], e["src"], e["dst"]])
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    return str(uuid.uuid5(_SORB_NAMESPACE, digest))


def run_timestamp(reproducible: bool) -> str | None:
    """RFC3339 UTC timestamp for run metadata (never content identity)."""
    if reproducible:
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch and epoch.isdigit():
            return (
                datetime.fromtimestamp(int(epoch), tz=UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
        return None  # omitted entirely: byte-identical output guaranteed
    return datetime.now(tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def emitted_components(store: GraphStore) -> list[Component]:
    """The emission set: reconciled components minus threshold-excluded ones."""
    return [
        c
        for c in sorted(store.components(), key=component_sort_key)
        if not c.attrs.get("excluded")
    ]


def tools_metadata(store: GraphStore) -> dict[str, Any]:
    from sorb import __version__

    return {
        "vendor": "sorbet",
        "name": "sorb",
        "version": __version__,
        "detectors": json.loads(store.get_meta("detectors") or "[]"),
        "config_fingerprint": store.get_meta("config_fingerprint") or "",
    }
