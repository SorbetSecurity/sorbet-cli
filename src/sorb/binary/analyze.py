"""BinaryInfo parsing with CAS caching.

`analyze_binary` parses a blob into `BinaryInfo`, caching the result by blob
digest so a `.so` shared across 40 images parses once. The cache stores the
JSON projection of `BinaryInfo`; a cache miss re-parses.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from sorb.binary.formats import parse_binary
from sorb.binary.info import BinaryInfo, Section, Symbol, digest_of


def _to_json(info: BinaryInfo) -> bytes:
    return json.dumps(asdict(info), sort_keys=True).encode()


def _from_json(data: bytes) -> BinaryInfo:
    d: dict[str, Any] = json.loads(data)
    d["sections"] = [Section(**s) for s in d.get("sections", [])]
    d["imported_symbols"] = [Symbol(**s) for s in d.get("imported_symbols", [])]
    d["exported_symbols"] = [Symbol(**s) for s in d.get("exported_symbols", [])]
    d["slices"] = [_from_json(json.dumps(s).encode()) for s in d.get("slices", [])]
    return BinaryInfo(**d)


def analyze_binary(data: bytes, cas: Any | None = None) -> BinaryInfo | None:
    """Parse `data` into BinaryInfo, using `cas` (a sorb.cache.Cas) if given."""
    if cas is not None and getattr(cas, "available", False):
        key = f"binaryinfo:v1:{digest_of(data)}"
        cached = cas.get(key)
        if cached is not None:
            try:
                return _from_json(cached)
            except (ValueError, TypeError):
                pass
        info = parse_binary(data)
        if info is not None:
            cas.put(key, _to_json(info))
        return info
    return parse_binary(data)
