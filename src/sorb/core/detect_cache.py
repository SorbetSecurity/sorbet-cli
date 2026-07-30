"""Incremental detector-result cache.

Keys a detector's output on `(entry path, blob digest, detector id+version, config
fingerprint)` and stores the serialized findings, so re-scanning an unchanged file
skips the parse entirely. Two tiers: a local `Cas` and an optional shared remote
`RemoteCas`; a local miss that hits the remote is written back locally, and every
remote call is fail-open (a dead cache costs a warning, never the scan).

Note: the key includes the entry *path*, not the blob digest alone —
cached findings carry path-bound evidence coordinates, so keying
on path keeps replayed evidence correct rather than stale. Same-target re-scans
(the fleet/CI case) still hit fully.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from sorb.cache import Cas
from sorb.cache.remote import RemoteCas
from sorb.model import Finding, finding_from_dict, finding_to_dict

_CACHE_VERSION = "det-v1"


@dataclass
class CachedDetect:
    findings: list[Finding]
    warnings: list[tuple[str, str]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


class DetectCache:
    """Local + optional remote content cache for detector results."""

    def __init__(
        self, local: Cas | None = None, remote: RemoteCas | None = None
    ) -> None:
        self.local = local
        self.remote = remote
        self.hits = 0
        self.local_hits = 0
        self.remote_hits = 0
        self.misses = 0
        self.stores = 0

    @staticmethod
    def key(path: str, blob_digest: str, detectors: list[str], config_fingerprint: str) -> str:
        det = ",".join(sorted(detectors))
        det_hash = hashlib.sha256(det.encode()).hexdigest()[:16]
        return f"{_CACHE_VERSION}:{config_fingerprint}:{det_hash}:{blob_digest}:{path}"

    def get(self, key: str) -> CachedDetect | None:
        if self.local is not None:
            raw = self.local.get(key)
            if raw is not None:
                self.hits += 1
                self.local_hits += 1
                return _decode(raw)
        if self.remote is not None:
            raw = self.remote.get(key)
            if raw is not None:
                self.hits += 1
                self.remote_hits += 1
                if self.local is not None:
                    self.local.put(key, raw)  # populate the local tier
                return _decode(raw)
        self.misses += 1
        return None

    def put(self, key: str, result: CachedDetect) -> None:
        raw = _encode(result)
        if self.local is not None:
            self.local.put(key, raw)
        if self.remote is not None:
            self.remote.put(key, raw)  # write-through (fail-open)
        self.stores += 1

    def stats(self) -> dict[str, int]:
        return {
            "hits": self.hits, "local_hits": self.local_hits,
            "remote_hits": self.remote_hits, "misses": self.misses, "stores": self.stores,
        }


def _encode(result: CachedDetect) -> bytes:
    payload = {
        "findings": [finding_to_dict(f) for f in result.findings],
        "warnings": [list(w) for w in result.warnings],
        "gaps": result.gaps,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _decode(raw: bytes) -> CachedDetect:
    d = json.loads(raw)
    return CachedDetect(
        findings=[finding_from_dict(f) for f in d.get("findings", [])],
        warnings=[(w[0], w[1]) for w in d.get("warnings", [])],
        gaps=list(d.get("gaps", [])),
    )


def build_detect_cache(
    *, enabled: bool, remote_url: str | None, offline: bool
) -> DetectCache | None:
    """Construct the cache the pipeline should use, or None if disabled."""
    if not enabled and not remote_url:
        return None
    local = Cas() if (enabled or remote_url) else None
    remote: RemoteCas | None = None
    if remote_url and not offline:  # --offline is absolute: never contact the remote
        from sorb.cache.remote import HttpTransport

        remote = RemoteCas(HttpTransport(remote_url))
    if local is None and remote is None:
        return None
    return DetectCache(local=local, remote=remote)
