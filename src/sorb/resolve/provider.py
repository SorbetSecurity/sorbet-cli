"""RegistryMetadataProvider.

Fetches package-registry metadata over HTTPS APIs only (never executing
anything), CAS-cached and content-addressed, fully offline-replayable: a
cached package resolves with zero network (the second-resolve test runs under
the socket guard). Offline or unreachable ⇒ ``None`` — callers degrade to
``resolution: incomplete``, never a guess.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from sorb.cache import Cas

NPM_REGISTRY = "https://registry.npmjs.org"
_ABBREVIATED = "application/vnd.npm.install-v1+json"  # versions + deps only


class RegistryMetadataProvider:
    """npm-registry metadata source (other ecosystems can join as needed)."""

    def __init__(
        self,
        *,
        cas: Cas | None = None,
        offline: bool = False,
        registry: str = NPM_REGISTRY,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cas = cas if cas is not None else Cas()
        self.offline = offline
        self._registry = registry.rstrip("/")
        self._client: httpx.Client | None = None
        self._transport = transport
        self.network_requests = 0

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                transport=self._transport, timeout=15.0, follow_redirects=True
            )
        return self._client

    def npm_metadata(self, name: str) -> dict[str, Any] | None:
        """The npm packument (abbreviated form): versions → dependencies."""
        key = f"npm-meta:{self._registry}:{name}"
        cached = self.cas.get(key)
        if cached is not None:
            doc: dict[str, Any] = json.loads(cached)
            return doc
        if self.offline:
            return None
        try:
            self.network_requests += 1
            resp = self._http().get(
                f"{self._registry}/{name}", headers={"Accept": _ABBREVIATED}
            )
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            doc = resp.json()
        except json.JSONDecodeError:
            return None
        if not isinstance(doc, dict) or "versions" not in doc:
            return None
        self.cas.put(key, json.dumps(doc, sort_keys=True).encode())
        return doc

    def npm_versions(self, name: str) -> list[str]:
        doc = self.npm_metadata(name)
        if doc is None:
            return []
        return list((doc.get("versions") or {}).keys())

    def npm_dependencies(self, name: str, version: str) -> dict[str, str] | None:
        doc = self.npm_metadata(name)
        if doc is None:
            return None
        entry = (doc.get("versions") or {}).get(version)
        if not isinstance(entry, dict):
            return None
        deps = entry.get("dependencies") or {}
        return {str(k): str(v) for k, v in deps.items()} if isinstance(deps, dict) else {}

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
