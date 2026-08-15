"""Remote shared cache — HTTP CAS client.

A CI fleet shares detector results through a content-addressed HTTP store so the
second machine to see a blob never re-detects it. Two invariants make this safe
to leave on by default:

- **Fail-open, budgeted.** Every call has a hard latency budget (default 100 ms);
  a slow or dead server costs at most that budget and a warning — never a scan
  failure. Offline is absolute: with `--offline` the remote is not contacted.
- **Content-addressed & write-through.** Keys are `sha256(cache-key)`; a value is
  immutable for its key, so reads need no coherence protocol and writes are
  idempotent. A local miss that hits the remote is written back locally.

The HTTP mechanism is behind a `Transport` so tests drive the reference server
in-process with no socket (the suite's network guard stays satisfied).
"""

from __future__ import annotations

from typing import Protocol

DEFAULT_BUDGET_S = 0.1


class Transport(Protocol):
    def request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        """Return (status, body). Must not raise; signal failure as status 0."""
        ...


class HttpTransport:
    """urllib-backed transport with a hard per-call timeout (fail-open)."""

    def __init__(self, base_url: str, timeout: float = DEFAULT_BUDGET_S) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        import urllib.error
        import urllib.request

        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - fixed base URL
                return (resp.status, resp.read())
        except urllib.error.HTTPError as e:
            return (e.code, b"")
        except (TimeoutError, OSError, ValueError):
            return (0, b"")  # fail-open: budget exceeded / unreachable


class RemoteCas:
    """Key-addressed remote cache over a `Transport`. Never raises."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.hits = 0
        self.misses = 0
        self.errors = 0

    @staticmethod
    def _key_hash(key: str) -> str:
        import hashlib

        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def get(self, key: str) -> bytes | None:
        status, body = self.transport.request("GET", f"/cas/{self._key_hash(key)}")
        if status == 200:
            self.hits += 1
            return body
        if status == 404:
            self.misses += 1
            return None
        self.errors += 1  # 0 (timeout/unreachable) or 5xx → fail-open miss
        return None

    def put(self, key: str, data: bytes) -> bool:
        status, _ = self.transport.request("PUT", f"/cas/{self._key_hash(key)}", data)
        if status in (200, 201, 204):
            return True
        self.errors += 1
        return False

    def has(self, key: str) -> bool:
        status, _ = self.transport.request("HEAD", f"/cas/{self._key_hash(key)}")
        return status == 200

    @property
    def healthy(self) -> bool:
        return self.errors == 0

    def stats(self) -> dict[str, int]:
        return {"remote_hits": self.hits, "remote_misses": self.misses, "remote_errors": self.errors}
