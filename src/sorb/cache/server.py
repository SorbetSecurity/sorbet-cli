"""Reference HTTP CAS server for the shared cache.

A tiny content-addressed key→value store: `GET/PUT/HEAD /cas/<key>`. Values are
immutable once written (a key is a hash of deterministic inputs), so there is no
update path and no coherence protocol. Backed by a local `Cas` on disk, so a
served cache is also LRU-prunable. Runs standalone via `wsgiref` (`sorb cache
serve`) and, in tests, is driven in-process through `WsgiTransport` — no socket.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sorb.cache import Cas

_CAS_RE = re.compile(r"^/cas/([0-9a-f]{64})$")

_StartResponse = Callable[[str, list[tuple[str, str]]], Any]


class CasServer:
    """WSGI app: a content-addressed key→value cache over a local `Cas`."""

    def __init__(self, cas: Cas | None = None, root: Path | None = None) -> None:
        self.cas = cas or Cas(root)

    def __call__(self, environ: dict[str, Any], start_response: _StartResponse) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")
        m = _CAS_RE.match(path)
        if path == "/health":
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]
        if m is None:
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"not found"]
        # a key→value store: address by the provided key (a hash of deterministic
        # inputs), not the value's own digest.
        store_key = f"remote:{m.group(1)}"
        if method in ("GET", "HEAD"):
            blob = self.cas.get(store_key)
            if blob is None:
                start_response("404 Not Found", [("Content-Type", "text/plain")])
                return [b""]
            start_response("200 OK", [
                ("Content-Type", "application/octet-stream"),
                ("Content-Length", str(len(blob))),
            ])
            return [] if method == "HEAD" else [blob]
        if method == "PUT":
            data = _read_body(environ)
            self.cas.put(store_key, data)
            start_response("204 No Content", [])
            return [b""]
        start_response("405 Method Not Allowed", [])
        return [b""]


def _read_body(environ: dict[str, Any]) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    stream = environ.get("wsgi.input")
    if stream is None or length <= 0:
        return b""
    data: bytes = stream.read(length)
    return data


class WsgiTransport:
    """In-process `Transport` that calls a WSGI app directly (no socket)."""

    def __init__(self, app: CasServer) -> None:
        self.app = app

    def request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        import io

        captured: dict[str, Any] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = int(status.split(" ", 1)[0])

        environ: dict[str, Any] = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body) if body else 0),
            "wsgi.input": io.BytesIO(body or b""),
        }
        chunks = self.app(environ, start_response)
        return (int(captured.get("status", 0)), b"".join(chunks))


def serve(host: str, port: int, root: Path | None = None) -> None:  # pragma: no cover - standalone
    from wsgiref.simple_server import make_server

    app = CasServer(root=root)
    with make_server(host, port, app) as httpd:
        httpd.serve_forever()
