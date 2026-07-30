"""Docker / Podman engine API client over the local unix socket.

Speaks the Docker Engine HTTP API (Podman serves a compatible one). Used for:
- ``docker:<ref>`` / ``podman:<ref>`` — image export (`docker save` stream)
- ``container://<id>`` — merged-rootfs export + live process list

The transport is injectable so tests exercise these paths without a daemon or
network (tests run socket-blocked).
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from sorb.errors import TargetError

_API_VERSION = "v1.43"


def _docker_socket() -> str:
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://") :]
    return "/var/run/docker.sock"


def _podman_socket() -> str:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.exists(f"{runtime}/podman/podman.sock"):
        return f"{runtime}/podman/podman.sock"
    return "/run/podman/podman.sock"


class DaemonClient:
    """Thin client over the engine API; every failure is a typed TargetError."""

    def __init__(self, socket_path: str, *, transport: httpx.BaseTransport | None = None):
        self._socket = socket_path
        if transport is None:
            if not os.path.exists(socket_path):
                raise TargetError(
                    f"container engine socket not found at {socket_path} "
                    "(is the daemon running?)"
                )
            transport = httpx.HTTPTransport(uds=socket_path)
        self._client = httpx.Client(
            transport=transport, base_url=f"http://engine/{_API_VERSION}", timeout=60.0
        )

    @classmethod
    def for_flavor(
        cls, flavor: str, *, transport: httpx.BaseTransport | None = None
    ) -> DaemonClient:
        socket = _docker_socket() if flavor == "docker" else _podman_socket()
        return cls(socket, transport=transport)

    def _get(self, path: str) -> httpx.Response:
        try:
            resp = self._client.get(path)
        except httpx.HTTPError as e:
            raise TargetError(f"engine API request failed ({path}): {e}") from e
        if resp.status_code == 404:
            raise TargetError(f"engine API: not found ({path})")
        if resp.status_code >= 400:
            raise TargetError(f"engine API error {resp.status_code} on {path}")
        return resp

    def image_save(self, ref: str) -> bytes:
        """`docker save` bytes for an image reference."""
        return self._get(f"/images/{ref}/get").content

    def container_export(self, container_id: str) -> bytes:
        """Merged-rootfs tar of a container's filesystem."""
        return self._get(f"/containers/{container_id}/export").content

    def container_inspect(self, container_id: str) -> dict[str, Any]:
        doc = json.loads(self._get(f"/containers/{container_id}/json").content)
        if not isinstance(doc, dict):
            raise TargetError("engine API returned unexpected inspect payload")
        return doc

    def container_top(self, container_id: str) -> dict[str, Any]:
        doc = json.loads(self._get(f"/containers/{container_id}/top").content)
        if not isinstance(doc, dict):
            raise TargetError("engine API returned unexpected top payload")
        return doc

    def close(self) -> None:
        self._client.close()
