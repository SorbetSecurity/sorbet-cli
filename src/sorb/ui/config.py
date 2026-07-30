"""Server configuration + the security invariants it must satisfy.

A `ServerConfig` is validated *before* the socket is opened so a misconfiguration
(binding beyond loopback without an explicit auth choice) fails fast with a clear
message rather than exposing an unauthenticated graph on the network.
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from pathlib import Path

_LOOPBACK_NAMES = {"localhost"}


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def mint_token() -> str:
    """A per-session, URL-safe random bearer token."""
    return secrets.token_urlsafe(24)


@dataclass
class ServerConfig:
    """Everything the embedded server needs; construct then ``validate()``."""

    bind: str = "127.0.0.1"
    port: int = 0  # 0 = ephemeral
    results_dir: Path | None = None
    #: "token" mints/requires a bearer token; "none" disables it (loopback only).
    auth: str = "token"
    token: str = field(default_factory=mint_token)
    allow_scan: bool = False
    open_browser: bool = False
    #: run id (or db path) to serve; None → latest in the workspace.
    run: str | None = None
    target: str | None = None
    #: extra Host header values to accept, for a reverse proxy fronting the
    #: server (or a test client). Never populated by default: every entry
    #: widens the DNS-rebinding defense.
    extra_allowed_hosts: tuple[str, ...] = ()

    @property
    def require_token(self) -> bool:
        return self.auth == "token"

    @property
    def is_loopback(self) -> bool:
        return _is_loopback(self.bind)

    def validate(self) -> None:
        """Enforce that non-loopback binds require an explicit auth choice."""
        if self.auth not in ("token", "none"):
            raise ValueError(f"--auth must be 'token' or 'none', not {self.auth!r}")
        if not self.is_loopback and self.auth == "none":
            raise ValueError(
                f"refusing to bind {self.bind} beyond loopback without authentication — "
                "pass --auth token (or bind 127.0.0.1)"
            )
        if not 0 <= self.port <= 65535:
            raise ValueError(f"--port out of range: {self.port}")

    def allowed_hosts(self, port: int) -> set[str]:
        """Host-header allowlist for the DNS-rebinding defense.

        `port` is the *actual* bound port (config.port may be 0 = ephemeral).
        """
        hosts = {self.bind, f"{self.bind}:{port}"}
        if self.is_loopback:
            for name in ("127.0.0.1", "localhost", "[::1]", "::1"):
                hosts.add(name)
                hosts.add(f"{name}:{port}")
        hosts.update(self.extra_allowed_hosts)
        return hosts

    def url(self, port: int) -> str:
        host = "localhost" if self.is_loopback else self.bind
        base = f"http://{host}:{port}/"
        if self.require_token:
            return f"{base}?token={self.token}"
        return base
