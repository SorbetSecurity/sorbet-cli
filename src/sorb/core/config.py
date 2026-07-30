"""Configuration model.

Precedence (highest wins): CLI flags → environment (``SORB_*``) → project
``sorb.toml`` (nearest ancestor of the target, or ``.sorb/sorb.toml``) → user
config (``~/.config/sorb/config.toml``) → built-in defaults.

The detector-relevant subset is hashed into ``config_fingerprint`` — a cache
key input and part of ``metadata.tools`` in emitted SBOMs.
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from sorb.errors import UsageError

#: Fields that change detector output — the fingerprint covers exactly these
#: (kept in one place).
FINGERPRINT_FIELDS = (
    "scope",
    "min_confidence",
    "paranoid",
    "env_matrix",
    "ignore",
    "include_installed_ignored",
    "evidence",
    "platform",
    "include_removed",
    "resolve",
)

_VALID_SCOPES = {"runtime", "dev", "all"}
_VALID_EVIDENCE = {"minimal", "standard", "full"}
_VALID_RESOLVE = {"pure", "native", "off"}


@dataclass(frozen=True)
class Config:
    scope: str = "all"  # emission filter: runtime|dev|all
    min_confidence: float = 0.8  # emission threshold for inferred-only components
    paranoid: bool = False  # only ≥ locked tier
    offline: bool = False  # absolute network kill-switch
    env_matrix: tuple[str, ...] = ()  # e.g. ("python=3.12", "platform=linux/amd64")
    ignore: tuple[str, ...] = ()  # extra .sorbignore-style patterns
    include_installed_ignored: bool = True  # walk gitignored install dirs
    evidence: str = "standard"  # minimal|standard|full snippet retention
    output: tuple[str, ...] = ()  # default output formats
    fail_on: tuple[str, ...] = ()  # policy findings that flip exit code to 2
    log_format: str = "auto"  # auto|json|tty
    reproducible: bool = False
    profile: bool = False
    project_filter: str | None = None  # --project
    platform: str | None = None  # --platform os/arch for image targets
    include_removed: bool = False  # --include-removed: emit state:removed components
    dockerfile: str | None = None  # --dockerfile: cross-link layer history
    enrich: bool = False  # --enrich: registry-metadata enrichment (additive)
    follow_images: bool = False  # --follow-images: chase IaC-referenced images
    resolve: str = "pure"  # pure|native|off — resolution mode
    allow_net: tuple[str, ...] = ()  # hosts the sandbox/enrichment may reach
    dangerously_no_sandbox: bool = False  # run native mode unsandboxed
    cache: bool = False  # --cache: reuse detector results by content
    remote_cache: str | None = None  # --remote-cache URL: shared HTTP CAS (fail-open)
    no_accel: bool = False  # --no-accel: force the pure-Python reference
    #: value origin per field name (flag/env/project/user/default) for `sorb config`
    origins: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

    def validate(self) -> None:
        if self.scope not in _VALID_SCOPES:
            raise UsageError(f"invalid scope {self.scope!r} (expected runtime|dev|all)")
        if self.evidence not in _VALID_EVIDENCE:
            raise UsageError(f"invalid evidence level {self.evidence!r}")
        if not (0.0 <= self.min_confidence <= 1.0):
            raise UsageError("--min-confidence must be between 0 and 1")
        if self.resolve not in _VALID_RESOLVE:
            raise UsageError(f"invalid --resolve {self.resolve!r} (expected pure|native|off)")

    def fingerprint(self) -> str:
        payload = {name: getattr(self, name) for name in FINGERPRINT_FIELDS}
        blob = json.dumps(payload, sort_keys=True, default=list).encode()
        return hashlib.sha256(blob).hexdigest()[:16]


_LIST_FIELDS = {"env_matrix", "ignore", "output", "fail_on", "allow_net"}
_BOOL_FIELDS = {
    "paranoid",
    "offline",
    "include_installed_ignored",
    "reproducible",
    "profile",
    "include_removed",
    "enrich",
    "follow_images",
    "dangerously_no_sandbox",
    "cache",
    "no_accel",
}
_FLOAT_FIELDS = {"min_confidence"}


def _coerce(name: str, value: Any) -> Any:
    if name in _LIST_FIELDS:
        if isinstance(value, str):
            return tuple(v.strip() for v in value.split(",") if v.strip())
        return tuple(str(v) for v in value)
    if name in _BOOL_FIELDS:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)
    if name in _FLOAT_FIELDS:
        return float(value)
    return value


def _flatten_toml(doc: dict[str, Any]) -> dict[str, Any]:
    """sorb.toml sections mirror flags 1:1: [scan] scope=... etc."""
    out: dict[str, Any] = {}
    known = {f.name for f in fields(Config)} - {"origins"}
    for key, value in doc.items():
        if isinstance(value, dict):
            for k2, v2 in value.items():
                k2n = k2.replace("-", "_")
                if k2n in known:
                    out[k2n] = v2
        else:
            kn = key.replace("-", "_")
            if kn in known:
                out[kn] = value
    return out


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            return _flatten_toml(tomllib.load(f))
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as e:
        raise UsageError(f"invalid TOML in {path}: {e}") from e


def find_project_config(start: Path) -> Path | None:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        for rel in ("sorb.toml", ".sorb/sorb.toml"):
            p = candidate / rel
            if p.is_file():
                return p
    return None


def load_config(
    target: Path | None = None,
    flags: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    user_config_path: Path | None = None,
) -> Config:
    """Build the effective Config with per-field origin tracking."""
    env = dict(os.environ) if env is None else env
    flags = flags or {}
    known = {f.name for f in fields(Config)} - {"origins"}

    values: dict[str, Any] = {}
    origins: dict[str, str] = {name: "default" for name in known}

    if user_config_path is None:
        user_config_path = Path.home() / ".config" / "sorb" / "config.toml"
    for name, val in _read_toml(user_config_path).items():
        values[name] = _coerce(name, val)
        origins[name] = "user"

    if target is not None:
        proj = find_project_config(target)
        if proj is not None:
            for name, val in _read_toml(proj).items():
                values[name] = _coerce(name, val)
                origins[name] = f"project ({proj})"

    for name in known:
        env_key = f"SORB_{name.upper()}"
        if env_key in env:
            values[name] = _coerce(name, env[env_key])
            origins[name] = f"env ({env_key})"

    for name, val in flags.items():
        if name in known and val is not None:
            values[name] = _coerce(name, val)
            origins[name] = "flag"

    cfg = Config(**values, origins=origins)
    cfg.validate()
    return cfg
