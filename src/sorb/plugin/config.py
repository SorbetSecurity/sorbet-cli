"""Load the WASM and gRPC plugin tiers a project has configured.

Entry-point plugins are discovered by installation (`sorb.catalogers`); the two
out-of-process tiers are not, because running them is a decision the project
has to make explicitly. Both are declared in `sorb.toml`:

```toml
[plugins]
wasm = [
  { namespace = "acme", module = "plugins/acme.wasm",
    signature = "plugins/acme.wasm.sig", key = "plugins/acme.pub" },
]

[plugins.grpc]
trusted = ["cataloger.internal:50051"]   # required before an endpoint is contacted
insecure = []                            # opt out of TLS, per endpoint
services = [{ namespace = "cloudsnap", endpoint = "cataloger.internal:50051" }]
```

A plugin that cannot be loaded is skipped with a warning rather than failing
the scan, and never silently: a refused signature is reported as such.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from sorb.catalogers.base import Cataloger

Warning_ = tuple[str, str]


def _read_plugins_section(config_path: Path) -> dict[str, object]:
    try:
        with open(config_path, "rb") as f:
            doc = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    section = doc.get("plugins")
    return section if isinstance(section, dict) else {}


def find_config(start: Path) -> Path | None:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        for rel in ("sorb.toml", ".sorb/sorb.toml"):
            path = candidate / rel
            if path.is_file():
                return path
    return None


def load_configured_plugins(target: Path) -> tuple[list[Cataloger], list[Warning_]]:
    """Return the catalogers a project's `sorb.toml` asks for, plus warnings."""
    config_path = find_config(target)
    if config_path is None:
        return [], []
    section = _read_plugins_section(config_path)
    if not section:
        return [], []
    base = config_path.parent
    catalogers: list[Cataloger] = []
    warnings: list[Warning_] = []
    catalogers.extend(_load_wasm(section.get("wasm"), base, warnings))
    catalogers.extend(_load_grpc(section.get("grpc"), warnings))
    return catalogers, warnings


def _load_wasm(
    spec: object, base: Path, warnings: list[Warning_]
) -> list[Cataloger]:
    if not isinstance(spec, list):
        return []
    from sorb.errors import SorbError
    from sorb.plugin.wasm import load_wasm_plugin

    out: list[Cataloger] = []
    for item in spec:
        if not isinstance(item, dict):
            continue
        namespace = str(item.get("namespace", "")).strip()
        module = item.get("module")
        if not namespace or not module:
            warnings.append(("SORB-W064", "a [plugins].wasm entry needs namespace and module"))
            continue
        try:
            artifact = (base / str(module)).read_bytes()
            signature = item.get("signature")
            key = item.get("key")
            out.append(
                load_wasm_plugin(
                    artifact,
                    namespace=namespace,
                    signature_bundle=(base / str(signature)).read_bytes() if signature else None,
                    public_key_pem=(base / str(key)).read_bytes() if key else None,
                )
            )
        except (SorbError, OSError) as e:
            warnings.append(("SORB-W064", f"wasm plugin {namespace!r} not loaded: {e}"))
    return out


def _load_grpc(spec: object, warnings: list[Warning_]) -> list[Cataloger]:
    if not isinstance(spec, dict):
        return []
    from sorb.errors import SorbError
    from sorb.plugin.grpc import GrpcCataloger, TrustConfig, matcher_globs

    trust = TrustConfig(
        trusted_endpoints={str(e) for e in spec.get("trusted", []) or []},
        insecure_endpoints={str(e) for e in spec.get("insecure", []) or []},
    )
    services = spec.get("services")
    if not isinstance(services, list):
        return []
    out: list[Cataloger] = []
    for item in services:
        if not isinstance(item, dict):
            continue
        namespace = str(item.get("namespace", "")).strip()
        endpoint = str(item.get("endpoint", "")).strip()
        if not namespace or not endpoint:
            warnings.append(
                ("SORB-W065", "a [plugins.grpc].services entry needs namespace and endpoint")
            )
            continue
        globs = [str(g) for g in item.get("globs", []) or []]
        try:
            trust.check(endpoint)
            if not globs:
                globs = matcher_globs(endpoint, trust)
        except (SorbError, OSError) as e:
            warnings.append(("SORB-W065", f"grpc plugin {namespace!r} not loaded: {e}"))
            continue
        if not globs:
            warnings.append(
                ("SORB-W065", f"grpc plugin {namespace!r} matches no paths — skipped")
            )
            continue
        out.append(GrpcCataloger(namespace, endpoint, globs, trust))
    return out
