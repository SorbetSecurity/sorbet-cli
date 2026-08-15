""".NET deps.json reader.

``*.deps.json`` is the runtime truth for published .NET apps: the exact
package graph including RID-specific assets. Parsed as plain JSON — the
CLR-metadata assembly-identity reader lives with the full binary formats
layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class DotnetPackage:
    name: str
    version: str
    ptype: str  # "package" | "project" | "runtimepack" | …
    sha512: str | None  # nuget content hash (base64) when present
    dependencies: tuple[tuple[str, str], ...] = ()  # (name, requested version)
    serviceable: bool = False


@dataclass(frozen=True, slots=True)
class DepsInfo:
    runtime_target: str
    packages: tuple[DotnetPackage, ...] = field(default=())


def parse_deps_json(data: bytes) -> DepsInfo | None:
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict) or "targets" not in doc:
        return None
    runtime_target = str((doc.get("runtimeTarget") or {}).get("name", ""))
    targets = doc.get("targets") or {}
    # prefer the runtimeTarget entry; fall back to the last (most specific) target
    target: dict[str, object] = {}
    if runtime_target and runtime_target in targets:
        target = targets[runtime_target] or {}
    elif targets:
        target = list(targets.values())[-1] or {}
    libraries = doc.get("libraries") or {}

    packages: list[DotnetPackage] = []
    for key, entry in target.items():
        name, _, version = key.partition("/")
        if not name or not version or not isinstance(entry, dict):
            continue
        lib = libraries.get(key) or {}
        deps: list[tuple[str, str]] = []
        for dep_name, dep_version in (entry.get("dependencies") or {}).items():
            deps.append((str(dep_name), str(dep_version)))
        sha512 = None
        raw_sha = str(lib.get("sha512", ""))
        if raw_sha.startswith("sha512-"):
            sha512 = raw_sha[len("sha512-") :]
        packages.append(
            DotnetPackage(
                name=name,
                version=version,
                ptype=str(lib.get("type", "package")),
                sha512=sha512 or None,
                dependencies=tuple(sorted(deps)),
                serviceable=bool(lib.get("serviceable", False)),
            )
        )
    if not packages:
        return None
    return DepsInfo(runtime_target=runtime_target, packages=tuple(packages))
