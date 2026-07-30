"""Offline Windows analysis over registry hives.

Pure readers over a parsed `Hive`: installed programs from the Uninstall keys
(both native and WOW6432Node), and auto-start services from the SYSTEM hive's
current control set. Each result carries the hive path it came from, so evidence
points at exactly `SOFTWARE\\…\\Uninstall\\<id>` — replayable, not asserted.
"""

from __future__ import annotations

from dataclasses import dataclass

from sorb.host.regf import Hive, Key

_UNINSTALL_PATHS = (
    ("Microsoft", "Windows", "CurrentVersion", "Uninstall"),
    ("WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"),
)
# service start types (SYSTEM\...\Services\<svc>\Start)
_START_LABELS = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}


@dataclass(frozen=True, slots=True)
class Program:
    name: str
    version: str | None
    publisher: str | None
    key_path: str  # registry path the evidence points at


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    display_name: str | None
    start: str  # "auto" | "manual" | …
    image_path: str | None
    key_path: str


def installed_programs(hive: Hive) -> list[Program]:
    """Every Uninstall subkey with a DisplayName → one installed program."""
    out: list[Program] = []
    root = hive.root()
    for path in _UNINSTALL_PATHS:
        base = root.path(*path)
        if base is None:
            continue
        prefix = "\\".join(path)
        for entry in base.subkeys():
            vals = entry.values()
            name = _s(vals.get("DisplayName"))
            if not name:
                continue  # component/update stubs have no DisplayName
            out.append(Program(
                name=name,
                version=_s(vals.get("DisplayVersion")),
                publisher=_s(vals.get("Publisher")),
                key_path=f"{prefix}\\{entry.name}",
            ))
    return out


def auto_start_services(hive: Hive) -> list[Service]:
    """Auto/boot-start services from the current control set (runtime-relevant)."""
    out: list[Service] = []
    root = hive.root()
    services = _services_key(root)
    if services is None:
        return out
    for svc in services.subkeys():
        vals = svc.values()
        start = vals.get("Start")
        if not isinstance(start, int) or start not in (0, 1, 2):
            continue  # only boot/system/auto services are "running-relevant"
        out.append(Service(
            name=svc.name,
            display_name=_s(vals.get("DisplayName")),
            start=_START_LABELS.get(start, str(start)),
            image_path=_s(vals.get("ImagePath")),
            key_path=f"Services\\{svc.name}",
        ))
    return out


def _services_key(root: Key) -> Key | None:
    # SYSTEM hive: prefer the active ControlSet, fall back to ControlSet001.
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        node = root.path(cs, "Services")
        if node is not None and node.subkeys():
            return node
    return None


def _s(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
