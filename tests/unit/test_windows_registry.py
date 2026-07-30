"""Offline Windows registry analysis.

A minimal but byte-correct `regf` hive is synthesized (root → Uninstall keys /
Services), so the hive parser, the installed-programs / services readers, and the
cataloger are all exercised offline — no Windows, no real hive file.
"""

from __future__ import annotations

import struct
from pathlib import Path

from sorb.core.config import load_config
from sorb.core.pipeline import run_scan
from sorb.graph.store import GraphStore
from sorb.host.regf import REG_DWORD, REG_SZ, Hive
from sorb.host.windows import auto_start_services, installed_programs


class HiveBuilder:
    """Emits a valid single-hbin regf hive with ASCII names and string/dword values."""

    def __init__(self) -> None:
        self.hbin = bytearray(32)  # hbin header, filled at build()

    def _alloc(self, data: bytes) -> int:
        pad = (-(4 + len(data))) % 8
        payload = data + b"\x00" * pad
        rel = len(self.hbin)
        self.hbin += struct.pack("<i", -(4 + len(payload))) + payload
        return rel

    def value(self, name: str, vtype: int, raw: bytes) -> int:
        data_off = self._alloc(raw)
        d = bytearray(0x14 + len(name))
        d[0:2] = b"vk"
        struct.pack_into("<H", d, 0x02, len(name))
        struct.pack_into("<I", d, 0x04, len(raw))  # not inline
        struct.pack_into("<I", d, 0x08, data_off)
        struct.pack_into("<I", d, 0x0C, vtype)
        struct.pack_into("<H", d, 0x10, 1)  # ASCII name
        d[0x14:0x14 + len(name)] = name.encode("latin-1")
        return self._alloc(bytes(d))

    def sz(self, name: str, text: str) -> int:
        return self.value(name, REG_SZ, (text + "\x00").encode("utf-16-le"))

    def dword(self, name: str, num: int) -> int:
        return self.value(name, REG_DWORD, struct.pack("<I", num))

    def _value_list(self, vks: list[int]) -> int:
        return self._alloc(b"".join(struct.pack("<I", o) for o in vks))

    def _subkey_list(self, nks: list[int]) -> int:
        d = bytearray(4)
        d[0:2] = b"lf"
        struct.pack_into("<H", d, 2, len(nks))
        for o in nks:
            d += struct.pack("<I", o) + struct.pack("<I", 0)
        return self._alloc(bytes(d))

    def key(
        self, name: str, subkeys: list[int] | None = None, values: list[int] | None = None
    ) -> int:
        subkeys = subkeys or []
        values = values or []
        subkey_off = self._subkey_list(subkeys) if subkeys else 0xFFFFFFFF
        value_off = self._value_list(values) if values else 0xFFFFFFFF
        d = bytearray(0x4C + len(name))
        d[0:2] = b"nk"
        struct.pack_into("<H", d, 0x02, 0x20)  # ASCII name flag
        struct.pack_into("<I", d, 0x14, len(subkeys))
        struct.pack_into("<I", d, 0x1C, subkey_off)
        struct.pack_into("<I", d, 0x24, len(values))
        struct.pack_into("<I", d, 0x28, value_off)
        struct.pack_into("<H", d, 0x48, len(name))
        d[0x4C:0x4C + len(name)] = name.encode("latin-1")
        return self._alloc(bytes(d))

    def build(self, root_offset: int) -> bytes:
        # pad hbin to a 4096 boundary
        while len(self.hbin) % 0x1000:
            self.hbin += b"\x00"
        self.hbin[0:4] = b"hbin"
        struct.pack_into("<I", self.hbin, 4, 0)
        struct.pack_into("<I", self.hbin, 8, len(self.hbin))
        header = bytearray(0x1000)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x24, root_offset)
        struct.pack_into("<I", header, 0x28, len(self.hbin))
        return bytes(header) + bytes(self.hbin)


def build_software_hive() -> bytes:
    b = HiveBuilder()
    sz7 = b.key("7-Zip", values=[
        b.sz("DisplayName", "7-Zip 22.01"), b.sz("DisplayVersion", "22.01"),
        b.sz("Publisher", "Igor Pavlov")])
    py = b.key("Python3.11", values=[
        b.sz("DisplayName", "Python 3.11.5"), b.sz("DisplayVersion", "3.11.5"),
        b.sz("Publisher", "Python Software Foundation")])
    stub = b.key("{stub-update}", values=[b.sz("DisplayVersion", "1.0")])  # no DisplayName
    uninstall = b.key("Uninstall", subkeys=[sz7, py, stub])
    cv = b.key("CurrentVersion", subkeys=[uninstall])
    win = b.key("Windows", subkeys=[cv])
    ms = b.key("Microsoft", subkeys=[win])
    root = b.key("ROOT", subkeys=[ms])
    return b.build(root)


def build_system_hive() -> bytes:
    b = HiveBuilder()
    w32 = b.key("W32Time", values=[
        b.dword("Start", 2), b.sz("DisplayName", "Windows Time"),
        b.sz("ImagePath", "%SystemRoot%\\system32\\svchost.exe")])
    manual = b.key("ManualSvc", values=[b.dword("Start", 3)])
    services = b.key("Services", subkeys=[w32, manual])
    cs = b.key("ControlSet001", subkeys=[services])
    root = b.key("ROOT", subkeys=[cs])
    return b.build(root)


# -- regf parser + readers ---------------------------------------------------------------


def test_hive_navigation() -> None:
    hive = Hive(build_software_hive())
    uninstall = hive.root().path("Microsoft", "Windows", "CurrentVersion", "Uninstall")
    assert uninstall is not None
    assert {k.name for k in uninstall.subkeys()} == {"7-Zip", "Python3.11", "{stub-update}"}
    seven = uninstall.subkey("7-Zip")
    assert seven is not None
    assert seven.values()["DisplayName"] == "7-Zip 22.01"


def test_installed_programs() -> None:
    progs = installed_programs(Hive(build_software_hive()))
    by_name = {p.name: p for p in progs}
    assert "7-Zip 22.01" in by_name and "Python 3.11.5" in by_name
    assert by_name["7-Zip 22.01"].version == "22.01"
    assert by_name["7-Zip 22.01"].publisher == "Igor Pavlov"
    assert "Uninstall\\7-Zip" in by_name["7-Zip 22.01"].key_path
    # a stub with no DisplayName is skipped
    assert all("stub" not in n.lower() for n in by_name)


def test_auto_start_services_only() -> None:
    svcs = auto_start_services(Hive(build_system_hive()))
    names = {s.name for s in svcs}
    assert "W32Time" in names  # Start=2 (auto)
    assert "ManualSvc" not in names  # Start=3 (manual) filtered out
    w = next(s for s in svcs if s.name == "W32Time")
    assert w.start == "auto" and w.display_name == "Windows Time"


# -- cataloger through a scan ------------------------------------------------------------


def test_registry_cataloger_via_scan(tmp_path: Path) -> None:
    root = tmp_path / "winmount"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SOFTWARE").write_bytes(build_software_hive())
    (root / "Windows/System32/config/SYSTEM").write_bytes(build_system_hive())
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    result = run_scan(str(root), cfg, store_path=tmp_path / "win.sorb.db")
    store = GraphStore.open_readonly(result.store_path)
    try:
        comps = {c.name: c for c in store.components()}
        assert "7-Zip 22.01" in comps and "Python 3.11.5" in comps
        assert comps["7-Zip 22.01"].attrs.get("publisher") == "Igor Pavlov"
        # auto-start service present as a component
        assert "W32Time" in comps and comps["W32Time"].ctype == "windows-service"
        # evidence points at the registry path
        detail = store.component_detail(comps["7-Zip 22.01"].id)
        assert detail is not None
        assert any("Uninstall\\7-Zip" in e["location"]["path"] for e in detail.evidence)
    finally:
        store.close()
