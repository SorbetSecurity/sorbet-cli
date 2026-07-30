"""Embedded-metadata readers — ELF/PE sections, cargo-auditable,
.NET deps.json, runtime detection — and the distroless-image acceptance."""

from __future__ import annotations

import json
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from container_fixtures import build_image, write_oci_layout  # noqa: E402
from sorb.binary.embedded.cargo_auditable import parse_cargo_auditable  # noqa: E402
from sorb.binary.embedded.dotnet import parse_deps_json  # noqa: E402
from sorb.binary.embedded.sections import elf_section, pe_section  # noqa: E402
from sorb.core.config import load_config  # noqa: E402
from sorb.core.pipeline import run_scan  # noqa: E402
from sorb.graph.store import GraphStore  # noqa: E402


def make_elf_with_section(name: str, payload: bytes) -> bytes:
    """Minimal but format-exact ELF64 LE with [null, <name>, .shstrtab] sections."""
    shstrtab = b"\x00" + name.encode() + b"\x00" + b".shstrtab\x00"
    name_off = 1
    shstrtab_name_off = 1 + len(name.encode()) + 1

    ehsize = 64
    payload_off = ehsize
    shstrtab_off = payload_off + len(payload)
    shoff = shstrtab_off + len(shstrtab)

    def shdr(sh_name: int, sh_offset: int, sh_size: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", sh_name, 1, 0, 0, sh_offset, sh_size, 0, 0, 1, 0
        )

    headers = (
        shdr(0, 0, 0)
        + shdr(name_off, payload_off, len(payload))
        + shdr(shstrtab_name_off, shstrtab_off, len(shstrtab))
    )
    ehdr = (
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0, ehsize, 0, 0, 64, 3, 2)
    )
    assert len(ehdr) == 64
    return ehdr + payload + shstrtab + headers


def make_pe_with_section(name: str, payload: bytes) -> bytes:
    """Minimal PE with one section."""
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    dos += b"\x00" * (e_lfanew - len(dos))
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    section_table_off = e_lfanew + 4 + 20
    raw_ptr = section_table_off + 40
    section = (
        name.encode()[:8].ljust(8, b"\x00")
        + struct.pack("<IIIIIIHHI", len(payload), 0x1000, len(payload), raw_ptr, 0, 0, 0, 0, 0)
    )
    out = dos + coff + section
    assert len(out) == raw_ptr
    return out + payload


AUDIT_JSON = {
    "packages": [
        {"name": "myapp", "version": "1.2.0", "source": "local", "root": True,
         "dependencies": [1, 2]},
        {"name": "serde", "version": "1.0.203", "source": "registry"},
        {"name": "tokio", "version": "1.38.0", "source": "registry"},
        {"name": "cc", "version": "1.0.99", "source": "registry", "kind": "build"},
    ]
}

DEPS_JSON = {
    "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/linux-x64"},
    "targets": {
        ".NETCoreApp,Version=v8.0/linux-x64": {
            "webapi/1.0.0": {"dependencies": {"Newtonsoft.Json": "13.0.3"}},
            "Newtonsoft.Json/13.0.3": {"runtime": {"lib/netstandard2.0/Newtonsoft.Json.dll": {}}},
        }
    },
    "libraries": {
        "webapi/1.0.0": {"type": "project", "serviceable": False},
        "Newtonsoft.Json/13.0.3": {
            "type": "package",
            "serviceable": True,
            "sha512": "sha512-" + "AAAA",
        },
    },
}

NODE_VERSION_H = b"""#ifndef SRC_NODE_VERSION_H_
#define NODE_MAJOR_VERSION 20
#define NODE_MINOR_VERSION 14
#define NODE_PATCH_VERSION 0
#endif
"""


def test_elf_and_pe_section_readers() -> None:
    payload = b"hello section"
    elf = make_elf_with_section(".dep-v0", payload)
    assert elf_section(elf, ".dep-v0") == payload
    assert elf_section(elf, ".missing") is None
    pe = make_pe_with_section(".dep-v0", payload)
    assert pe_section(pe, ".dep-v0") == payload
    assert pe_section(b"MZ garbage", ".dep-v0") is None
    assert elf_section(b"\x7fELF" + b"\x00" * 10, ".dep-v0") is None


def test_cargo_auditable_roundtrip() -> None:
    blob = make_elf_with_section(".dep-v0", zlib.compress(json.dumps(AUDIT_JSON).encode()))
    info = parse_cargo_auditable(blob)
    assert info is not None
    assert info.root_package is not None and info.root_package.name == "myapp"
    names = {p.name for p in info.packages}
    assert names == {"myapp", "serde", "tokio", "cc"}
    assert parse_cargo_auditable(b"\x7fELF" + b"\x00" * 100) is None


def test_deps_json_parse() -> None:
    info = parse_deps_json(json.dumps(DEPS_JSON).encode())
    assert info is not None
    by_name = {p.name: p for p in info.packages}
    assert by_name["webapi"].ptype == "project"
    newtonsoft = by_name["Newtonsoft.Json"]
    assert newtonsoft.version == "13.0.3" and newtonsoft.ptype == "package"
    assert newtonsoft.sha512 is not None
    assert parse_deps_json(b"{}") is None


def _distroless_scan(tmp_path: Path, monkeypatch):
    """A distroless image (no package DB at all)
    yields a real, correct inventory at installed tier."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    sys.path.insert(0, str(Path(__file__).parent))
    from test_gobuildinfo import MODINFO, make_binary

    go_binary = make_binary(MODINFO)
    rust_binary = make_elf_with_section(
        ".dep-v0", zlib.compress(json.dumps(AUDIT_JSON).encode())
    )
    layers = [
        {  # distroless base: ca-certs style files only, no package DB
            "etc/ssl/certs/ca-certificates.crt": b"CERTS",
            "usr/local/lib/python3.12/os.py": b"# stdlib marker",
            "usr/local/include/node/node_version.h": NODE_VERSION_H,
        },
        {
            "app/server": go_binary,
            "app/worker": rust_binary,
            "app/webapi.deps.json": json.dumps(DEPS_JSON).encode(),
        },
    ]
    bundle = build_image(layers, history=["FROM distroless", "COPY app /app"], ref_name="acme/distroless:1")
    root = write_oci_layout(bundle, tmp_path / "layout")
    cfg = load_config(flags={}, env={}, user_config_path=tmp_path / "nc.toml")
    return run_scan(f"oci-dir:{root}", cfg, store_path=tmp_path / "run.sorb.db")


def test_distroless_image_yields_real_inventory(tmp_path: Path, monkeypatch) -> None:
    result = _distroless_scan(tmp_path, monkeypatch)
    assert not result.had_scan_errors
    store = GraphStore.open_readonly(result.store_path)
    try:
        comps = {c.name: c for c in store.components()}
        # Go buildinfo (the reader exercised through the container pipeline)
        assert "github.com/gorilla/mux" in comps
        assert comps["github.com/gorilla/mux"].version == "v1.8.1"
        # replace directive honored: replacement wins
        assert "golang.org/x/text" in comps
        assert comps["golang.org/x/text"].version == "v0.14.0"
        # cargo-auditable
        assert comps["serde"].version == "1.0.203"
        assert comps["myapp"].ctype == "application"
        # .NET deps.json
        assert comps["Newtonsoft.Json"].version == "13.0.3"
        # bundled runtimes by directory structure
        assert comps["python"].version == "3.12"
        assert comps["node"].version == "20.14.0"
        # everything carries installed-tier evidence
        for name in ("github.com/gorilla/mux", "serde", "Newtonsoft.Json", "python", "node"):
            assert comps[name].tier.label == "installed", name
            assert store.evidence_for_component(comps[name].id), name
        # layer attribution: app components in layer 2, runtimes in layer 1
        assert comps["serde"].attrs["layer_ordinal"] == 1
        assert comps["python"].attrs["layer_ordinal"] == 0
    finally:
        store.close()
