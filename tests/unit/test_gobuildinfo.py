"""Go buildinfo parsing from a synthetic (but format-exact) blob."""

from __future__ import annotations

from sorb.binary.embedded.go_buildinfo import MAGIC, parse_buildinfo


def _varint_str(s: str) -> bytes:
    data = s.encode()
    length = len(data)
    out = bytearray()
    while True:
        b = length & 0x7F
        length >>= 7
        if length:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out) + data


def make_binary(modinfo: str, go_version: str = "go1.21.5") -> bytes:
    header = MAGIC + bytes([8, 0x2]) + b"\x00" * (32 - len(MAGIC) - 2)
    return b"\x7fELF" + b"\x00" * 100 + header + _varint_str(go_version) + _varint_str(modinfo)


MODINFO = (
    "path\texample.com/cmd/app\n"
    "mod\texample.com/app\tv1.2.3\th1:AAAA\n"
    "dep\tgithub.com/gorilla/mux\tv1.8.1\th1:TuBL49tXwgrFYWhqrNgrUNEY92u81SPhu7sTdzQEiWY=\n"
    "dep\tgolang.org/x/text\tv0.13.0\t\n"
    "=>\tgolang.org/x/text\tv0.14.0\th1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n"
    "build\t-buildmode=exe\n"
)


def test_parse_synthetic_buildinfo() -> None:
    info = parse_buildinfo(make_binary(MODINFO))
    assert info is not None
    assert info.go_version == "go1.21.5"
    assert info.main_path == "example.com/cmd/app"
    assert info.main_module and info.main_module.version == "v1.2.3"
    assert len(info.deps) == 2
    mux = info.deps[0]
    assert mux.path == "github.com/gorilla/mux" and mux.version == "v1.8.1"
    text = info.deps[1]
    assert text.replaced_by is not None and text.replaced_by.version == "v0.14.0"


def test_non_go_binary_returns_none() -> None:
    assert parse_buildinfo(b"\x7fELF" + b"\x00" * 500) is None
    assert parse_buildinfo(b"not a binary at all") is None
