"""In-process WebAssembly reader.

Parses the import section (module/field imports → "needed" modules) and the
custom ``name``/``producers`` sections (toolchain provenance). Enough for the
inventory + fingerprint entry points; the full instruction stream is out of
scope here.
"""

from __future__ import annotations

from sorb.binary.info import BinaryInfo, Symbol

_SEC_IMPORT = 2
_SEC_CUSTOM = 0


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("truncated LEB128")


def parse_wasm(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt="wasm", arch="wasm32")
    if len(data) < 8:
        info.warnings.append("truncated wasm header")
        return info
    version = int.from_bytes(data[4:8], "little")
    info.bits = 32
    pos = 8
    modules: set[str] = set()
    for _ in range(65536):
        if pos >= len(data):
            break
        sec_id = data[pos]
        pos += 1
        try:
            sec_len, pos = _uleb(data, pos)
        except ValueError:
            info.warnings.append("truncated section length")
            break
        body_end = pos + sec_len
        if body_end > len(data):
            info.warnings.append("section overruns file")
            break
        if sec_id == _SEC_IMPORT:
            _read_imports(data, pos, body_end, info, modules)
        elif sec_id == _SEC_CUSTOM:
            _read_custom(data, pos, body_end, info)
        pos = body_end
    info.needed = sorted(modules)
    if version != 1:
        info.warnings.append(f"wasm version {version} (expected 1)")
    return info


def _read_imports(data: bytes, pos: int, end: int, info: BinaryInfo, modules: set[str]) -> None:
    try:
        count, pos = _uleb(data, pos)
        for _ in range(min(count, 1 << 20)):
            mlen, pos = _uleb(data, pos)
            module = data[pos : pos + mlen].decode("utf-8", "replace")
            pos += mlen
            flen, pos = _uleb(data, pos)
            field = data[pos : pos + flen].decode("utf-8", "replace")
            pos += flen
            kind = data[pos]
            pos += 1
            # skip the type descriptor (varies by kind)
            if kind == 0:  # function: type index
                _t, pos = _uleb(data, pos)
            elif kind in (1, 2):  # table / memory: flags then limits
                _f, pos = _uleb(data, pos)
                _min, pos = _uleb(data, pos)
                if _f & 1:
                    _max, pos = _uleb(data, pos)
            elif kind == 3:  # global: valtype + mutability
                pos += 2
            modules.add(module)
            info.imported_symbols.append(Symbol(name=f"{module}.{field}", kind="import"))
            if pos >= end:
                break
    except (ValueError, IndexError):
        info.warnings.append("malformed import section")


def _read_custom(data: bytes, pos: int, end: int, info: BinaryInfo) -> None:
    try:
        nlen, pos = _uleb(data, pos)
        name = data[pos : pos + nlen].decode("utf-8", "replace")
        if name == "producers":
            info.strings_hint.append("wasm-producers")
    except (ValueError, IndexError):
        pass
