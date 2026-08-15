"""In-process binary format adapters.

No external tool or heavyweight wheel: ELF/PE/Mach-O/WASM are parsed directly
(the same "in-process readers for everything" rule as the OS-package DBs and
registry hives). `parse_binary` sniffs the format and dispatches; malformed or
unsupported inputs return a `BinaryInfo` carrying a warning, never raise.
"""

from __future__ import annotations

from sorb.binary.info import BinaryInfo

_MAX_BINARY_BYTES = 512 << 20  # per-file parse budget

ELF_MAGIC = b"\x7fELF"
PE_MZ = b"MZ"
WASM_MAGIC = b"\x00asm"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # 32-bit BE
    b"\xce\xfa\xed\xfe",  # 32-bit LE
    b"\xfe\xed\xfa\xcf",  # 64-bit BE
    b"\xcf\xfa\xed\xfe",  # 64-bit LE
}
_MACHO_FAT = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}


def sniff_binary_format(head: bytes) -> str | None:
    if head[:4] == ELF_MAGIC:
        return "elf"
    if head[:4] == WASM_MAGIC:
        return "wasm"
    if head[:4] in _MACHO_FAT:
        return "macho-fat"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:2] == PE_MZ:
        return "pe"
    return None


def parse_binary(data: bytes) -> BinaryInfo | None:
    """Parse any supported binary into `BinaryInfo`; None if not a binary."""
    fmt = sniff_binary_format(data[:8])
    if fmt is None:
        return None
    if len(data) > _MAX_BINARY_BYTES:
        return BinaryInfo(fmt=fmt, warnings=[f"binary exceeds parse budget ({len(data)} bytes)"])
    try:
        if fmt == "elf":
            from sorb.binary.formats.elf import parse_elf

            return parse_elf(data)
        if fmt == "pe":
            from sorb.binary.formats.pe import parse_pe

            return parse_pe(data)
        if fmt in ("macho", "macho-fat"):
            from sorb.binary.formats.macho import parse_macho

            return parse_macho(data)
        if fmt == "wasm":
            from sorb.binary.formats.wasm import parse_wasm

            return parse_wasm(data)
    except Exception as e:  # noqa: BLE001 — hostile input: gap, never crash
        return BinaryInfo(fmt=fmt, warnings=[f"parse failed: {type(e).__name__}: {e}"])
    return None
