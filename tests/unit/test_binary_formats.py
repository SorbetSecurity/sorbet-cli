"""Binary format adapters, embedded extractors, and the link graph.

Real system binaries validate the Mach-O path; format-exact synthetic ELF/PE/
WASM fixtures validate the rest deterministically and offline."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from sorb.binary.analyze import analyze_binary
from sorb.binary.embedded.extractors import (
    detect_frozen_app,
    extract_embedded_sbom,
    versioninfo_identity,
)
from sorb.binary.formats import parse_binary, sniff_binary_format
from sorb.binary.formats.elf import parse_elf
from sorb.binary.formats.wasm import parse_wasm
from sorb.binary.info import BinaryInfo
from sorb.binary.linkgraph import resolve_links
from sorb.cache import Cas

# -- a format-exact ELF64 shared library builder ---------------------------------------------


def build_elf_so(
    *,
    soname: str = "libfoo.so.1",
    needed: list[str] | None = None,
    rpath: str = "$ORIGIN/../lib",
    build_id: bytes = b"\xde\xad\xbe\xef",
    symver: str = "GLIBC_2.34",
    sbom: bytes | None = None,
) -> bytes:
    needed = needed or ["libc.so.6", "libssl.so.3"]
    # Layout: [ehdr][phdrs][.dynstr][.dynamic][verneed][.note.build-id][sbom?][shdrs]
    # We place everything at file offsets == "vaddr" so _vaddr_to_offset resolves.
    ehsize = 64
    phentsize = 56
    n_ph = 2  # PT_INTERP-less; PT_DYNAMIC + PT_LOAD placeholder
    ph_off = ehsize

    # build dynstr
    dynstr = b"\x00"
    offsets: dict[str, int] = {}

    def add_str(s: str) -> int:
        nonlocal dynstr
        off = len(dynstr)
        offsets[s] = off
        dynstr += s.encode() + b"\x00"
        return off

    for n in needed:
        add_str(n)
    add_str(soname)
    for rp in rpath.split(":"):
        add_str(rp)
    add_str(symver)
    add_str("libc.so.6")  # verneed filename

    body_start = ph_off + n_ph * phentsize
    dynstr_off = body_start
    dynamic_off = dynstr_off + len(dynstr)
    dynamic_off = (dynamic_off + 7) & ~7

    # dynamic entries
    DT_NEEDED, DT_SONAME, DT_RPATH, DT_STRTAB, DT_STRSZ = 1, 14, 15, 5, 10
    DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
    dyn = b""
    for n in needed:
        dyn += struct.pack("<qQ", DT_NEEDED, offsets[n])
    dyn += struct.pack("<qQ", DT_SONAME, offsets[soname])
    dyn += struct.pack("<qQ", DT_RPATH, offsets[rpath.split(":")[0]])
    dyn += struct.pack("<qQ", DT_STRTAB, dynstr_off)
    dyn += struct.pack("<qQ", DT_STRSZ, len(dynstr))
    verneed_off = dynamic_off + 0  # patched below
    # we need verneed offset before writing DT_VERNEED — compute now
    dyn_placeholder_len = len(dyn) + 8 * 8  # + VERNEED, VERNEEDNUM, DT_NULL
    verneed_off = dynamic_off + dyn_placeholder_len
    verneed_off = (verneed_off + 3) & ~3
    dyn += struct.pack("<qQ", DT_VERNEED, verneed_off)
    dyn += struct.pack("<qQ", DT_VERNEEDNUM, 1)
    dyn += struct.pack("<qQ", 0, 0)  # DT_NULL

    # verneed: one Elf64_Verneed + one Vernaux
    verneed = struct.pack("<HHIII", 1, 1, offsets["libc.so.6"], 16, 0)
    vernaux = struct.pack("<IHHII", 0, 0, 0, offsets[symver], 0)
    verneed_blob = verneed + vernaux

    # build-id note
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\x00" + build_id

    # assemble body
    parts = bytearray()
    parts += dynstr
    parts += b"\x00" * (dynamic_off - (dynstr_off + len(dynstr)))
    parts += dyn
    parts += b"\x00" * (verneed_off - (dynamic_off + len(dyn)))
    parts += verneed_blob
    note_off = verneed_off + len(verneed_blob)
    parts += note
    sbom_off = note_off + len(note)
    if sbom is not None:
        parts += sbom

    body = bytes(parts)
    sh_off = body_start + len(body)
    sh_off = (sh_off + 7) & ~7

    # section headers: null, .dynamic, .note.gnu.build-id, .sbom?, .shstrtab
    shstrtab = b"\x00.dynamic\x00.note.gnu.build-id\x00.sbom\x00.shstrtab\x00"
    sh_dynamic = shstrtab.index(b".dynamic\x00")
    sh_note = shstrtab.index(b".note.gnu.build-id\x00")
    sh_sbom = shstrtab.index(b".sbom\x00")
    sh_shstr = shstrtab.index(b".shstrtab\x00")
    n_sh = 5 if sbom is not None else 4
    shstrtab_file_off = sh_off + n_sh * 64

    def shdr(name_off: int, sh_type: int, flags: int, offset: int, size: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, flags, 0, offset, size, 0, 0, 1, 0)

    shdrs = shdr(0, 0, 0, 0, 0)
    shdrs += shdr(sh_dynamic, 6, 0x2, dynamic_off, len(dyn))  # SHT_DYNAMIC, ALLOC
    shdrs += shdr(sh_note, 7, 0x2, note_off, len(note))  # SHT_NOTE
    if sbom is not None:
        shdrs += shdr(sh_sbom, 1, 0, sbom_off, len(sbom))  # PROGBITS
    shdrs += shdr(sh_shstr, 3, 0, shstrtab_file_off, len(shstrtab))  # SHT_STRTAB
    strndx = n_sh - 1

    # program headers (PT_LOAD covering everything so vaddr==offset holds)
    PT_LOAD, PT_DYNAMIC = 1, 2
    ph = struct.pack("<IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, sh_off, sh_off, 0x1000)
    ph += struct.pack("<IIQQQQQQ", PT_DYNAMIC, 6, dynamic_off, dynamic_off, dynamic_off,
                      len(dyn), len(dyn), 8)

    # ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,  # ET_DYN
        0x3E,  # x86_64
        1,
        0,  # entry
        ph_off,
        sh_off,
        0,
        ehsize,
        phentsize,
        n_ph,
        64,  # shentsize
        n_sh,
        strndx,
    )
    assert len(ehdr) == 64
    out = bytearray(ehdr + ph + body)
    out += b"\x00" * (sh_off - len(out))
    out += shdrs
    out += shstrtab
    return bytes(out)


def test_sniff() -> None:
    assert sniff_binary_format(b"\x7fELF\x02\x01") == "elf"
    assert sniff_binary_format(b"MZ\x90\x00") == "pe"
    assert sniff_binary_format(b"\x00asm\x01\x00") == "wasm"
    assert sniff_binary_format(b"\xcf\xfa\xed\xfe") == "macho"
    assert sniff_binary_format(b"\xca\xfe\xba\xbe") == "macho-fat"
    assert sniff_binary_format(b"not a binary") is None


def test_elf_dynamic_table() -> None:
    blob = build_elf_so()
    info = parse_elf(blob)
    assert info.fmt == "elf" and info.arch == "x86_64" and info.bits == 64
    assert info.kind == "dylib"
    assert info.soname == "libfoo.so.1"
    assert "libc.so.6" in info.needed and "libssl.so.3" in info.needed
    assert info.rpaths == ["$ORIGIN/../lib"]
    assert info.build_id == "deadbeef"
    assert "GLIBC_2.34" in info.version_requirements


def test_elf_embedded_sbom_verified_not_trusted() -> None:
    sbom = b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'
    blob = build_elf_so(sbom=sbom)
    info = parse_elf(blob)
    found = extract_embedded_sbom(blob, info)
    assert found is not None and found.section == ".sbom"
    assert b"bomFormat" in found.data


def test_corrupt_elf_gaps_gracefully() -> None:
    info = parse_binary(b"\x7fELF\x02\x01\x01\x00" + b"\xff" * 40)
    assert info is not None and info.fmt == "elf"  # info-or-gap, never a crash


def test_real_macho_and_fat() -> None:
    ls = parse_binary(Path("/bin/ls").read_bytes())
    assert ls is not None and ls.fmt == "macho-fat"
    assert len(ls.slices) >= 1
    slice0 = ls.slices[0]
    assert any("libSystem" in n for n in slice0.needed)
    py = parse_binary(Path(sys.executable).read_bytes())
    assert py is not None and py.fmt in ("macho", "macho-fat")


def test_wasm_imports() -> None:
    # minimal wasm: header + import section (1 func import "env"."memcpy")
    body = b""
    body += bytes([1])  # count
    module = b"env"
    field = b"memcpy"
    body += bytes([len(module)]) + module + bytes([len(field)]) + field + bytes([0x00, 0x00])
    section = bytes([2]) + bytes([len(body)]) + body
    wasm = b"\x00asm" + struct.pack("<I", 1) + section
    info = parse_wasm(wasm)
    assert info.fmt == "wasm" and "env" in info.needed
    assert any("memcpy" in s.name for s in info.imported_symbols)


def make_pe_with_versioninfo(product: str, version: str, company: str, imports: list[str]) -> bytes:
    """Minimal PE with an import table + a .rsrc VS_VERSIONINFO string blob."""
    e_lfanew = 0x80
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", e_lfanew)
    dos += b"\x00" * (e_lfanew - len(dos))
    n_sections = 2
    opt_size = 96 + 16 * 8
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, n_sections, 0, 0, 0, opt_size, 0x2000)
    section_table = e_lfanew + 4 + 20 + opt_size
    idata_ptr = ((section_table + n_sections * 40) + 0x1FF) & ~0x1FF

    # import table at RVA 0x1000: one descriptor for the DLL then a null one;
    # the DLL name string sits after both 20-byte descriptors (RVA 0x1000+40).
    import_name = imports[0].encode() + b"\x00"
    descr = struct.pack("<IIIII", 0, 0, 0, 0x1000 + 40, 0) + struct.pack("<IIIII", 0, 0, 0, 0, 0)
    idata = descr + import_name
    idata += b"\x00" * (0x200 - len(idata))

    # .rsrc at RVA 0x2000 with UTF-16LE key\0value\0 pairs
    def kv(k: str, v: str) -> bytes:
        return k.encode("utf-16-le") + b"\x00\x00" + v.encode("utf-16-le") + b"\x00\x00"

    rsrc = kv("ProductName", product) + kv("ProductVersion", version) + kv("CompanyName", company)
    rsrc += b"\x00" * (0x200 - len(rsrc))
    rsrc_ptr = idata_ptr + 0x200

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    dd = 112
    struct.pack_into("<II", opt, dd + 1 * 8, 0x1000, len(idata))  # import dir

    def sect(name: bytes, vaddr: int, rawptr: int, rawsize: int) -> bytes:
        return name.ljust(8, b"\x00") + struct.pack(
            "<IIIIIIHHI", rawsize, vaddr, rawsize, rawptr, 0, 0, 0, 0, 0x40000040
        )

    sections = sect(b".idata", 0x1000, idata_ptr, 0x200) + sect(b".rsrc", 0x2000, rsrc_ptr, 0x200)
    out = bytearray(dos + coff + bytes(opt) + sections)
    out += b"\x00" * (idata_ptr - len(out))
    out += idata
    out += rsrc
    return bytes(out)


def test_pe_imports_and_versioninfo() -> None:
    blob = make_pe_with_versioninfo("Acme Widget", "2.5.1.0", "Acme Corp", ["KERNEL32.dll"])
    info = parse_binary(blob)
    assert info is not None and info.fmt == "pe" and info.arch == "x86_64"
    assert any("KERNEL32" in n for n in info.needed)
    assert info.version_info.get("ProductName") == "Acme Widget"
    identity = versioninfo_identity(info)
    assert identity == ("Acme Widget", "2.5.1.0", "Acme Corp")


def test_cas_caches_parse() -> None:
    import tempfile

    blob = build_elf_so()
    with tempfile.TemporaryDirectory() as tmp:
        cas = Cas(Path(tmp))
        first = analyze_binary(blob, cas)
        stats_before = cas.stats()["entries"]
        second = analyze_binary(blob, cas)
        assert first is not None and second is not None
        assert first.soname == second.soname == "libfoo.so.1"
        assert cas.hits >= 1  # the second parse was a cache hit
        assert stats_before >= 1


def test_frozen_app_detection() -> None:
    pyinstaller = b"MZ" + b"\x00" * 1000 + b"MEI\x0c\x0b\x0a\x0b\x0e" + b"\x00" * 20
    assert detect_frozen_app(pyinstaller).kind == "pyinstaller"
    sea = b"MZ" + b"NODE_SEA_BLOB" + b"\x00" * 100
    assert detect_frozen_app(sea).kind == "node-sea"
    assert detect_frozen_app(b"just a normal binary" * 100) is None


# -- link graph -------------------------------------------------------------------------------


def test_link_graph_resolves_chain_and_rpath() -> None:
    info = BinaryInfo(
        fmt="elf", needed=["libssl.so.3", "libc.so.6"],
        rpaths=["/opt/app/lib"], version_requirements=["GLIBC_2.34", "GLIBC_2.17"],
    )
    file_index = {
        "/opt/app/lib/libssl.so.3",  # RPATH wins for libssl
        "/usr/lib/libssl.so.3",
        "/usr/lib/libc.so.6",
    }
    owners = {
        "/opt/app/lib/libssl.so.3": "openssl 3.0.13",
        "/usr/lib/libc.so.6": "glibc 2.35",
    }
    result = resolve_links("/opt/app/bin/app", info, file_index=file_index, file_owner=owners)
    by_soname = {t.soname: t for t in result.targets}
    # RPATH override honored over the default /usr/lib
    assert by_soname["libssl.so.3"].resolved_path == "/opt/app/lib/libssl.so.3"
    assert by_soname["libssl.so.3"].via_rpath is True
    assert by_soname["libssl.so.3"].owner_package == "openssl 3.0.13"
    assert by_soname["libc.so.6"].owner_package == "glibc 2.35"
    # symbol-version requirement → minimum version evidence
    assert result.min_versions["GLIBC"] == "2.34"
    assert not result.unresolved


def test_link_graph_reports_unresolved() -> None:
    info = BinaryInfo(fmt="elf", needed=["libmissing.so.1"])
    result = resolve_links("/bin/app", info, file_index=set())
    assert result.unresolved == ["libmissing.so.1"]
    assert result.targets[0].resolved_path is None


# -- ELF dynamic symbols ---------------------------------------------------------------


def _elf_with_dynsym(
    symbols: list[tuple[str, int, int, int]],  # name, st_info, st_shndx, version index
    versions: dict[int, str],
) -> bytes:
    """A minimal ELF64 carrying only what the symbol reader needs."""
    strings = b"\x00"
    offset_of: dict[str, int] = {}

    def add(text: str) -> int:
        nonlocal strings
        if text not in offset_of:
            offset_of[text] = len(strings)
            strings += text.encode() + b"\x00"
        return offset_of[text]

    for name, _info, _shndx, _v in symbols:
        add(name)
    for label in versions.values():
        add(label)

    dynsym = b"\x00" * 24  # reserved null entry
    for name, st_info, st_shndx, _v in symbols:
        dynsym += struct.pack("<IBBHQQ", add(name), st_info, 0, st_shndx, 0, 0)
    versym = struct.pack("<H", 0) + b"".join(struct.pack("<H", s[3]) for s in symbols)

    # one verneed entry listing every version, so each index resolves to a name
    aux = b""
    items = sorted(versions.items())
    for pos, (idx, label) in enumerate(items):
        nxt = 16 if pos + 1 < len(items) else 0
        aux += struct.pack("<IHHII", 0, 0, idx, add(label), nxt)
    verneed = struct.pack("<HHIII", 1, len(items), add("libc.so.6"), 16, 0) + aux

    names = [b"", b".shstrtab", b".dynstr", b".dynsym", b".gnu.version", b".gnu.version_r"]
    shstrtab = b"\x00".join(names) + b"\x00"
    name_off = {}
    cursor = 0
    for n in names:
        name_off[n] = cursor
        cursor += len(n) + 1

    blobs = [b"", shstrtab, strings, dynsym, versym, verneed]
    offsets, cur = [], 64 + 64 * len(names)
    for b in blobs:
        offsets.append(cur)
        cur += len(b)

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1
    struct.pack_into("<HH", ehdr, 16, 3, 0x3E)  # ET_DYN, x86_64
    struct.pack_into("<Q", ehdr, 0x28, 64)  # e_shoff
    struct.pack_into("<HHH", ehdr, 0x3A, 64, len(names), 1)  # shentsize, shnum, shstrndx

    shdrs = b""
    for i, n in enumerate(names):
        shdrs += struct.pack(
            "<IIQQQQIIQQ", name_off[n], 1, 0, 0, offsets[i], len(blobs[i]), 0, 0, 1, 0
        )
    return bytes(ehdr) + shdrs + b"".join(blobs)


def test_elf_dynsym_splits_imports_from_exports() -> None:
    """SHN_UNDEF entries are needed elsewhere; defined global/weak are offered."""
    blob = _elf_with_dynsym(
        symbols=[
            ("SSL_new", 0x12, 5, 2),          # GLOBAL FUNC, defined  -> export
            ("weak_hook", 0x22, 5, 2),        # WEAK   FUNC, defined  -> export
            ("local_helper", 0x02, 5, 2),     # LOCAL  FUNC, defined  -> neither
            ("malloc", 0x12, 0, 3),           # GLOBAL FUNC, undefined -> import
            ("__gmon_start__", 0x20, 0, 0),   # WEAK undefined         -> import
        ],
        versions={2: "OPENSSL_3.0.0", 3: "GLIBC_2.34"},
    )
    info = parse_elf(blob)
    exported = {s.name: s for s in info.exported_symbols}
    imported = {s.name: s for s in info.imported_symbols}
    assert set(exported) == {"SSL_new", "weak_hook"}
    assert set(imported) == {"malloc", "__gmon_start__"}
    assert exported["SSL_new"].version == "OPENSSL_3.0.0"
    assert exported["SSL_new"].kind == "func"
    assert imported["malloc"].version == "GLIBC_2.34"
    assert imported["__gmon_start__"].version is None


def test_elf_version_labels_are_not_reported_as_symbols() -> None:
    """A library's own version labels sit in .dynsym but name no interface."""
    blob = _elf_with_dynsym(
        symbols=[
            ("OPENSSL_3.0.0", 0x11, 0xFFF1, 0),  # SHN_ABS version label
            ("SSL_free", 0x12, 5, 2),
        ],
        versions={2: "OPENSSL_3.0.0"},
    )
    info = parse_elf(blob)
    names = {s.name for s in info.exported_symbols} | {s.name for s in info.imported_symbols}
    assert names == {"SSL_free"}


def test_elf_without_a_symbol_table_is_not_an_error() -> None:
    info = parse_elf(build_elf_so())
    assert info.imported_symbols == [] and info.exported_symbols == []
    assert info.needed  # the rest of the parse still works
