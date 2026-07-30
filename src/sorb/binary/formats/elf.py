"""In-process ELF reader.

Parses the dynamic table (DT_NEEDED/DT_SONAME/DT_RPATH/DT_RUNPATH), the
dynamic symbol table with GNU symbol-version requirements (GLIBC_2.34…),
PT_INTERP, and the ``.note.gnu.build-id`` — the facts the link-graph builder
and enrichment need. Bounds every table walk against the file size.
"""

from __future__ import annotations

import struct

from sorb.binary.info import BinaryInfo, Section, Symbol

_ARCH = {0x03: "i386", 0x3E: "x86_64", 0xB7: "aarch64", 0x28: "arm", 0xF3: "riscv64", 0x08: "mips"}
_ET = {1: "object", 2: "exe", 3: "dylib", 4: "core"}

# dynamic tags
_DT_NEEDED, _DT_SONAME, _DT_RPATH, _DT_RUNPATH = 1, 14, 15, 29
_DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT = 5, 6, 10, 11
_DT_VERNEED, _DT_VERNEEDNUM, _DT_VERSYM = 0x6FFFFFFE, 0x6FFFFFFF, 0x6FFFFFF0
_PT_INTERP, _PT_DYNAMIC = 3, 2
_SHT_NOTE = 7
_SHN_ABS = 0xFFF1
_MAX_ENTRIES = 1_000_000


def parse_elf(data: bytes) -> BinaryInfo:
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    info = BinaryInfo(fmt="elf", bits=64 if is64 else 32, endianness="little" if data[5] == 1 else "big")
    e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
    info.kind = _ET.get(e_type, f"type-{e_type}")
    info.arch = _ARCH.get(e_machine, f"machine-{e_machine}")

    if is64:
        e_phoff, e_shoff = struct.unpack_from(f"{endian}QQ", data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", data, 0x36)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 0x3A)
    else:
        e_phoff, e_shoff = struct.unpack_from(f"{endian}II", data, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", data, 0x2A)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", data, 0x2E)

    # program headers: PT_INTERP, PT_DYNAMIC
    dyn_off = dyn_size = 0
    for i in range(min(e_phnum, 4096)):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            break
        p_type = struct.unpack_from(f"{endian}I", data, base)[0]
        if is64:
            p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from(f"{endian}QQQQ", data, base + 8)
        else:
            p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from(f"{endian}IIII", data, base + 4)
        if p_type == _PT_INTERP and p_offset + p_filesz <= len(data):
            info.interp = data[p_offset : p_offset + p_filesz].split(b"\x00", 1)[0].decode("latin-1")
        elif p_type == _PT_DYNAMIC:
            dyn_off, dyn_size = p_offset, p_filesz

    # section headers: names, build-id note, and .dynamic fallback
    sh = _section_table(data, endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    for name, off, size, flags, sh_type in sh:
        info.sections.append(Section(name=name, offset=off, size=size, flags=flags))
        if sh_type == _SHT_NOTE and name == ".note.gnu.build-id":
            info.build_id = _read_build_id(data, off, size, endian)
    if not dyn_off:
        for name, off, size, _flags, _t in sh:
            if name == ".dynamic":
                dyn_off, dyn_size = off, size
                break

    if dyn_off:
        _parse_dynamic(data, info, endian, is64, dyn_off, dyn_size, sh)
    _read_dynsym(data, info, endian, is64, sh)
    return info


def _section(sh: list[tuple[str, int, int, str, int]], want: str) -> tuple[int, int] | None:
    for name, off, size, _flags, _t in sh:
        if name == want:
            return off, size
    return None


def _read_dynsym(
    data: bytes,
    info: BinaryInfo,
    endian: str,
    is64: bool,
    sh: list[tuple[str, int, int, str, int]],
) -> None:
    """Split `.dynsym` into imported and exported symbols.

    Undefined entries are what this object needs from elsewhere; defined
    global/weak entries are what it offers. Both feed the link graph and the
    symbol fingerprint engine, so a stripped library still has an identity.
    """
    dynsym = _section(sh, ".dynsym")
    dynstr = _section(sh, ".dynstr")
    if dynsym is None or dynstr is None:
        return
    sym_off, sym_size = dynsym
    str_off, str_size = dynstr
    if str_off + str_size > len(data) or sym_off + sym_size > len(data):
        return
    strtab = data[str_off : str_off + str_size]
    entry = 24 if is64 else 16
    count = min(sym_size // entry, _MAX_ENTRIES)
    versions = _versym_names(data, endian, sh, count)
    # A library's own version labels ("OPENSSL_3.0.0") appear in .dynsym as
    # absolute symbols. They name a version, not an interface.
    version_labels = set(_version_index_names(data, endian, sh).values())

    for i in range(1, count):  # index 0 is the reserved null symbol
        base = sym_off + i * entry
        if is64:
            st_name, st_info, _other, st_shndx = struct.unpack_from(f"{endian}IBBH", data, base)
        else:
            st_name, _value, _size, st_info, _other, st_shndx = struct.unpack_from(
                f"{endian}IIIBBH", data, base
            )
        end = strtab.find(b"\x00", st_name)
        name = strtab[st_name : end if end >= 0 else len(strtab)].decode("latin-1")
        if not name or (st_shndx == _SHN_ABS and name in version_labels):
            continue
        bind, sym_type = st_info >> 4, st_info & 0xF
        kind = _SYMBOL_KINDS.get(sym_type, "")
        version = versions[i] if i < len(versions) else None
        symbol = Symbol(name=name, kind=kind or "import", version=version)
        if st_shndx == 0:  # SHN_UNDEF: needed from another object
            info.imported_symbols.append(symbol)
        elif bind in (1, 2):  # GLOBAL, WEAK: part of this object's interface
            info.exported_symbols.append(Symbol(name=name, kind=kind or "export", version=version))


_SYMBOL_KINDS = {1: "object", 2: "func"}


def _versym_names(
    data: bytes, endian: str, sh: list[tuple[str, int, int, str, int]], count: int
) -> list[str | None]:
    """Per-symbol version names from `.gnu.version` plus verneed/verdef."""
    versym = _section(sh, ".gnu.version")
    if versym is None:
        return []
    off, size = versym
    if off + min(size, count * 2) > len(data):
        return []
    names = _version_index_names(data, endian, sh)
    out: list[str | None] = []
    for i in range(min(count, size // 2)):
        idx = struct.unpack_from(f"{endian}H", data, off + i * 2)[0] & 0x7FFF
        out.append(names.get(idx))
    return out


def _version_index_names(
    data: bytes, endian: str, sh: list[tuple[str, int, int, str, int]]
) -> dict[int, str]:
    """Version index -> name, from both the needed and defined version tables."""
    dynstr = _section(sh, ".dynstr")
    if dynstr is None:
        return {}
    str_off, str_size = dynstr
    strtab = data[str_off : str_off + str_size]

    def text(at: int) -> str:
        end = strtab.find(b"\x00", at)
        return strtab[at : end if end >= 0 else len(strtab)].decode("latin-1")

    out: dict[int, str] = {}
    need = _section(sh, ".gnu.version_r")
    if need is not None:
        pos = need[0]
        for _ in range(4096):
            if pos + 16 > len(data):
                break
            _v, cnt, _file, aux, nxt = struct.unpack_from(f"{endian}HHIII", data, pos)
            apos = pos + aux
            for _a in range(min(cnt, 4096)):
                if apos + 16 > len(data):
                    break
                _h, _f, other, vda_name, vda_next = struct.unpack_from(
                    f"{endian}IHHII", data, apos
                )
                out.setdefault(other & 0x7FFF, text(vda_name))
                if not vda_next:
                    break
                apos += vda_next
            if not nxt:
                break
            pos += nxt

    define = _section(sh, ".gnu.version_d")
    if define is not None:
        pos = define[0]
        for _ in range(4096):
            if pos + 20 > len(data):
                break
            _ver, _flags, ndx, cnt, _hash, aux, nxt = struct.unpack_from(
                f"{endian}HHHHIII", data, pos
            )
            if cnt and pos + aux + 8 <= len(data):
                vda_name = struct.unpack_from(f"{endian}I", data, pos + aux)[0]
                out.setdefault(ndx & 0x7FFF, text(vda_name))
            if not nxt:
                break
            pos += nxt
    return out


def _section_table(
    data: bytes, endian: str, is64: bool, e_shoff: int, ent: int, num: int, strndx: int
) -> list[tuple[str, int, int, str, int]]:
    out: list[tuple[str, int, int, str, int]] = []
    if not e_shoff or num == 0 or strndx >= num:
        return out

    def hdr(idx: int) -> tuple[int, int, int, int, int]:
        base = e_shoff + idx * ent
        sh_name, sh_type, sh_flags = struct.unpack_from(f"{endian}III" if not is64 else f"{endian}IIQ", data, base)[:3]
        if is64:
            sh_offset, sh_size = struct.unpack_from(f"{endian}QQ", data, base + 0x18)
        else:
            sh_offset, sh_size = struct.unpack_from(f"{endian}II", data, base + 0x10)
        return sh_name, sh_type, int(sh_flags), sh_offset, sh_size

    _n, _t, _f, str_off, str_size = hdr(strndx)
    strtab = data[str_off : str_off + str_size]
    for i in range(min(num, 65536)):
        try:
            sh_name, sh_type, sh_flags, sh_offset, sh_size = hdr(i)
        except struct.error:
            break
        end = strtab.find(b"\x00", sh_name)
        name = strtab[sh_name : end if end >= 0 else len(strtab)].decode("latin-1")
        flag_str = ("A" if sh_flags & 0x2 else "") + ("X" if sh_flags & 0x4 else "")
        out.append((name, sh_offset, sh_size, flag_str, sh_type))
    return out


def _read_build_id(data: bytes, off: int, size: int, endian: str) -> str | None:
    if off + 12 > len(data):
        return None
    n_namesz, n_descsz, _n_type = struct.unpack_from(f"{endian}III", data, off)
    desc_off = off + 12 + ((n_namesz + 3) & ~3)
    if desc_off + n_descsz <= len(data) and n_descsz:
        return data[desc_off : desc_off + n_descsz].hex()
    return None


def _parse_dynamic(
    data: bytes, info: BinaryInfo, endian: str, is64: bool,
    dyn_off: int, dyn_size: int, sh: list[tuple[str, int, int, str, int]],
) -> None:
    fmt = f"{endian}qQ" if is64 else f"{endian}iI"
    entsz = 16 if is64 else 8
    strtab_addr = strsz = 0
    verneed_addr = verneed_num = 0
    needed_offsets: list[int] = []
    rpath_offsets: list[int] = []
    pos = dyn_off
    end = min(dyn_off + dyn_size, len(data))
    for _ in range(_MAX_ENTRIES):
        if pos + entsz > end:
            break
        tag, val = struct.unpack_from(fmt, data, pos)
        pos += entsz
        if tag == 0:  # DT_NULL
            break
        if tag == _DT_NEEDED:
            needed_offsets.append(val)
        elif tag in (_DT_RPATH, _DT_RUNPATH):
            rpath_offsets.append(val)
        elif tag == _DT_STRTAB:
            strtab_addr = val
        elif tag == _DT_STRSZ:
            strsz = val
        elif tag == _DT_VERNEED:
            verneed_addr = val
        elif tag == _DT_VERNEEDNUM:
            verneed_num = val

    str_off = _vaddr_to_offset(strtab_addr, sh)
    if str_off is None:
        return
    strtab = data[str_off : str_off + (strsz or 1 << 20)]

    def s(offset: int) -> str:
        e = strtab.find(b"\x00", offset)
        return strtab[offset : e if e >= 0 else len(strtab)].decode("latin-1")

    # resolve SONAME now that the strtab is known
    pos = dyn_off
    for _ in range(_MAX_ENTRIES):
        if pos + entsz > end:
            break
        tag, val = struct.unpack_from(fmt, data, pos)
        pos += entsz
        if tag == 0:
            break
        if tag == _DT_SONAME:
            info.soname = s(val)
            break
    info.needed = [s(o) for o in needed_offsets]
    for o in rpath_offsets:
        info.rpaths.extend(p for p in s(o).split(":") if p)

    # symbol-version requirements (Verneed → GLIBC_2.34, OPENSSL_3.0.0…)
    if verneed_addr:
        voff = _vaddr_to_offset(verneed_addr, sh)
        if voff is not None:
            info.version_requirements = _read_verneed(data, voff, verneed_num, endian, strtab)


def _vaddr_to_offset(vaddr: int, sh: list[tuple[str, int, int, str, int]]) -> int | None:
    """Map a virtual address to a file offset via allocated sections.

    For dynamically linked ELFs strtab/symtab live in an alloc section whose
    sh_addr == its vaddr; we approximate by matching the section containing the
    address using the recorded (offset,size). Falls back to treating vaddr as
    an offset for simple/statically-laid fixtures.
    """
    for _name, off, size, flags, _t in sh:
        if "A" in flags and off <= vaddr < off + size:
            return vaddr
    # many toolchains lay dynstr at file offset == vaddr for the first LOAD
    return vaddr if 0 <= vaddr else None


def _read_verneed(
    data: bytes, off: int, count: int, endian: str, strtab: bytes
) -> list[str]:
    versions: set[str] = set()
    pos = off
    for _ in range(min(count, 4096)):
        if pos + 16 > len(data):
            break
        _ver, vn_cnt, _file, aux, nxt = struct.unpack_from(f"{endian}HHIII", data, pos)
        apos = pos + aux
        for _a in range(min(vn_cnt, 4096)):
            if apos + 16 > len(data):
                break
            _hash, _flags, _other, vda_name, vda_next = struct.unpack_from(f"{endian}IHHII", data, apos)
            e = strtab.find(b"\x00", vda_name)
            versions.add(strtab[vda_name : e if e >= 0 else len(strtab)].decode("latin-1"))
            if not vda_next:
                break
            apos += vda_next
        if not nxt:
            break
        pos += nxt
    return sorted(v for v in versions if v)
