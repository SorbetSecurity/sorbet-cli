"""Installer/firmware unpackers, APK/AAB, IPA."""

from __future__ import annotations

import io
import plistlib
import struct
import zipfile

from sorb.binary.unpack import sniff_container, unpack_container
from sorb.catalogers.base import CatalogerContext, dispatch
from sorb.catalogers.mobile import _scan_dependencies_pb, decode_axml_versions
from sorb.model import Coordinates, Finding, Tier
from sorb.source.base import Entry


class MapSource:
    def __init__(self, files):  # noqa: ANN001
        self.files = files

    def exists(self, path: str) -> bool:
        return path in self.files

    def open(self, path: str) -> bytes:
        return self.files[path]

    def coords(self, path: str, span=None):  # noqa: ANN001
        return Coordinates(source_id="s1", path=path, span=span)


def catalog(files, path):  # noqa: ANN001
    raw = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    blob = raw[path]
    entry = Entry(path=path, size=len(blob), sniff=blob[:64])
    out: list[Finding] = []
    for c in dispatch(entry):
        ctx = CatalogerContext(source=MapSource(raw), detector=c.detector)  # type: ignore[arg-type]
        out.extend(c.parse(ctx, entry, blob))
    return out


def by_name(fs):  # noqa: ANN001
    return {f.claim.name: f for f in fs}


# -- unpackers --------------------------------------------------------------------------


def make_ar(members: dict[str, bytes]) -> bytes:
    out = b"!<arch>\n"
    for name, data in members.items():
        header = (
            f"{name + '/':<16}".encode()
            + b"0" * 12 + b"0" * 6 + b"0" * 6 + b"100644  "
            + f"{len(data):<10}".encode() + b"`\n"
        )
        out += header + data
        if len(data) & 1:
            out += b"\n"
    return out


def make_cpio(members: dict[str, bytes]) -> bytes:
    out = b""
    for name, data in list(members.items()) + [("TRAILER!!!", b"")]:
        namebytes = name.encode() + b"\x00"
        fields = [0] * 13
        fields[6] = len(data)  # filesize
        fields[11] = len(namebytes)  # namesize
        header = b"070701" + b"".join(f"{f:08x}".encode() for f in fields)
        header += namebytes
        header += b"\x00" * ((-len(header)) % 4)
        out += header + data + b"\x00" * ((-len(data)) % 4)
    return out


def test_unpack_ar_deb() -> None:
    ar = make_ar({"debian-binary": b"2.0\n", "control.tar.gz": b"\x1f\x8bdata"})
    assert sniff_container(ar[:16]) == "ar"
    unpacked = unpack_container(ar)
    assert unpacked and unpacked.format == "ar"
    assert unpacked.members["debian-binary"] == b"2.0\n"
    assert "control.tar.gz" in unpacked.members


def test_unpack_cpio_initramfs() -> None:
    cpio = make_cpio({"bin/busybox": b"ELFDATA", "etc/passwd": b"root:x:0:0"})
    assert sniff_container(cpio[:16]) == "cpio"
    unpacked = unpack_container(cpio)
    assert unpacked and unpacked.members["bin/busybox"] == b"ELFDATA"
    assert unpacked.members["etc/passwd"] == b"root:x:0:0"


def test_unpack_squashfs_superblock() -> None:
    # minimal squashfs superblock: magic + inode_count + ... + comp_id at 20
    sb = bytearray(96)
    sb[0:4] = b"hsqs"
    struct.pack_into("<I", sb, 4, 42)  # inode count
    struct.pack_into("<H", sb, 20, 4)  # xz
    struct.pack_into("<H", sb, 28, 4)  # version major
    unpacked = unpack_container(bytes(sb))
    assert unpacked and "squashfs:superblock" in unpacked.members
    assert b"xz" in unpacked.members["squashfs:superblock"]
    assert unpacked.warnings  # honest: contents not decompressed


def test_unpack_malformed_gaps_gracefully() -> None:
    bad = b"!<arch>\n" + b"\xff" * 40  # ar magic but garbage header
    unpacked = unpack_container(bad)
    assert unpacked is not None  # info-or-gap, never crash


# -- APK / AAB --------------------------------------------------------------------------


def build_axml(package: str, version_name: str) -> bytes:
    """A minimal binary AndroidManifest.xml with a decodable string pool."""
    strings = ["manifest", "package", "versionName", package, version_name]
    # string pool (UTF-16)
    encoded = b""
    offsets = []
    for s in strings:
        offsets.append(len(encoded))
        encoded += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    n = len(strings)
    header_size = 28
    offsets_size = n * 4
    string_start = header_size + offsets_size
    pool_size = string_start + len(encoded)
    pool = struct.pack("<IIIIIII", 0x001C0001, pool_size, n, 0, 0, string_start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets)
    pool += encoded
    file_header = struct.pack("<II", 0x00080003, 8 + len(pool))
    return file_header + pool


def make_apk(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_axml_decode() -> None:
    axml = build_axml("com.acme.app", "2.5.1")
    versions = decode_axml_versions(axml)
    assert versions.get("package") == "com.acme.app"
    assert versions.get("versionName") == "2.5.1"


def test_dependencies_pb_scan() -> None:
    # a protobuf-ish blob embedding maven coordinates as strings
    pb = b"\x0a\x2c" + b"androidx.core:core:1.12.0" + b"\x0a\x30" + b"com.google.guava:guava:33.0.0-android"
    triples = _scan_dependencies_pb(pb)
    assert ("androidx.core", "core", "1.12.0") in triples
    assert ("com.google.guava", "guava", "33.0.0-android") in triples


def test_apk_metainf_and_dependencies_pb_corroborate() -> None:
    """dependencies.pb corroborates META-INF versions; native
    lib identified through the ELF pipeline."""
    from test_binary_formats import build_elf_so

    axml = build_axml("com.acme.app", "1.0.0")
    dep_pb = b"stuff androidx.core:core:1.12.0 more"
    files = {
        "AndroidManifest.xml": axml,
        "META-INF/androidx.core.version": b"1.12.0\n",
        "BUNDLE-METADATA/com.android.tools.build.gradle/dependencies.pb": dep_pb,
        "lib/arm64-v8a/libnative.so": build_elf_so(soname="libnative.so"),
        "classes.dex": b"dex\n035\x00fakedex",
    }
    fs = catalog({"app.aab": make_apk(files)}, "app.aab")
    names = by_name(fs)
    assert "com.acme.app" in names
    assert names["com.acme.app"].evidence[0].tier is Tier.INSTALLED
    # META-INF version → installed-tier component
    androidx = [f for f in fs if "androidx" in f.claim.name]
    assert androidx and androidx[0].claim.version == "1.12.0"
    # native lib went through the ELF pipeline
    native = [f for f in fs if f.claim.name == "libnative.so"]
    assert native and native[0].claim.attrs
    # DEX marker
    codes = {a.code for f in fs for a in f.annotations}
    assert "contains-unidentified-classes" in codes


# -- IPA --------------------------------------------------------------------------------


def make_ipa(app_name: str, plists: dict[str, dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, plist in plists.items():
            zf.writestr(path, plistlib.dumps(plist))
    return buf.getvalue()


def test_ipa_inventories_frameworks() -> None:
    """IPA inventories frameworks with versions; pod-name mapping asserted."""
    plists = {
        "Payload/Acme.app/Info.plist": {
            "CFBundleIdentifier": "com.acme.app", "CFBundleShortVersionString": "3.1.0",
        },
        "Payload/Acme.app/Frameworks/Alamofire.framework/Info.plist": {
            "CFBundleIdentifier": "org.alamofire.Alamofire",
            "CFBundleShortVersionString": "5.8.1",
        },
    }
    ipa = make_ipa("Acme", plists)
    fs = by_name(catalog({"Acme.ipa": ipa}, "Acme.ipa"))
    assert "com.acme.app" in fs and fs["com.acme.app"].claim.version == "3.1.0"
    assert "Alamofire" in fs
    assert fs["Alamofire"].claim.version == "5.8.1"
    assert fs["Alamofire"].claim.purl == "pkg:cocoapods/Alamofire@5.8.1"
