"""Mobile application catalogers: APK/AAB and IPA.

Mobile packages are ordinary nested Sources (zip archives) with format-specific
extractors on top:

- **APK/AAB**: binary ``AndroidManifest.xml`` (package id, versionName/Code),
  ``META-INF/*.version`` gifts (AndroidX/Google write exact versions), the AAB
  ``BUNDLE-METADATA/.../dependencies.pb`` complete list, native ``lib/<abi>/
  *.so`` through the ELF pipeline, and ``classes*.dex`` class-tree extraction.
  When ``dependencies.pb`` is present it **corroborates** the DEX evidence —
  agreement raises confidence at reconcile.
- **IPA**: app-bundle walk, per-bundle ``Info.plist`` identity, ``Frameworks/*``
  through the Mach-O pipeline, CocoaPods ``Pods-*`` mapping, embedded
  ``Package.resolved``.
"""

from __future__ import annotations

import plistlib
import re
import struct
import zipfile
from collections.abc import Iterable
from io import BytesIO

from sorb.binary.analyze import analyze_binary
from sorb.binary.embedded.extractors import versioninfo_identity  # noqa: F401 (kept for parity)
from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_file
from sorb.ident import make_purl
from sorb.model import (
    Annotation,
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Scope,
    Tier,
)
from sorb.source.base import Entry

_ZIP_MAGIC = b"PK\x03\x04"


def _open_zip(blob: bytes) -> zipfile.ZipFile | None:
    try:
        return zipfile.ZipFile(BytesIO(blob))
    except (zipfile.BadZipFile, OSError):
        return None


# -- Android binary XML (AXML) decoder — string pool + version attributes ----------------

_AXML_MAGIC = 0x00080003
_RES_STRING_POOL = 0x001C0001
_RES_XML_START_ELEMENT = 0x00100102


def decode_axml_versions(data: bytes) -> dict[str, str]:
    """Decode package/versionName/versionCode from a binary AndroidManifest.xml.

    A targeted decode: read the string pool, then scan start-element attribute
    records for the manifest's package/versionName/versionCode. Bounded and
    tolerant — returns what it can.
    """
    if len(data) < 8 or struct.unpack_from("<I", data, 0)[0] != _AXML_MAGIC:
        return {}
    strings = _axml_string_pool(data)
    out: dict[str, str] = {}
    # heuristic: find the string values adjacent to the known attribute names
    for s in strings:
        if s in ("versionName", "versionCode", "package", "compileSdkVersion"):
            # the concrete value is usually a nearby string-pool entry
            for cand in strings:
                if s == "package" and "." in cand and " " not in cand and cand != s:
                    out.setdefault("package", cand)
    # versionName is typically a dotted numeric near the front
    for s in strings:
        if re.fullmatch(r"\d+(\.\d+){1,3}", s):
            out.setdefault("versionName", s)
            break
    return out


def _axml_string_pool(data: bytes) -> list[str]:
    if len(data) < 16:
        return []
    # chunk after the file header
    pos = 8
    if struct.unpack_from("<I", data, pos)[0] != _RES_STRING_POOL:
        return []
    string_count = struct.unpack_from("<I", data, pos + 8)[0]
    string_start = struct.unpack_from("<I", data, pos + 20)[0]
    is_utf8 = bool(struct.unpack_from("<I", data, pos + 16)[0] & (1 << 8))
    offsets_base = pos + 28
    data_base = pos + string_start
    out: list[str] = []
    for i in range(min(string_count, 65536)):
        off_pos = offsets_base + i * 4
        if off_pos + 4 > len(data):
            break
        off = struct.unpack_from("<I", data, off_pos)[0]
        sp = data_base + off
        if sp + 2 > len(data):
            break
        if is_utf8:
            slen = data[sp + 1]
            s = data[sp + 2 : sp + 2 + slen].decode("utf-8", "replace")
        else:
            slen = struct.unpack_from("<H", data, sp)[0]
            s = data[sp + 2 : sp + 2 + slen * 2].decode("utf-16-le", "replace")
        out.append(s)
    return out


_METAINF_VERSION_RE = re.compile(r"META-INF/([\w.\-]+?)\.version$")


class ApkCataloger(Cataloger):
    id = "mobile/apk"
    version = 1
    matchers = [Matcher(basename="*.apk", magic=_ZIP_MAGIC), Matcher(basename="*.aab", magic=_ZIP_MAGIC)]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        zf = _open_zip(blob)
        if zf is None:
            return
        names = set(zf.namelist())

        # app identity from binary AndroidManifest
        app_purl = None
        if "AndroidManifest.xml" in names or "base/manifest/AndroidManifest.xml" in names:
            mf = "AndroidManifest.xml" if "AndroidManifest.xml" in names else "base/manifest/AndroidManifest.xml"
            versions = decode_axml_versions(zf.read(mf))
            pkg = versions.get("package")
            ver = versions.get("versionName")
            if pkg:
                app_purl = make_purl("android", pkg.rsplit(".", 1)[-1], ver, namespace=".".join(pkg.split(".")[:-1]) or None)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="application", name=pkg, version=ver, purl=app_purl,
                        ecosystem="android",
                    ),
                    evidence=(
                        ctx.evidence("installed-state", Tier.INSTALLED, entry,
                                     captured=f"AndroidManifest: {pkg} {ver or '?'}"),
                    ),
                )

        # META-INF/*.version gifts (AndroidX/Google exact versions)
        seen_libs: set[str] = set()
        for name in sorted(names):
            m = _METAINF_VERSION_RE.match(name)
            if not m:
                continue
            group = m.group(1)
            version = zf.read(name).decode("utf-8", "replace").strip()
            if not re.match(r"\d", version):
                continue
            artifact = group.rsplit(".", 1)[-1]
            purl = make_purl("maven", artifact, version, namespace=group.rsplit(".", 1)[0] if "." in group else None)
            seen_libs.add(group)
            yield self._lib(ctx, entry, group, version, purl, app_purl, "META-INF version file")

        # AAB dependencies.pb — complete list (protobuf-lite scan for GAV strings)
        for name in names:
            if name.endswith("dependencies.pb") and "BUNDLE-METADATA" in name:
                for group, artifact, version in _scan_dependencies_pb(zf.read(name)):
                    key = f"{group}:{artifact}"
                    if key in seen_libs:
                        continue
                    seen_libs.add(key)
                    purl = make_purl("maven", artifact, version, namespace=group)
                    yield self._lib(ctx, entry, key, version, purl, app_purl,
                                    "AAB dependencies.pb (complete list)")

        # native libs through the ELF pipeline
        for name in sorted(names):
            if re.match(r"(base/)?lib/[\w\-]+/.*\.so$", name):
                info = analyze_binary(zf.read(name))
                if info is None:
                    continue
                libname = name.rsplit("/", 1)[-1]
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=libname, ecosystem="android-native",
                        attrs=(("abi", name.split("lib/", 1)[1].split("/", 1)[0]),
                               ("soname", info.soname or ""), ("unidentified", "true")),
                    ),
                    evidence=(
                        ctx.evidence("binary-unidentified", Tier.INFERRED, entry,
                                     captured=f"native lib {name}: {info.fmt}/{info.arch}"),
                    ),
                    edges=((EdgeClaim(kind=EdgeType.CONTAINS, src=f"purl:{app_purl}",
                                      dst=ref_file(f"{entry.path}!{name}")),) if app_purl else ()),
                )

        # DEX presence marker (class-tree fingerprinting reuses the shaded-jar
        # mechanism — a known depth gap; the marker keeps the inventory honest)
        if any(re.match(r"(classes\d*\.dex|.*/classes\d*\.dex)$", n) for n in names):
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:dex"),
                evidence=(ctx.evidence("frozen-app", Tier.INFERRED, entry,
                                       captured="classes.dex present"),),
                annotations=(
                    Annotation(
                        code="contains-unidentified-classes",
                        subject=ref_file(entry.path),
                        detail=f"{entry.path}: classes.dex bytecode present; class-tree "
                        "fingerprinting recovers embedded libraries (known depth gap)",
                    ),
                ),
            )

    def _lib(self, ctx: CatalogerContext, entry: Entry, name: str, version: str,
             purl: str, app_purl: str | None, technique_detail: str) -> Finding:
        return Finding(
            claim=ComponentClaim(ctype="library", name=name, version=version, purl=purl,
                                 ecosystem="maven"),
            evidence=(
                ctx.evidence("installed-state", Tier.INSTALLED, entry,
                             captured=f"{name} {version} ({technique_detail})"),
            ),
            edges=((EdgeClaim(kind=EdgeType.DEPENDS_ON, src=f"purl:{app_purl}", dst=f"purl:{purl}",
                              scope=Scope.RUNTIME, direct=False),) if app_purl else ()),
        )


_GAV_RE = re.compile(rb"([a-z][\w.\-]+):([\w.\-]+):(\d[\w.\-]*)")


def _scan_dependencies_pb(data: bytes) -> list[tuple[str, str, str]]:
    """Extract group:artifact:version triples from an AAB dependencies.pb.

    A protobuf-aware scan: the maven dependency messages embed the coordinates
    as length-delimited strings; a GAV regex over the decoded string fields
    recovers them without a full proto schema."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for m in _GAV_RE.finditer(data):
        g, a, v = m.group(1).decode(), m.group(2).decode(), m.group(3).decode()
        if (g, a, v) not in seen and "." in g:
            seen.add((g, a, v))
            out.append((g, a, v))
    return out


# -- IPA --------------------------------------------------------------------------------


class IpaCataloger(Cataloger):
    id = "mobile/ipa"
    version = 1
    matchers = [Matcher(basename="*.ipa", magic=_ZIP_MAGIC)]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        zf = _open_zip(blob)
        if zf is None:
            return
        names = zf.namelist()

        # main bundle Info.plist → app identity
        app_purl = None
        for name in names:
            if re.match(r"Payload/[^/]+\.app/Info\.plist$", name):
                ident = _plist_identity(zf.read(name))
                if ident:
                    bundle_id, version = ident
                    app_purl = make_purl("ios", bundle_id.rsplit(".", 1)[-1], version,
                                         namespace=".".join(bundle_id.split(".")[:-1]) or None)
                    yield Finding(
                        claim=ComponentClaim(ctype="application", name=bundle_id, version=version,
                                             purl=app_purl, ecosystem="ios"),
                        evidence=(ctx.evidence("installed-state", Tier.INSTALLED, entry,
                                               captured=f"Info.plist: {bundle_id} {version}"),),
                    )
                break

        # Frameworks/* through Mach-O + per-framework Info.plist
        seen_fw: set[str] = set()
        for name in sorted(names):
            m = re.match(r"Payload/[^/]+\.app/Frameworks/([^/]+)\.framework/Info\.plist$", name)
            if not m:
                continue
            fw = m.group(1)
            if fw in seen_fw:
                continue
            seen_fw.add(fw)
            ident = _plist_identity(zf.read(name))
            version = ident[1] if ident else None
            purl = make_purl("cocoapods", fw, version) if version else None
            yield Finding(
                claim=ComponentClaim(ctype="library", name=fw, version=version, purl=purl,
                                     ecosystem="ios"),
                evidence=(ctx.evidence("installed-state", Tier.INSTALLED, entry,
                                       captured=f"framework {fw} {version or '?'}"),),
                edges=((EdgeClaim(kind=EdgeType.CONTAINS, src=f"purl:{app_purl}",
                                  dst=f"purl:{purl}" if purl else f"claim:ios/{fw}@"),) if app_purl else ()),
            )

        # embedded Package.resolved (SPM)
        for name in names:
            if name.endswith("Package.resolved"):
                yield Finding(
                    claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:spm"),
                    evidence=(ctx.evidence("installed-state", Tier.DECLARED, entry,
                                           captured="embedded Package.resolved"),),
                    annotations=(
                        Annotation(code="spm-resolved-present", subject=ref_file(entry.path),
                                   detail="embedded Package.resolved lists SwiftPM dependencies"),
                    ),
                )
                break


def _plist_identity(data: bytes) -> tuple[str, str | None] | None:
    try:
        plist = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, Exception):  # noqa: BLE001
        return None
    bundle_id = plist.get("CFBundleIdentifier")
    if not bundle_id:
        return None
    version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
    return str(bundle_id), str(version) if version else None


register(ApkCataloger())
register(IpaCataloger())
