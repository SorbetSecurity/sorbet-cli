""".NET catalogers.

- ``*.csproj``/``*.fsproj`` + ``Directory.Packages.props`` (central package
  management) — declared tier;
- ``packages.lock.json`` — locked tier with direct/transitive and content hashes;
- ``project.assets.json`` — installed tier (resolution output);
- ``*.deps.json`` is the published-app runtime truth (`dotnet/deps-json`);
- assembly identity via minimal CLR metadata (extends the embedded-metadata reader).
"""

from __future__ import annotations

import base64
import json
import posixpath
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_family, ref_file, ref_project, ref_purl
from sorb.errors import DetectorFailure
from sorb.ident import make_purl
from sorb.model import (
    ComponentClaim,
    EdgeClaim,
    EdgeType,
    Finding,
    Scope,
    Tier,
)
from sorb.source.base import Entry


def _parse_xml(blob: bytes, path: str, detector: str) -> ET.Element:
    try:
        return ET.fromstring(blob.decode("utf-8-sig", errors="replace"))
    except ET.ParseError as e:
        raise DetectorFailure(str(e), path=path, detector=detector) from e


def _package_references(root: ET.Element) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] != "PackageReference":
            continue
        name = el.get("Include") or el.get("Update")
        if not name:
            continue
        version = el.get("Version")
        if version is None:
            for child in el:
                if child.tag.rsplit("}", 1)[-1] == "Version":
                    version = (child.text or "").strip() or None
        out.append((name, version))
    return out


class CsprojCataloger(Cataloger):
    id = "dotnet/csproj"
    version = 1
    matchers = [Matcher(basename="*.csproj"), Matcher(basename="*.fsproj"), Matcher(basename="*.vbproj")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        root = _parse_xml(blob, entry.path, self.detector)
        text = blob.decode("utf-8-sig", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_name = posixpath.basename(entry.path).rsplit(".", 1)[0]
        ctx.declare_project(proj_dir, proj_name, "dotnet-project")
        proj_ref = ref_project(proj_dir)

        central = self._central_versions(ctx, proj_dir)
        for name, version in _package_references(root):
            source = "csproj"
            if version is None and name in central:
                version = central[name]
                source = "Directory.Packages.props"
            concrete = version is not None and re.fullmatch(r"[\w.\-+]+", version or "") is not None
            purl = make_purl("nuget", name, version) if concrete else None
            claim = ComponentClaim(
                ctype="library",
                name=name,
                version=version if concrete else None,
                purl=purl,
                ecosystem="nuget",
                requested=None if concrete else version,
                attrs=(("version-source", source),) if source != "csproj" else (),
            )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=find_span(text, f'"{name}"'),
                        captured=f"PackageReference {name} {version or '(no version)'}",
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_purl(purl) if purl else ref_family("nuget", name),
                        scope=Scope.RUNTIME,
                        direct=True,
                        requested=version,
                    ),
                ),
            )

    def _central_versions(self, ctx: CatalogerContext, proj_dir: str) -> dict[str, str]:
        """Walk up for Directory.Packages.props (central package management)."""
        parts = proj_dir.split("/") if proj_dir != "." else []
        for depth in range(len(parts), -1, -1):
            prefix = "/".join(parts[:depth])
            candidate = f"{prefix}/Directory.Packages.props" if prefix else "Directory.Packages.props"
            raw = ctx.peek(candidate)
            if raw is None:
                continue
            try:
                root = _parse_xml(raw, candidate, self.detector)
            except DetectorFailure:
                return {}
            out: dict[str, str] = {}
            for el in root.iter():
                if el.tag.rsplit("}", 1)[-1] == "PackageVersion":
                    name, version = el.get("Include"), el.get("Version")
                    if name and version:
                        out[name] = version
            return out
        return {}


class NugetLockCataloger(Cataloger):
    id = "dotnet/packages-lock"
    version = 1
    matchers = [Matcher(basename="packages.lock.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, proj_dir or ".", "dotnet-project")
        proj_ref = ref_project(proj_dir)
        seen: set[tuple[str, str]] = set()
        for _tfm, packages in (doc.get("dependencies") or {}).items():
            if not isinstance(packages, dict):
                continue
            for name, info in packages.items():
                if not isinstance(info, dict):
                    continue
                resolved = info.get("resolved")
                ptype = str(info.get("type", ""))
                if not resolved or ptype == "Project" or (name, str(resolved)) in seen:
                    continue
                seen.add((name, str(resolved)))
                hashes: tuple[tuple[str, str], ...] = ()
                content_hash = str(info.get("contentHash", ""))
                if content_hash:
                    try:
                        hashes = (("sha512", base64.b64decode(content_hash).hex()),)
                    except (ValueError, TypeError):
                        pass
                purl = make_purl("nuget", name, str(resolved))
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library",
                        name=name,
                        version=str(resolved),
                        purl=purl,
                        ecosystem="nuget",
                        hashes=hashes,
                        requested=str(info.get("requested")) if info.get("requested") else None,
                    ),
                    evidence=(
                        ctx.evidence(
                            "lockfile-parse",
                            Tier.LOCKED,
                            entry,
                            span=find_span(text, f'"{name}"'),
                            captured=f"{name} {resolved} ({ptype})",
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_purl(purl),
                            scope=Scope.RUNTIME,
                            direct=ptype == "Direct",
                            requested=str(info.get("requested")) if info.get("requested") else None,
                        ),
                    ),
                )


class ProjectAssetsCataloger(Cataloger):
    """`project.assets.json` — NuGet resolution output (installed tier)."""

    id = "dotnet/project-assets"
    version = 1
    matchers = [Matcher(basename="project.assets.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        libraries = doc.get("libraries") or {}
        targets = doc.get("targets") or {}
        # RID-qualified targets (".NETCoreApp,Version=v8.0/linux-x64") — record the RID
        rid_of: dict[str, str] = {}
        for target_name, packages in targets.items():
            rid = target_name.partition("/")[2]
            if not isinstance(packages, dict):
                continue
            for key in packages:
                if rid:
                    rid_of.setdefault(key, rid)
        for key, lib in libraries.items():
            if not isinstance(lib, dict) or lib.get("type") != "package":
                continue
            name, _, version = key.partition("/")
            if not name or not version:
                continue
            hashes: tuple[tuple[str, str], ...] = ()
            raw_sha = str(lib.get("sha512", ""))
            if raw_sha:
                try:
                    hashes = (("sha512", base64.b64decode(raw_sha).hex()),)
                except (ValueError, TypeError):
                    pass
            qualifiers = {"rid": rid_of[key]} if key in rid_of else {}
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version,
                    purl=make_purl("nuget", name, version, qualifiers=qualifiers),
                    ecosystem="nuget",
                    hashes=hashes,
                    qualifiers=tuple(sorted(qualifiers.items())),
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state",
                        Tier.INSTALLED,
                        entry,
                        span=find_span(text, f'"{key}"'),
                        captured=f"{key} (resolved package)",
                    ),
                ),
            )


class DotnetAssemblyCataloger(Cataloger):
    """Assembly identity from CLR metadata (inferred tier: identity, not origin)."""

    id = "dotnet/assembly"
    version = 1
    matchers = [Matcher(basename="*.dll", magic=b"MZ"), Matcher(basename="*.exe", magic=b"MZ")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        from sorb.binary.embedded.clr import parse_assembly_identity

        identity = parse_assembly_identity(blob)
        if identity is None:
            return
        claim = ComponentClaim(
            ctype="library",
            name=identity.name,
            version=identity.version,
            ecosystem="nuget",  # identity only; nuget attribution needs the sig DB
            attrs=(("assembly", "true"),),
        )
        edges = [
            EdgeClaim(kind=EdgeType.INSTANCE_OF, src=ref_file(entry.path), dst=claim.ref())
        ]
        for ref_name, ref_version in identity.references:
            edges.append(
                EdgeClaim(
                    kind=EdgeType.DEPENDS_ON,
                    src=claim.ref(),
                    dst=f"claim:nuget/{ref_name}@{ref_version}",
                    scope=Scope.RUNTIME,
                    direct=True,
                )
            )
        yield Finding(
            claim=claim,
            evidence=(
                ctx.evidence(
                    "assembly-identity",
                    Tier.INFERRED,
                    entry,
                    captured=f"CLR Assembly {identity.name}, Version={identity.version}",
                ),
            ),
            edges=tuple(edges),
        )


register(CsprojCataloger())
register(NugetLockCataloger())
register(ProjectAssetsCataloger())
register(DotnetAssemblyCataloger())
