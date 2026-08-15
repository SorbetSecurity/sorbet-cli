"""Gradle artifacts + JAR/WAR/EAR analysis.

Gradle builds are programs, so static extraction is inherently partial: we
prefer ``gradle.lockfile`` / ``verification-metadata.xml`` (sha256 digests!) /
``libs.versions.toml``, extract literal coordinates from ``build.gradle(.kts)``
at declared tier, and mark no-lock projects ``resolution: incomplete`` rather
than guessing.

JAR analysis: ``META-INF/maven/**/pom.properties`` gives exact GAV (installed
tier); ``MANIFEST.MF`` identity is inferred tier; Spring Boot
``BOOT-INF/lib/*.jar`` inner jars become CONTAINS children; unidentifiable
class trees get a ``contains-unidentified-classes`` annotation until the
fingerprint DB lands.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_file, ref_project, ref_purl
from sorb.errors import DetectorFailure, TargetError
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
from sorb.source.archive import ArchiveBudget, ArchiveSource
from sorb.source.base import Entry

# -- gradle.lockfile ---------------------------------------------------------------

_LOCK_LINE_RE = re.compile(r"^([\w.\-]+):([\w.\-]+):([\w.\-+]+)=(.+)$")


def _scope_for_configurations(configs: str) -> Scope:
    names = configs.lower()
    if "test" in names:
        return Scope.TEST
    if "compileonly" in names or "annotationprocessor" in names:
        return Scope.BUILD
    return Scope.RUNTIME


class GradleLockfileCataloger(Cataloger):
    id = "jvm/gradle-lockfile"
    version = 1
    matchers = [Matcher(basename="gradle.lockfile")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, proj_dir or ".", "gradle-project")
        proj_ref = ref_project(proj_dir)
        for lineno, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            m = _LOCK_LINE_RE.match(line)
            if not m:
                continue
            group, artifact, version, configs = m.groups()
            purl = make_purl("maven", artifact, version, namespace=group)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=f"{group}:{artifact}",
                    version=version,
                    purl=purl,
                    ecosystem="maven",
                    namespace=group,
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=(lineno, lineno),
                        captured=line[:200],
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_purl(purl),
                        scope=_scope_for_configurations(configs),
                        direct=False,
                    ),
                ),
            )


class GradleVerificationCataloger(Cataloger):
    """`verification-metadata.xml` — locked tier with sha256 per artifact."""

    id = "jvm/gradle-verification"
    version = 1
    matchers = [Matcher(basename="verification-metadata.xml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            root = ET.fromstring(blob.decode("utf-8", errors="replace"))
        except ET.ParseError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e

        def strip(tag: str) -> str:
            return tag.rsplit("}", 1)[-1]

        text = blob.decode("utf-8", errors="replace")
        for comp in root.iter():
            if strip(comp.tag) != "component":
                continue
            group = comp.get("group") or ""
            artifact = comp.get("name") or ""
            version = comp.get("version") or ""
            if not artifact or not version:
                continue
            sha256 = None
            for art in comp:
                for h in art:
                    if strip(h.tag) == "sha256" and h.get("value"):
                        sha256 = h.get("value")
                        break
            purl = make_purl("maven", artifact, version, namespace=group or None)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=f"{group}:{artifact}" if group else artifact,
                    version=version,
                    purl=purl,
                    ecosystem="maven",
                    namespace=group or None,
                    hashes=(("sha256", sha256),) if sha256 else (),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=find_span(text, f'name="{artifact}"'),
                        captured=f"{group}:{artifact}:{version} sha256={sha256 or '?'}",
                    ),
                ),
            )


class GradleVersionCatalogCataloger(Cataloger):
    """`gradle/libs.versions.toml` — declared-tier version catalog."""

    id = "jvm/gradle-version-catalog"
    version = 1
    matchers = [Matcher(basename="libs.versions.toml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        versions = {k: str(v) for k, v in (doc.get("versions") or {}).items() if isinstance(v, str)}
        for alias, lib in (doc.get("libraries") or {}).items():
            group = artifact = version = None
            if isinstance(lib, str):  # "group:artifact:version"
                parts = lib.split(":")
                if len(parts) == 3:
                    group, artifact, version = parts
            elif isinstance(lib, dict):
                module = lib.get("module")
                if isinstance(module, str) and ":" in module:
                    group, _, artifact = module.partition(":")
                else:
                    group, artifact = lib.get("group"), lib.get("name")
                v = lib.get("version")
                if isinstance(v, str):
                    version = v
                elif isinstance(v, dict) and v.get("ref"):
                    version = versions.get(str(v["ref"]))
            if not group or not artifact or not version:
                continue
            purl = make_purl("maven", artifact, version, namespace=group)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=f"{group}:{artifact}",
                    version=version,
                    purl=purl,
                    ecosystem="maven",
                    namespace=group,
                    attrs=(("catalog-alias", str(alias)),),
                ),
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=find_span(text, str(alias)),
                        captured=f"{alias} = {group}:{artifact}:{version}",
                    ),
                ),
            )


_GRADLE_DEP_RE = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
    r"annotationProcessor|classpath)\s*[(\s]\s*['\"]"
    r"([\w.\-]+):([\w.\-]+):([\w.\-+\[\],)(]+)['\"]"
)


class GradleBuildCataloger(Cataloger):
    """Literal extraction from build.gradle(.kts) — declared tier; explicitly
    incomplete when no lock/verification metadata backs it (never guessed)."""

    id = "jvm/gradle-build"
    version = 1
    matchers = [Matcher(basename="build.gradle"), Matcher(basename="build.gradle.kts")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, proj_dir or ".", "gradle-project")
        proj_ref = ref_project(proj_dir)
        prefix = "" if proj_dir == "." else f"{proj_dir}/"
        has_lock = (
            ctx.peek(f"{prefix}gradle.lockfile") is not None
            or ctx.peek(f"{prefix}gradle/verification-metadata.xml") is not None
        )
        emitted = 0
        for m in _GRADLE_DEP_RE.finditer(text):
            group, artifact, version = m.groups()
            concrete = bool(re.fullmatch(r"[\w.\-+]+", version)) and not version.endswith("+")
            purl = make_purl("maven", artifact, version, namespace=group) if concrete else None
            claim = ComponentClaim(
                ctype="library",
                name=f"{group}:{artifact}",
                version=version if concrete else None,
                purl=purl,
                ecosystem="maven",
                namespace=group,
                requested=None if concrete else version,
            )
            line = text.count("\n", 0, m.start()) + 1
            annotations: tuple[Annotation, ...] = ()
            if not has_lock:
                annotations = (
                    Annotation(
                        code="resolution-incomplete",
                        subject=claim.ref(),
                        detail="Gradle build without gradle.lockfile or verification-metadata: "
                        "declared coordinates only (run with --resolve=native, or "
                        "enable dependency locking)",
                    ),
                )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=(line, line),
                        captured=m.group(0)[:200],
                    ),
                ),
                edges=(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=proj_ref,
                        dst=ref_purl(purl) if purl else claim.ref(),
                        scope=Scope.TEST if "test" in m.group(0)[:20].lower() else Scope.RUNTIME,
                        direct=True,
                        requested=version,
                    ),
                ),
                annotations=annotations,
            )
            emitted += 1


# -- JAR / WAR / EAR analysis ---------------------------------------------------------

_ZIP_MAGIC = b"PK\x03\x04"
_POM_PROPS_RE = re.compile(r"^META-INF/maven/([^/]+)/([^/]+)/pom\.properties$")


def _parse_properties(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _parse_manifest(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        if line.startswith(" ") and last:  # 72-byte continuation lines
            out[last] += line[1:]
            continue
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
            last = key.strip()
    return out


class JarCataloger(Cataloger):
    id = "jvm/jar"
    version = 1
    matchers = [
        Matcher(basename="*.jar", magic=_ZIP_MAGIC),
        Matcher(basename="*.war", magic=_ZIP_MAGIC),
        Matcher(basename="*.ear", magic=_ZIP_MAGIC),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        budget = ArchiveBudget(max_depth=3, max_total_bytes=1 << 30, max_members=50_000)
        try:
            jar = ArchiveSource(blob, name=entry.path, budget=budget)
        except TargetError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        yield from self._analyse(ctx, entry, jar, container_ref=None, inner_path="")

    def _analyse(
        self,
        ctx: CatalogerContext,
        entry: Entry,
        jar: ArchiveSource,
        container_ref: str | None,
        inner_path: str,
    ) -> Iterable[Finding]:
        members = jar.member_paths()
        gav_hits: list[tuple[str, str, str, str]] = []  # (g, a, v, member path)
        for path in members:
            m = _POM_PROPS_RE.match(path)
            if m:
                props = _parse_properties(jar.open(path).decode("utf-8", "replace"))
                g = props.get("groupId", m.group(1))
                a = props.get("artifactId", m.group(2))
                v = props.get("version", "")
                if a and v:
                    gav_hits.append((g, a, v, path))

        manifest: dict[str, str] = {}
        if jar.exists("META-INF/MANIFEST.MF"):
            manifest = _parse_manifest(jar.open("META-INF/MANIFEST.MF").decode("utf-8", "replace"))

        where = f"{entry.path}!{inner_path}" if inner_path else entry.path
        self_ref: str | None = None
        # identity of THIS jar: a pom.properties whose artifact matches the
        # filename beats manifest identity
        stem = posixpath.basename(inner_path or entry.path)
        own = next((h for h in gav_hits if stem.startswith(h[1])), None)
        if own is None and len(gav_hits) == 1 and not inner_path:
            own = gav_hits[0]
        if own is not None:
            g, a, v, member = own
            purl = make_purl("maven", a, v, namespace=g)
            self_ref = ref_purl(purl)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=f"{g}:{a}",
                    version=v,
                    purl=purl,
                    ecosystem="maven",
                    namespace=g,
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state",
                        Tier.INSTALLED,
                        entry,
                        captured=f"{where}!{member}: {g}:{a}:{v}",
                    ),
                ),
                edges=(
                    (
                        EdgeClaim(kind=EdgeType.CONTAINS, src=container_ref, dst=ref_purl(purl)),
                    )
                    if container_ref
                    else (
                        EdgeClaim(kind=EdgeType.INSTANCE_OF, src=ref_file(entry.path), dst=ref_purl(purl)),
                    )
                ),
            )
        elif manifest.get("Implementation-Title") or manifest.get("Bundle-SymbolicName"):
            name = manifest.get("Bundle-SymbolicName", manifest.get("Implementation-Title", "")).split(";")[0].strip()
            version = manifest.get("Bundle-Version") or manifest.get("Implementation-Version")
            vendor = manifest.get("Implementation-Vendor-Id") or manifest.get("Implementation-Vendor")
            if name and version:
                purl = make_purl("maven", name.rsplit(".", 1)[-1], version, namespace=vendor or None)
                self_ref = ref_purl(purl)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library",
                        name=name,
                        version=version,
                        purl=purl,
                        ecosystem="maven",
                        namespace=vendor,
                    ),
                    evidence=(
                        ctx.evidence(
                            "jar-manifest",
                            Tier.INFERRED,
                            entry,
                            captured=f"{where}!META-INF/MANIFEST.MF: {name} {version}",
                        ),
                    ),
                    edges=(
                        (EdgeClaim(kind=EdgeType.CONTAINS, src=container_ref, dst=ref_purl(purl)),)
                        if container_ref
                        else ()
                    ),
                )

        # embedded pom.properties for shaded content (other than our own)
        for g, a, v, member in gav_hits:
            if own is not None and (g, a, v) == own[:3]:
                continue
            purl = make_purl("maven", a, v, namespace=g)
            parent_ref = self_ref or container_ref
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=f"{g}:{a}",
                    version=v,
                    purl=purl,
                    ecosystem="maven",
                    namespace=g,
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state",
                        Tier.INSTALLED,
                        entry,
                        captured=f"{where}!{member}: {g}:{a}:{v}",
                    ),
                ),
                edges=(
                    (EdgeClaim(kind=EdgeType.CONTAINS, src=parent_ref, dst=ref_purl(purl)),)
                    if parent_ref
                    else ()
                ),
            )

        # Spring Boot / WAR nested jars → recurse one level as CONTAINS children
        inner_jars = [
            p for p in members
            if (p.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and p.endswith(".jar"))
        ]
        identified_inner: set[str] = set()
        for inner in inner_jars:
            if inner_path:
                continue  # bounded: one nesting level here
            try:
                nested = ArchiveSource(
                    jar.open(inner), name=inner, budget=jar.budget
                )
            except (TargetError, DetectorFailure):
                continue
            produced = list(
                self._analyse(ctx, entry, nested, container_ref=self_ref, inner_path=inner)
            )
            if produced:
                identified_inner.add(inner)
            yield from produced

        unidentified = [p for p in inner_jars if p not in identified_inner and not inner_path]
        has_loose_classes = any(
            p.endswith(".class") and not p.startswith(("BOOT-INF/", "WEB-INF/", "META-INF/"))
            for p in members
        )
        if self_ref and (unidentified or (has_loose_classes and not gav_hits)):
            what = ", ".join(unidentified[:5]) if unidentified else "class trees without pom.properties"
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:gaps"),
                evidence=(
                    ctx.evidence(
                        "jar-manifest", Tier.INFERRED, entry, captured=f"unidentified: {what}"
                    ),
                ),
                annotations=(
                    Annotation(
                        code="contains-unidentified-classes",
                        subject=self_ref,
                        detail=f"{where}: {what} could not be identified statically",
                    ),
                ),
            )


register(GradleLockfileCataloger())
register(GradleVerificationCataloger())
register(GradleVersionCatalogCataloger())
register(GradleBuildCataloger())
register(JarCataloger())
