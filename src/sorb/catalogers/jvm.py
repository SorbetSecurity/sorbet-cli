"""Maven POM cataloger.

Full POM model, statically: parent-chain resolution (repo layout via
``relativePath``/``../pom.xml``; absent parents annotated, never guessed),
property interpolation, ``dependencyManagement`` + BOM imports (in-repo),
default-active profiles (others become marker-conditional edges), and scope
mapping including ``provided`` (excluded-at-runtime annotation).
"""

from __future__ import annotations

import posixpath
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_project, ref_purl
from sorb.errors import DetectorFailure
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

_MAX_POM_BYTES = 8 << 20
_MAX_PARENT_DEPTH = 16
_PROP_RE = re.compile(r"\$\{([^}]+)\}")

_SCOPE_MAP = {
    "compile": Scope.RUNTIME,
    "runtime": Scope.RUNTIME,
    "test": Scope.TEST,
    "provided": Scope.PROVIDED,
    "system": Scope.PROVIDED,
}


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_xml(blob: bytes, what: str) -> ET.Element:
    if len(blob) > _MAX_POM_BYTES:
        raise DetectorFailure(f"{what}: POM exceeds size budget")
    try:
        root = ET.fromstring(blob.decode("utf-8", errors="replace"))
    except ET.ParseError as e:
        raise DetectorFailure(f"{what}: malformed XML: {e}") from e
    return root


def _child_text(node: ET.Element, name: str) -> str | None:
    for child in node:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def _children(node: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in node if _strip_ns(c.tag) == name]


@dataclass
class PomDependency:
    group: str
    artifact: str
    version: str | None  # raw, pre-interpolation
    scope: str | None
    optional: bool
    profile: str | None = None  # non-default profile id, when conditional


@dataclass
class PomModel:
    group: str | None
    artifact: str | None
    version: str | None
    packaging: str
    parent: tuple[str, str, str] | None  # (group, artifact, version)
    parent_relative_path: str | None
    properties: dict[str, str]
    dep_management: dict[tuple[str, str], tuple[str | None, str | None]]  # (g,a) → (version, scope)
    bom_imports: list[tuple[str, str, str]]  # (g, a, version)
    dependencies: list[PomDependency]
    modules: list[str] = field(default_factory=list)


def parse_pom(blob: bytes, what: str = "pom.xml") -> PomModel:
    root = _parse_xml(blob, what)
    parent = None
    parent_rel = None
    parent_el = next(iter(_children(root, "parent")), None)
    if parent_el is not None:
        parent = (
            _child_text(parent_el, "groupId") or "",
            _child_text(parent_el, "artifactId") or "",
            _child_text(parent_el, "version") or "",
        )
        parent_rel = _child_text(parent_el, "relativePath")

    properties: dict[str, str] = {}
    for props in _children(root, "properties"):
        for p in props:
            properties[_strip_ns(p.tag)] = (p.text or "").strip()

    dep_mgmt: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    boms: list[tuple[str, str, str]] = []
    for dm in _children(root, "dependencyManagement"):
        for deps in _children(dm, "dependencies"):
            for d in _children(deps, "dependency"):
                g = _child_text(d, "groupId") or ""
                a = _child_text(d, "artifactId") or ""
                v = _child_text(d, "version")
                scope = _child_text(d, "scope")
                if scope == "import" and _child_text(d, "type") == "pom" and v:
                    boms.append((g, a, v))
                else:
                    dep_mgmt[(g, a)] = (v, scope)

    def deps_of(node: ET.Element, profile: str | None) -> list[PomDependency]:
        out: list[PomDependency] = []
        for deps in _children(node, "dependencies"):
            for d in _children(deps, "dependency"):
                out.append(
                    PomDependency(
                        group=_child_text(d, "groupId") or "",
                        artifact=_child_text(d, "artifactId") or "",
                        version=_child_text(d, "version"),
                        scope=_child_text(d, "scope"),
                        optional=(_child_text(d, "optional") or "") == "true",
                        profile=profile,
                    )
                )
        return out

    dependencies = deps_of(root, None)
    for profiles in _children(root, "profiles"):
        for prof in _children(profiles, "profile"):
            pid = _child_text(prof, "id") or "unnamed"
            activation = next(iter(_children(prof, "activation")), None)
            active = (
                activation is not None
                and (_child_text(activation, "activeByDefault") or "") == "true"
            )
            dependencies.extend(deps_of(prof, None if active else pid))

    modules: list[str] = []
    for mods in _children(root, "modules"):
        modules.extend(m for m in ((_m.text or "").strip() for _m in _children(mods, "module")) if m)

    return PomModel(
        group=_child_text(root, "groupId"),
        artifact=_child_text(root, "artifactId"),
        version=_child_text(root, "version"),
        packaging=_child_text(root, "packaging") or "jar",
        parent=parent,
        parent_relative_path=parent_rel,
        properties=properties,
        dep_management=dep_mgmt,
        bom_imports=boms,
        dependencies=dependencies,
        modules=modules,
    )


class MavenPomCataloger(Cataloger):
    id = "jvm/maven-pom"
    version = 1
    matchers = [Matcher(basename="pom.xml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        pom = parse_pom(blob, entry.path)
        proj_dir = dirname_of(entry.path)
        annotations: list[Annotation] = []

        # ---- parent chain (repo layout; absent parents annotated) -------------
        chain = [pom]
        node, node_dir = pom, proj_dir
        for _ in range(_MAX_PARENT_DEPTH):
            if node.parent is None:
                break
            rel = node.parent_relative_path or "../pom.xml"
            if not rel.endswith(".xml"):
                rel = posixpath.join(rel, "pom.xml")
            parent_path = posixpath.normpath(posixpath.join(node_dir, rel))
            raw = ctx.peek(parent_path)
            if raw is None:
                annotations.append(
                    Annotation(
                        code="unresolved-parent",
                        subject=ref_project(proj_dir),
                        detail=f"parent {':'.join(node.parent)} not found at {parent_path} "
                        "(not in this repo; resolution via ~/.m2 or network is out of static scope)",
                    )
                )
                break
            parent_pom = parse_pom(raw, parent_path)
            chain.append(parent_pom)
            node, node_dir = parent_pom, dirname_of(parent_path)

        # ---- effective model: child wins over parent ---------------------------
        properties: dict[str, str] = {}
        dep_mgmt: dict[tuple[str, str], tuple[str | None, str | None]] = {}
        for p in reversed(chain):  # root-most parent first, child overrides
            properties.update(p.properties)
            dep_mgmt.update(p.dep_management)

        group = pom.group or (pom.parent[0] if pom.parent else None)
        version = pom.version or (pom.parent[2] if pom.parent else None)
        artifact = pom.artifact or "unknown"
        if group:
            properties.setdefault("project.groupId", group)
        if version:
            properties.setdefault("project.version", version)
            properties.setdefault("version", version)

        def interpolate(value: str | None, depth: int = 0) -> str | None:
            if value is None or depth > 8:
                return value

            def sub(m: re.Match[str]) -> str:
                return properties.get(m.group(1), m.group(0))

            out = _PROP_RE.sub(sub, value)
            return interpolate(out, depth + 1) if out != value and "${" in out else out

        # ---- BOM imports (in-repo only; anything else is annotated) ------------
        for bg, ba, bv in [
            (g, a, interpolate(v) or v) for p in reversed(chain) for (g, a, v) in p.bom_imports
        ]:
            imported = self._find_bom(ctx, proj_dir, bg, ba)
            if imported is None:
                annotations.append(
                    Annotation(
                        code="unresolved-import",
                        subject=ref_project(proj_dir),
                        detail=f"BOM {bg}:{ba}:{bv} not found in repo; its managed versions "
                        "are unavailable to static resolution",
                    )
                )
                continue
            bom = parse_pom(imported, f"{bg}:{ba}")
            for key, managed_entry in bom.dep_management.items():
                dep_mgmt.setdefault(key, managed_entry)

        ctx.declare_project(proj_dir, f"{group}:{artifact}" if group else artifact, "maven-module")
        proj_ref = ref_project(proj_dir)
        text = blob.decode("utf-8", errors="replace")

        # the module itself (versioned modules only; DESCRIBES via project)
        if group and version and not version.startswith("${"):
            self_purl = make_purl("maven", artifact, interpolate(version), namespace=group)
            yield Finding(
                claim=ComponentClaim(
                    ctype="application" if pom.packaging in ("war", "ear") else "library",
                    name=f"{group}:{artifact}",
                    version=interpolate(version),
                    purl=self_purl,
                    ecosystem="maven",
                    namespace=group,
                    attrs=(("packaging", pom.packaging), ("module", proj_dir)),
                ),
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=find_span(text, f"<artifactId>{artifact}</artifactId>"),
                        captured=f"{group}:{artifact}:{interpolate(version)}",
                    ),
                ),
                annotations=tuple(annotations),
            )
            annotations = []

        for dep in pom.dependencies:
            g = interpolate(dep.group) or dep.group
            a = interpolate(dep.artifact) or dep.artifact
            raw_version = dep.version
            managed = dep_mgmt.get((g, a))
            if raw_version is None and managed is not None:
                raw_version = managed[0]
            v: str | None = interpolate(raw_version)
            scope_name = dep.scope or (managed[1] if managed else None) or "compile"
            scope = _SCOPE_MAP.get(scope_name, Scope.RUNTIME)

            dep_annotations: list[Annotation] = []
            if v is None or "${" in (v or ""):
                subject = f"claim:maven/{g}:{a}@"
                dep_annotations.append(
                    Annotation(
                        code="resolution-incomplete",
                        subject=subject,
                        detail=f"{g}:{a}: no version in POM chain or dependencyManagement "
                        "(central-repo mediation requires network resolution)",
                    )
                )
                v = None
            purl = make_purl("maven", a, v, namespace=g) if v else None
            claim = ComponentClaim(
                ctype="library",
                name=f"{g}:{a}",
                version=v,
                purl=purl,
                ecosystem="maven",
                namespace=g,
                requested=dep.version if dep.version and dep.version != v else None,
                attrs=(("maven-scope", scope_name),) + ((("optional", "true"),) if dep.optional else ()),
            )
            if scope_name == "provided":
                dep_annotations.append(
                    Annotation(
                        code="provided-scope",
                        subject=claim.ref(),
                        detail=f"{g}:{a} is provided at runtime by the container "
                        "(excluded from the runtime dependency set)",
                    )
                )
            edge = EdgeClaim(
                kind=EdgeType.DEPENDS_ON,
                src=proj_ref,
                dst=ref_purl(purl) if purl else claim.ref(),
                scope=scope,
                direct=True,
                requested=dep.version,
                marker=f"profile:{dep.profile}" if dep.profile else None,
            )
            span = find_span(text, f"<artifactId>{dep.artifact}</artifactId>")
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=span,
                        captured=f"{g}:{a}:{v or dep.version or '?'} (scope {scope_name})",
                    ),
                ),
                edges=(edge,),
                annotations=tuple(dep_annotations) + tuple(annotations),
            )
            annotations = []

    def _find_bom(self, ctx: CatalogerContext, proj_dir: str, group: str, artifact: str) -> bytes | None:
        """Locate an imported BOM inside the repo (conventional spots only)."""
        candidates = [
            posixpath.normpath(posixpath.join(proj_dir, rel))
            for rel in (f"{artifact}/pom.xml", f"../{artifact}/pom.xml", "bom/pom.xml")
        ]
        for cand in candidates:
            raw = ctx.peek(cand)
            if raw is None:
                continue
            try:
                pom = parse_pom(raw, cand)
            except DetectorFailure:
                continue
            if pom.artifact == artifact and (pom.group == group or pom.group is None):
                return raw
        return None


register(MavenPomCataloger())
