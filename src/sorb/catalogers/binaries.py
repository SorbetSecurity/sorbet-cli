"""Embedded-metadata catalogers.

Wrap the `sorb.binary.embedded` readers as catalogers so distroless images —
no package DB at all — still produce real inventories: cargo-auditable Rust
binaries, .NET deps.json, and bundled language-runtime detection by directory
structure. (Go buildinfo lives in `sorb.catalogers.golang`.)
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sorb.binary.embedded.sections import ELF_MAGIC, PE_MAGIC
from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, register
from sorb.catalogers.common import ref_family, ref_purl
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


class CargoAuditableCataloger(Cataloger):
    id = "binary/cargo-auditable"
    version = 1
    matchers = [Matcher(magic=ELF_MAGIC), Matcher(magic=PE_MAGIC)]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        from sorb.binary.embedded.cargo_auditable import parse_cargo_auditable

        info = parse_cargo_auditable(blob)
        if info is None:
            return
        refs: list[str] = []
        for pkg in info.packages:
            purl = make_purl("cargo", pkg.name, pkg.version)
            refs.append(purl)
        for i, pkg in enumerate(info.packages):
            purl = refs[i]
            edges: list[EdgeClaim] = []
            for dep_idx in pkg.dependencies:
                if 0 <= dep_idx < len(refs):
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_purl(refs[dep_idx]),
                            scope=Scope.BUILD if pkg.kind == "build" else Scope.RUNTIME,
                            direct=False,
                        )
                    )
            attrs: tuple[tuple[str, str], ...] = (("source", pkg.source),)
            if pkg.kind == "build":
                attrs += (("dev", "true"),)
            yield Finding(
                claim=ComponentClaim(
                    ctype="application" if pkg.root else "library",
                    name=pkg.name,
                    version=pkg.version,
                    purl=purl,
                    ecosystem="cargo",
                    attrs=attrs,
                ),
                evidence=(
                    ctx.evidence(
                        "binary-buildinfo",
                        Tier.INSTALLED,
                        entry,
                        captured=f"cargo-auditable: {pkg.name} {pkg.version}",
                    ),
                ),
                edges=tuple(edges),
            )


class DotnetDepsCataloger(Cataloger):
    id = "dotnet/deps-json"
    version = 1
    matchers = [Matcher(basename="*.deps.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        from sorb.binary.embedded.dotnet import parse_deps_json

        info = parse_deps_json(blob)
        if info is None:
            return
        app_name = entry.path.rsplit("/", 1)[-1].removesuffix(".deps.json")
        for pkg in info.packages:
            if pkg.ptype == "project":
                # the application itself (or a sibling project) — not a nuget package
                yield Finding(
                    claim=ComponentClaim(
                        ctype="application",
                        name=pkg.name,
                        version=pkg.version,
                        ecosystem="nuget",
                        attrs=(("deps-json", app_name),),
                    ),
                    evidence=(
                        ctx.evidence(
                            "installed-state",
                            Tier.INSTALLED,
                            entry,
                            captured=f"{pkg.name}/{pkg.version} (project)",
                        ),
                    ),
                    edges=tuple(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=f"claim:nuget/{pkg.name}@{pkg.version}",
                            dst=ref_family("nuget", dep_name),
                            scope=Scope.RUNTIME,
                            direct=True,
                            requested=dep_version,
                        )
                        for dep_name, dep_version in pkg.dependencies
                    ),
                )
                continue
            purl = make_purl("nuget", pkg.name, pkg.version)
            hashes: tuple[tuple[str, str], ...] = ()
            if pkg.sha512:
                import base64

                try:
                    hashes = (("sha512", base64.b64decode(pkg.sha512).hex()),)
                except (ValueError, TypeError):
                    pass
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=pkg.name,
                    version=pkg.version,
                    purl=purl,
                    ecosystem="nuget",
                    hashes=hashes,
                ),
                evidence=(
                    ctx.evidence(
                        "installed-state",
                        Tier.INSTALLED,
                        entry,
                        captured=f"{pkg.name}/{pkg.version}",
                    ),
                ),
                edges=tuple(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=ref_purl(purl),
                        dst=ref_family("nuget", dep_name),
                        scope=Scope.RUNTIME,
                        direct=False,
                        requested=dep_version,
                    )
                    for dep_name, dep_version in pkg.dependencies
                ),
            )


_PY_VERSION_RE = re.compile(r"(?:^|/)lib/python(3\.\d+)/os\.py$")


class PythonRuntimeCataloger(Cataloger):
    """Bundled CPython detection by directory structure."""

    id = "runtime/python"
    version = 1
    matchers = [Matcher(glob="*lib/python3.*/os.py")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        m = _PY_VERSION_RE.search(entry.path)
        if m is None:
            return
        minor = m.group(1)
        yield Finding(
            claim=ComponentClaim(
                ctype="application",
                name="python",
                version=minor,
                purl=make_purl("generic", "python", minor),
                ecosystem="generic",
                attrs=(("runtime", "true"),),
            ),
            evidence=(
                ctx.evidence(
                    "installed-state",
                    Tier.INSTALLED,
                    entry,
                    captured=f"bundled CPython stdlib at {entry.path.rsplit('/os.py', 1)[0]}",
                    extra_modifiers=("directory-structure (minor version only)",),
                ),
            ),
            annotations=(
                Annotation(
                    code="resolution-incomplete",
                    subject=ref_purl(make_purl("generic", "python", minor)),
                    detail=f"runtime detected by directory structure; patch version unknown ({minor}.x)",
                ),
            ),
        )


_NODE_DEFINE_RE = re.compile(
    rb"#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+(\d+)"
)


class NodeRuntimeCataloger(Cataloger):
    """Bundled Node.js detection via its installed node_version.h header."""

    id = "runtime/node"
    version = 1
    matchers = [Matcher(basename="node_version.h")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        parts = {m.group(1): m.group(2) for m in _NODE_DEFINE_RE.finditer(blob)}
        if not {b"MAJOR", b"MINOR", b"PATCH"} <= set(parts):
            return
        version = b".".join((parts[b"MAJOR"], parts[b"MINOR"], parts[b"PATCH"])).decode()
        yield Finding(
            claim=ComponentClaim(
                ctype="application",
                name="node",
                version=version,
                purl=make_purl("generic", "node", version),
                ecosystem="generic",
                attrs=(("runtime", "true"),),
            ),
            evidence=(
                ctx.evidence(
                    "installed-state",
                    Tier.INSTALLED,
                    entry,
                    captured=f"NODE_VERSION {version} ({entry.path})",
                ),
            ),
        )


register(CargoAuditableCataloger())
register(DotnetDepsCataloger())
register(PythonRuntimeCataloger())
register(NodeRuntimeCataloger())
