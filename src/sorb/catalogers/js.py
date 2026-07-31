"""JavaScript / TypeScript catalogers.

- ``js/package-json`` — manifests: all dep classes, workspaces → Project
  nodes, ``packageManager`` → build-tool component, aliases, git/file deps,
  bundledDependencies → CONTAINS.
- ``js/npm-lock`` — package-lock.json v1/v2/v3 with nearest-ancestor
  resolution; SRI integrity decoded to hashes.
- ``js/pnpm-lock`` — pnpm-lock.yaml v5/v6/v9; ``importers`` give exact
  per-project direct-vs-transitive attribution.
- ``js/yarn-lock`` — yarn.lock classic (quasi-YAML) and Berry (real YAML).
- ``js/node-modules`` — installed state: node_modules/**/package.json
  including the .pnpm virtual store → INSTANCE_OF edges.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

import yaml

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
    snippet_at,
)
from sorb.catalogers.common import (
    decode_sri,
    dirname_of,
    ref_family,
    ref_file,
    ref_project,
    ref_purl,
)
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

_DEP_SCOPES: list[tuple[str, Scope]] = [
    ("dependencies", Scope.RUNTIME),
    ("devDependencies", Scope.DEV),
    ("peerDependencies", Scope.PROVIDED),
    ("optionalDependencies", Scope.OPTIONAL),
]


def _npm_purl(name: str, version: str | None = None, qualifiers: dict[str, str] | None = None) -> str:
    namespace = None
    pname = name
    if name.startswith("@") and "/" in name:
        namespace, pname = name.split("/", 1)
    return make_purl("npm", pname, version, namespace=namespace, qualifiers=qualifiers)


def _in_node_modules(path: str) -> bool:
    return "node_modules/" in path or path.startswith("node_modules")


class PackageJsonCataloger(Cataloger):
    id = "js/package-json"
    version = 1
    matchers = [Matcher(basename="package.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if _in_node_modules(entry.path):
            return  # installed state belongs to js/node-modules
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_name = str(doc.get("name") or proj_dir)
        project = ctx.declare_project(proj_dir, proj_name, "npm")
        proj_ref = ref_project(project.path)

        # packageManager pin → build-tool component
        pm = doc.get("packageManager")
        if isinstance(pm, str) and "@" in pm:
            tool, _, tool_ver = pm.partition("@")
            tool_ver = tool_ver.split("+", 1)[0]
            yield Finding(
                claim=ComponentClaim(
                    ctype="build-tool",
                    name=tool,
                    version=tool_ver,
                    purl=_npm_purl(tool, tool_ver),
                    ecosystem="npm",
                ),
                evidence=(
                    ctx.evidence(
                        "manifest-parse",
                        Tier.DECLARED,
                        entry,
                        span=find_span(text, "packageManager"),
                        captured=snippet_at(text, "packageManager"),
                    ),
                ),
            )

        bundled = doc.get("bundledDependencies") or doc.get("bundleDependencies") or []
        root_ref = proj_ref

        for section, scope in _DEP_SCOPES:
            deps = doc.get(section)
            if not isinstance(deps, dict):
                continue
            for raw_name, raw_range in deps.items():
                if not isinstance(raw_range, str):
                    continue
                name, rng, qualifiers, attrs = _resolve_alias(raw_name, raw_range)
                claim = ComponentClaim(
                    ctype="library",
                    name=name,
                    version=None,
                    purl=None,  # no version — never guess
                    ecosystem="npm",
                    requested=rng,
                    qualifiers=tuple(sorted(qualifiers.items())),
                    attrs=tuple(sorted(attrs.items())),
                )
                ev = ctx.evidence(
                    "manifest-parse",
                    Tier.DECLARED,
                    entry,
                    span=find_span(text, f'"{raw_name}"'),
                    captured=snippet_at(text, f'"{raw_name}"'),
                )
                edge = EdgeClaim(
                    kind=EdgeType.DEPENDS_ON,
                    src=root_ref,
                    dst=ref_family("npm", name),
                    scope=scope,
                    direct=True,
                    requested=rng,
                )
                contains: tuple[EdgeClaim, ...] = ()
                if isinstance(bundled, list) and raw_name in bundled:
                    contains = (
                        EdgeClaim(
                            kind=EdgeType.CONTAINS,
                            src=root_ref,
                            dst=ref_family("npm", name),
                        ),
                    )
                yield Finding(claim=claim, evidence=(ev,), edges=(edge, *contains))


def _resolve_alias(
    raw_name: str, raw_range: str
) -> tuple[str, str, dict[str, str], dict[str, str]]:
    """Handle npm alias / git / file / link specifiers."""
    name, rng = raw_name, raw_range
    qualifiers: dict[str, str] = {}
    attrs: dict[str, str] = {}
    if raw_range.startswith("npm:"):
        spec = raw_range[4:]
        real, _, real_range = spec.rpartition("@")
        if real:
            name, rng = real, real_range or "*"
            attrs["alias-of"] = raw_name
    elif raw_range.startswith(("git+", "git:", "github:")):
        qualifiers["vcs_url"] = raw_range
        attrs["source"] = "git"
        rng = "*"
    elif raw_range.startswith(("file:", "link:")):
        attrs["source"] = raw_range
        rng = "*"
    return name, rng, qualifiers, attrs


class NpmLockCataloger(Cataloger):
    id = "js/npm-lock"
    version = 1
    matchers = [Matcher(basename="package-lock.json"), Matcher(basename="npm-shrinkwrap.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        if _in_node_modules(entry.path):
            return
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        lock_version = int(doc.get("lockfileVersion", 1))
        if lock_version >= 2 and isinstance(doc.get("packages"), dict):
            yield from self._parse_v2(ctx, entry, doc, text, proj_dir)
        elif isinstance(doc.get("dependencies"), dict):
            yield from self._parse_v1(ctx, entry, doc, text, proj_ref)

    # -- v2/v3: `packages` map with nearest-ancestor resolution ----------------

    def _parse_v2(
        self,
        ctx: CatalogerContext,
        entry: Entry,
        doc: dict[str, Any],
        text: str,
        proj_dir: str,
    ) -> Iterable[Finding]:
        packages: dict[str, Any] = doc["packages"]

        def name_of(key: str, info: dict[str, Any]) -> str | None:
            if info.get("name"):
                return str(info["name"])
            if "node_modules/" in key:
                return key.rsplit("node_modules/", 1)[1]
            return None

        def resolve(from_key: str, dep: str) -> str | None:
            """npm nearest-ancestor resolution over the packages map.

            Walks outward from the dependent's own ``node_modules`` to the
            root, mirroring how node resolves at runtime.
            """
            base = from_key
            while True:
                candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                if candidate in packages:
                    return candidate
                if not base:
                    return None
                head, sep, _ = base.rpartition("node_modules/")
                base = head.rstrip("/") if sep else ""

        purl_by_key: dict[str, str] = {}
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link"):
                continue
            nm = name_of(key, info)
            ver = info.get("version")
            if not nm or not ver:
                continue
            purl_by_key[key] = _npm_purl(nm, str(ver))

        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            if key == "":
                # root: direct dep edges with scope, per section
                for section, scope in _DEP_SCOPES:
                    for dep in (info.get(section) or {}):
                        target = resolve("", dep)
                        if target and target in purl_by_key:
                            yield Finding(
                                claim=_stub_claim(),
                                evidence=(),
                                edges=(
                                    EdgeClaim(
                                        kind=EdgeType.DEPENDS_ON,
                                        src=ref_project(proj_dir),
                                        dst=ref_purl(purl_by_key[target]),
                                        scope=scope,
                                        direct=True,
                                        requested=str((info.get(section) or {}).get(dep, "")),
                                    ),
                                ),
                            )
                continue
            if key not in purl_by_key:
                continue
            nm = name_of(key, info) or ""
            ver = str(info.get("version"))
            hashes: tuple[tuple[str, str], ...] = ()
            if isinstance(info.get("integrity"), str):
                decoded = decode_sri(info["integrity"])
                if decoded:
                    hashes = (decoded,)
            edges: list[EdgeClaim] = []
            for dep, rng in (info.get("dependencies") or {}).items():
                target = resolve(key, dep)
                if target and target in purl_by_key:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl_by_key[key]),
                            dst=ref_purl(purl_by_key[target]),
                            requested=str(rng),
                            direct=False,
                        )
                    )
            v2_attrs: list[tuple[str, str]] = []
            if info.get("dev"):
                v2_attrs.append(("dev", "true"))
            if info.get("optional"):
                v2_attrs.append(("optional", "true"))
            if info.get("os") or info.get("cpu"):
                v2_attrs.append(("conditional", "platform"))
            claim = ComponentClaim(
                ctype="library",
                name=nm,
                version=ver,
                purl=purl_by_key[key],
                ecosystem="npm",
                hashes=hashes,
                attrs=tuple(v2_attrs),
            )
            ev = ctx.evidence(
                "lockfile-parse",
                Tier.LOCKED,
                entry,
                span=find_span(text, f'"{key}"'),
                captured=snippet_at(text, f'"{key}"', context=2),
            )
            yield Finding(claim=claim, evidence=(ev,), edges=tuple(edges))

    # -- v1: nested dependencies tree ------------------------------------------

    def _parse_v1(
        self,
        ctx: CatalogerContext,
        entry: Entry,
        doc: dict[str, Any],
        text: str,
        proj_ref: str,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []

        def walk(
            tree: dict[str, Any], scope_stack: list[dict[str, Any]], depth: int
        ) -> None:
            for name, info in tree.items():
                if not isinstance(info, dict) or not info.get("version"):
                    continue
                ver = str(info["version"])
                purl = _npm_purl(name, ver)
                hashes: tuple[tuple[str, str], ...] = ()
                if isinstance(info.get("integrity"), str):
                    decoded = decode_sri(info["integrity"])
                    if decoded:
                        hashes = (decoded,)
                edges: list[EdgeClaim] = []
                if depth == 0:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_purl(purl),
                            scope=Scope.DEV if info.get("dev") else Scope.RUNTIME,
                            direct=True,
                        )
                    )
                for req_name in (info.get("requires") or {}):
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_family("npm", req_name),
                            direct=False,
                        )
                    )
                ev = ctx.evidence(
                    "lockfile-parse",
                    Tier.LOCKED,
                    entry,
                    span=find_span(text, f'"{name}"'),
                    captured=snippet_at(text, f'"{name}"', context=1),
                )
                findings.append(
                    Finding(
                        claim=ComponentClaim(
                            ctype="library",
                            name=name,
                            version=ver,
                            purl=purl,
                            ecosystem="npm",
                            hashes=hashes,
                            attrs=(("dev", "true"),) if info.get("dev") else (),
                        ),
                        evidence=(ev,),
                        edges=tuple(edges),
                    )
                )
                if isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"], scope_stack, depth + 1)

        walk(doc["dependencies"], [], 0)
        yield from findings


def _stub_claim() -> ComponentClaim:
    """Edge-only findings carry a stub claim that reconcile drops."""
    return ComponentClaim(ctype="edge-only", name="__edges__")


_PNPM_KEY_RE = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)[@/](.+)$")


class PnpmLockCataloger(Cataloger):
    id = "js/pnpm-lock"
    version = 1
    matchers = [Matcher(basename="pnpm-lock.yaml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = yaml.safe_load(blob)
        except yaml.YAMLError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        text = blob.decode("utf-8", errors="replace")
        base_dir = dirname_of(entry.path)

        def norm_version(v: str) -> str:
            # "1.2.3(react@18.2.0)" → "1.2.3"; "/foo@1.2.3" → "1.2.3"
            v = v.split("(", 1)[0]
            m = _PNPM_KEY_RE.match(v)
            if m and v.startswith("/"):
                return m.group(2)
            return v

        packages = doc.get("packages") or {}
        snapshots = doc.get("snapshots") or {}  # v9

        # optional (platform-specific) packages: flagged, exempt from drift
        optional_keys: set[tuple[str, str]] = set()
        for holder in (packages, snapshots):
            for key, info in holder.items():
                m = _PNPM_KEY_RE.match(str(key))
                if m and isinstance(info, dict) and info.get("optional") is True:
                    optional_keys.add((m.group(1), norm_version(m.group(2))))

        claims: dict[tuple[str, str], ComponentClaim] = {}
        for key, info in packages.items():
            m = _PNPM_KEY_RE.match(str(key))
            if not m:
                continue
            name, ver = m.group(1), norm_version(m.group(2))
            hashes: tuple[tuple[str, str], ...] = ()
            resolution = (info or {}).get("resolution") or {}
            if isinstance(resolution, dict) and isinstance(resolution.get("integrity"), str):
                decoded = decode_sri(resolution["integrity"])
                if decoded:
                    hashes = (decoded,)
            attr_list: list[tuple[str, str]] = []
            if (info or {}).get("dev") is True:
                attr_list.append(("dev", "true"))
            if (name, ver) in optional_keys:
                attr_list.append(("optional", "true"))
            if isinstance(info, dict) and (info.get("os") or info.get("cpu")):
                attr_list.append(("conditional", "platform"))
            attrs: tuple[tuple[str, str], ...] = tuple(attr_list)
            claims[(name, ver)] = ComponentClaim(
                ctype="library",
                name=name,
                version=ver,
                purl=_npm_purl(name, ver),
                ecosystem="npm",
                hashes=hashes,
                attrs=attrs,
            )

        # dependency edges: v9 snapshots hold deps; v5/v6 packages hold deps
        dep_holder = snapshots if snapshots else packages
        edges_by_pkg: dict[tuple[str, str], list[EdgeClaim]] = {}
        for key, info in dep_holder.items():
            m = _PNPM_KEY_RE.match(str(key))
            if not m or not isinstance(info, dict):
                continue
            name, ver = m.group(1), norm_version(m.group(2))
            if (name, ver) not in claims:
                continue
            src = ref_purl(claims[(name, ver)].purl or "")
            for section, sec_scope in (
                ("dependencies", None),
                ("optionalDependencies", Scope.OPTIONAL),
            ):
                for dep_name, dep_ver in (info.get(section) or {}).items():
                    dv = norm_version(str(dep_ver))
                    edges_by_pkg.setdefault((name, ver), []).append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=src,
                            dst=ref_purl(_npm_purl(str(dep_name), dv)),
                            direct=False,
                            scope=sec_scope,
                        )
                    )

        for (name, ver), claim in sorted(claims.items()):
            ev = ctx.evidence(
                "lockfile-parse",
                Tier.LOCKED,
                entry,
                span=find_span(text, f"{name}@{ver}") or find_span(text, f"/{name}@{ver}")
                or find_span(text, f"/{name}/{ver}"),
                captured=None,
            )
            yield Finding(
                claim=claim,
                evidence=(ev,),
                edges=tuple(edges_by_pkg.get((name, ver), ())),
            )

        # importers → per-project direct deps (exact attribution)
        importers = doc.get("importers")
        if not isinstance(importers, dict):
            importers = {".": {k: doc.get(k) for k, _ in _PNPM_IMPORTER_SECTIONS}}
        for imp_path, sections in importers.items():
            if not isinstance(sections, dict):
                continue
            rel = imp_path if imp_path != "." else base_dir
            if base_dir != "." and imp_path != ".":
                rel = f"{base_dir}/{imp_path}"
            proj_ref = ref_project(rel)
            for section, scope in _PNPM_IMPORTER_SECTIONS:
                deps = sections.get(section)
                if not isinstance(deps, dict):
                    continue
                for dep_name, spec in deps.items():
                    if isinstance(spec, dict):
                        ver = norm_version(str(spec.get("version", "")))
                        requested = str(spec.get("specifier", ""))
                    else:
                        ver = norm_version(str(spec))
                        requested = ""
                    if not ver:
                        continue
                    yield Finding(
                        claim=_stub_claim(),
                        evidence=(),
                        edges=(
                            EdgeClaim(
                                kind=EdgeType.DEPENDS_ON,
                                src=proj_ref,
                                dst=ref_purl(_npm_purl(str(dep_name), ver)),
                                scope=scope,
                                direct=True,
                                requested=requested,
                            ),
                        ),
                    )


_PNPM_IMPORTER_SECTIONS: list[tuple[str, Scope]] = [
    ("dependencies", Scope.RUNTIME),
    ("devDependencies", Scope.DEV),
    ("optionalDependencies", Scope.OPTIONAL),
]

_YARN_SELECTOR_RE = re.compile(r'^"?((?:@[^/@"]+/)?[^@/"]+)@')


class YarnLockCataloger(Cataloger):
    id = "js/yarn-lock"
    version = 1
    matchers = [Matcher(basename="yarn.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        if "__metadata:" in text:
            yield from self._parse_berry(ctx, entry, text)
        else:
            yield from self._parse_classic(ctx, entry, text)

    def _parse_berry(self, ctx: CatalogerContext, entry: Entry, text: str) -> Iterable[Finding]:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        for key, info in doc.items():
            if key == "__metadata" or not isinstance(info, dict):
                continue
            version = info.get("version")
            resolution = str(info.get("resolution", ""))
            if not version or "@workspace:" in resolution:
                continue
            m = _YARN_SELECTOR_RE.match(str(key).split(",")[0].strip())
            if not m:
                continue
            name = m.group(1)
            attrs: tuple[tuple[str, str], ...] = ()
            if "@patch:" in resolution:
                attrs = (("modified", "true"), ("patch-source", resolution[:200]))
            edges = []
            src = ref_purl(_npm_purl(name, str(version)))
            for dep_name in (info.get("dependencies") or {}):
                edges.append(
                    EdgeClaim(
                        kind=EdgeType.DEPENDS_ON,
                        src=src,
                        dst=ref_family("npm", str(dep_name)),
                        direct=False,
                    )
                )
            ann = (
                (
                    Annotation(
                        code="patched-dependency",
                        subject=src,
                        detail=f"patched via {resolution[:200]}",
                    ),
                )
                if attrs
                else ()
            )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=str(version),
                    purl=_npm_purl(name, str(version)),
                    ecosystem="npm",
                    attrs=attrs,
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse",
                        Tier.LOCKED,
                        entry,
                        span=find_span(text, str(key).split(",")[0].strip().strip('"')),
                    ),
                ),
                edges=tuple(edges),
                annotations=ann,
            )

    def _parse_classic(self, ctx: CatalogerContext, entry: Entry, text: str) -> Iterable[Finding]:
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line or line.startswith("#") or line.startswith(" "):
                i += 1
                continue
            if line.rstrip().endswith(":"):
                selectors = [s.strip().strip('"') for s in line.rstrip()[:-1].split(",")]
                name = None
                first = selectors[0]
                if first.startswith("@"):
                    parts = first.rsplit("@", 1)
                    name = parts[0] if len(parts) == 2 else first
                else:
                    name = first.rsplit("@", 1)[0] if "@" in first else first
                version = None
                integrity = None
                deps: list[str] = []
                j = i + 1
                in_deps = False
                while j < len(lines) and (lines[j].startswith(" ") or not lines[j].strip()):
                    body = lines[j].strip()
                    if body.startswith("version"):
                        version = body.split(None, 1)[1].strip().strip('"')
                        in_deps = False
                    elif body.startswith("integrity"):
                        integrity = body.split(None, 1)[1].strip().strip('"')
                        in_deps = False
                    elif body == "dependencies:":
                        in_deps = True
                    elif in_deps and body:
                        deps.append(body.split(None, 1)[0].strip('"'))
                    j += 1
                if name and version:
                    hashes: tuple[tuple[str, str], ...] = ()
                    if integrity:
                        decoded = decode_sri(integrity)
                        if decoded:
                            hashes = (decoded,)
                    purl = _npm_purl(name, version)
                    yield Finding(
                        claim=ComponentClaim(
                            ctype="library",
                            name=name,
                            version=version,
                            purl=purl,
                            ecosystem="npm",
                            hashes=hashes,
                        ),
                        evidence=(
                            ctx.evidence(
                                "lockfile-parse",
                                Tier.LOCKED,
                                entry,
                                span=(i + 1, j),
                                captured="\n".join(lines[i : min(j, i + 6)]),
                            ),
                        ),
                        edges=tuple(
                            EdgeClaim(
                                kind=EdgeType.DEPENDS_ON,
                                src=ref_purl(purl),
                                dst=ref_family("npm", d),
                                direct=False,
                            )
                            for d in deps
                        ),
                    )
                i = j
            else:
                i += 1


_NM_PKG_RE = re.compile(
    r"(?:^|/)node_modules/(\.pnpm/[^/]+/node_modules/)?((?:@[^/]+/)?[^/@.][^/]*)/package\.json$"
)


class NodeModulesCataloger(Cataloger):
    id = "js/node-modules"
    #: 2 — aliased installs (dir name != declared name) are real packages.
    version = 2
    matchers = [Matcher(glob="*node_modules/*package.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        m = _NM_PKG_RE.search(entry.path)
        if not m:
            return
        try:
            doc = json.loads(blob)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return  # junk package.json inside a package's dist — not evidence
        if not isinstance(doc, dict):
            return
        name = doc.get("name")
        version = doc.get("version")
        if not name or not version:
            return
        # An npm *alias* install deliberately puts a package in a directory of
        # another name (`npm i wrap-ansi-cjs@npm:wrap-ansi@7.0.0`), so the two
        # disagreeing is normal, not junk. What is actually installed is what
        # the manifest declares, and the directory is recorded alongside it —
        # requiring them to match dropped every aliased package on the floor.
        dir_name = m.group(2)
        declared = str(name)
        aliased = not (declared == dir_name or declared.endswith("/" + dir_name))
        purl = _npm_purl(str(name), str(version))
        license_val = doc.get("license")
        yield Finding(
            claim=ComponentClaim(
                ctype="library",
                name=str(name),
                version=str(version),
                purl=purl,
                ecosystem="npm",
                licenses_declared=license_val if isinstance(license_val, str) else None,
                attrs=(("installed-as", dir_name),) if aliased else (),
            ),
            evidence=(
                ctx.evidence("installed-state", Tier.INSTALLED, entry, span=(1, 1)),
            ),
            edges=(
                EdgeClaim(
                    kind=EdgeType.INSTANCE_OF,
                    src=ref_file(entry.path),
                    dst=ref_purl(purl),
                ),
            ),
        )


register(PackageJsonCataloger())
register(NpmLockCataloger())
register(PnpmLockCataloger())
register(YarnLockCataloger())
register(NodeModulesCataloger())


# -- Bun -------------------------------------------------------------------------

#: `bun.lock` is JSONC: bun writes trailing commas, which strict JSON rejects.
#: Only commas that directly precede a closing brace/bracket are removed, and
#: never inside a string, so integrity values survive untouched.
_TRAILING_COMMA_RE = re.compile(r",(?=\s*[}\]])")
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def strip_jsonc_trailing_commas(text: str) -> str:
    """Remove trailing commas outside string literals."""
    out: list[str] = []
    last = 0
    for m in _STRING_RE.finditer(text):
        out.append(_TRAILING_COMMA_RE.sub("", text[last : m.start()]))
        out.append(m.group(0))  # strings pass through verbatim
        last = m.end()
    out.append(_TRAILING_COMMA_RE.sub("", text[last:]))
    return "".join(out)


#: `@scope/name@1.2.3` → ("@scope/name", "1.2.3"). A protocol version
#: (`github:…`, `workspace:*`, `file:…`) is not a released version.
def split_name_version(spec: str) -> tuple[str, str | None]:
    name, sep, version = spec.rpartition("@")
    if not sep or not name:  # bare name, or a leading-@ scope with no version
        return spec, None
    if ":" in version:  # protocol reference, not a version
        return name, None
    return name, version or None


class BunLockCataloger(Cataloger):
    """`bun.lock` — Bun's text lockfile (default since Bun 1.2)."""

    id = "js/bun-lock"
    version = 1
    matchers = [Matcher(basename="bun.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(strip_jsonc_trailing_commas(text))
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        packages = doc.get("packages")
        if not isinstance(packages, dict):
            return
        for key, value in packages.items():
            # ["name@version", registry, {meta}, "sha512-…"]
            if not isinstance(value, list) or not value or not isinstance(value[0], str):
                continue
            name, version = split_name_version(value[0])
            if not name:
                continue
            integrity = next(
                (v for v in value[1:] if isinstance(v, str) and v.startswith("sha")), None
            )
            decoded = decode_sri(integrity) if integrity else None
            hashes: tuple[tuple[str, str], ...] = (decoded,) if decoded else ()
            purl = make_purl("npm", name, version) if version else None
            claim = ComponentClaim(
                ctype="library", name=name, version=version, purl=purl, ecosystem="npm",
                hashes=hashes,
                attrs=(("bun-key", str(key)),) if str(key) != name else (),
            )
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                 span=find_span(text, value[0]),
                                 captured=snippet_at(text, value[0])),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                              dst=ref_purl(purl) if purl else ref_family("npm", name),
                              scope=Scope.RUNTIME, direct=False),
                ),
            )


# -- Deno ------------------------------------------------------------------------

#: A deno.lock key: `@scope/name@1.2.3`, optionally followed by `_peer@ver`
#: suffixes recording peer resolution. Semver never contains an underscore, so
#: the version ends at the first one.
_DENO_KEY_RE = re.compile(r"^(?P<name>@[^/@]+/[^@]+|[^@][^@]*)@(?P<version>[0-9][^_]*)")


class DenoLockCataloger(Cataloger):
    """`deno.lock` — the `jsr` and `npm` sections are the resolved set.

    They are different registries, so they keep different purl types rather
    than being flattened into one ecosystem.
    """

    id = "js/deno-lock"
    version = 1
    matchers = [Matcher(basename="deno.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        proj_ref = ref_project(dirname_of(entry.path))
        for section, purl_type in (("jsr", "jsr"), ("npm", "npm")):
            entries = doc.get(section)
            if not isinstance(entries, dict):
                continue
            seen: set[tuple[str, str]] = set()
            for key, meta in entries.items():
                m = _DENO_KEY_RE.match(str(key))
                if not m:
                    continue
                name, version = m.group("name"), m.group("version")
                if (name, version) in seen:
                    continue  # same package, different peer resolution
                seen.add((name, version))
                integrity = (meta or {}).get("integrity") if isinstance(meta, dict) else None
                hashes: tuple[tuple[str, str], ...] = ()
                if isinstance(integrity, str) and integrity:
                    # npm entries carry SRI (`sha512-<b64>`); jsr entries carry a
                    # bare hex digest.
                    decoded = decode_sri(integrity) if "-" in integrity else None
                    if decoded:
                        hashes = (decoded,)
                    elif "-" not in integrity:
                        hashes = (("sha256", integrity),)
                purl = make_purl(purl_type, name, version)
                yield Finding(
                    claim=ComponentClaim(
                        ctype="library", name=name, version=version, purl=purl,
                        ecosystem=purl_type, hashes=hashes,
                    ),
                    evidence=(
                        ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                     span=find_span(text, str(key)),
                                     captured=str(key)[:120]),
                    ),
                    edges=(
                        EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                                  scope=Scope.RUNTIME, direct=False),
                    ),
                )


register(BunLockCataloger())
register(DenoLockCataloger())
