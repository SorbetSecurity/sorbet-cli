"""Long-tail lockfile catalogers that need small hand parsers.

The purely-declarative formats live in `table_specs.py`; these have quirks:
Elixir terms (mix.lock), hackage coordinate strings (stack.yaml.lock),
constraint lines (cabal freeze), three schema generations (Package.resolved),
an indentation graph (Podfile.lock), word lines (Cartfile.resolved), Zig
object notation (build.zig.zon), and Cargo.toml workspace inheritance.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable

import yaml

from sorb.catalogers.base import (
    Cataloger,
    CatalogerContext,
    Matcher,
    find_span,
    register,
)
from sorb.catalogers.common import dirname_of, ref_family, ref_project, ref_purl
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

# -- Elixir mix.lock -------------------------------------------------------------

_MIX_RE = re.compile(
    r'^\s*"([\w_]+)":\s*\{:(hex|git),\s*(?::([\w_]+)|"([^"]+)"),\s*"([^"]+)"(?:,\s*"([0-9a-f]{64})")?',
    re.MULTILINE,
)


class MixLockCataloger(Cataloger):
    id = "elixir/mix-lock"
    version = 1
    matchers = [Matcher(basename="mix.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in _MIX_RE.finditer(text):
            name, kind, hex_name, _git_url, version_or_rev, sha = m.groups()
            name = hex_name or name
            version = version_or_rev
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version,
                    purl=make_purl("hex", name, version) if kind == "hex" else None,
                    ecosystem="hex",
                    hashes=(("sha256", sha),) if sha else (),
                    attrs=(("vcs", "git"),) if kind == "git" else (),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=(line, line), captured=m.group(0)[:160],
                    ),
                ),
            )


# -- Haskell: stack.yaml.lock + cabal.project.freeze --------------------------------

_HACKAGE_RE = re.compile(r"^([\w\-]+?)-([\d.]+)@sha256:([0-9a-f]+)")


class StackLockCataloger(Cataloger):
    id = "haskell/stack-lock"
    version = 1
    matchers = [Matcher(basename="stack.yaml.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        for pkg in doc.get("packages") or []:
            completed = pkg.get("completed") if isinstance(pkg, dict) else None
            hackage = completed.get("hackage") if isinstance(completed, dict) else None
            if not isinstance(hackage, str):
                continue
            m = _HACKAGE_RE.match(hackage)
            if not m:
                continue
            name, version, sha = m.groups()
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version,
                    purl=make_purl("hackage", name, version),
                    ecosystem="hackage",
                    hashes=(("sha256", sha),),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=find_span(text, hackage), captured=hackage[:160],
                    ),
                ),
            )


_CABAL_CONSTRAINT_RE = re.compile(r"any\.([\w\-]+)\s*==\s*([\d.]+)")


class CabalFreezeCataloger(Cataloger):
    id = "haskell/cabal-freeze"
    version = 1
    matchers = [Matcher(basename="cabal.project.freeze")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in _CABAL_CONSTRAINT_RE.finditer(text):
            name, version = m.groups()
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version,
                    purl=make_purl("hackage", name, version),
                    ecosystem="hackage",
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=(line, line), captured=m.group(0),
                    ),
                ),
            )


# -- Swift: Package.resolved v1–v3 ---------------------------------------------------


class PackageResolvedCataloger(Cataloger):
    id = "swift/package-resolved"
    version = 1
    matchers = [Matcher(basename="Package.resolved")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        pins = (
            (doc.get("object") or {}).get("pins")  # v1
            if "object" in doc
            else doc.get("pins")  # v2/v3
        ) or []
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            name = pin.get("identity") or pin.get("package")
            url = pin.get("location") or pin.get("repositoryURL") or ""
            state = pin.get("state") or {}
            version = state.get("version")
            revision = state.get("revision")
            if not name or not (version or revision):
                continue
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=str(name),
                    version=str(version) if version else None,
                    purl=make_purl(
                        "swift",
                        str(name),
                        str(version) if version else None,
                        namespace=_swift_namespace(str(url)),
                    )
                    if version
                    else None,
                    ecosystem="swift",
                    attrs=(("revision", str(revision)),) if revision else (),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=find_span(text, f'"{name}"'),
                        captured=f"{name} {version or revision}",
                    ),
                ),
            )


def _swift_namespace(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([^/]+)/", url)
    return f"github.com/{m.group(1)}" if m else None


# -- CocoaPods: Podfile.lock (the PODS: section is the resolved graph) -----------------

_POD_RE = re.compile(r"^([\w+/\-.]+)\s*\(([^)]+)\)$")


class PodfileLockCataloger(Cataloger):
    id = "cocoapods/podfile-lock"
    version = 1
    matchers = [Matcher(basename="Podfile.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        for item in doc.get("PODS") or []:
            deps: list[object] = []
            if isinstance(item, str):
                spec = item
            elif isinstance(item, dict) and len(item) == 1:
                spec, raw_deps = next(iter(item.items()))
                if isinstance(raw_deps, list):
                    deps = raw_deps
            else:
                continue
            m = _POD_RE.match(str(spec).strip())
            if not m:
                continue
            name, version = m.groups()
            root_name = name.split("/", 1)[0]  # subspecs belong to the root pod
            purl = make_purl("cocoapods", root_name, version)
            edges = []
            for dep in deps or []:
                dm = re.match(r"^([\w+/\-.]+)", str(dep).strip())
                if dm:
                    edges.append(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=ref_purl(purl),
                            dst=ref_family("cocoapods", dm.group(1).split("/", 1)[0]),
                            scope=Scope.RUNTIME,
                            direct=False,
                        )
                    )
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=root_name,
                    version=version,
                    purl=purl,
                    ecosystem="cocoapods",
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=find_span(text, str(spec)), captured=str(spec),
                    ),
                ),
                edges=tuple(edges),
            )


# -- Carthage: Cartfile.resolved -------------------------------------------------------

_CARTFILE_RE = re.compile(r'^(github|git|binary)\s+"([^"]+)"\s+"([^"]+)"\s*$', re.MULTILINE)


class CartfileResolvedCataloger(Cataloger):
    id = "carthage/cartfile-resolved"
    version = 1
    matchers = [Matcher(basename="Cartfile.resolved")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in _CARTFILE_RE.finditer(text):
            kind, ref, version = m.groups()
            name = ref.rsplit("/", 1)[-1].removesuffix(".git").removesuffix(".json")
            namespace = ref.split("/", 1)[0] if kind == "github" and "/" in ref else None
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=ComponentClaim(
                    ctype="library",
                    name=name,
                    version=version.lstrip("v"),
                    purl=make_purl("github", name, version.lstrip("v"), namespace=namespace)
                    if kind == "github"
                    else None,
                    ecosystem="carthage",
                    attrs=(("source", ref),),
                ),
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=(line, line), captured=m.group(0),
                    ),
                ),
            )


# -- Zig: build.zig.zon -------------------------------------------------------------------

# innermost `.name = .{ ... }` blocks (no nested braces inside), url/hash within
_ZON_BLOCK_RE = re.compile(r"\.(?:@\")?([\w\-]+)\"?\s*=\s*\.\{([^{}]*)\}", re.DOTALL)
_ZON_URL_RE = re.compile(r"\.url\s*=\s*\"([^\"]+)\"")
_ZON_HASH_RE = re.compile(r"\.hash\s*=\s*\"([^\"]+)\"")
_ZON_VERSION_IN_URL_RE = re.compile(r"[/#-]v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)(?:\.tar|\.zip|/|$)")


class ZigZonCataloger(Cataloger):
    id = "zig/build-zon"
    version = 1
    matchers = [Matcher(basename="build.zig.zon")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        for m in _ZON_BLOCK_RE.finditer(text):
            name, body = m.groups()
            url_m = _ZON_URL_RE.search(body)
            if url_m is None:
                continue
            url = url_m.group(1)
            hash_m = _ZON_HASH_RE.search(body)
            hash_ = hash_m.group(1) if hash_m else None
            vm = _ZON_VERSION_IN_URL_RE.search(url)
            version = vm.group(1) if vm else None
            annotations: tuple[Annotation, ...] = ()
            claim = ComponentClaim(
                ctype="library",
                name=name,
                version=version,
                ecosystem="zig",
                hashes=(("zig-multihash", hash_),) if hash_ else (),
                attrs=(("url", url),),
            )
            if version is None:
                annotations = (
                    Annotation(
                        code="resolution-incomplete",
                        subject=claim.ref(),
                        detail=f"{name}: no version in the dependency URL; identified by "
                        "content hash only",
                    ),
                )
            line = text.count("\n", 0, m.start()) + 1
            yield Finding(
                claim=claim,
                evidence=(
                    ctx.evidence(
                        "lockfile-parse", Tier.LOCKED, entry,
                        span=(line, line), captured=f"{name} = {url}",
                    ),
                ),
                annotations=annotations,
            )


# -- Cargo.toml with workspace inheritance ---------------------------------------------------


class CargoTomlCataloger(Cataloger):
    id = "rust/cargo-toml"
    version = 1
    matchers = [Matcher(basename="Cargo.toml")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        proj_dir = dirname_of(entry.path)
        package = doc.get("package") or {}
        name = str(package.get("name", "")) if isinstance(package, dict) else ""
        if name:
            ctx.declare_project(proj_dir, name, "cargo-package")
        elif "workspace" in doc:
            ctx.declare_project(proj_dir, proj_dir or ".", "cargo-workspace")
        proj_ref = ref_project(proj_dir)

        workspace_deps = self._workspace_dependencies(ctx, doc, proj_dir)
        for section, scope in (
            ("dependencies", Scope.RUNTIME),
            ("dev-dependencies", Scope.DEV),
            ("build-dependencies", Scope.BUILD),
        ):
            deps = doc.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, spec in deps.items():
                version: str | None = None
                inherited = False
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    if spec.get("workspace") is True:
                        inherited = True
                        ws = workspace_deps.get(dep_name)
                        if isinstance(ws, str):
                            version = ws
                        elif isinstance(ws, dict):
                            version = str(ws.get("version")) if ws.get("version") else None
                    else:
                        version = str(spec.get("version")) if spec.get("version") else None
                requested = version
                # In Cargo a bare version string is shorthand for a caret
                # range: `anyhow = "1.0.75"` means ^1.0.75, so it is a
                # requirement and not the version that will be built. Only an
                # explicit `=x.y.z` pins one.
                pinned = version[1:].strip() if version and version.startswith("=") else None
                concrete = pinned is not None and re.fullmatch(r"[\d][\w.\-+]*", pinned) is not None
                version = pinned if concrete else None
                claim = ComponentClaim(
                    ctype="library",
                    name=dep_name,
                    version=version if concrete else None,
                    purl=make_purl("cargo", dep_name, version) if concrete else None,
                    ecosystem="cargo",
                    requested=None if concrete else requested,
                    attrs=(("workspace-inherited", "true"),) if inherited else (),
                )
                yield Finding(
                    claim=claim,
                    evidence=(
                        ctx.evidence(
                            "manifest-parse",
                            Tier.DECLARED,
                            entry,
                            span=find_span(text, dep_name),
                            captured=f"{dep_name} = {version or spec!r}"[:160],
                        ),
                    ),
                    edges=(
                        EdgeClaim(
                            kind=EdgeType.DEPENDS_ON,
                            src=proj_ref,
                            dst=ref_purl(claim.purl) if claim.purl else ref_family("cargo", dep_name),
                            scope=scope,
                            direct=True,
                            requested=requested,
                        ),
                    ),
                )

    def _workspace_dependencies(
        self, ctx: CatalogerContext, doc: dict[str, object], proj_dir: str
    ) -> dict[str, object]:
        """[workspace.dependencies] of this file or the nearest ancestor root."""
        ws = doc.get("workspace")
        if isinstance(ws, dict):
            ws_deps = ws.get("dependencies")
            if isinstance(ws_deps, dict):
                return dict(ws_deps)
        parts = proj_dir.split("/") if proj_dir != "." else []
        for depth in range(len(parts) - 1, -1, -1):
            prefix = "/".join(parts[:depth])
            candidate = f"{prefix}/Cargo.toml" if prefix else "Cargo.toml"
            raw = ctx.peek(candidate)
            if raw is None:
                continue
            try:
                root = tomllib.loads(raw.decode("utf-8", errors="replace"))
            except tomllib.TOMLDecodeError:
                continue
            root_ws = root.get("workspace")
            if isinstance(root_ws, dict):
                root_deps = root_ws.get("dependencies")
                if isinstance(root_deps, dict):
                    return dict(root_deps)
        return {}


register(MixLockCataloger())
register(StackLockCataloger())
register(CabalFreezeCataloger())
register(PackageResolvedCataloger())
register(PodfileLockCataloger())
register(CartfileResolvedCataloger())
register(ZigZonCataloger())
register(CargoTomlCataloger())
