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
from dataclasses import dataclass

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


# -- conda environment.yml -------------------------------------------------------

#: A conda match spec: `[channel::]name[ op version[=build]]`. Conda accepts the
#: operator attached (`numpy=1.26`), spaced (`numpy >=1.26`), or absent.
_CONDA_SPEC_RE = re.compile(
    r"^(?:(?P<channel>[^\s:]+)::)?"
    r"(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*(?P<rest>.+))?$"
)
_CONDA_OPS = ("==", ">=", "<=", "!=", "~=", ">", "<", "=")


@dataclass(frozen=True)
class CondaSpec:
    """One parsed conda dependency line."""

    name: str
    version: str | None  # only when the spec pins exactly
    requested: str | None  # the constraint as written, when it is not exact
    build: str | None
    channel: str | None


def parse_conda_spec(raw: str) -> CondaSpec | None:
    """Parse a conda match spec.

    Only `==` pins a version. Conda's bare `=` is a *fuzzy* pin — `numpy=1.26.4`
    matches `1.26.4.1` too — so it is recorded as a request, exactly as an npm
    caret range is, rather than asserting a version that may never have been
    built.
    """
    text = raw.strip()
    if not text or text.startswith("#"):
        return None
    m = _CONDA_SPEC_RE.match(text)
    if not m:
        return None
    name = m.group("name")
    rest = (m.group("rest") or "").strip()
    if not rest:
        return CondaSpec(name, None, None, None, m.group("channel"))

    for op in _CONDA_OPS:
        if rest.startswith(op):
            value = rest[len(op) :].strip()
            break
    else:  # space-separated form: `numpy 1.26.4`
        op, value = "=", rest

    build: str | None = None
    if op == "=" and "=" in value:  # name=version=build
        value, _, build = value.partition("=")
    if not value:
        return CondaSpec(name, None, None, build, m.group("channel"))
    exact = op == "=="
    return CondaSpec(
        name=name,
        version=value if exact else None,
        requested=None if exact else f"{op}{value}",
        build=build,
        channel=m.group("channel"),
    )


class CondaEnvironmentCataloger(Cataloger):
    """`environment.yml` — the declared conda environment.

    The nested `pip:` list is a different ecosystem living in the same file, so
    those entries are emitted as PyPI rather than conda.
    """

    id = "conda/environment"
    version = 1
    matchers = [
        Matcher(basename="environment.yml"),
        Matcher(basename="environment.yaml"),
        Matcher(basename="conda-lock.yml"),
    ]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict):
            return
        proj_dir = dirname_of(entry.path)
        ctx.declare_project(proj_dir, str(doc.get("name") or proj_dir or "."), "conda")
        proj_ref = ref_project(proj_dir)

        for item in doc.get("dependencies") or []:
            if isinstance(item, str):
                yield from self._conda_dep(ctx, entry, text, item, proj_ref)
            elif isinstance(item, dict):
                for nested in item.get("pip") or []:
                    if isinstance(nested, str):
                        yield from self._pip_dep(ctx, entry, text, nested, proj_ref)

    def _conda_dep(
        self, ctx: CatalogerContext, entry: Entry, text: str, raw: str, proj_ref: str
    ) -> Iterable[Finding]:
        spec = parse_conda_spec(raw)
        if spec is None:
            return
        attrs: tuple[tuple[str, str], ...] = ()
        if spec.build:
            attrs += (("conda-build", spec.build),)
        if spec.channel:
            attrs += (("conda-channel", spec.channel),)
        purl = make_purl("conda", spec.name, spec.version) if spec.version else None
        claim = ComponentClaim(
            ctype="library", name=spec.name, version=spec.version, purl=purl,
            ecosystem="conda", requested=spec.requested, attrs=attrs,
        )
        yield Finding(
            claim=claim,
            evidence=(
                ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                             span=find_span(text, raw), captured=raw.strip()),
            ),
            edges=(
                EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                          dst=ref_purl(purl) if purl else ref_family("conda", spec.name),
                          scope=Scope.RUNTIME, direct=True, requested=spec.requested),
            ),
        )

    def _pip_dep(
        self, ctx: CatalogerContext, entry: Entry, text: str, raw: str, proj_ref: str
    ) -> Iterable[Finding]:
        from packaging.requirements import InvalidRequirement, Requirement

        try:
            req = Requirement(raw)
        except InvalidRequirement:
            return
        pinned = [s for s in req.specifier if s.operator in ("==", "===")]
        version = pinned[0].version if len(pinned) == 1 else None
        name = req.name.lower().replace("_", "-")
        purl = make_purl("pypi", name, version) if version else None
        claim = ComponentClaim(
            ctype="library", name=name, version=version, purl=purl, ecosystem="pypi",
            requested=str(req.specifier) or None,
            attrs=(("declared-in", "conda-pip-section"),),
        )
        yield Finding(
            claim=claim,
            evidence=(
                ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                             span=find_span(text, raw), captured=raw.strip()),
            ),
            edges=(
                EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref,
                          dst=ref_purl(purl) if purl else ref_family("pypi", name),
                          scope=Scope.RUNTIME, direct=True,
                          requested=str(req.specifier) or None),
            ),
        )


register(CondaEnvironmentCataloger())


# -- Erlang rebar.lock -----------------------------------------------------------

#: `{<<"name">>,{pkg,<<"name">>,<<"version">>},level}` — a Hex package entry in
#: rebar's Erlang-term lockfile. Git and path deps use other shapes and are not
#: released packages, so they are left alone.
_REBAR_PKG_RE = re.compile(
    r'\{<<"(?P<name>[^"]+)">>\s*,\s*\{pkg\s*,\s*<<"[^"]+">>\s*,\s*<<"(?P<version>[^"]+)">>\}'
)
#: The `pkg_hash` section maps the same names to their upper-case hex digests.
_REBAR_HASH_RE = re.compile(r'\{<<"(?P<name>[^"]+)">>\s*,\s*<<"(?P<digest>[0-9A-Fa-f]{64})">>\}')


class RebarLockCataloger(Cataloger):
    """`rebar.lock` — Erlang/Hex, the same registry Elixir's mix.lock uses."""

    id = "erlang/rebar-lock"
    version = 1
    matchers = [Matcher(basename="rebar.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        digests = {m.group("name"): m.group("digest").lower() for m in _REBAR_HASH_RE.finditer(text)}
        proj_ref = ref_project(dirname_of(entry.path))
        seen: set[str] = set()
        for m in _REBAR_PKG_RE.finditer(text):
            name, version = m.group("name"), m.group("version")
            if name in seen:
                continue
            seen.add(name)
            purl = make_purl("hex", name, version)
            digest = digests.get(name)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=version, purl=purl, ecosystem="hex",
                    hashes=(("sha256", digest),) if digest else (),
                ),
                evidence=(
                    ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                 span=find_span(text, m.group(0)[:40]),
                                 captured=m.group(0)[:120]),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                              scope=Scope.RUNTIME, direct=False),
                ),
            )


# -- Paket (.NET) ----------------------------------------------------------------

#: A resolved package sits at four-space indent with its exact version in
#: parentheses: `    Argu (6.1.1)`. Its own requirements are nested deeper and
#: are *ranges* (`      FSharp.Core (>= 4.3.2)`), never resolutions.
_PAKET_RESOLVED_RE = re.compile(r"^ {4}(?P<name>\S+) \((?P<version>[^)<>=!~ ]+)\)")


class PaketLockCataloger(Cataloger):
    """`paket.lock` — Paket's resolved NuGet graph."""

    id = "dotnet/paket-lock"
    version = 1
    matchers = [Matcher(basename="paket.lock")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        source = ""
        seen: set[tuple[str, str]] = set()
        for lineno, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            if stripped in ("NUGET", "GITHUB", "GIT", "HTTP"):
                source = stripped
                continue
            if source != "NUGET":  # only NuGet entries are versioned packages
                continue
            m = _PAKET_RESOLVED_RE.match(raw)
            if not m:
                continue
            name, version = m.group("name"), m.group("version")
            if (name, version) in seen:
                continue
            seen.add((name, version))
            purl = make_purl("nuget", name, version)
            yield Finding(
                claim=ComponentClaim(
                    ctype="library", name=name, version=version, purl=purl, ecosystem="nuget",
                ),
                evidence=(
                    ctx.evidence("lockfile-parse", Tier.LOCKED, entry,
                                 span=(lineno, lineno), captured=stripped[:120]),
                ),
                edges=(
                    EdgeClaim(kind=EdgeType.DEPENDS_ON, src=proj_ref, dst=ref_purl(purl),
                              scope=Scope.RUNTIME, direct=False),
                ),
            )


register(RebarLockCataloger())
register(PaketLockCataloger())
