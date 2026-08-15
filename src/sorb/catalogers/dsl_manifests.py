"""Manifests written in a programming language rather than a data format.

`Package.swift`, `build.sbt`, `MODULE.bazel`, `deps.edn`, `project.clj`,
`*.opam`, `dune-project`, `cpanfile` and `*.rockspec` are all *evaluated* by
their tool. Statically they can only be read conservatively, which is the whole
point of this module: a literal is a fact, an identifier is not.

Two rules hold throughout:

* **Only string literals become components.** A rockspec that says
  ``package = package_name`` names a Lua variable, not a package, and emitting
  `package_name` as a dependency would be a fabrication.
* **A constraint is a request, not a version.** `cpanfile`'s ``requires 'X',
  '1.0'`` means *at least* 1.0, and Swift's ``from:`` means "up to the next
  major", so both are recorded as `requested` with a versionless purl.

Where a file evidently computes its dependencies, the scope of what static
reading can see is recorded as `unresolved-dynamic-manifest` (`SORB-W012`)
rather than being passed off as complete.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator

from sorb.catalogers.base import Cataloger, CatalogerContext, Matcher, find_span, register
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


def _emit(
    ctx: CatalogerContext,
    entry: Entry,
    text: str,
    *,
    proj_ref: str,
    purl_type: str,
    name: str,
    version: str | None,
    requested: str | None,
    anchor: str,
    scope: Scope = Scope.RUNTIME,
    namespace: str | None = None,
    attrs: tuple[tuple[str, str], ...] = (),
) -> Finding:
    """One declared dependency, with its span anchored on the source text."""
    purl = make_purl(purl_type, name, version, namespace=namespace) if version else None
    claim = ComponentClaim(
        ctype="library",
        name=f"{namespace}/{name}" if namespace and purl_type == "maven" else name,
        version=version,
        purl=purl,
        ecosystem=purl_type,
        namespace=namespace,
        requested=requested,
        attrs=attrs,
    )
    return Finding(
        claim=claim,
        evidence=(
            ctx.evidence(
                "manifest-parse", Tier.DECLARED, entry,
                span=find_span(text, anchor), captured=anchor[:160],
            ),
        ),
        edges=(
            EdgeClaim(
                kind=EdgeType.DEPENDS_ON, src=proj_ref,
                dst=ref_purl(purl) if purl else ref_family(purl_type, name),
                scope=scope, direct=True, requested=requested,
            ),
        ),
    )


def _dynamic(subject: str, detail: str) -> Annotation:
    return Annotation(code="unresolved-dynamic-manifest", subject=subject, detail=detail)


# -- Swift Package.swift ---------------------------------------------------------

#: `.package(url: "…", from: "1.1.0")` and its exact/branch/revision variants.
_SWIFT_PKG_RE = re.compile(
    r"\.package\(\s*(?:name:\s*\"[^\"]*\"\s*,\s*)?url:\s*\"(?P<url>[^\"]+)\""
    r"(?P<rest>[^)]*)\)",
    re.DOTALL,
)
_SWIFT_EXACT_RE = re.compile(r"exact:\s*\"(?P<v>[^\"]+)\"")
_SWIFT_RANGE_RE = re.compile(r"(?:from|upToNextMajor|upToNextMinor)\s*:?\s*\"(?P<v>[^\"]+)\"")
_SWIFT_PIN_RE = re.compile(r"(?:revision|branch):\s*\"(?P<v>[^\"]+)\"")


class PackageSwiftCataloger(Cataloger):
    """`Package.swift` — the declared side; `Package.resolved` has the pins."""

    id = "swift/package-swift"
    version = 1
    matchers = [Matcher(basename="Package.swift")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        seen: set[str] = set()
        for m in _SWIFT_PKG_RE.finditer(text):
            url = m.group("url")
            name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            if not name or name in seen:
                continue
            seen.add(name)
            rest = m.group("rest")
            exact = _SWIFT_EXACT_RE.search(rest)
            loose = _SWIFT_RANGE_RE.search(rest) or _SWIFT_PIN_RE.search(rest)
            version = exact.group("v") if exact else None
            requested = None if exact else (loose.group("v") if loose else None)
            namespace = _git_namespace(url)
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="swift", name=name,
                version=version, requested=requested, anchor=m.group(0)[:80],
                namespace=namespace, attrs=(("source-url", url),),
            )
        # `.package(path: …)` is a local checkout, not a released package.
        if "if " in text and ".package(" in text:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:conditional"),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured="conditional package list"),),
                annotations=(
                    _dynamic(
                        ref_project(proj_dir),
                        "Package.swift selects dependencies with Swift control flow; only "
                        "the literal `.package(url:)` entries are visible statically",
                    ),
                ),
            )


def _git_namespace(url: str) -> str | None:
    m = re.search(r"(?:github\.com|gitlab\.com)[:/]([^/]+)/", url)
    return m.group(1) if m else None


# -- Scala build.sbt -------------------------------------------------------------

#: `"group" %% "artifact" % "version"` — `%%` appends the Scala binary version
#: to the artifact, which is why it is recorded rather than folded into the name.
_SBT_DEP_RE = re.compile(
    r"\"(?P<group>[\w.\-]+)\"\s*(?P<sep>%%?)\s*\"(?P<artifact>[\w.\-]+)\"\s*%\s*\"(?P<version>[^\"]+)\""
)


class BuildSbtCataloger(Cataloger):
    """`build.sbt` / `project/*.scala` — inline `libraryDependencies` entries."""

    id = "jvm/build-sbt"
    version = 1
    matchers = [Matcher(basename="build.sbt"), Matcher(glob="*project/*.scala")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        seen: set[tuple[str, str]] = set()
        found = False
        for m in _SBT_DEP_RE.finditer(text):
            group, artifact = m.group("group"), m.group("artifact")
            version = m.group("version")
            if version.startswith("$") or "(" in version:  # an interpolated val
                continue
            if (group, artifact) in seen:
                continue
            seen.add((group, artifact))
            found = True
            attrs: tuple[tuple[str, str], ...] = ()
            if m.group("sep") == "%%":
                attrs = (("scala-binary-suffix", "true"),)
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="maven", name=artifact,
                version=version, requested=None, anchor=m.group(0), namespace=group,
                attrs=attrs,
            )
        if not found and "libraryDependencies" in text:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:dynamic"),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured="libraryDependencies without literals"),),
                annotations=(
                    _dynamic(
                        ref_project(dirname_of(entry.path)),
                        "build.sbt declares libraryDependencies through Scala values "
                        "(commonly project/Dependencies.scala); no literal coordinates here",
                    ),
                ),
            )


# -- Bazel MODULE.bazel ----------------------------------------------------------

_BAZEL_DEP_RE = re.compile(
    r"bazel_dep\(\s*name\s*=\s*\"(?P<name>[^\"]+)\"\s*,\s*version\s*=\s*\"(?P<version>[^\"]+)\""
)


class BazelModuleCataloger(Cataloger):
    """`MODULE.bazel` — bzlmod's `bazel_dep` entries are literal and pinned."""

    id = "bazel/module"
    version = 1
    matchers = [Matcher(basename="MODULE.bazel")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        seen: set[str] = set()
        for m in _BAZEL_DEP_RE.finditer(text):
            name = m.group("name")
            if name in seen:
                continue
            seen.add(name)
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="bazel", name=name,
                version=m.group("version"), requested=None, anchor=m.group(0),
            )


# -- Clojure ---------------------------------------------------------------------

#: `org.clojure/clojure {:mvn/version "1.12.5"}` inside `:deps`.
_EDN_MVN_RE = re.compile(
    r"(?P<coord>[\w.\-]+(?:/[\w.\-]+)?)\s*\{\s*:mvn/version\s+\"(?P<version>[^\"]+)\""
)
#: `[ring/ring-core "1.15.5"]` inside Leiningen's `:dependencies` vector.
_LEIN_DEP_RE = re.compile(r"\[\s*(?P<coord>[\w.\-]+(?:/[\w.\-]+)?)\s+\"(?P<version>[^\"]+)\"")


def _clojure_coord(coord: str) -> tuple[str, str]:
    """`group/artifact` → (group, artifact); a bare name is its own group."""
    group, _, artifact = coord.partition("/")
    return (group, artifact) if artifact else (group, group)


class ClojureDepsCataloger(Cataloger):
    """`deps.edn` and `project.clj` — Clojure resolves Maven coordinates."""

    id = "clojure/deps"
    version = 1
    matchers = [Matcher(basename="deps.edn"), Matcher(basename="project.clj")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        pattern = _EDN_MVN_RE if entry.path.endswith("deps.edn") else _LEIN_DEP_RE
        seen: set[tuple[str, str]] = set()
        local_roots = text.count(":local/root")
        for m in pattern.finditer(text):
            group, artifact = _clojure_coord(m.group("coord"))
            if (group, artifact) in seen:
                continue
            seen.add((group, artifact))
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="maven", name=artifact,
                version=m.group("version"), requested=None, anchor=m.group(0), namespace=group,
            )
        if local_roots:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:local-roots"),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured=f"{local_roots} :local/root dependencies"),),
                annotations=(
                    Annotation(
                        code="local-path-dependency",
                        subject=ref_project(dirname_of(entry.path)),
                        detail=f"{local_roots} dependencies resolve to local paths "
                        "(:local/root); they are source checkouts, not released packages",
                    ),
                ),
            )


# -- OCaml -----------------------------------------------------------------------

#: An opam `depends:` entry: `"pkg" {>= "1.0"}`; the filter is a constraint.
_OPAM_DEP_RE = re.compile(r"\"(?P<name>[A-Za-z0-9_.\-+]+)\"\s*(?:\{(?P<filter>[^}]*)\})?")
_OPAM_VERSION_RE = re.compile(r"(?P<op>[<>=!]+)\s*\"(?P<v>[^\"]+)\"")


def _block(text: str, opener: str) -> str | None:
    """The bracketed block following `opener`, brackets balanced."""
    idx = text.find(opener)
    if idx < 0:
        return None
    start = idx + len(opener) - 1
    pairs = {"[": "]", "(": ")", "{": "}"}
    close = pairs.get(text[start])
    if close is None:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == text[start]:
            depth += 1
        elif text[i] == close:
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    return None


class OpamCataloger(Cataloger):
    """`*.opam` and `dune-project` — OCaml's declared dependencies."""

    id = "ocaml/opam"
    version = 1
    matchers = [Matcher(basename="*.opam"), Matcher(basename="dune-project")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        if entry.path.endswith("dune-project"):
            yield from self._dune(ctx, entry, text, proj_ref)
            return
        body = _block(text, "depends: [")
        if body is None:
            return
        for m in _OPAM_DEP_RE.finditer(body):
            name = m.group("name")
            filt = m.group("filter") or ""
            ver = _OPAM_VERSION_RE.search(filt)
            # `{= version}` refers to *this* package's version, not a literal.
            exact = ver is not None and ver.group("op") == "=" and "version" not in filt
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="opam", name=name,
                version=ver.group("v") if exact and ver else None,
                requested=(f"{ver.group('op')}{ver.group('v')}" if ver and not exact else None),
                anchor=f'"{name}"',
            )

    def _dune(
        self, ctx: CatalogerContext, entry: Entry, text: str, proj_ref: str
    ) -> Iterator[Finding]:
        body = _block(text, "(depends")
        if body is None:
            return
        # entries are `name` or `(name (>= 1.0))`; comments start with ;
        cleaned = re.sub(r";[^\n]*", "", body)
        for m in re.finditer(r"\(?\s*(?P<name>[A-Za-z0-9_.\-+]+)(?P<rest>[^()]*)", cleaned):
            name = m.group("name")
            if name in ("and", "or", "not"):
                continue
            ver = re.search(r"(?P<op>[<>=]+)\s*(?P<v>[\w.]+)", m.group("rest") or "")
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="opam", name=name,
                version=None,
                requested=f"{ver.group('op')}{ver.group('v')}" if ver else None,
                anchor=name,
            )


# -- Perl ------------------------------------------------------------------------

#: `requires 'Name', '1.0';` — the version is a *minimum*, never an equality.
_CPAN_REQ_RE = re.compile(
    r"^\s*(?P<kind>requires|recommends|suggests|test_requires)\s+"
    r"['\"](?P<name>[\w:]+)['\"]\s*(?:,\s*['\"](?P<version>[^'\"]+)['\"])?",
    re.MULTILINE,
)
_CPAN_PHASE_RE = re.compile(r"^\s*on\s+['\"](?P<phase>\w+)['\"]", re.MULTILINE)


class CpanfileCataloger(Cataloger):
    """`cpanfile` — Perl prerequisites."""

    id = "perl/cpanfile"
    version = 1
    matchers = [Matcher(basename="cpanfile")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        phases = [(m.start(), m.group("phase")) for m in _CPAN_PHASE_RE.finditer(text)]
        for m in _CPAN_REQ_RE.finditer(text):
            name = m.group("name")
            if name == "perl":  # the interpreter, not a distribution
                continue
            phase = next((p for pos, p in reversed(phases) if pos < m.start()), "runtime")
            scope = Scope.TEST if phase in ("test", "develop") else Scope.RUNTIME
            if m.group("kind") in ("test_requires",):
                scope = Scope.TEST
            version = m.group("version")
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="cpan", name=name,
                version=None,  # a cpanfile version is a minimum, not a pin
                requested=f">={version}" if version else None,
                anchor=m.group(0).strip(), scope=scope,
            )


class PerlMetaCataloger(Cataloger):
    """`META.json` — a CPAN distribution's declared prereqs (CPAN::Meta v2)."""

    id = "perl/meta-json"
    version = 1
    matchers = [Matcher(basename="META.json")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError as e:
            raise DetectorFailure(str(e), path=entry.path, detector=self.detector) from e
        if not isinstance(doc, dict) or "prereqs" not in doc:
            return  # some other META.json; claim nothing
        text = blob.decode("utf-8", errors="replace")
        proj_ref = ref_project(dirname_of(entry.path))
        for phase, kinds in (doc.get("prereqs") or {}).items():
            if not isinstance(kinds, dict):
                continue
            scope = Scope.TEST if phase in ("test", "develop") else Scope.RUNTIME
            for kind, deps in kinds.items():
                if kind != "requires" or not isinstance(deps, dict):
                    continue
                for name, constraint in deps.items():
                    if name == "perl":
                        continue
                    text_c = str(constraint)
                    yield _emit(
                        ctx, entry, text, proj_ref=proj_ref, purl_type="cpan", name=str(name),
                        version=None,
                        requested=f">={text_c}" if text_c not in ("0", "") else None,
                        anchor=f'"{name}"', scope=scope,
                    )


# -- Lua rockspec ----------------------------------------------------------------

_ROCK_ASSIGN_RE = re.compile(r"^\s*(?P<key>package|version)\s*=\s*\"(?P<value>[^\"]+)\"", re.MULTILINE)
_ROCK_DEP_RE = re.compile(r"\"(?P<spec>[A-Za-z0-9_.\-]+(?:\s*[<>=~]+\s*[\w.\-]+)?)\"")


class RockspecCataloger(Cataloger):
    """`*.rockspec` — LuaRocks.

    A rockspec is Lua source: `package = package_name` assigns a *variable*.
    Only string literals are believed; anything computed is annotated instead.
    """

    id = "lua/rockspec"
    version = 1
    matchers = [Matcher(basename="*.rockspec")]

    def parse(self, ctx: CatalogerContext, entry: Entry, blob: bytes) -> Iterable[Finding]:
        text = blob.decode("utf-8", errors="replace")
        proj_dir = dirname_of(entry.path)
        proj_ref = ref_project(proj_dir)
        literals = {m.group("key"): m.group("value") for m in _ROCK_ASSIGN_RE.finditer(text)}
        if "package" not in literals:
            yield Finding(
                claim=ComponentClaim(ctype="edge-only", name=f"{entry.path}:computed"),
                evidence=(ctx.evidence("manifest-parse", Tier.DECLARED, entry,
                                       captured="package/version computed in Lua"),),
                annotations=(
                    _dynamic(
                        proj_ref,
                        "the rockspec builds its package name/version from Lua variables; "
                        "only its literal dependencies are readable statically",
                    ),
                ),
            )
        body = _block(text, "dependencies = {")
        if body is None:
            return
        for m in _ROCK_DEP_RE.finditer(body):
            spec = m.group("spec").strip()
            parts = re.split(r"\s*([<>=~]+)\s*", spec, maxsplit=1)
            name = parts[0].strip()
            if not name or name == "lua":  # the interpreter itself
                continue
            requested = "".join(parts[1:]).strip() or None
            yield _emit(
                ctx, entry, text, proj_ref=proj_ref, purl_type="luarocks", name=name,
                version=None, requested=requested, anchor=m.group(0),
            )


register(PackageSwiftCataloger())
register(BuildSbtCataloger())
register(BazelModuleCataloger())
register(ClojureDepsCataloger())
register(OpamCataloger())
register(CpanfileCataloger())
register(PerlMetaCataloger())
register(RockspecCataloger())
